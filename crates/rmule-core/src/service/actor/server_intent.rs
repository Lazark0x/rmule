//! The operator's intent to stay connected (ADR-0093, "A lost session is
//! re-made"). A `ConnectToServer` says *stay connected to this server*;
//! the intent outlives one TCP link and ends when the operator disconnects,
//! connects elsewhere, or quits. While it stands, a lost session is re-made
//! through the one establishment — listener, mapping wait, login — after a
//! delay that grows to a ceiling and then repeats at it, for as long as the
//! intent stands, and only ever to the server the operator chose. Nothing of it is durable: after a
//! restart only Autoconnect dials.

use std::time::Duration;

use rmule_primitives::ServerEndpoint;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};
use crate::run_log::Level;
use crate::search::LostServerLeg;
use crate::server_session::ServerSessionHandle;
use crate::service::{CoreEvent, ReconnectEnd, ServerConnectionEvent};

use super::{CoreActor, send_event};

/// How many times rmule re-dials a lost session before it gives up and waits
/// for the operator: `None`, never — it keeps trying every
/// `CoreConfig::server_reconnect_ceiling` (10 min) until the operator
/// disconnects, as aMule does (`CS_RETRYCONNECTTIME`,
/// `ServerConnect.cpp:424-430`), so an overnight run does not end
/// disconnected (ADR-0096, "How many attempts"). The human's ruling
/// asked for a growing delay, not for a count; `Some(12)` bounds the tries
/// (the last attempt about 85 minutes after the loss).
pub const RECONNECT_ATTEMPTS: Option<u32> = None;

/// The delay before attempt `attempt` (from 1): `first`, doubling each
/// attempt, never past `ceiling`.
pub(crate) fn reconnect_delay(attempt: u32, first: Duration, ceiling: Duration) -> Duration {
    let doublings = attempt.saturating_sub(1).min(16);
    first.saturating_mul(1 << doublings).min(ceiling)
}

/// One standing intent: the server, and where its retries stand. Its logins
/// present the Core Settings' credentials.
pub(super) struct ServerIntent {
    server: ServerEndpoint,
    /// Which intent this is, so news about an earlier one's session is told
    /// apart.
    epoch: u64,
    /// `0` while the operator's own connect is in flight or a session stands;
    /// otherwise the number of the next (or running) retry.
    attempt: u32,
    /// The standing session: when it came up, and the retry it came up on.
    /// Its loss before `CoreConfig::server_session_holds` continues the count
    /// from that retry; a loss after it starts the count over.
    standing: Option<(Instant, u32)>,
    /// When the next retry dials; `None` while none is pending.
    retry_at: Option<Instant>,
}

/// What an establishment or a session under an intent reports back.
pub(super) enum IntentNews {
    /// A dial under intent `epoch` installed `session`.
    Established {
        epoch: u64,
        session: ServerSessionHandle,
    },
    /// A dial under intent `epoch` produced no session.
    Failed { epoch: u64 },
    /// The session a dial under intent `epoch` installed has ended.
    Ended { epoch: u64 },
}

/// The actor's intent ledger: the standing intent, the epoch counter, and the
/// lane its dials and sessions report on.
pub(super) struct IntentLedger {
    current: Option<ServerIntent>,
    epoch: u64,
    news_tx: mpsc::UnboundedSender<IntentNews>,
    news_rx: Option<mpsc::UnboundedReceiver<IntentNews>>,
    /// Where a search's server leg says its session ended unanswered.
    lost_legs_tx: mpsc::UnboundedSender<LostServerLeg>,
    lost_legs_rx: Option<mpsc::UnboundedReceiver<LostServerLeg>>,
}

impl Default for IntentLedger {
    fn default() -> Self {
        let (news_tx, news_rx) = mpsc::unbounded_channel();
        let (lost_legs_tx, lost_legs_rx) = mpsc::unbounded_channel();
        Self {
            current: None,
            epoch: 0,
            news_tx,
            news_rx: Some(news_rx),
            lost_legs_tx,
            lost_legs_rx: Some(lost_legs_rx),
        }
    }
}

impl IntentLedger {
    /// The news lane, taken once by the actor's loop.
    pub(super) fn take_news(&mut self) -> mpsc::UnboundedReceiver<IntentNews> {
        self.news_rx
            .take()
            .expect("the intent news lane is taken once")
    }

    /// The lost-leg lane, taken once by the actor's loop.
    pub(super) fn take_lost_legs(&mut self) -> mpsc::UnboundedReceiver<LostServerLeg> {
        self.lost_legs_rx
            .take()
            .expect("the lost-leg lane is taken once")
    }

    /// Where a search task reports its server leg lost.
    pub(super) fn lost_legs(&self) -> mpsc::UnboundedSender<LostServerLeg> {
        self.lost_legs_tx.clone()
    }

    /// Whether the operator's intent to stay connected stands.
    pub(super) const fn stands(&self) -> bool {
        self.current.is_some()
    }

    /// When the pending retry dials, if one is pending.
    pub(super) fn retry_at(&self) -> Option<Instant> {
        self.current.as_ref().and_then(|intent| intent.retry_at)
    }

    /// Where a dial under the current intent reports.
    pub(super) fn reporter(&self) -> (u64, mpsc::UnboundedSender<IntentNews>) {
        (self.epoch, self.news_tx.clone())
    }
}

/// Sleep until `at`; never, with none.
pub(super) async fn until_retry(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// The operator connects to `server`: a new intent replaces whatever
    /// stood, a retry to another server included, which is said.
    pub(super) async fn begin_intent(&mut self, server: ServerEndpoint) {
        if let Some(old) = self.intent.current.take()
            && old.attempt > 0
            && old.server != server
        {
            self.end_reconnect(old.server, ReconnectEnd::Replaced).await;
        }
        self.intent.epoch += 1;
        self.intent.current = Some(ServerIntent {
            server,
            epoch: self.intent.epoch,
            attempt: 0,
            standing: None,
            retry_at: None,
        });
    }

    /// `DisconnectFromServer`: the intent ends, a retry pending or in flight
    /// is dropped and said so, and the live session is hung up.
    pub(super) async fn on_disconnect_from_server(&mut self) {
        self.intent.epoch += 1;
        if let Some(intent) = self.intent.current.take()
            && intent.attempt > 0
        {
            self.end_reconnect(intent.server, ReconnectEnd::OperatorDisconnected)
                .await;
        }
        self.end_waiting_server_legs();
        let live = self.wiring.shared_server_session.slot().lock().await.take();
        if let Some(live) = live {
            // Its own task says `Disconnected` once it is down.
            tokio::spawn(async move { live.disconnect().await });
        }
    }

    /// What a dial or a session under an intent reported.
    pub(super) async fn on_intent_news(&mut self, news: IntentNews) {
        match news {
            IntentNews::Established { epoch, session } => {
                if self.current_epoch() == Some(epoch) {
                    if let Some(intent) = self.intent.current.as_mut() {
                        intent.standing = Some((Instant::now(), intent.attempt));
                        intent.attempt = 0;
                    }
                    let lane = self.intent.news_tx.clone();
                    tokio::spawn(async move {
                        session.closed().await;
                        let _ = lane.send(IntentNews::Ended { epoch });
                    });
                } else if self.intent.current.is_none() {
                    // The operator disconnected while this dial ran.
                    tokio::spawn(async move { session.disconnect().await });
                }
            }
            IntentNews::Failed { epoch } => {
                let Some(intent) = self.intent.current.as_ref() else {
                    return;
                };
                if intent.epoch != epoch {
                    return;
                }
                if intent.attempt == 0 {
                    // The operator's own connect failed: shown as
                    // `ConnectFailed`, and not retried — aMule's single
                    // connect is not either (`ServerConnect.cpp:456-466`).
                    self.intent.current = None;
                    self.end_waiting_server_legs();
                } else {
                    self.schedule_retry().await;
                }
            }
            IntentNews::Ended { epoch } => {
                if self.current_epoch() != Some(epoch) {
                    return;
                }
                let holds = self.wiring.config.server_session_holds;
                if let Some(intent) = self.intent.current.as_mut()
                    && let Some((since, came_up_on)) = intent.standing.take()
                    && since.elapsed() < holds
                {
                    intent.attempt = came_up_on;
                }
                self.schedule_retry().await;
            }
        }
    }

    /// The pending retry is due: dial the chosen server again, through the
    /// one establishment, if it is still listed.
    pub(super) async fn on_reconnect_due(&mut self) {
        let Some(intent) = self.intent.current.as_mut() else {
            return;
        };
        intent.retry_at = None;
        let server = intent.server.clone();
        let listed = self
            .wiring
            .server_list
            .servers()
            .is_ok_and(|rows| rows.iter().any(|row| row.endpoint == server));
        if !listed {
            self.intent.current = None;
            self.end_waiting_server_legs();
            self.end_reconnect(server, ReconnectEnd::Unlisted).await;
            return;
        }
        if self
            .server_connect_in_flight
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            // A dial is already running; its news decides what follows.
            return;
        }
        self.establish(server).await;
    }

    fn current_epoch(&self) -> Option<u64> {
        self.intent.current.as_ref().map(|intent| intent.epoch)
    }

    /// The session is gone, or a retry failed: the next attempt, or the end.
    async fn schedule_retry(&mut self) {
        let Some(intent) = self.intent.current.as_mut() else {
            return;
        };
        intent.attempt += 1;
        let bound = self.wiring.config.server_reconnect_attempts;
        if let Some(attempts) = bound.filter(|attempts| intent.attempt > *attempts) {
            let server = intent.server.clone();
            self.intent.current = None;
            self.end_waiting_server_legs();
            self.end_reconnect(server, ReconnectEnd::AttemptsSpent { attempts })
                .await;
            return;
        }
        let ceiling = self.wiring.config.server_reconnect_ceiling;
        let next_in = reconnect_delay(
            intent.attempt,
            self.wiring.config.server_reconnect_first,
            ceiling,
        );
        let at = Instant::now() + next_in;
        intent.retry_at = Some(at);
        let event = ServerConnectionEvent::Reconnecting {
            server: intent.server.clone(),
            attempt: intent.attempt,
            bound,
            next_in,
            at: at.into_std(),
            steady: next_in >= ceiling,
        };
        tracing::info!(
            record = %event.record().render(Level::Full),
            "the operator's session was lost; reconnecting"
        );
        send_event(&self.evt_tx, CoreEvent::ServerConnection(event)).await;
    }

    async fn end_reconnect(&mut self, server: ServerEndpoint, reason: ReconnectEnd) {
        let event = ServerConnectionEvent::ReconnectEnded { server, reason };
        tracing::info!(
            record = %event.record().render(Level::Full),
            "no more reconnects"
        );
        send_event(&self.evt_tx, CoreEvent::ServerConnection(event)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_delay_starts_at_amules_thirty_seconds_doubles_and_stops_at_ten_minutes() {
        let config = crate::CoreConfig::default();
        let delays: Vec<u64> = (1..=12)
            .map(|attempt| {
                reconnect_delay(
                    attempt,
                    config.server_reconnect_first,
                    config.server_reconnect_ceiling,
                )
                .as_secs()
            })
            .collect();
        assert_eq!(
            delays,
            [30, 60, 120, 240, 480, 600, 600, 600, 600, 600, 600, 600]
        );
    }
}
