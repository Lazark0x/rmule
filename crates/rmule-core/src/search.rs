//! The search activity: one query, three surfaces. The connected server answers
//! over TCP, the server-UDP sweep asks the managed list in parallel (ADR-0051),
//! and the Kad keyword leg asks the DHT (ADR-0062); [`SearchTask`] merges all
//! three into one deduplicated result set and completes once every leg has
//! settled and a quiet window has passed — never while a leg is
//! still due to answer. Searches run side by side and none waits on another:
//! the eD2k answers, which name no search, reach each search through **Search
//! Attribution** ([`LiveSearches`], ADR-0034), and Kad rows
//! through the walk on the search's lead keyword, screened by its own query.
//!
//! A completed search whose server holds more rows waits, unregistered, for the
//! operator to ask for them (`more`, ADR-0036): it then runs
//! again with its set kept, and completes again. It ends once another search
//! request has made the server let the rows go.

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::pin::Pin;
use std::time::Duration;

use rmule_primitives::{SearchResult, SearchResultKey};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{Instant, Sleep, sleep_until};

use crate::server_session::{SearchStream, ServerSearchEvent, ServerSessionHandle};
use crate::service::{
    CoreEvent, LegNotSent, SearchEvent, SearchFailure, SearchId, SearchLegState, SearchLegs,
};

mod attribution;
mod global_sweep;
mod kad_leg;
mod more;
pub(crate) mod related;
mod server_leg;

pub use kad_leg::KadKeywordSink;
pub use more::{MORE_RESULTS_ASKS, ServerMoreResults};
pub use related::RelatedSearchRefusal;

pub(crate) use attribution::{AttributedRows, LiveSearches};
pub(crate) use global_sweep::{GlobalSearchSweep, UdpSearchPacer, forward_global_search_answers};
pub(crate) use kad_leg::{KadKeywordEnd, KadKeywordLeg, KadLegNews, KadWalkFact, kad_keyword_leg};
pub(crate) use more::Paging;
pub(crate) use server_leg::{LostServerLeg, SentServerLeg};

/// The sweep's settle signal, carrying how many servers it asked.
pub(crate) type SweepDone = oneshot::Receiver<u32>;

pub(crate) struct SearchTask {
    pub(crate) search_id: SearchId,
    /// The server leg's own news — a refusal, an undecodable answer, the
    /// session ending — closing once the answer in its place has arrived or its
    /// answer wait ran out.
    pub(crate) stream: SearchStream,
    /// This search's share of every eD2k answer, TCP and `0x99` alike, by
    /// **Search Attribution**; dropping it at the task's end ends the search's
    /// liveness.
    pub(crate) rows: AttributedRows,
    /// The Kad walk on this search's lead keyword (ADR-0062 requester): its
    /// rows, already screened by this search's query — the storer applies
    /// nothing but the keyword — and how it ended, which settles the leg;
    /// settled at once when there is no Kad leg.
    pub(crate) kad_rx: KadKeywordLeg,
    /// Resolves once this search's **Global Search Sweep** has sent its last
    /// datagram, with how many servers it asked — or at once, its sender
    /// dropped, when there is no sweep: the global leg's settle signal.
    pub(crate) global_sweep: SweepDone,
    pub(crate) windows: SearchWindows,
    pub(crate) evt_tx: mpsc::Sender<CoreEvent>,
    /// The search's stop: raised, or its sender dropped, the task ends at
    /// once and says nothing — its retire says `SearchCancelled`.
    pub(crate) cancel_rx: watch::Receiver<bool>,
    /// How the search asks its server for the next page of its answer.
    pub(crate) paging: Paging,
    /// Where each leg stands as the task starts (ADR-0034). A leg that
    /// is not [`SearchLegState::Sent`] here has its field above as a
    /// placeholder, never polled, until [`Self::late`] brings the real one.
    pub(crate) legs: SearchLegs,
    /// The legs that wait, and where they arrive once they are sent.
    pub(crate) late: LateLegs,
    /// Where the task says its server leg lost its session unanswered, handing
    /// the actor the way to send it again.
    pub(crate) lost: mpsc::UnboundedSender<LostServerLeg>,
}

/// Where the legs that wait arrive once they are sent: the actor holds the
/// senders beside the running search and sends on the session's arrival or
/// Kad's start. `None` for a leg that does not wait.
#[derive(Default)]
pub(crate) struct LateLegs {
    pub(crate) server: Option<oneshot::Receiver<SentServerLeg>>,
    /// The server leg waits because its session ended unanswered, not
    /// because it never went out: let go, it reads
    /// [`SearchLegState::Unanswered`], not [`SearchLegState::NotSent`].
    pub(crate) server_lost: bool,
    pub(crate) kad: Option<oneshot::Receiver<KadKeywordLeg>>,
}

impl SearchLegs {
    /// Every leg sent at the start: a search whose session and Kad both run.
    #[cfg(test)]
    pub(crate) const SENT: Self = Self {
        server: SearchLegState::Sent,
        sweep: SearchLegState::Sent,
        kad: SearchLegState::Sent,
        sweep_servers: crate::service::SweepTally {
            asked: 0,
            answered: 0,
        },
    };

    /// Whether any leg still holds completion open.
    fn hold_completion(self) -> bool {
        self.server.holds_completion()
            || self.sweep.holds_completion()
            || self.kad.holds_completion()
    }
}

/// How a search task ended, as its retire reads it (ADR-0093).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SearchEnd {
    /// On its own, its terminal event out: it failed, or it completed and no
    /// one can ask its server for more.
    Ended,
    /// At its stop, saying nothing: the retire that stopped it says
    /// `SearchCancelled`.
    Stopped,
    /// By a panic in the task, which could say nothing: the retire says
    /// [`SearchFailure::TaskPanicked`].
    Panicked,
}

/// How one run of the search's loop ended.
enum Phase {
    /// Every leg settled and the quiet window passed; `SearchCompleted` is out.
    Completed,
    /// Failed; its terminal event is out.
    Failed,
    /// Its stop came; nothing is said.
    Stopped,
}

/// The windows one **Search Activity** runs on. Completion is
/// *settled legs plus quiet*: each leg settles on its own signal or its own
/// ceiling, and only then does the **Search Quiet Timeout** count — so a leg
/// that has not answered yet is waited for, not mistaken for silence. The
/// server's answer wait is not here: the session counts it from the send and
/// closes the leg when it runs out.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SearchWindows {
    /// The **Search Quiet Timeout**: counted once every leg has settled, reset
    /// by each accepted batch and by each leg settling.
    pub(crate) quiet: Duration,
    /// The Kad leg's ceiling should the walk's end never be reported (aMule
    /// `SEARCHKEYWORD_LIFETIME`, 45 s); the channel closing settles it sooner.
    pub(crate) kad_lifetime: Duration,
}

impl SearchTask {
    /// Run the search until it ends on its own or its stop comes.
    pub(crate) async fn run(mut self) -> SearchEnd {
        let mut results = SearchResultSet::default();
        self.emit_legs().await;
        let kad_lifetime = tokio::time::sleep(self.windows.kad_lifetime);
        tokio::pin!(kad_lifetime);
        loop {
            match self.run_phase(&mut results, kad_lifetime.as_mut()).await {
                Phase::Failed => return SearchEnd::Ended,
                Phase::Stopped => return SearchEnd::Stopped,
                // Its server may hold more rows: it waits for the operator to
                // ask, and runs again on the page.
                Phase::Completed => {
                    self.rows.lapse();
                    if let ControlFlow::Break(end) = self.park().await {
                        return end;
                    }
                    self.move_leg(|legs| legs.server = SearchLegState::Sent)
                        .await;
                }
            }
        }
    }

    /// Merge every leg until the search completes or ends.
    async fn run_phase(
        &mut self,
        results: &mut SearchResultSet,
        mut kad_lifetime: Pin<&mut Sleep>,
    ) -> Phase {
        let windows = self.windows;
        let mut quiet_timer = quiet_timer(windows.quiet);
        // A leg is settled once it has nothing more it is due to say: the TCP
        // leg when its stream closes (the answer in its place, or the answer
        // wait), the global leg when its sweep has sent its last datagram
        // (answers still in flight are what the quiet window after it is for),
        // the Kad leg when its walk ends (the channel closes) or its lifetime
        // runs out. An arm is polled only while its leg is live; attributed
        // rows are taken for as long as the search lives. A leg that waits is
        // polled only for its arrival.
        loop {
            // A Kad leg still waiting once nothing else holds the search open
            // will not run for it: the search completes without it.
            if self.legs.kad == SearchLegState::WaitingForKad
                && !self.legs.server.holds_completion()
                && !self.legs.sweep.holds_completion()
            {
                self.late.kad = None;
                self.move_leg(|legs| legs.kad = SearchLegState::NotRun)
                    .await;
                reset_quiet_timer(&mut quiet_timer, windows.quiet);
            }
            let all_settled = !self.legs.hold_completion();
            let server_sent = self.legs.server == SearchLegState::Sent;
            let sweep_sent = self.legs.sweep == SearchLegState::Sent;
            let kad_sent = self.legs.kad == SearchLegState::Sent;
            tokio::select! {
                changed = self.cancel_rx.changed() => {
                    // A stop, or a dropped sender — the same ruling the
                    // serve loop makes. `changed()` answers `Err` immediately
                    // and forever once the sender is gone, so treating that
                    // as a spurious wakeup spins the loop at full speed and
                    // never ends the task. The owner being gone is stronger
                    // than a stop, and reads as one.
                    if changed.is_err() || *self.cancel_rx.borrow() {
                        return Phase::Stopped;
                    }
                }
                Some(batch) = self.rows.recv() => {
                    if batch.new_answerer {
                        let answered = self.rows.answered();
                        self.move_leg(|legs| legs.sweep_servers.answered = answered).await;
                    }
                    if self.merge(results, batch.rows).await {
                        reset_quiet_timer(&mut quiet_timer, windows.quiet);
                    }
                }
                sent = late_leg(&mut self.late.server), if self.late.server.is_some() => {
                    self.late.server = None;
                    match sent {
                        Ok(leg) => self.attach_server_leg(leg).await,
                        // Let go: no intent stands to bring a session.
                        Err(_) => self.let_go_server_leg().await,
                    }
                    reset_quiet_timer(&mut quiet_timer, windows.quiet);
                }
                Ok(kad_rx) = late_leg(&mut self.late.kad) => {
                    self.late.kad = None;
                    self.kad_rx = kad_rx;
                    kad_lifetime.as_mut().reset(Instant::now() + windows.kad_lifetime);
                    self.move_leg(|legs| legs.kad = SearchLegState::Sent).await;
                    reset_quiet_timer(&mut quiet_timer, windows.quiet);
                }
                news = self.kad_rx.next(), if kad_sent => {
                    match news {
                        KadLegNews::Rows(batch) => {
                            if self.merge(results, batch).await {
                                reset_quiet_timer(&mut quiet_timer, windows.quiet);
                            }
                        }
                        KadLegNews::RowSkipped(reason) => {
                            self.emit(SearchEvent::SearchResultSkipped {
                                search_id: self.search_id,
                                reason,
                            })
                            .await;
                        }
                        KadLegNews::PublishDeferred => {
                            self.emit(SearchEvent::SearchDeferredKadPublish {
                                search_id: self.search_id,
                            })
                            .await;
                        }
                        KadLegNews::Ended(state) => {
                            self.move_leg(|legs| legs.kad = state).await;
                            reset_quiet_timer(&mut quiet_timer, windows.quiet);
                        }
                    }
                }
                done = &mut self.global_sweep, if sweep_sent => {
                    self.move_leg(|legs| {
                        legs.sweep = SearchLegState::Settled;
                        if let Ok(asked) = done {
                            legs.sweep_servers.asked = asked;
                        }
                    })
                    .await;
                    reset_quiet_timer(&mut quiet_timer, windows.quiet);
                }
                () = kad_lifetime.as_mut(), if kad_sent => {
                    self.move_leg(|legs| legs.kad = SearchLegState::Settled).await;
                    reset_quiet_timer(&mut quiet_timer, windows.quiet);
                }
                event = self.stream.next_event(), if server_sent => {
                    let failure = match event {
                        None => {
                            // The answer in its place arrived — empty
                            // included, the server has said what it has — or
                            // the wait ran out.
                            self.move_leg(|legs| legs.server = SearchLegState::Settled).await;
                            reset_quiet_timer(&mut quiet_timer, windows.quiet);
                            None
                        }
                        Some(ServerSearchEvent::Skipped { reason }) => {
                            self.emit(SearchEvent::SearchResultSkipped {
                                search_id: self.search_id,
                                reason,
                            })
                            .await;
                            None
                        }
                        Some(ServerSearchEvent::RelatedSearchNotOffered) => {
                            Some(SearchFailure::RelatedSearchNotOffered)
                        }
                        Some(ServerSearchEvent::RelatedAnswerUnattributable) => {
                            Some(SearchFailure::RelatedAnswerUnattributable)
                        }
                        Some(ServerSearchEvent::WaitingForTurn { send_in }) => {
                            self.emit(SearchEvent::SearchWaitingForTurn {
                                search_id: self.search_id,
                                send_in,
                            })
                            .await;
                            None
                        }
                        Some(ServerSearchEvent::SentToServer) => {
                            self.emit(SearchEvent::SearchSentToServer {
                                search_id: self.search_id,
                            })
                            .await;
                            None
                        }
                        Some(ServerSearchEvent::MoreNotOffered) => {
                            self.emit(SearchEvent::SearchMoreRefused {
                                search_id: self.search_id,
                            })
                            .await;
                            None
                        }
                        // The session ended before the answer: the leg
                        // waits for the reconnect while the operator's intent
                        // stands, and ends unanswered otherwise; the other legs
                        // and every row received stand either way.
                        Some(ServerSearchEvent::Disconnected) => {
                            self.lose_server_leg().await;
                            reset_quiet_timer(&mut quiet_timer, windows.quiet);
                            None
                        }
                    };
                    if let Some(reason) = failure {
                        self.emit(SearchEvent::SearchFailed {
                            search_id: self.search_id,
                            reason,
                        })
                        .await;
                        return Phase::Failed;
                    }
                }
                // The operator asks for the next page while the search still
                // runs: its server leg opens again.
                Some(()) = self.paging.requests.recv(), if self.legs.server == SearchLegState::Settled => {
                    if self.ask_more().await {
                        self.move_leg(|legs| legs.server = SearchLegState::Sent).await;
                        reset_quiet_timer(&mut quiet_timer, windows.quiet);
                    }
                }
                () = &mut quiet_timer, if all_settled => {
                    self.emit(SearchEvent::SearchCompleted {
                        search_id: self.search_id,
                        total_results: results.len(),
                    })
                    .await;
                    return Phase::Completed;
                }
            }
        }
    }

    /// Fold `batch` into the set and publish the snapshot. `false` for an
    /// empty batch: it is not a result event, so it neither publishes nor
    /// holds the quiet window open.
    async fn merge(&self, results: &mut SearchResultSet, batch: Vec<SearchResult>) -> bool {
        if !results.merge_batch(batch) {
            return false;
        }
        self.emit(SearchEvent::SearchResultsReceived {
            search_id: self.search_id,
            results: results.snapshot(),
        })
        .await;
        true
    }

    async fn emit(&self, event: SearchEvent) {
        let _ = self.evt_tx.send(event.into()).await;
    }

    /// Move the leg picture and say so, once per real change.
    async fn move_leg(&mut self, change: impl FnOnce(&mut SearchLegs)) {
        let before = self.legs;
        change(&mut self.legs);
        if self.legs != before {
            self.emit_legs().await;
        }
    }

    async fn emit_legs(&self) {
        self.emit(SearchEvent::SearchLegsChanged {
            search_id: self.search_id,
            legs: self.legs,
        })
        .await;
    }
}

/// A waiting leg's arrival; never resolves for a leg that does not wait.
async fn late_leg<T>(
    slot: &mut Option<oneshot::Receiver<T>>,
) -> Result<T, oneshot::error::RecvError> {
    match slot {
        Some(rx) => rx.await,
        None => std::future::pending().await,
    }
}

#[derive(Default)]
struct SearchResultSet {
    order: Vec<SearchResult>,
    by_key: HashMap<SearchResultKey, usize>,
}

impl SearchResultSet {
    fn merge_batch(&mut self, batch: Vec<SearchResult>) -> bool {
        let mut accepted = false;
        for result in batch {
            accepted = true;
            let key = result.key();
            if let Some(index) = self.by_key.get(&key).copied() {
                self.order[index].merge_aliases_from(&result);
            } else {
                let index = self.order.len();
                self.order.push(result);
                self.by_key.insert(key, index);
            }
        }
        accepted
    }

    fn snapshot(&self) -> Vec<SearchResult> {
        self.order.clone()
    }

    fn len(&self) -> usize {
        self.order.len()
    }
}

fn quiet_timer(timeout: Duration) -> Pin<Box<Sleep>> {
    Box::pin(sleep_until(Instant::now() + timeout))
}

fn reset_quiet_timer(timer: &mut Pin<Box<Sleep>>, timeout: Duration) {
    timer.as_mut().reset(Instant::now() + timeout);
}

#[cfg(test)]
mod tests;
