//! Starting a search: a keyword search on every leg that can go out now, a
//! **Related-Files Search** on the live session alone, and the task that
//! merges the legs into one result set (ADR-0034, ADR-0051, ADR-0062).

use std::sync::Arc;

use rmule_primitives::{RelatedFilesQuery, SearchQuery};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::Instrument;

use crate::adapters::{
    KadRuntimeFactory, KadSourceChannel, PeerTransferService, ServeRuntimeService,
    SourceLookupService,
};
use crate::search::{KadKeywordLeg, LateLegs, kad_keyword_leg};
use crate::server_session::{SearchStream, ServerSearchStartError, ServerSessionHandle};
use crate::service::activity::{ActiveSearch, WaitingLegs, WaitingSearch};
use crate::service::{LegNotSent, SearchEvent, SearchFailure, SearchId, SearchLegState};

use super::super::{CoreActor, send_event};

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// A keyword search: the connected server over TCP, the Global Search
    /// Sweep and the Kad keyword walk (ADR-0034, ADR-0051, ADR-0062). Each
    /// leg goes out when what it needs exists and waits otherwise, holding
    /// no other leg back; with neither a session nor Kad the whole
    /// search waits and says so. With no session the server leg and its sweep
    /// wait while the operator's Server Intent stands, and are not sent
    /// otherwise (ADR-0034, "A server leg's states"); a session that ended
    /// before the request reached it is no session. It never dials.
    pub(super) async fn start_keyword_search(
        &mut self,
        search: WaitingSearch,
        session: Option<ServerSessionHandle>,
    ) {
        let kad_running = self.kad.is_some();
        if session.is_none() && !kad_running {
            self.wait_whole(search).await;
            return;
        }
        let WaitingSearch { search_id, query } = search;
        let query_for_paging: SearchQuery = query.clone().into();
        // Registered live before the request goes out, so its own answer
        // finds it.
        let rows = self
            .live_searches
            .register(search_id, query_for_paging.clone());
        let opened = match session {
            Some(handle) => self
                .open_server_leg(&handle, search_id, query_for_paging.clone())
                .await
                .ok()
                .map(|stream| (handle, stream)),
            None => None,
        };
        if opened.is_none() && !kad_running {
            drop(rows);
            self.wait_whole(WaitingSearch { search_id, query }).await;
            return;
        }
        let session = opened.as_ref().map(|(handle, _)| handle.clone());
        let mut waiting = WaitingLegs {
            query: Some(query.clone()),
            ..WaitingLegs::default()
        };
        let mut late = LateLegs::default();
        // The server leg and the sweep beside it, on the session's own
        // server; or both wait for the operator's connect.
        let (stream, sweep, global_settled, server_state, sweep_state) = match opened {
            Some((handle, stream)) => {
                let (sweep, settled) = self.spawn_sweep(&query, handle.server().clone());
                let sweep_state = if settled.is_some() {
                    SearchLegState::Sent
                } else {
                    SearchLegState::NotRun
                };
                (
                    stream,
                    sweep,
                    settled.unwrap_or_else(settled_signal),
                    SearchLegState::Sent,
                    sweep_state,
                )
            }
            // A session is on its way only while the operator's intent
            // stands; with none, nothing is going to send these legs.
            None if self.intent.stands() => {
                let (tx, rx) = oneshot::channel();
                waiting.server = Some(tx);
                late.server = Some(rx);
                (
                    unsent_stream(),
                    None,
                    settled_signal(),
                    SearchLegState::WaitingForSession,
                    SearchLegState::WaitingForSession,
                )
            }
            None => {
                let not_sent = SearchLegState::NotSent(LegNotSent::NoServer);
                (unsent_stream(), None, settled_signal(), not_sent, not_sent)
            }
        };
        // The Kad keyword requester (ADR-0062): with Kad running, subscribe to
        // the walk on the query's lead keyword — started, or joined and
        // replayed — whose rows arrive screened by this query. Otherwise the
        // leg waits for Kad while another leg runs.
        let (kad_rx, kad_state) = match self.spawn_kad_walk(query) {
            Some(kad_rx) => (kad_rx, SearchLegState::Sent),
            None => {
                let (tx, rx) = oneshot::channel();
                waiting.kad = Some(tx);
                late.kad = Some(rx);
                (KadKeywordLeg::settled(), SearchLegState::WaitingForKad)
            }
        };
        send_event(
            &self.evt_tx,
            SearchEvent::SearchStarted { search_id }.into(),
        )
        .await;
        self.run_search(
            search_id,
            stream,
            session,
            SearchLegs {
                query: query_for_paging,
                rows,
                global_settled,
                global_sweep: sweep,
                kad_rx,
                states: crate::service::SearchLegs {
                    server: server_state,
                    sweep: sweep_state,
                    kad: kad_state,
                    sweep_servers: crate::service::SweepTally::default(),
                },
                late,
                waiting,
            },
        );
    }

    /// The **Global Search Sweep** (ADR-0051) for `query`: every managed
    /// server, one per tick, `connected` skipped (it has the TCP search), at
    /// once and beside any other search's sweep; its `0x99` answers reach the
    /// search through Search Attribution. `(None, None)` with no server-UDP
    /// socket bound. The receiver resolves once the sweep sent its last
    /// datagram or was aborted.
    pub(super) fn spawn_sweep(
        &self,
        query: &rmule_primitives::KeywordQuery,
        connected: rmule_primitives::ServerEndpoint,
    ) -> (Option<JoinHandle<()>>, Option<crate::search::SweepDone>) {
        let Some(front) = self.server_udp.as_ref() else {
            return (None, None);
        };
        let ctx = &front.search;
        let (done_tx, done_rx) = oneshot::channel::<u32>();
        // Each datagram is sized for its addressee: a bound past `u32::MAX`
        // widens only toward a server advertising large-file UDP support
        // (ADR-0051).
        let sweep = crate::search::GlobalSearchSweep {
            transport: Arc::clone(&ctx.transport),
            servers: self
                .global_source_servers
                .lock()
                .expect("global source server list")
                .clone(),
            capabilities: Arc::clone(&ctx.capabilities),
            connected,
            query: query.clone(),
            pacer: ctx.pacer.clone(),
            tick: self.wiring.config.global_search_tick,
        };
        let handle = tokio::spawn(async move {
            let asked = sweep.run().await;
            let _ = done_tx.send(asked);
        });
        (Some(handle), Some(done_rx))
    }

    /// Subscribe to the Kad walk on `query`'s lead keyword, or `None` when
    /// Kad is not running. The walk answers on the channel alone and closes
    /// it when it ends.
    pub(super) fn spawn_kad_walk(
        &self,
        query: rmule_primitives::KeywordQuery,
    ) -> Option<KadKeywordLeg> {
        let channel = Arc::clone(self.kad.as_ref()?.search_channel());
        let (sink, leg) = kad_keyword_leg();
        tokio::spawn(async move { channel.search_keyword(query, sink).await });
        Some(leg)
    }

    /// A **Related-Files Search** (ADR-0037): the connected
    /// server over TCP, nothing else. Refused before anything is sent — and
    /// before a running search is touched — when no session is up or its
    /// server does not grant the search; it never dials a server of its own.
    pub(super) async fn start_related_search(
        &mut self,
        search_id: SearchId,
        query: RelatedFilesQuery,
    ) {
        let live = self
            .wiring
            .shared_server_session
            .slot()
            .lock()
            .await
            .clone()
            .filter(ServerSessionHandle::is_alive);
        let grants = self.diagnostics.connected_server_grants();
        let refusal = crate::search::related::refusal(
            live.is_some() && grants.is_some(),
            grants.unwrap_or_default(),
        );
        let (Some(handle), None) = (live, refusal) else {
            let reason = refusal.unwrap_or(crate::RelatedSearchRefusal::NotConnected);
            send_event(
                &self.evt_tx,
                SearchEvent::SearchRefused { search_id, reason }.into(),
            )
            .await;
            return;
        };
        let query: SearchQuery = query.into();
        let rows = self.live_searches.register(search_id, query.clone());
        let Ok(stream) = self
            .open_server_leg(&handle, search_id, query.clone())
            .await
        else {
            self.fail_search(search_id).await;
            return;
        };
        send_event(
            &self.evt_tx,
            SearchEvent::SearchStarted { search_id }.into(),
        )
        .await;
        // No sweep and no Kad walk: the server leg is its only one, so the
        // search completes on the server's answer or its answer wait.
        self.run_search(
            search_id,
            stream,
            Some(handle),
            SearchLegs {
                query,
                rows,
                global_settled: settled_signal(),
                global_sweep: None,
                kad_rx: KadKeywordLeg::settled(),
                states: crate::service::SearchLegs {
                    server: SearchLegState::Sent,
                    sweep: SearchLegState::NotRun,
                    kad: SearchLegState::NotRun,
                    sweep_servers: crate::service::SweepTally::default(),
                },
                late: LateLegs::default(),
                waiting: WaitingLegs::default(),
            },
        );
    }

    async fn fail_search(&mut self, search_id: SearchId) {
        send_event(
            &self.evt_tx,
            SearchEvent::SearchFailed {
                search_id,
                reason: SearchFailure::ServerDisconnected,
            }
            .into(),
        )
        .await;
    }

    /// Put `query` on the session: the search's server leg.
    pub(super) async fn open_server_leg(
        &mut self,
        handle: &ServerSessionHandle,
        search_id: SearchId,
        query: SearchQuery,
    ) -> Result<SearchStream, ServerSearchStartError> {
        handle
            .start_search(
                search_id,
                query,
                self.wiring.config.search_server_answer_timeout,
                self.live_searches.clone(),
            )
            .await
    }

    /// Spawn the task that merges every leg into one result set, and hold it
    /// beside the other running searches.
    fn run_search(
        &mut self,
        search_id: SearchId,
        stream: SearchStream,
        session: Option<ServerSessionHandle>,
        legs: SearchLegs,
    ) {
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let (more_tx, requests) = mpsc::channel(1);
        let search_span = tracing::info_span!("search", search_id = search_id.as_u64(),);
        let handle = tokio::spawn(
            crate::search::SearchTask {
                search_id,
                stream,
                rows: legs.rows,
                kad_rx: legs.kad_rx,
                global_sweep: legs.global_settled,
                windows: crate::search::SearchWindows {
                    quiet: self.wiring.config.search_quiet_timeout,
                    kad_lifetime: self.wiring.config.search_kad_lifetime,
                },
                evt_tx: self.evt_tx.clone(),
                cancel_rx,
                finished_tx: self.finished_tx.clone(),
                paging: crate::search::Paging {
                    requests,
                    session,
                    pager: self.live_searches.watch_more(),
                    live: self.live_searches.clone(),
                    query: legs.query,
                    answer_wait: self.wiring.config.search_server_answer_timeout,
                },
                legs: legs.states,
                late: legs.late,
                lost: self.intent.lost_legs(),
            }
            .run()
            .instrument(search_span),
        );
        self.activities.searches.insert(
            search_id,
            ActiveSearch {
                cancel_tx,
                handle,
                more_tx,
                global_sweep: legs.global_sweep,
                waiting: legs.waiting,
            },
        );
    }
}

/// The legs beside the connected server's answer, as the search task takes
/// them.
struct SearchLegs {
    /// What the search asks, kept to be live under again should it ask its
    /// server for more.
    query: SearchQuery,
    rows: crate::search::AttributedRows,
    global_settled: crate::search::SweepDone,
    global_sweep: Option<JoinHandle<()>>,
    kad_rx: KadKeywordLeg,
    /// Where each leg stands as the search starts.
    states: crate::service::SearchLegs,
    late: LateLegs,
    waiting: WaitingLegs,
}

/// A settle signal already given: its sender is gone.
fn settled_signal() -> crate::search::SweepDone {
    oneshot::channel().1
}

/// The placeholder for a server leg not yet sent: never polled until the
/// real stream replaces it.
fn unsent_stream() -> SearchStream {
    SearchStream {
        event_rx: mpsc::channel(1).1,
    }
}
