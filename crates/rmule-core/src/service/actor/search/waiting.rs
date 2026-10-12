//! A search's legs that wait: the whole search with nothing to carry it, the
//! server leg and its sweep for a session, the Kad leg for Kad (ADR-0034,
//! "The legs are independent", "A server leg's states"). Each is sent the
//! moment what it waits for arrives, and let go once that can no longer
//! happen.

use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};
use crate::server_session::ServerSessionHandle;
use crate::service::activity::{ActiveSearch, WaitingSearch};
use crate::service::{SearchEvent, SearchId};

use super::super::{CoreActor, send_event};

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// A session came up (the **Session Generation** moved): every search
    /// that waited whole starts on it, in the order asked, and every running
    /// search whose server leg waited sends it now, the sweep beside it.
    pub(in crate::service::actor) async fn start_waiting_searches(&mut self) {
        let Some(session) = self.wiring.shared_server_session.session_in_slot().await else {
            return;
        };
        for waiting in self.activities.searches.take_waiting() {
            self.start_keyword_search(waiting, Some(session.clone()))
                .await;
        }
        let ids: Vec<SearchId> = self
            .activities
            .searches
            .each_running_mut()
            .filter(|(_, active)| active.waiting.server.is_some())
            .map(|(id, _)| id)
            .collect();
        for search_id in ids {
            self.send_waiting_server_leg(search_id, &session).await;
        }
    }

    /// A search's server leg lost its session unanswered (ADR-0034).
    /// While the operator's intent stands the leg waits for the re-made
    /// session — sent at once if one is already up — and is sent on it;
    /// otherwise, or for a Related-Files Search, which keeps no query to send
    /// again, it is let go and ends unanswered.
    pub(in crate::service::actor) async fn on_server_leg_lost(
        &mut self,
        lost: crate::search::LostServerLeg,
    ) {
        let crate::search::LostServerLeg { search_id, rearm } = lost;
        if !self.intent.stands() {
            return;
        }
        let Some(active) = self.activities.searches.running_mut(search_id) else {
            return;
        };
        if active.waiting.query.is_none() {
            return;
        }
        active.waiting.server = Some(rearm);
        if let Some(session) = self.wiring.shared_server_session.session_now().await {
            self.send_waiting_server_leg(search_id, &session).await;
        }
    }

    /// The operator's intent ended: no session is on its way, so every server
    /// leg waiting for one is let go — one lost after it went out ends
    /// unanswered, one that never went out ends not sent, its sweep
    /// with it (ADR-0034, "A server leg's states").
    pub(in crate::service::actor) fn end_waiting_server_legs(&mut self) {
        for (_, active) in self.activities.searches.each_running_mut() {
            active.waiting.server = None;
        }
    }

    /// Kad started: every search that waited whole starts on it (its server
    /// leg waits on), and every running search whose Kad leg waited sends it.
    pub(in crate::service::actor) async fn start_waiting_kad_legs(&mut self) {
        let session = self.wiring.shared_server_session.session_now().await;
        for waiting in self.activities.searches.take_waiting() {
            self.start_keyword_search(waiting, session.clone()).await;
        }
        let mut sends = Vec::new();
        for (_, active) in self.activities.searches.each_running_mut() {
            if let (Some(tx), Some(query)) =
                (active.waiting.kad.take(), active.waiting.query.clone())
            {
                sends.push((tx, query));
            }
        }
        for (tx, query) in sends {
            if let Some(kad_rx) = self.spawn_kad_walk(query) {
                // A task that already let the leg go (every other leg settled
                // first) dropped its receiver; the walk then feeds nobody.
                let _ = tx.send(kad_rx);
            }
        }
    }

    /// Send the server leg of a running search that waited for `session`,
    /// and its sweep. A session that ends before the request goes out
    /// leaves the leg waiting for the next.
    async fn send_waiting_server_leg(
        &mut self,
        search_id: SearchId,
        session: &ServerSessionHandle,
    ) {
        let Some(query) = self
            .activities
            .searches
            .running(search_id)
            .and_then(|active| active.waiting.query.clone())
        else {
            return;
        };
        let Ok(stream) = self
            .open_server_leg(session, search_id, query.clone().into())
            .await
        else {
            return;
        };
        // A sweep that already ran, before a lost session sent the leg back
        // to waiting, is not sent again.
        let swept = self
            .activities
            .searches
            .running(search_id)
            .is_some_and(ActiveSearch::has_swept);
        let (sweep, sweep_settled) = if swept {
            (None, None)
        } else {
            self.spawn_sweep(&query, session.server().clone())
        };
        let Some(active) = self.activities.searches.running_mut(search_id) else {
            return;
        };
        let Some(tx) = active.waiting.server.take() else {
            return;
        };
        active.attach_sweep(sweep);
        let _ = tx.send(crate::search::SentServerLeg {
            stream,
            session: session.clone(),
            sweep: sweep_settled,
        });
    }

    /// Hold `search` whole until a session or Kad can carry a leg of it, and
    /// say so.
    pub(super) async fn wait_whole(&mut self, search: WaitingSearch) {
        let search_id = search.search_id;
        self.activities.searches.wait(search);
        send_event(
            &self.evt_tx,
            SearchEvent::SearchWaitingForConnection { search_id }.into(),
        )
        .await;
    }
}
