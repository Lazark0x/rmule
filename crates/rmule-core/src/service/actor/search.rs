//! The search command arms: starting a search on the surfaces its kind rides
//! and cancelling one in flight. A keyword search rides three — the
//! connected server's TCP answer, the server-UDP global sweep and Kad keyword;
//! a **Related-Files Search** rides the first alone, and only on a session
//! already up with a server that grants it (ADR-0037). A
//! keyword search asked for with no session waits for the operator's connect
//! and is sent the moment it lands (ADR-0093, "Connecting is the operator's
//! act"); no search dials a server. Any
//! number run side by side and none waits on another: each
//! search is registered live before its request goes out, and every eD2k
//! answer reaches the searches it belongs to by **Search Attribution**
//! (ADR-0034).

use rmule_primitives::SearchQuery;

use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};
use crate::service::activity::WaitingSearch;
use crate::service::{CoreCommandRejectReason, CoreEvent, SearchCommand, SearchEvent, SearchId};

use super::{CoreActor, send_event};

mod start;
mod waiting;

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// Enact one search command against the live activity ledger.
    pub(super) async fn on_search_command(&mut self, command: SearchCommand) {
        match command {
            SearchCommand::StartSearch { search_id, .. }
                if self.activities.searches.contains_key(&search_id)
                    || self.search_waits(search_id) =>
            {
                send_event(
                    &self.evt_tx,
                    CoreEvent::CommandRejected {
                        reason: CoreCommandRejectReason::SearchIdInUse,
                    },
                )
                .await;
            }
            SearchCommand::StartSearch {
                search_id,
                query: SearchQuery::Keywords(query),
                ..
            } => {
                let session = self.wiring.shared_server_session.session_now().await;
                self.start_keyword_search(WaitingSearch { search_id, query }, session)
                    .await;
            }
            SearchCommand::StartSearch {
                search_id,
                query: SearchQuery::RelatedFiles(query),
                ..
            } => self.start_related_search(search_id, query).await,
            SearchCommand::MoreResults { search_id } => {
                // A full channel is a request already on its way: the second
                // would only be refused.
                let forwarded = self
                    .activities
                    .searches
                    .get(&search_id)
                    .is_some_and(|active| active.more_tx.try_send(()).is_ok());
                if !forwarded {
                    send_event(
                        &self.evt_tx,
                        SearchEvent::SearchMoreRefused { search_id }.into(),
                    )
                    .await;
                }
            }
            SearchCommand::CancelSearch { search_id } if self.search_waits(search_id) => {
                self.activities
                    .waiting_searches
                    .retain(|waiting| waiting.search_id != search_id);
                send_event(
                    &self.evt_tx,
                    SearchEvent::SearchCancelled { search_id }.into(),
                )
                .await;
            }
            SearchCommand::CancelSearch { search_id } => {
                if let Some(mut active) = self.activities.searches.remove(&search_id) {
                    // The server request, if out, keeps its place on the link;
                    // its answer's rows reach whichever live searches they
                    // prove, and none of them is this one any more.
                    active.stop_global();
                    let _ = active.cancel_tx.send(true);
                    let _ = active.handle.await;
                } else {
                    send_event(
                        &self.evt_tx,
                        CoreEvent::CommandRejected {
                            reason: CoreCommandRejectReason::UnknownSearch,
                        },
                    )
                    .await;
                }
            }
        }
    }

    /// Whether `search_id` names a search still waiting for a session.
    fn search_waits(&self, search_id: SearchId) -> bool {
        self.activities
            .waiting_searches
            .iter()
            .any(|waiting| waiting.search_id == search_id)
    }
}

#[cfg(test)]
mod tests;
