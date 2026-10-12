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
use crate::service::{CoreCommandRejectReason, CoreEvent, SearchCommand, SearchEvent};

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
                if self.activities.searches.holds(search_id) =>
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
                if !self.activities.searches.ask_more(search_id) {
                    send_event(
                        &self.evt_tx,
                        SearchEvent::SearchMoreRefused { search_id }.into(),
                    )
                    .await;
                }
            }
            SearchCommand::CancelSearch { search_id } => {
                if !self.activities.searches.stop(search_id, &self.evt_tx).await {
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
}

#[cfg(test)]
mod tests;
