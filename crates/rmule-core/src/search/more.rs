//! **More results** (ADR-0036): a server's answer may say it
//! holds more rows than it sent, and `OP_QUERY_MORE_RESULT` asks for the next
//! page. The request names no search — the server pages the link's last search
//! request — so at most one search on a session can ask: the **pager**, named
//! by the session and published here for the front ends to read.

use std::ops::ControlFlow;
use std::time::Duration;

use rmule_primitives::SearchQuery;
use tokio::sync::{mpsc, watch};

use super::{LiveSearches, SearchEnd, SearchTask};
use crate::server_session::ServerSessionHandle;
use crate::service::{SearchEvent, SearchId};

/// How many pages past the first one search may ask for: eMule's
/// `MAX_MORE_SEARCH_REQ` (`Opcodes.h:61`, "a max. total search results of
/// (1+5)*201"). aMule never asks.
pub const MORE_RESULTS_ASKS: u8 = 5;

/// The search whose connected server holds more rows for it — its own answer
/// said so while its request was the newest on the link, and no search request
/// has gone out since.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ServerMoreResults {
    /// The search the server holds more rows for.
    pub search_id: SearchId,
    /// How many more pages rmule will still ask for; `0` once it has asked
    /// [`MORE_RESULTS_ASKS`] times — the server still has more, rmule stops.
    pub asks_left: u8,
}

/// How one search asks its server for the next page of its answer: the
/// operator's requests, forwarded by the actor; the session its answer came
/// on, since no other server kept its rows; and the pager as the session names
/// it.
pub(crate) struct Paging {
    /// One `()` per `SearchCommand::MoreResults` naming this search.
    pub(crate) requests: mpsc::Receiver<()>,
    /// `None` while the server leg waits for a session.
    pub(crate) session: Option<ServerSessionHandle>,
    pub(crate) live: LiveSearches,
    pub(crate) query: SearchQuery,
    pub(crate) answer_wait: Duration,
    pub(crate) pager: watch::Receiver<Option<ServerMoreResults>>,
}

#[cfg(test)]
impl Paging {
    /// A search that is never asked for more, on a session that has ended.
    pub(crate) fn inert(query: SearchQuery) -> Self {
        let live = LiveSearches::default();
        Self {
            requests: mpsc::channel(1).1,
            session: None,
            pager: live.watch_more(),
            live,
            query,
            answer_wait: Duration::from_secs(12),
        }
    }
}

impl SearchTask {
    /// Its server holds more rows it may still ask for.
    fn may_ask_more(&self) -> bool {
        self.paging
            .pager
            .borrow()
            .is_some_and(|more| more.search_id == self.search_id && more.asks_left > 0)
    }

    /// Completed, with its server holding more rows: wait for the operator to
    /// ask for them. `Continue` once the request is on its way and the search
    /// runs again; [`SearchEnd::Ended`] once nobody can ask any more — another
    /// search request went out, the session ended — and
    /// [`SearchEnd::Stopped`] at its stop.
    pub(super) async fn park(&mut self) -> ControlFlow<SearchEnd> {
        loop {
            if !self.may_ask_more() {
                return ControlFlow::Break(SearchEnd::Ended);
            }
            tokio::select! {
                changed = self.cancel_rx.changed() => {
                    if changed.is_err() || *self.cancel_rx.borrow() {
                        return ControlFlow::Break(SearchEnd::Stopped);
                    }
                }
                request = self.paging.requests.recv() => {
                    if request.is_none() {
                        return ControlFlow::Break(SearchEnd::Ended);
                    }
                    self.rows.renew(self.paging.query.clone());
                    if self.ask_more().await {
                        return ControlFlow::Continue(());
                    }
                    self.rows.lapse();
                }
                changed = self.paging.pager.changed() => {
                    if changed.is_err() {
                        return ControlFlow::Break(SearchEnd::Ended);
                    }
                }
            }
        }
    }

    /// Put the request for the next page on the session, or say why not.
    /// The search must be live before it is sent: its answer is the owner's.
    pub(super) async fn ask_more(&mut self) -> bool {
        let search_id = self.search_id;
        if self.may_ask_more()
            && let Some(session) = self.paging.session.as_ref()
            && let Ok(stream) = session
                .more_results(search_id, self.paging.answer_wait, self.paging.live.clone())
                .await
        {
            self.stream = stream;
            self.emit(SearchEvent::SearchMoreRequested { search_id })
                .await;
            return true;
        }
        self.emit(SearchEvent::SearchMoreRefused { search_id })
            .await;
        false
    }
}
