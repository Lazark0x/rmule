//! The search panes the Searches view reads, and the fold arm that maintains
//! them.
//!
//! A pane accumulates one search's results and its terminal status. Every
//! search of the run keeps its pane, receiving results whether or not it is
//! in view, until the operator closes its **Held Search**.

use rmule_core::{RelatedSearchRefusal, SearchEvent, SearchFailure, SearchId, SearchLegs};
use rmule_primitives::SearchResult;

use super::{UiState, note};
use crate::words::search as words;

/// A search's lifecycle status (spec §3.3 status line). `SearchStarted` has no
/// query text — the core echoes none — so the pane labels itself by status,
/// not by phrase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchStatus {
    /// Neither a server session nor Kad exists, so core holds the search and
    /// sends it the moment the operator connects or Kad starts (ADR-0095,
    /// "Connecting is the operator's act"; ADR-0034); nothing dials on
    /// its behalf.
    WaitingForConnection,
    /// The server has the query; more results may still arrive.
    Running,
    /// The server said it was done.
    Completed {
        /// What the server called the result count on completion — its own
        /// tally, not `results.len()`.
        total: usize,
    },
    /// Ended on request; whatever arrived before that stays on the pane.
    Cancelled,
    /// Core gave up on it.
    Failed {
        /// Why core gave up on the search.
        reason: SearchFailure,
    },
}

/// One search's event-folded results + status (spec §3.3), keyed by its
/// [`SearchId`] in [`UiState::searches`].
#[derive(Clone, Debug)]
pub struct SearchPane {
    /// Where this search stands.
    pub status: SearchStatus,
    /// The whole merged set as core last published it — replaced per batch,
    /// never appended, because core re-sends the full set on every change.
    pub results: Vec<SearchResult>,
    /// Server-skipped results (malformed/filtered). Surfaced in the status line
    /// only when non-zero, so the tally stays honest without noise.
    pub skipped: usize,
    /// Held back by the session's search spacing (ADR-0035):
    /// the wait core announced, until the request is sent.
    pub waiting_for_turn: Option<std::time::Duration>,
    /// Why the server no longer holds more rows for this search, once it did
    /// — `None` while it still does, or never did.
    pub more_ended: Option<MoreEnded>,
    /// Where each leg of the search stands, as core last said;
    /// `None` until it has said.
    pub legs: Option<SearchLegs>,
}

/// Why a search whose server held more rows for it no longer does. Core
/// publishes only the level — which search the server holds more for, if
/// any — so the TUI reads the reason off the level's move.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MoreEnded {
    /// A newer search went to the server, which keeps rows for one search
    /// only and dropped this one's.
    Replaced,
    /// The server sent its last page: nothing is left.
    Answered,
    /// The connection to the server that kept them ended.
    Disconnected,
}

/// The level of which search the server holds more rows for moved from
/// `before` to `after`: the search it left learns why, and a search
/// that holds more again forgets it. A move to another search, or to none
/// while a newer search exists, is a replacement — the server keeps rows for
/// one search, the newest sent; a move to none with no server connected is
/// the connection ending; and a move to none otherwise is the server running
/// out. Reads the level set `after` belongs to, already applied.
pub(super) fn fold_more(
    state: &mut UiState,
    before: Option<rmule_core::ServerMoreResults>,
    after: Option<rmule_core::ServerMoreResults>,
) {
    if let Some(after) = after
        && let Some(pane) = state.searches.get_mut(&after.search_id)
    {
        pane.more_ended = None;
    }
    let Some(before) = before else {
        return;
    };
    if after.is_some_and(|after| after.search_id == before.search_id) {
        return;
    }
    let newer = state.searches.keys().any(|id| *id > before.search_id);
    let ended = if after.is_some() || newer {
        MoreEnded::Replaced
    } else if state.diagnostics.connected_server.is_none() {
        MoreEnded::Disconnected
    } else {
        MoreEnded::Answered
    };
    if let Some(pane) = state.searches.get_mut(&before.search_id) {
        pane.more_ended = Some(ended);
    }
}

/// Core refused a Related-Files Search before it started: record it under the
/// id it names, and say why on the status bar.
fn fold_refusal(state: &mut UiState, search_id: SearchId, reason: RelatedSearchRefusal) -> bool {
    state.refused_searches.insert(search_id, reason);
    note(state, words::related_refused(reason))
}

impl SearchStatus {
    /// Whether core still holds the search — sent or waiting to be — so a
    /// stop is a cancel rather than a close.
    #[must_use]
    pub fn is_live(&self) -> bool {
        matches!(self, Self::Running | Self::WaitingForConnection)
    }
}

impl SearchPane {
    fn running() -> Self {
        Self {
            status: SearchStatus::Running,
            results: Vec::new(),
            skipped: 0,
            waiting_for_turn: None,
            more_ended: None,
            legs: None,
        }
    }
}

pub(super) fn fold(state: &mut UiState, event: SearchEvent) -> bool {
    use SearchEvent as E;
    match event {
        // A fresh search resets its pane (empty, running) and notes the start.
        E::SearchStarted { search_id } => {
            state.searches.insert(search_id, SearchPane::running());
            note(state, words::STARTED)
        }
        // The event carries the whole merged set, deduped by `(hash, size)`,
        // re-sent on every change — appending it would list every row again
        // per batch.
        E::SearchResultsReceived { search_id, results } => {
            search_pane(state, search_id).results = results;
            true
        }
        E::SearchResultSkipped { search_id, .. } => {
            search_pane(state, search_id).skipped += 1;
            true
        }
        E::SearchCompleted {
            search_id,
            total_results,
        } => {
            search_pane(state, search_id).status = SearchStatus::Completed {
                total: total_results,
            };
            note(state, words::COMPLETED)
        }
        E::SearchWaitingForConnection { search_id } => {
            state.searches.insert(
                search_id,
                SearchPane {
                    status: SearchStatus::WaitingForConnection,
                    ..SearchPane::running()
                },
            );
            note(state, words::WAITING_FOR_CONNECTION)
        }
        E::SearchWaitingForTurn { search_id, send_in } => {
            search_pane(state, search_id).waiting_for_turn = Some(send_in);
            true
        }
        E::SearchLegsChanged { search_id, legs } => {
            search_pane(state, search_id).legs = Some(legs);
            true
        }
        // Told in the Networks log; the search's own picture is unchanged.
        E::SearchDeferredKadPublish { .. } => false,
        E::SearchSentToServer { search_id } => {
            search_pane(state, search_id).waiting_for_turn = None;
            true
        }
        // The search runs again for its next page; what it holds stays.
        E::SearchMoreRequested { search_id } => {
            search_pane(state, search_id).status = SearchStatus::Running;
            note(state, words::ASKING_FOR_MORE)
        }
        E::SearchMoreRefused { .. } => note(state, words::MORE_REFUSED_NOTE),
        E::SearchCancelled { search_id } => {
            search_pane(state, search_id).status = SearchStatus::Cancelled;
            note(state, words::CANCELLED)
        }
        E::SearchRefused { search_id, reason } => fold_refusal(state, search_id, reason),
        E::SearchFailed { search_id, reason } => {
            search_pane(state, search_id).status = SearchStatus::Failed { reason };
            note(state, words::failed(reason))
        }
    }
}

/// Pane accessor tolerating edge order: results/skips/completion for an unseen
/// search (a bridge race, or events observed mid-stream) create a running pane
/// instead of being lost — mirrors [`row_mut`](super::download::row_mut) for downloads.
fn search_pane(state: &mut UiState, search_id: SearchId) -> &mut SearchPane {
    state
        .searches
        .entry(search_id)
        .or_insert_with(SearchPane::running)
}

#[cfg(test)]
mod tests {
    use rmule_core::SearchEvent;

    use super::*;
    use crate::fixture::{search_event, search_id, search_result};
    use crate::state::fold;

    #[test]
    fn search_results_track_the_snapshot_then_completion_records_the_total() {
        let mut state = UiState::default();
        fold(
            &mut state,
            search_event(SearchEvent::SearchStarted {
                search_id: search_id(1),
            }),
        );
        assert_eq!(state.searches[&search_id(1)].status, SearchStatus::Running);
        assert_eq!(state.notable.as_deref(), Some("search started"));

        fold(
            &mut state,
            search_event(SearchEvent::SearchResultsReceived {
                search_id: search_id(1),
                results: vec![search_result("a.avi", 5), search_result("b.avi", 250)],
            }),
        );
        // Core re-sends the whole merged set, so the second event repeats the
        // first two rows and adds one. Appending would show five.
        fold(
            &mut state,
            search_event(SearchEvent::SearchResultsReceived {
                search_id: search_id(1),
                results: vec![
                    search_result("a.avi", 5),
                    search_result("b.avi", 250),
                    search_result("c.mp3", 40),
                ],
            }),
        );
        let pane = &state.searches[&search_id(1)];
        assert_eq!(
            pane.results.len(),
            3,
            "the pane mirrors the latest snapshot"
        );

        let dirty = fold(
            &mut state,
            search_event(SearchEvent::SearchCompleted {
                search_id: search_id(1),
                total_results: 3,
            }),
        );
        assert!(dirty);
        assert_eq!(
            state.searches[&search_id(1)].status,
            SearchStatus::Completed { total: 3 }
        );
        assert_eq!(state.notable.as_deref(), Some("search completed"));
    }

    #[test]
    fn a_second_search_gets_its_own_pane_and_the_first_keeps_its_results() {
        let mut state = UiState::default();
        fold(
            &mut state,
            search_event(SearchEvent::SearchStarted {
                search_id: search_id(1),
            }),
        );
        fold(
            &mut state,
            search_event(SearchEvent::SearchResultsReceived {
                search_id: search_id(1),
                results: vec![search_result("old.avi", 12)],
            }),
        );
        fold(
            &mut state,
            search_event(SearchEvent::SearchStarted {
                search_id: search_id(2),
            }),
        );
        let pane = &state.searches[&search_id(2)];
        assert!(pane.results.is_empty(), "the new pane starts empty");
        assert_eq!(pane.status, SearchStatus::Running);
        // A batch for the first, out of view, still lands in the first.
        fold(
            &mut state,
            search_event(SearchEvent::SearchResultsReceived {
                search_id: search_id(1),
                results: vec![search_result("old.avi", 12), search_result("late.avi", 3)],
            }),
        );
        assert_eq!(state.searches[&search_id(1)].results.len(), 2);
        assert!(state.searches[&search_id(2)].results.is_empty());
    }

    #[test]
    fn cancel_and_fail_transition_the_pane_status_and_note() {
        let mut state = UiState::default();
        fold(
            &mut state,
            search_event(SearchEvent::SearchStarted {
                search_id: search_id(1),
            }),
        );
        fold(
            &mut state,
            search_event(SearchEvent::SearchCancelled {
                search_id: search_id(1),
            }),
        );
        assert_eq!(
            state.searches[&search_id(1)].status,
            SearchStatus::Cancelled
        );
        assert_eq!(state.notable.as_deref(), Some("search cancelled"));

        fold(
            &mut state,
            search_event(SearchEvent::SearchStarted {
                search_id: search_id(2),
            }),
        );
        fold(
            &mut state,
            search_event(SearchEvent::SearchFailed {
                search_id: search_id(2),
                reason: SearchFailure::ServerDisconnected,
            }),
        );
        assert_eq!(
            state.searches[&search_id(2)].status,
            SearchStatus::Failed {
                reason: SearchFailure::ServerDisconnected
            }
        );
        assert!(
            state
                .notable
                .as_deref()
                .is_some_and(|s| s.starts_with("search failed")),
        );
    }

    /// Asking for the next page reopens the search and keeps what it holds:
    /// core's next snapshot is the whole set, page included.
    #[test]
    fn a_request_for_more_runs_the_search_again_with_its_results() {
        let mut state = UiState::default();
        fold(
            &mut state,
            search_event(SearchEvent::SearchResultsReceived {
                search_id: search_id(1),
                results: vec![search_result("a.avi", 5)],
            }),
        );
        fold(
            &mut state,
            search_event(SearchEvent::SearchCompleted {
                search_id: search_id(1),
                total_results: 1,
            }),
        );
        fold(
            &mut state,
            search_event(SearchEvent::SearchMoreRequested {
                search_id: search_id(1),
            }),
        );
        let pane = &state.searches[&search_id(1)];
        assert_eq!(pane.status, SearchStatus::Running);
        assert_eq!(pane.results.len(), 1);

        fold(
            &mut state,
            search_event(SearchEvent::SearchMoreRefused {
                search_id: search_id(1),
            }),
        );
        assert_eq!(
            state.notable.as_deref(),
            Some(crate::words::search::MORE_REFUSED)
        );
    }
}
