//! **More results** on a Held Search (ADR-0036): the status
//! line says when the entry's server holds more rows than it sent, and `n`
//! asks for the next page, which joins the same results. Only the operator
//! asks — as eMule's *More* button; aMule never asks — and a search asks at
//! most [`MORE_RESULTS_ASKS`](rmule_core::MORE_RESULTS_ASKS) times.

use rmule_core::{CoreCommand, SearchCommand, SearchId, ServerMoreResults};

use super::{SearchesView, ViewOutcome};
use crate::action::Action;
use crate::state::{MoreEnded, UiState, more_ended_words};

/// What the entry's server holds for it, when it is the search core names.
pub(super) fn offered(state: &UiState, search_id: SearchId) -> Option<ServerMoreResults> {
    state
        .diagnostics
        .search_more_results
        .filter(|more| more.search_id == search_id)
}

/// The status line's clause for a server that holds more, if it does, or
/// why it no longer does, once it did; the hint beside it names the
/// key while one may still be asked for.
pub(super) fn status_clause(
    more: Option<ServerMoreResults>,
    ended: Option<MoreEnded>,
) -> Option<String> {
    let Some(more) = more else {
        return ended.map(|ended| more_ended_words(ended).to_string());
    };
    Some(crate::words::search::more_clause(more.asks_left))
}

impl SearchesView {
    /// `n`: ask the current entry's server for its next page, or say why not.
    pub(super) fn ask_more(&self, state: &UiState) -> ViewOutcome {
        let Some(search_id) = self.held.current_id() else {
            return ViewOutcome::Ignored;
        };
        if super::no_core::absent(state).is_some() {
            return ViewOutcome::Emit(Action::Flash(crate::words::search::nothing_sent(
                state.ui_only,
            )));
        }
        match offered(state, search_id) {
            Some(more) if more.asks_left > 0 => ViewOutcome::Emit(Action::Command(
                CoreCommand::Search(SearchCommand::MoreResults { search_id }),
            )),
            Some(_) => ViewOutcome::Emit(Action::Flash(crate::words::search::more_spent())),
            None => ViewOutcome::Emit(Action::Flash(crate::words::search::more_ended(
                state
                    .searches
                    .get(&search_id)
                    .and_then(|pane| pane.more_ended),
            ))),
        }
    }
}

#[cfg(test)]
mod tests;
