//! A **Related-Files Search** as the Search tab holds it (ADR-0037): opened from any row
//! menu's *Search related*, named on the query line by the file it asks about, and answered in words that claim only what rmule
//! knows.

use rmule_core::{CoreCommand, SearchCommand, SearchFailure};
use rmule_primitives::{RelatedFilesQuery, SearchQuery};

use super::method::SearchMethod;
use super::{SearchesView, ViewOutcome};
use crate::action::Action;
use crate::state::{SearchPane, SearchStatus, UiState, refusal_text};

/// An empty answer. A server that grants the search and does not implement it
/// reads the same, and rmule keeps no per-server verdict (ADR-0037).
pub(super) const NO_RELATED_FILES: &str =
    "no related files — the server found none, or the file has too few sources for it to answer";

impl SearchesView {
    /// Open a Held Search for `query` and send it, focus on the results. The
    /// item was lit when chosen; if the level dimmed it since, nothing is sent
    /// and the reason is said instead.
    pub(crate) fn start_related(
        &mut self,
        query: RelatedFilesQuery,
        state: &UiState,
    ) -> ViewOutcome {
        self.held.bind(state);
        // No core to send through: the entry says so, where the
        // operator is taken to see it.
        if let Some(reason) = super::no_core::absent(state) {
            self.menu = None;
            self.readd = None;
            self.filters_open = false;
            self.input_focused = false;
            self.held.open_unsent(
                &query.file_name().to_display_string(),
                Some(query.file_hash()),
                SearchMethod::default(),
                reason,
            );
            self.show_current_query();
            return ViewOutcome::Emit(Action::SwitchView(crate::view::ViewId::Searches));
        }
        if let Some(reason) = crate::views::related::unavailable(state) {
            return ViewOutcome::Emit(Action::Flash(crate::words::search::related_unavailable(
                reason,
            )));
        }
        if state.session.is_none() {
            return ViewOutcome::Emit(Action::Flash(crate::words::app::CORE_NOT_ATTACHED));
        }
        let query = SearchQuery::from(query);
        self.menu = None;
        self.readd = None;
        self.filters_open = false;
        self.input_focused = false;
        let search_id = rmule_core::SearchId::mint();
        self.held.open(&query, SearchMethod::default(), search_id);
        self.show_current_query();
        ViewOutcome::Emit(Action::Command(CoreCommand::Search(
            SearchCommand::StartSearch { search_id, query },
        )))
    }

    /// The query line of a current Related-Files entry: the file by name, or by
    /// hash while its name is not known — never a made-up name.
    pub(super) fn related_query_line(&self) -> Option<String> {
        let entry = self.held.current()?;
        let hash = entry.kind.related_file()?;
        Some(if entry.query.trim().is_empty() {
            format!(
                "related to: the file with hash {} — its name is not known yet",
                crate::words::units::short_hex(hash.as_bytes())
            )
        } else {
            format!("related to: {}", entry.query)
        })
    }

    /// What the results pane says in place of rows for a current
    /// Related-Files entry that has none, when it differs from a keyword
    /// search's words.
    pub(super) fn related_message(&self, pane: Option<&SearchPane>) -> Option<String> {
        let entry = self.held.current()?;
        entry.kind.related_file()?;
        if let Some(reason) = entry.kind.refused() {
            return Some(format!("refused: {}", refusal_text(reason)));
        }
        match pane?.status {
            SearchStatus::Completed { .. } => Some(NO_RELATED_FILES.to_string()),
            SearchStatus::Failed {
                reason: SearchFailure::RelatedSearchNotOffered,
            } => Some(format!(
                "refused: {}",
                refusal_text(rmule_core::RelatedSearchRefusal::NotOffered)
            )),
            _ => None,
        }
    }

    /// The input block is describing a current Related-Files entry rather than
    /// what is being typed.
    pub(super) fn showing_related(&self) -> bool {
        !self.input_focused
            && self.query.is_empty()
            && self
                .held
                .current()
                .is_some_and(|entry| entry.kind.related_file().is_some())
    }

    /// The current entry was refused before it started.
    pub(super) fn current_refused(&self) -> bool {
        self.held
            .current()
            .is_some_and(|entry| entry.kind.refused().is_some())
    }
}

#[cfg(test)]
mod tests;
