//! The Search tab with no core to send through: a UI-only run,
//! where the core failed to attach, or a run whose core has stopped. A search
//! asked for then is held as an entry that says, at once and in words, that
//! nothing was sent and why — never one that waits for an answer nobody will
//! give — and the typed query stays in the input. A search that was running
//! when the core stopped says so instead of running for ever.

use super::SearchesView;
use crate::state::UiState;

/// Why nothing can be sent now, in the words the entry shows; `None` while a
/// core is attached and running.
pub(super) fn absent(state: &UiState) -> Option<String> {
    (state.ui_only.is_some() || !state.core_alive)
        .then(|| crate::words::search::no_core_words(state.ui_only))
}

/// What a held entry shows when the core stopped under it while it ran.
pub(super) const STOPPED_WITH_THE_CORE: &str = "stopped with the core";

impl SearchesView {
    /// Why the current entry was never sent, if it was not.
    pub(super) fn current_not_sent(&self) -> Option<&str> {
        self.held.current()?.kind.not_sent()
    }

    /// What the results pane says for an entry never sent.
    pub(super) fn not_sent_message(&self) -> Option<String> {
        let entry = self.held.current()?;
        let why = entry.kind.not_sent()?;
        Some(if entry.kind.related_file().is_some() {
            format!("not sent — {why}")
        } else {
            format!("not sent — {why}. The query is still in the input.")
        })
    }
}

#[cfg(test)]
mod tests;
