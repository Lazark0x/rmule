//! *Search related*, the row-menu item every row that names a file offers — a
//! search result, a download, a shared file (ADR-0037, Related-Files Search).
//!
//! Its availability is read off the level core publishes
//! ([`DiagnosticsSnapshot::related_search_refusal`](rmule_core::diagnostics::DiagnosticsSnapshot::related_search_refusal))
//! every time a menu is drawn or acted on, never cached when the menu opens:
//! a server switch under an open menu dims or lights the item on the next
//! frame, and an Enter on an item dimmed meanwhile sends nothing.

use rmule_primitives::{Ed2kText, FileHash, RelatedFilesQuery};

use crate::action::Action;
use crate::state::{UiState, refusal_text};

/// The item's label, the same in every menu.
pub(crate) const LABEL: &str = "Search related";

/// Why the item is dimmed now, or `None` when the connected server grants the
/// search. With no core there is nothing to send it through, whatever the level
/// last said.
pub(crate) fn unavailable(state: &UiState) -> Option<&'static str> {
    if state.ui_only.is_some() {
        return Some(NO_CORE);
    }
    if !state.core_alive {
        return Some(CORE_STOPPED);
    }
    state.diagnostics.related_search_refusal().map(refusal_text)
}

/// The dimmed item's reason on a UI-only run.
const NO_CORE: &str = "no core attached";
/// The dimmed item's reason once the core has stopped.
const CORE_STOPPED: &str = "the core has stopped";

/// The action for the file with `file_hash`, known as `file_name` when a name
/// is known — or `None` while the item is dimmed, so nothing is sent.
///
/// A file whose name is not known yet travels with an empty name: the name is
/// never sent (only the hash reaches the wire), and the Search tab shows the
/// hash in its place rather than inventing one.
pub(crate) fn action(
    state: &UiState,
    file_hash: FileHash,
    file_name: Option<&Ed2kText>,
) -> Option<Action> {
    if unavailable(state).is_some() {
        return None;
    }
    let name = file_name
        .filter(|name| !name.to_display_string().trim().is_empty())
        .cloned()
        .unwrap_or_else(|| Ed2kText::from_utf8(""));
    Some(Action::SearchRelated(RelatedFilesQuery::new(
        file_hash, name,
    )))
}

/// A shared file's name: the name its **Shared File Registry** row is shared
/// under, read off the Shared Files row — `None` until core has said where
/// the file lies.
pub(crate) fn shared_file_name(state: &UiState, file_hash: FileHash) -> Option<Ed2kText> {
    let name = state.shared.get(&file_hash)?.name()?;
    Some(Ed2kText::from_utf8(name))
}
