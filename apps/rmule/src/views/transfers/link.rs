//! The canonical eD2k link for a download.
//!
//! A link needs three facts — name, exact size, content hash — so the action
//! stays greyed *with the reason* while any of them is genuinely absent,
//! rather than offering a link that would be wrong.

use rmule_primitives::{Ed2kFileLink, Ed2kLink, Ed2kText, FileHash};

use crate::state::DownloadRow;

/// The facts `Copy eD2k link` needs to build a link: `None` when metadata is
/// genuinely absent — the row's edge has not landed yet, or it landed with
/// an `Unknown`-origin empty name (a backfilled junk link, ADR-0078).
fn copy_link_facts(row: Option<&DownloadRow>) -> Option<(&Ed2kText, u64, FileHash)> {
    let row = row?;
    let metadata = row.metadata.as_ref()?;
    let hash = row.file_hash?;
    if metadata.name.to_display_string().trim().is_empty() {
        return None;
    }
    Some((&metadata.name, metadata.size, hash))
}

/// Greyed-with-reason for the row menu when [`copy_link_facts`]
/// cannot build a link. Distinguishes "nothing known yet" from "known but
/// nameless" so the reason tag names the actual gap.
pub(super) fn copy_link_reason(row: Option<&DownloadRow>) -> Option<&'static str> {
    if copy_link_facts(row).is_some() {
        return None;
    }
    match row.and_then(|r| r.metadata.as_ref()) {
        Some(_) => Some("file name unknown"),
        None => Some("no metadata yet"),
    }
}

/// Build the canonical eD2k link for `Copy eD2k link` through
/// [`Ed2kLink`]'s `Display`, the same percent-escaping idiom the Searches
/// view's link-copy uses, so names with spaces or `|` come out escaped.
pub(super) fn copy_link_for(row: Option<&DownloadRow>) -> Option<String> {
    let (name, size, file_hash) = copy_link_facts(row)?;
    let link = Ed2kFileLink {
        name: name.clone(),
        size,
        file_hash,
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    };
    Some(Ed2kLink::File(link).to_string())
}

#[cfg(test)]
mod tests {

    use ratatui::crossterm::event::KeyCode;

    use super::super::menu::menu_items;
    use super::super::{Overlay, TransfersView};
    use crate::action::Action;
    use crate::fixture::*;
    use crate::state::DownloadStatus;
    use crate::views::ViewOutcome;

    #[test]
    fn copy_link_greys_with_a_reason_matching_why_metadata_is_missing() {
        let state = three_downloads();
        // download_id(2): no `DownloadQueued`/`DownloadRecovered` edge has landed.
        assert_eq!(
            menu_items(
                DownloadStatus::Paused,
                state.downloads.get(&download_id(2)),
                &state
            )
            .iter()
            .find(|item| item.label == "Copy eD2k link")
            .and_then(|item| item.reason),
            Some("no metadata yet"),
        );
        // download_id(3): metadata landed, but its name is empty (Unknown-origin
        // backfill) — a different, more specific reason.
        assert_eq!(
            menu_items(
                DownloadStatus::Completed,
                state.downloads.get(&download_id(3)),
                &state
            )
            .iter()
            .find(|item| item.label == "Copy eD2k link")
            .and_then(|item| item.reason),
            Some("file name unknown"),
        );
    }

    #[test]
    fn copy_link_is_enabled_once_metadata_names_the_file_and_emits_the_canonical_link() {
        let mut view = TransfersView::new();
        let state = three_downloads(); // download_id(1): "bunny.mp4", 92_000_000, hash 0x07.
        view.select_row(&state, 0);
        view.handle_key(press(KeyCode::Char('m')), &state); // open (cursor 0 = Pause)
        view.handle_key(press(KeyCode::Char('j')), &state); // → Cancel…
        view.handle_key(press(KeyCode::Char('j')), &state); // → Show file details
        view.handle_key(press(KeyCode::Char('j')), &state); // → Copy eD2k link
        assert_eq!(
            view.overlay,
            Overlay::Menu {
                cursor: super::super::menu::MenuAction::CopyLink
            },
            "copy is now a selectable stop"
        );
        match view.handle_key(press(KeyCode::Enter), &state) {
            ViewOutcome::Emit(Action::CopyLink(link)) => assert_eq!(
                link,
                format!(
                    "ed2k://|file|bunny.mp4|92000000|{}|/",
                    file_hash(0x07).to_hex_upper()
                ),
            ),
            other => panic!("expected a CopyLink action, got {other:?}"),
        }
        assert_eq!(view.overlay, Overlay::None, "menu closes after acting");
    }
}
