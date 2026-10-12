//! The per-result action menu: download the file, copy its eD2k link, or
//! search for files related to it.
//!
//! Download needs a core, which a UI-only run lacks, so without one it says so
//! instead of emitting a command nothing would take. *Search related* is dimmed with its reason while the connected
//! server cannot answer it, read off the level on every frame.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use rmule_primitives::SearchResult;

use super::SearchesView;
use super::ViewOutcome;
use crate::action::Action;
use crate::state::UiState;
use crate::theme::Theme;
use crate::views::modal::Modal;
use crate::wrap::{clamp_u16, labeled_lines};

/// One row-menu action (spec §3.3): Download · Copy eD2k link · Search
/// related.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MenuItem {
    Download,
    CopyLink,
    SearchRelated,
}

impl MenuItem {
    const ALL: [MenuItem; 3] = [
        MenuItem::Download,
        MenuItem::CopyLink,
        MenuItem::SearchRelated,
    ];

    fn label(self) -> &'static str {
        match self {
            MenuItem::Download => "Download",
            MenuItem::CopyLink => "Copy eD2k link",
            MenuItem::SearchRelated => crate::views::related::LABEL,
        }
    }

    fn selectable(self, state: &UiState) -> bool {
        self.reason(state).is_none()
    }

    /// Greyed-with-reason while the action cannot work now.
    fn reason(self, state: &UiState) -> Option<&'static str> {
        match self {
            MenuItem::SearchRelated => crate::views::related::unavailable(state),
            _ => None,
        }
    }
}

/// Step the menu cursor by `dir`, skipping non-selectable (greyed) items so it
/// never rests on one.
pub(super) fn menu_step(cursor: usize, dir: i32, state: &UiState) -> usize {
    let len = MenuItem::ALL.len();
    let modulus = len as i32;
    let mut index = cursor as i32;
    for _ in 0..len {
        index = (index + dir).rem_euclid(modulus);
        if MenuItem::ALL[index as usize].selectable(state) {
            return index as usize;
        }
    }
    cursor
}

/// Build the eD2k file link for *Copy eD2k link* (spec §3.3) through the
/// canonical [`rmule_primitives::Ed2kLink`] `Display`, so names with spaces or `|` come out
/// properly percent-escaped — never hand-built.
fn ed2k_link(result: &SearchResult) -> String {
    rmule_primitives::Ed2kLink::File(result.to_file_link()).to_string()
}

/// The centered row-action menu (spec §3.3 / §4 menu conventions), modal over
/// the view like the help overlay.
pub(super) fn draw_menu(
    frame: &mut Frame,
    area: Rect,
    cursor: usize,
    state: &UiState,
    theme: &Theme,
) {
    let items = MenuItem::ALL;
    // Greedy width: wide enough for every item whole, clamped to the frame;
    // whatever still overflows wraps under its marker.
    let natural = items
        .iter()
        .map(|item| {
            2 + item.label().chars().count()
                + item
                    .reason(state)
                    .map_or(0, |reason| reason.chars().count() + 3)
        })
        .max()
        .unwrap_or(0)
        + 2;
    let width = clamp_u16(natural.max(48)).min(area.width);
    let text_w = usize::from(width).saturating_sub(4).max(1);

    let lines: Vec<Line> = items
        .iter()
        .enumerate()
        .flat_map(|(index, item)| {
            let selected = index == cursor && item.selectable(state);
            let marker = if selected { "▸ " } else { "  " };
            let (text, style) = match item.reason(state) {
                Some(reason) => (format!("{} ({reason})", item.label()), theme.dim_text()),
                None if selected => (
                    item.label().to_string(),
                    Style::new().fg(theme.accent).add_modifier(Modifier::BOLD),
                ),
                None => (item.label().to_string(), Style::new().fg(theme.fg)),
            };
            labeled_lines(Span::styled(marker, style), &text, style, text_w)
        })
        .collect();

    Modal::new(" Result actions ", theme).draw(frame, area, width, theme, lines);
}

impl SearchesView {
    pub(super) fn open_menu(&mut self, state: &UiState) {
        // The menu acts on the row it opened over, whatever lands meanwhile.
        let ids = self.result_ids(state);
        if let Some(entry) = self.held.current_mut() {
            entry.cursor.pin(&ids);
        }
        self.menu = Some(0); // Download is the first selectable item.
    }

    pub(super) fn activate_menu(&mut self, state: &UiState) -> ViewOutcome {
        let Some(cursor) = self.menu else {
            return ViewOutcome::Ignored;
        };
        self.menu = None; // any activation closes the menu.
        match MenuItem::ALL[cursor] {
            MenuItem::Download => self.download_selected(state),
            MenuItem::CopyLink => match self.selected_result(state) {
                Some(result) => ViewOutcome::Emit(Action::CopyLink(ed2k_link(result))),
                None => ViewOutcome::Redraw,
            },
            // Dimmed since the cursor rested here (a server switch under the
            // open menu): nothing is sent.
            MenuItem::SearchRelated => match self.selected_result(state).and_then(|result| {
                crate::views::related::action(
                    state,
                    result.file_hash(),
                    Some(result.primary_name()),
                )
            }) {
                Some(action) => ViewOutcome::Emit(action),
                None => ViewOutcome::Redraw,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::state::SearchStatus;
    use ratatui::crossterm::event::KeyCode;
    use rmule_core::{CoreCommand, DownloadCommand};
    use std::time::Instant;

    use crate::golden::assert_golden;

    use super::*;
    use crate::fixture::*;

    #[test]
    fn the_row_menu_skips_the_greyed_item() {
        let state = state_with(three_tier_results(), SearchStatus::Completed { total: 3 });
        let mut view = SearchesView::new();
        view.handle_key(press(KeyCode::Char('g')), &state); // select row 0
        view.handle_key(press(KeyCode::Char('m')), &state); // open menu at Download
        assert_eq!(view.menu, Some(0));
        view.handle_key(press(KeyCode::Char('j')), &state);
        assert_eq!(view.menu, Some(1), "j → Copy eD2k link");
        view.handle_key(press(KeyCode::Char('j')), &state);
        assert_eq!(
            view.menu,
            Some(0),
            "j wraps past greyed Search related back to Download"
        );
    }

    #[test]
    fn the_download_menu_item_degrades_without_a_session_and_emits_with_one() {
        let mut no_session = state_with(three_tier_results(), SearchStatus::Completed { total: 3 });
        let mut view = SearchesView::new();
        view.handle_key(press(KeyCode::Char('g')), &no_session);
        view.handle_key(press(KeyCode::Char('m')), &no_session);
        match view.handle_key(press(KeyCode::Enter), &no_session) {
            ViewOutcome::Emit(Action::Flash(text)) => {
                assert!(text.contains("core not attached"), "got {text:?}");
            }
            other => panic!("Download degrades to a flash, got {other:?}"),
        }
        assert_eq!(view.menu, None, "activating closes the menu");

        // With a session: the real StartDownload, the file named, the
        // folder left to core.
        no_session.session = session_state().session;
        let state = no_session;
        view.handle_key(press(KeyCode::Char('m')), &state);
        match view.handle_key(press(KeyCode::Enter), &state) {
            ViewOutcome::Emit(Action::Command(CoreCommand::Download(
                DownloadCommand::StartDownload {
                    name, source_hint, ..
                },
            ))) => {
                assert_eq!(source_hint.expect("a hint").host(), "srv.example");
                assert_eq!(name.as_str(), "clip_low.avi");
            }
            other => panic!("expected StartDownload, got {other:?}"),
        }
    }

    #[test]
    fn copy_link_emits_a_well_formed_ed2k_link() {
        // Known result: name "video.avi", size 1000, hash = 16×0xAB.
        let state = state_with(
            vec![server_result(0xAB, "video.avi", 1000, 42, 0)],
            SearchStatus::Completed { total: 1 },
        );
        let mut view = SearchesView::new();
        view.handle_key(press(KeyCode::Char('g')), &state); // select row 0
        view.handle_key(press(KeyCode::Char('m')), &state); // open menu (Download)
        view.handle_key(press(KeyCode::Char('j')), &state); // → Copy eD2k link
        match view.handle_key(press(KeyCode::Enter), &state) {
            ViewOutcome::Emit(Action::CopyLink(link)) => assert_eq!(
                link,
                "ed2k://|file|video.avi|1000|ABABABABABABABABABABABABABABABAB|/",
            ),
            _ => panic!("Copy eD2k link emits a CopyLink action"),
        }
    }

    #[test]
    fn golden_searches_menu() {
        let state = state_with(three_tier_results(), SearchStatus::Completed { total: 3 });
        let theme = Theme::default_dark();
        let mut view = SearchesView::new().having_sent("ubuntu");
        view.handle_key(press(KeyCode::Char('g')), &state);
        view.handle_key(press(KeyCode::Char('m')), &state);
        assert_golden("searches_menu", 78, 21, |frame| {
            view.draw(frame, frame.area(), &state, &theme, Instant::now());
        });
    }
}
