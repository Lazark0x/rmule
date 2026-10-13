//! The file row menu and the unshare confirm.
//!
//! Unsharing is the one action here that changes what peers can fetch, so it
//! asks first; the items the current selection cannot use stay visible and
//! greyed rather than disappearing.

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use rmule_core::{CoreCommand, ServeCommand};
use rmule_primitives::FileHash;

use super::ViewOutcome;
use super::{GUTTER_W, Pane, SharedView};
use crate::action::Action;
use crate::row_selection::MARKER;
use crate::state::UiState;
use crate::theme::Theme;
use crate::views::modal::Modal;
use crate::words::units::short_hash;
use crate::wrap::{clamp_u16, labeled_lines, wrapped_lines};

/// The files-table row menu: one real action (Unshare) plus two greyed
/// placeholders that name their reason instead of vanishing (
/// visible deferral, never silent absence).
pub(super) struct FileMenu {
    /// The file the menu was opened on, resolved to a hash at open time so it
    /// survives later selection drift.
    file_hash: FileHash,
    selected: usize,
}

/// The unshare confirmation (names the object and the consequence).
pub(super) struct Confirm {
    file_hash: FileHash,
}

#[derive(Clone, Copy)]
pub(super) enum MenuAction {
    CopyLink,
    SearchRelated,
    Unshare,
    Comments,
}

pub(super) struct MenuItem {
    label: &'static str,
    /// `Some(reason)` renders the item greyed and makes it unselectable.
    greyed: Option<&'static str>,
    action: MenuAction,
}

/// The files-table menu (spec §3.5). Copy is greyed because an eD2k link needs
/// the name+size the UI does not have; *Search related* sits directly under
/// it, as in every row menu, dimmed while the connected server cannot answer
/// it (read from `state` on every call, so a server switch shows at once);
/// Comments is a standing non-goal.
fn file_menu(state: &UiState) -> [MenuItem; 4] {
    [
        MenuItem {
            label: "Copy eD2k link",
            greyed: Some("core exposes no name/size yet"),
            action: MenuAction::CopyLink,
        },
        MenuItem {
            label: crate::views::related::LABEL,
            greyed: crate::views::related::unavailable(state),
            action: MenuAction::SearchRelated,
        },
        MenuItem {
            label: "Unshare…",
            greyed: None,
            action: MenuAction::Unshare,
        },
        MenuItem {
            label: "Comments",
            greyed: Some("non-goal, ADR-0068"),
            action: MenuAction::Comments,
        },
    ]
}

pub(super) fn draw_confirm(frame: &mut Frame, area: Rect, confirm: &Confirm, theme: &Theme) {
    let short = short_hash(confirm.file_hash);
    let question = format!("Unshare {short}?");
    let consequence = "Stops serving it; peers lose the source.";
    let title = " Unshare? ";
    // Greedy width, wrapped prose.
    let natural = [
        question.chars().count(),
        consequence.chars().count(),
        title.chars().count(),
    ]
    .into_iter()
    .max()
    .unwrap_or(0)
        + 4;
    let width = clamp_u16(natural).min(area.width);
    let text_w = usize::from(width).saturating_sub(4).max(1);

    let mut lines = wrapped_lines(&question, text_w, Style::new().fg(theme.fg));
    lines.push(Line::from(""));
    lines.extend(wrapped_lines(consequence, text_w, theme.dim_text()));
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("y", Style::new().fg(theme.bad).add_modifier(Modifier::BOLD)),
        Span::styled(" confirm    ", Style::new().fg(theme.fg)),
        Span::styled("Esc", Style::new().fg(theme.accent)),
        Span::styled(" cancel", Style::new().fg(theme.fg)),
    ]));
    Modal::new(title, theme)
        .padded()
        .draw(frame, area, width, theme, lines);
}

/// Natural (unwrapped) width of a menu item, gutter included.
fn menu_item_width(item: &MenuItem) -> usize {
    GUTTER_W
        + item.label.chars().count()
        + item.greyed.map_or(0, |reason| reason.chars().count() + 4)
}

/// The menu cursor's gutter: an accent marker on the item the menu is on.
fn menu_gutter(selected: bool, theme: &Theme) -> Span<'static> {
    if selected {
        Span::styled(MARKER, Style::new().fg(theme.accent))
    } else {
        Span::raw("  ")
    }
}

/// One menu item, wrapping under its gutter rather than clipping.
fn menu_item_lines(
    item: &MenuItem,
    selected: bool,
    width: usize,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let (text, style) = match item.greyed {
        Some(reason) => (format!("{}  ({reason})", item.label), theme.dim_text()),
        None => (item.label.to_string(), Style::new().fg(theme.fg)),
    };
    labeled_lines(menu_gutter(selected, theme), &text, style, width)
}

/// First selectable (non-greyed) menu index — where a fresh menu lands.
fn first_enabled_menu_index(state: &UiState) -> usize {
    file_menu(state)
        .iter()
        .position(|item| item.greyed.is_none())
        .unwrap_or(0)
}

/// Step menu selection to the nearest selectable item in `delta`'s direction,
/// skipping greyed items and staying put when there is none that way.
fn step_menu(current: usize, delta: isize, state: &UiState) -> usize {
    let items = file_menu(state);
    let len = items.len() as isize;
    let mut cursor = current as isize;
    loop {
        let next = cursor + delta;
        if next < 0 || next >= len {
            return current;
        }
        cursor = next;
        if items[cursor as usize].greyed.is_none() {
            return cursor as usize;
        }
    }
}

impl SharedView {
    pub(super) fn handle_confirm_key(&mut self, key: KeyEvent) -> ViewOutcome {
        match key.code {
            // Confirm: emit the real unshare command for the named file.
            KeyCode::Char('y') => match self.confirm.take() {
                Some(confirm) => ViewOutcome::Emit(Action::Command(CoreCommand::Serve(
                    ServeCommand::UnshareFile {
                        file_hash: confirm.file_hash,
                    },
                ))),
                None => ViewOutcome::Redraw,
            },
            // Abort back to the table. `q` dismisses a modal too,
            // so it never falls through to the global quit mid-confirm.
            KeyCode::Esc | KeyCode::Char('q') => {
                self.confirm = None;
                ViewOutcome::Redraw
            }
            _ => ViewOutcome::Ignored,
        }
    }

    pub(super) fn handle_menu_key(&mut self, key: KeyEvent, state: &UiState) -> ViewOutcome {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                if let Some(menu) = self.menu.as_mut() {
                    menu.selected = step_menu(menu.selected, 1, state);
                }
                ViewOutcome::Redraw
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if let Some(menu) = self.menu.as_mut() {
                    menu.selected = step_menu(menu.selected, -1, state);
                }
                ViewOutcome::Redraw
            }
            KeyCode::Enter => self.activate_menu(state),
            // `m` toggles the menu closed; Esc/`q` dismiss it so `q`
            // never falls through to the global quit with a menu open.
            KeyCode::Esc | KeyCode::Char('m') | KeyCode::Char('q') => {
                self.menu = None;
                ViewOutcome::Redraw
            }
            _ => ViewOutcome::Ignored,
        }
    }

    fn activate_menu(&mut self, state: &UiState) -> ViewOutcome {
        let Some(menu) = self.menu.as_ref() else {
            return ViewOutcome::Ignored;
        };
        let action = file_menu(state)[menu.selected].action;
        let file_hash = menu.file_hash;
        match action {
            // Dimmed since the cursor rested here (a server switch under the
            // open menu): nothing is sent, and the menu stays.
            MenuAction::SearchRelated => {
                let name = crate::views::related::shared_file_name(state, file_hash);
                match crate::views::related::action(state, file_hash, name.as_ref()) {
                    Some(action) => {
                        self.menu = None;
                        ViewOutcome::Emit(action)
                    }
                    None => ViewOutcome::Redraw,
                }
            }
            MenuAction::Unshare => {
                self.confirm = Some(Confirm { file_hash });
                self.menu = None;
                ViewOutcome::Redraw
            }
            // Greyed items are never landable (see `step_menu`), so activation
            // cannot reach them; handled for match exhaustiveness only.
            MenuAction::CopyLink | MenuAction::Comments => ViewOutcome::Redraw,
        }
    }

    /// Open the files-table row menu. The menu lives on the FILES table only
    /// (spec §3.5); there is no peer menu in v1.
    pub(super) fn open_file_menu(&mut self, state: &UiState) -> ViewOutcome {
        if self.focus != Pane::Files {
            return ViewOutcome::Ignored;
        }
        self.clamp_selection(state);
        // Nothing shared, or a Partial Share: its offer is its download's,
        // ended only by cancelling it, so it has no menu.
        let Some(row) = self.selected_row(state) else {
            return ViewOutcome::Ignored;
        };
        self.menu = Some(FileMenu {
            file_hash: row.file_hash,
            selected: first_enabled_menu_index(state),
        });
        ViewOutcome::Redraw
    }

    pub(super) fn draw_menu(&self, frame: &mut Frame, area: Rect, state: &UiState, theme: &Theme) {
        let Some(menu) = &self.menu else {
            return;
        };
        let title = format!(" File · {} ", short_hash(menu.file_hash));
        // Greedy modal: as wide as the widest item, clamped to the frame; what
        // still overflows wraps under the gutter instead of clipping.
        let items = file_menu(state);
        let natural = items
            .iter()
            .map(menu_item_width)
            .chain(std::iter::once(title.chars().count()))
            .max()
            .unwrap_or(0)
            + 4; // borders + 1-col pad each side
        let width = clamp_u16(natural).min(area.width);
        let text_w = usize::from(width).saturating_sub(6).max(1);
        let lines: Vec<Line<'static>> = items
            .iter()
            .enumerate()
            .flat_map(|(idx, item)| menu_item_lines(item, idx == menu.selected, text_w, theme))
            .collect();
        Modal::new(title, theme)
            .padded()
            .draw(frame, area, width, theme, lines);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use crate::golden::assert_golden;

    use super::*;
    use crate::fixture::*;

    #[test]
    fn the_files_menu_opens_on_unshare_skipping_the_greyed_items() {
        let state = served_files();
        let mut view = SharedView::default();
        view.handle_key(press(KeyCode::Char('m')), &state);
        // Copy (0) and, not connected, Search related (1) are greyed → the
        // menu lands on Unshare (2).
        assert_eq!(view.menu.as_ref().unwrap().selected, 2);
        // Nothing selectable above or below, so j/k stay put (greyed-skip).
        view.handle_key(press(KeyCode::Char('j')), &state);
        assert_eq!(view.menu.as_ref().unwrap().selected, 2);
        view.handle_key(press(KeyCode::Char('k')), &state);
        assert_eq!(view.menu.as_ref().unwrap().selected, 2);
    }

    #[test]
    fn the_peers_pane_has_no_row_menu() {
        let state = served_files();
        let mut view = SharedView::default();
        view.handle_key(press(KeyCode::Tab), &state); // focus peers
        assert!(matches!(
            view.handle_key(press(KeyCode::Char('m')), &state),
            ViewOutcome::Ignored
        ));
        assert!(view.menu.is_none());
    }

    #[test]
    fn confirming_unshare_emits_the_command_for_the_selected_files_hash() {
        let state = served_files();
        let mut view = SharedView::default();
        view.handle_key(press(KeyCode::Char('m')), &state); // open menu (Unshare selected)
        view.handle_key(press(KeyCode::Enter), &state); // open confirm
        assert!(view.confirm.is_some());
        assert!(view.menu.is_none(), "confirm supersedes the menu");

        let outcome = view.handle_key(press(KeyCode::Char('y')), &state);
        match outcome {
            ViewOutcome::Emit(Action::Command(CoreCommand::Serve(ServeCommand::UnshareFile {
                file_hash,
            }))) => assert_eq!(
                file_hash,
                crate::fixture::file_hash(1),
                "the first shared file (sorted by hash)"
            ),
            _ => panic!("expected an UnshareFile command"),
        }
        assert!(view.confirm.is_none(), "confirm closes after y");
    }

    #[test]
    fn escaping_the_confirm_aborts_without_a_command() {
        let state = served_files();
        let mut view = SharedView::default();
        view.handle_key(press(KeyCode::Char('m')), &state);
        view.handle_key(press(KeyCode::Enter), &state);
        assert!(matches!(
            view.handle_key(press(KeyCode::Esc), &state),
            ViewOutcome::Redraw
        ));
        assert!(view.confirm.is_none());
    }

    fn menu_screen(view: &mut SharedView, state: &UiState) -> String {
        crate::golden::render_to_lines(golden_area().width, golden_area().height, |frame| {
            view.draw(frame, golden_area(), state, &theme(), Instant::now());
        })
    }

    fn with_history(mut state: UiState) -> UiState {
        let history = rmule_core::file_history::FileHistory {
            shared: vec![rmule_core::file_history::SharedFileFact {
                identity: rmule_core::file_history::Ed2kIdentity::new(
                    crate::fixture::file_hash(1),
                    1000,
                ),
                path: std::path::PathBuf::from("/srv/share/debian.iso"),
                withheld: None,
            }],
            ..rmule_core::file_history::FileHistory::default()
        };
        crate::state::fold(&mut state, rmule_core::CoreEvent::FileHistory { history });
        state
    }

    #[test]
    fn search_related_is_dimmed_with_each_reason_and_sends_nothing() {
        for (state, reason) in [
            (served_files(), "Search related  (not connected)"),
            (
                connected_granting(served_files(), false),
                "Search related  (server does not offer it)",
            ),
        ] {
            let mut view = SharedView::default();
            view.handle_key(press(KeyCode::Char('m')), &state);
            assert!(menu_screen(&mut view, &state).contains(reason), "{reason}");
            view.handle_key(press(KeyCode::Char('k')), &state);
            assert_eq!(
                view.menu.as_ref().unwrap().selected,
                2,
                "the cursor never rests on it"
            );
        }
    }

    /// Lit, it is the first item the cursor can rest on, directly under
    /// *Copy eD2k link*; the name is the one the registry's path holds.
    #[test]
    fn search_related_asks_about_the_shared_file_by_hash_and_name() {
        let state = with_history(connected_granting(served_files(), true));
        let mut view = SharedView::default();
        view.handle_key(press(KeyCode::Char('m')), &state);
        assert_eq!(view.menu.as_ref().unwrap().selected, 1);
        match view.handle_key(press(KeyCode::Enter), &state) {
            ViewOutcome::Emit(Action::SearchRelated(query)) => {
                assert_eq!(query.file_hash(), crate::fixture::file_hash(1));
                assert_eq!(query.file_name().to_display_string(), "debian.iso");
            }
            other => panic!("expected SearchRelated, got {other:?}"),
        }
        assert!(view.menu.is_none());
    }

    /// Before core has answered the File History no name is known: the query
    /// carries none rather than one made up.
    #[test]
    fn a_shared_file_with_no_known_name_asks_by_hash_alone() {
        let state = connected_granting(served_files(), true);
        let mut view = SharedView::default();
        view.handle_key(press(KeyCode::Char('m')), &state);
        match view.handle_key(press(KeyCode::Enter), &state) {
            ViewOutcome::Emit(Action::SearchRelated(query)) => {
                assert_eq!(query.file_name().to_display_string(), "");
            }
            other => panic!("expected SearchRelated, got {other:?}"),
        }
    }

    #[test]
    fn golden_shared_menu() {
        assert_golden(
            "shared_menu",
            golden_area().width,
            golden_area().height,
            |frame| {
                let state = served_files();
                let mut view = SharedView::default();
                view.handle_key(press(KeyCode::Char('m')), &state);
                view.draw(frame, golden_area(), &state, &theme(), Instant::now());
            },
        );
    }

    #[test]
    fn golden_shared_confirm_unshare() {
        assert_golden(
            "shared_confirm_unshare",
            golden_area().width,
            golden_area().height,
            |frame| {
                let state = served_files();
                let mut view = SharedView::default();
                view.handle_key(press(KeyCode::Char('m')), &state);
                view.handle_key(press(KeyCode::Enter), &state);
                view.draw(frame, golden_area(), &state, &theme(), Instant::now());
            },
        );
    }
}
