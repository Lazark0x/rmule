//! The file row menu and the unshare confirm.
//!
//! Unsharing is the one action here that changes what peers can fetch, so it
//! asks first; the items the current selection cannot use stay visible and
//! greyed rather than disappearing.

use std::cell::Cell;

use ratatui::Frame;
use ratatui::crossterm::event::KeyEvent;
use ratatui::layout::Rect;

use rmule_core::{CoreCommand, ServeCommand};
use rmule_primitives::FileHash;

use super::ViewOutcome;
use super::{Pane, SharedView};
use crate::action::Action;
use crate::row_selection::viewport::Viewport;
use crate::state::UiState;
use crate::table_sort::RowMove;
use crate::theme::Theme;
use crate::views::menu::{self, Asked, Item, Place};
use crate::views::modal::{Question, confirm_key, draw_question, scroll_key};
use crate::words::{app as words, labels};

/// The files-table row menu.
pub(super) struct FileMenu {
    /// The file the menu was opened on, resolved to a hash at open time so it
    /// survives later selection drift.
    file_hash: FileHash,
    selected: usize,
    /// Where it is, and what part of it is on screen.
    place: Place,
}

/// The unshare confirmation (names the object and the consequence).
pub(super) struct Confirm {
    targets: Vec<FileHash>,
    /// What part of the question is on screen, in a frame too short for it.
    viewport: Cell<Viewport>,
}

#[derive(Clone, Copy)]
pub(super) enum MenuAction {
    CopyLink,
    SearchRelated,
    Unshare,
    Comments,
}

/// The eD2k link of a shared file, once its name and size are known.
fn shared_link(state: &UiState, file_hash: FileHash) -> Option<String> {
    let row = state.shared.get(&file_hash)?;
    let name = rmule_primitives::Ed2kText::from_utf8(row.name()?);
    Some(crate::views::ed2k_file_link(
        &name,
        row.file_size?,
        file_hash,
    ))
}

/// The files-table menu (spec §3.5). Copy is greyed until the file's name and
/// size are read; *Search related* sits directly under
/// it, as in every row menu, dimmed while the connected server cannot answer
/// it (read from `state` on every call, so a server switch shows at once);
/// Comments is a standing non-goal.
fn file_menu(state: &UiState, file_hash: FileHash) -> [Item<MenuAction>; 4] {
    [
        Item::new(labels::COPY_LINK, MenuAction::CopyLink).greyed(
            shared_link(state, file_hash)
                .is_none()
                .then_some("its name and size are not read yet"),
        ),
        Item::new(labels::SEARCH_RELATED, MenuAction::SearchRelated)
            .greyed(crate::views::related::unavailable(state)),
        Item::new(labels::UNSHARE, MenuAction::Unshare).keyed('x'),
        Item::new(labels::COMMENTS, MenuAction::Comments).greyed(Some(labels::COMMENTS_REASON)),
    ]
}

/// A shared file as a sentence names it, never by its hash.
fn file_name(state: &UiState, file_hash: FileHash) -> String {
    state
        .shared
        .get(&file_hash)
        .and_then(crate::state::SharedRow::name)
        .unwrap_or_else(|| words::UNNAMED_FILE.to_string())
}

pub(super) fn draw_confirm(
    frame: &mut Frame,
    area: Rect,
    confirm: &Confirm,
    state: &UiState,
    theme: &Theme,
) {
    let asks = match confirm.targets.as_slice() {
        [file_hash] => words::unshare_one(&file_name(state, *file_hash)),
        many => words::unshare_many(many.len()),
    };
    let question = Question {
        title: labels::UNSHARE_TITLE,
        asks: &asks,
        does: words::UNSHARE_DOES,
    };
    draw_question(frame, area, &question, theme, &confirm.viewport);
}

impl SharedView {
    pub(super) fn handle_confirm_key(&mut self, key: KeyEvent) -> ViewOutcome {
        match (confirm_key(key.code), key.code) {
            (Some(true), _) => {
                let Some(confirm) = self.confirm.take() else {
                    return ViewOutcome::Redraw;
                };
                ViewOutcome::Emit(Action::Commands(
                    confirm
                        .targets
                        .into_iter()
                        .map(|file_hash| {
                            CoreCommand::Serve(ServeCommand::UnshareFile { file_hash })
                        })
                        .collect(),
                ))
            }
            (Some(false), _) => {
                self.confirm = None;
                ViewOutcome::Redraw
            }
            (None, code) => match self.confirm.as_mut() {
                Some(confirm) if RowMove::of(code).is_some() => {
                    scroll_key(&mut confirm.viewport, code);
                    ViewOutcome::Redraw
                }
                _ => ViewOutcome::Ignored,
            },
        }
    }

    pub(super) fn handle_menu_key(&mut self, key: KeyEvent, state: &UiState) -> ViewOutcome {
        let Some(open) = self.menu.as_ref() else {
            return ViewOutcome::Ignored;
        };
        let items = file_menu(state, open.file_hash);
        let asked = menu::key(&items, open.selected, key.code);
        self.answer_menu(asked, state)
    }

    /// A click on the open menu: an item runs, outside closes.
    pub(super) fn click_menu(&mut self, column: u16, row: u16, state: &UiState) -> ViewOutcome {
        let Some(open) = self.menu.as_ref() else {
            return ViewOutcome::Ignored;
        };
        let items = file_menu(state, open.file_hash);
        let asked = open.place.click(&items, column, row);
        self.answer_menu(asked, state)
    }

    fn answer_menu(&mut self, asked: Asked, state: &UiState) -> ViewOutcome {
        match asked {
            Asked::Close => self.menu = None,
            Asked::Move(index) => {
                if let Some(open) = self.menu.as_mut() {
                    open.selected = index;
                }
            }
            Asked::Run(index) => {
                if let Some(open) = self.menu.as_mut() {
                    open.selected = index;
                }
                return self.activate_menu(state);
            }
            Asked::Nothing => {}
        }
        ViewOutcome::Redraw
    }

    fn activate_menu(&mut self, state: &UiState) -> ViewOutcome {
        let Some(open) = self.menu.as_ref() else {
            return ViewOutcome::Ignored;
        };
        let file_hash = open.file_hash;
        let action = file_menu(state, file_hash)[open.selected].action;
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
                self.ask_unshare(vec![file_hash]);
                ViewOutcome::Redraw
            }
            MenuAction::CopyLink => match shared_link(state, file_hash) {
                Some(link) => {
                    self.menu = None;
                    ViewOutcome::Emit(Action::CopyLink(link))
                }
                None => ViewOutcome::Redraw,
            },
            // Greyed items are never landable, so activation cannot reach it;
            // handled for match exhaustiveness only.
            MenuAction::Comments => ViewOutcome::Redraw,
        }
    }

    /// Ask before unsharing `targets`.
    pub(super) fn ask_unshare(&mut self, targets: Vec<FileHash>) {
        self.menu = None;
        self.confirm = Some(Confirm {
            targets,
            viewport: Cell::default(),
        });
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
            selected: menu::first_enabled(&file_menu(state, row.file_hash)),
            place: Place::default(),
        });
        ViewOutcome::Redraw
    }

    pub(super) fn draw_menu(&self, frame: &mut Frame, area: Rect, state: &UiState, theme: &Theme) {
        let Some(open) = &self.menu else {
            return;
        };
        let name = file_name(state, open.file_hash);
        let items = file_menu(state, open.file_hash);
        menu::draw(
            frame,
            area,
            (&name, &items, open.selected),
            theme,
            &open.place,
        );
    }
}

#[cfg(test)]
mod tests {
    use ratatui::crossterm::event::KeyCode;

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
            ViewOutcome::Emit(Action::Commands(commands)) => assert!(
                matches!(
                    commands.as_slice(),
                    [CoreCommand::Serve(ServeCommand::UnshareFile { file_hash })]
                        if *file_hash == crate::fixture::file_hash(1)
                ),
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
            (served_files(), "Search related  not connected"),
            (
                connected_granting(served_files(), false),
                "Search related  server does not offer it",
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
        view.handle_key(press(KeyCode::Char('j')), &state);
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

    /// The name and size were on the row all along: Copy works.
    #[test]
    fn a_file_with_a_known_name_copies_its_link() {
        let state = with_history(served_files());
        let mut view = SharedView::default();
        view.handle_key(press(KeyCode::Char('m')), &state);
        match view.handle_key(press(KeyCode::Enter), &state) {
            ViewOutcome::Emit(Action::CopyLink(link)) => {
                assert!(link.starts_with("ed2k://|file|debian.iso|"), "{link}");
            }
            other => panic!("expected CopyLink, got {other:?}"),
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
