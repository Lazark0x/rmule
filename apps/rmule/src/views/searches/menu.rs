//! The per-result action menu: download the file, copy its eD2k link, or
//! search for files related to it.
//!
//! Download is greyed until a download directory is set. *Search related* is
//! dimmed with its reason while the connected server cannot answer it, read off
//! the level on every frame.

use ratatui::Frame;
use ratatui::crossterm::event::KeyCode;
use ratatui::layout::Rect;

use rmule_primitives::SearchResult;

use super::SearchesView;
use super::ViewOutcome;
use crate::action::Action;
use crate::state::UiState;
use crate::theme::Theme;
use crate::views::menu::{self, Asked, Item};
use crate::words::labels;

/// One row-menu action (spec §3.3): Download · Copy eD2k link · Search
/// related.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MenuAction {
    Download,
    CopyLink,
    SearchRelated,
}

/// The menu as `state` has it. Download is greyed until a directory is set,
/// and *Search related* while the connected server cannot answer it.
pub(super) fn menu_items(state: &UiState, tagged: bool) -> [Item<MenuAction>; 3] {
    let one = |reason: Option<&'static str>| {
        if tagged {
            Some(crate::words::app::ONE_ROW_ONLY)
        } else {
            reason
        }
    };
    [
        Item::new(labels::DOWNLOAD, MenuAction::Download).greyed(
            state
                .session
                .download_dir
                .is_none()
                .then_some(crate::words::download::SET_DOWNLOAD_DIR_FIRST),
        ),
        Item::new(labels::COPY_LINK, MenuAction::CopyLink).greyed(one(None)),
        Item::new(labels::SEARCH_RELATED, MenuAction::SearchRelated)
            .greyed(one(crate::views::related::unavailable(state))),
    ]
}

/// Build the eD2k file link for *Copy eD2k link* (spec §3.3) through the
/// canonical [`rmule_primitives::Ed2kLink`] `Display`, so names with spaces or `|` come out
/// properly percent-escaped — never hand-built.
fn ed2k_link(result: &SearchResult) -> String {
    rmule_primitives::Ed2kLink::File(result.to_file_link()).to_string()
}

impl SearchesView {
    pub(super) fn open_menu(&mut self, state: &UiState) {
        // The menu acts on the row it opened over, whatever lands meanwhile.
        let ids = self.result_ids(state);
        if let Some(entry) = self.held.current_mut() {
            entry.cursor.pin(&ids);
        }
        self.menu_place.reset();
        self.menu = Some(menu::first_enabled(&self.items_now(state)));
    }

    fn items_now(&self, state: &UiState) -> [Item<MenuAction>; 3] {
        let tagged = self
            .held
            .current()
            .is_some_and(|entry| !entry.tags.is_empty());
        menu_items(state, tagged)
    }

    /// One key over the open menu.
    pub(super) fn menu_key(
        &mut self,
        cursor: usize,
        code: KeyCode,
        state: &UiState,
    ) -> ViewOutcome {
        let asked = menu::key(&self.items_now(state), cursor, code);
        self.answer_menu(asked, state)
    }

    /// A click on the open menu: an item runs, outside closes.
    pub(super) fn click_menu(&mut self, column: u16, row: u16, state: &UiState) -> ViewOutcome {
        let asked = self.menu_place.click(&self.items_now(state), column, row);
        self.answer_menu(asked, state)
    }

    fn answer_menu(&mut self, asked: Asked, state: &UiState) -> ViewOutcome {
        match asked {
            Asked::Close => self.menu = None,
            Asked::Move(index) => self.menu = Some(index),
            Asked::Run(index) => {
                self.menu = None;
                return self.run_menu(self.items_now(state)[index].action, state);
            }
            Asked::Nothing => {}
        }
        ViewOutcome::Redraw
    }

    fn run_menu(&mut self, action: MenuAction, state: &UiState) -> ViewOutcome {
        match action {
            MenuAction::Download => self.download_selected(state),
            MenuAction::CopyLink => match self.selected_result(state) {
                Some(result) => ViewOutcome::Emit(Action::CopyLink(ed2k_link(result))),
                None => ViewOutcome::Redraw,
            },
            // Dimmed since the cursor rested here (a server switch under the
            // open menu): nothing is sent.
            MenuAction::SearchRelated => match self.selected_result(state).and_then(|result| {
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

    /// Draw the open menu, titled by the row it acts on.
    pub(super) fn draw_menu(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        cursor: usize,
        state: &UiState,
        theme: &Theme,
    ) {
        let items = self.items_now(state);
        let tagged = self.held.current().map_or(0, |entry| entry.tags.len());
        let name = if tagged > 0 {
            crate::words::app::tagged(tagged)
        } else {
            self.selected_result(state)
                .map_or_else(String::new, |result| {
                    result.primary_name().to_display_string()
                })
        };
        menu::draw(
            frame,
            area,
            (&name, &items, cursor),
            theme,
            &self.menu_place,
        );
    }
}

#[cfg(test)]
mod tests {
    /// Offered with no directory, Download would be refused at the last step.
    #[test]
    fn download_is_greyed_with_the_way_on_until_a_directory_is_set() {
        let mut state = session_state();
        assert_eq!(menu_items(&state, false)[0].reason, None);
        state.session.download_dir = None;
        assert_eq!(
            menu_items(&state, false)[0].reason.as_deref(),
            Some("set a download dir first: press 6")
        );
    }

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
        let mut view = SearchesView::by_name();
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

    /// The real StartDownload, the file named, the folder left to core.
    #[test]
    fn the_download_menu_item_emits_the_start() {
        let mut state = state_with(three_tier_results(), SearchStatus::Completed { total: 3 });
        state.session = session_state().session;
        let mut view = SearchesView::by_name();
        view.handle_key(press(KeyCode::Char('g')), &state);
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
        let mut view = SearchesView::by_name();
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
        let mut view = SearchesView::by_name().having_sent("ubuntu");
        view.handle_key(press(KeyCode::Char('g')), &state);
        view.handle_key(press(KeyCode::Char('m')), &state);
        assert_golden("searches_menu", 78, 21, |frame| {
            view.draw(frame, frame.area(), &state, &theme, Instant::now());
        });
    }
}
