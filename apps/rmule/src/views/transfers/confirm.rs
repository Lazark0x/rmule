//! The cancel confirm: the one download action that destroys work, so it asks
//! first, and names the file, or how many.

use ratatui::Frame;
use ratatui::crossterm::event::KeyEvent;
use ratatui::layout::Rect;
use rmule_core::{CoreCommand, DownloadCommand, DownloadId};

use super::downloads::display_name;
use super::sort::DownloadLine;
use super::{Overlay, TransfersView};
use crate::action::Action;
use crate::state::UiState;
use crate::theme::Theme;
use crate::views::ViewOutcome;
use crate::views::modal::{Question, confirm_key, draw_question, scroll_key};
use crate::words::{app as words, labels};

/// A download as a sentence names it: its file's name, never its hash; a word
/// for a row whose name has not landed yet.
pub(super) fn download_name(state: &UiState, id: DownloadId) -> String {
    let row = state.downloads.get(&id);
    let metadata = row.and_then(|row| row.metadata.as_ref());
    match display_name(metadata, None) {
        (name, true) => name,
        _ => words::UNNAMED_FILE.to_string(),
    }
}

impl TransfersView {
    /// Ask before cancelling `targets`.
    pub(super) fn ask_cancel(&mut self, targets: Vec<DownloadId>) {
        self.overlay = Overlay::ConfirmCancel { targets };
        self.confirm_viewport.take();
    }

    pub(super) fn handle_confirm(&mut self, key: KeyEvent, targets: &[DownloadId]) -> ViewOutcome {
        match confirm_key(key.code) {
            Some(true) => {
                self.overlay = Overlay::None;
                ViewOutcome::Emit(Action::Commands(
                    targets
                        .iter()
                        .map(|id| {
                            CoreCommand::Download(DownloadCommand::CancelDownload {
                                download_id: *id,
                            })
                        })
                        .collect(),
                ))
            }
            Some(false) => {
                self.overlay = Overlay::None;
                ViewOutcome::Redraw
            }
            None => {
                scroll_key(&mut self.confirm_viewport, key.code);
                ViewOutcome::Redraw
            }
        }
    }

    pub(super) fn draw_confirm(
        &self,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
        targets: &[DownloadId],
    ) {
        let asks = match targets {
            [id] => {
                let line = DownloadLine::new(*id, state);
                let done = line.done_cell();
                let done = done.ends_with('%').then_some(done.as_str());
                words::cancel_one(&download_name(state, *id), &line.size_cell(), done)
            }
            many => words::cancel_many(many.len()),
        };
        let question = Question {
            title: labels::CANCEL_TITLE,
            asks: &asks,
            does: words::cancel_does(targets.len()),
        };
        draw_question(frame, area, &question, theme, &self.confirm_viewport);
    }
}

#[cfg(test)]
mod tests {

    use ratatui::crossterm::event::KeyCode;

    use crate::golden::assert_golden;

    use super::*;
    use crate::fixture::*;

    /// The confirm says what is lost by name, never by hash.
    #[test]
    fn the_confirm_names_the_file_never_its_hash() {
        let mut view = TransfersView::by_name();
        let state = three_downloads();
        view.select_row(&state, 0);
        let id = crate::fixture::download_id(1);
        view.ask_cancel(vec![id]);
        let shown = crate::golden::render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now());
        });
        let name = download_name(&state, id);
        assert!(shown.contains(&format!("Cancel {name}")), "{shown}");
    }

    #[test]
    fn a_confirm_over_many_counts_them() {
        let mut view = TransfersView::by_name();
        let state = three_downloads();
        view.ask_cancel(vec![
            crate::fixture::download_id(1),
            crate::fixture::download_id(2),
        ]);
        let shown = crate::golden::render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now());
        });
        assert!(shown.contains("Cancel 2 downloads?"), "{shown}");
        assert!(shown.contains("part files"), "{shown}");
    }

    #[test]
    fn cancel_flows_menu_to_confirm_to_command() {
        let mut view = TransfersView::by_name();
        let state = three_downloads();
        view.select_row(&state, 0);
        view.handle_key(press(KeyCode::Char('m')), &state);
        view.handle_key(press(KeyCode::Char('j')), &state); // cursor → Cancel…
        assert!(matches!(
            view.handle_key(press(KeyCode::Enter), &state),
            ViewOutcome::Redraw
        ));
        let Overlay::ConfirmCancel { targets } = &view.overlay else {
            panic!("the confirm is up");
        };
        assert_eq!(targets, &[crate::fixture::download_id(1)]);
        match view.handle_key(press(KeyCode::Char('y')), &state) {
            ViewOutcome::Emit(Action::Commands(commands)) => assert!(matches!(
                commands.as_slice(),
                [CoreCommand::Download(DownloadCommand::CancelDownload { download_id })]
                    if *download_id == crate::fixture::download_id(1)
            )),
            _ => panic!("y must confirm the cancel"),
        }
        assert_eq!(view.overlay, Overlay::None);
    }

    #[test]
    fn esc_aborts_the_cancel_confirm_without_emitting() {
        let mut view = TransfersView::by_name();
        let state = three_downloads();
        view.select_row(&state, 0);
        view.ask_cancel(vec![crate::fixture::download_id(1)]);
        assert!(matches!(
            view.handle_key(press(KeyCode::Esc), &state),
            ViewOutcome::Redraw
        ));
        assert_eq!(view.overlay, Overlay::None);
    }

    #[test]
    fn golden_confirm_cancel() {
        let mut view = TransfersView::by_name();
        view.ask_cancel(vec![crate::fixture::download_id(1)]);
        let state = three_downloads();
        assert_golden("transfers_confirm_cancel", GOLDEN_W, GOLDEN_H, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now());
        });
    }

    /// In a frame too short for the question, `G` scrolls to the legend and
    /// the bottom border says where the operator is.
    #[test]
    fn golden_confirm_cancel_scrolls_in_a_short_frame() {
        let mut view = TransfersView::by_name();
        view.ask_cancel(vec![crate::fixture::download_id(1)]);
        let state = three_downloads();
        let shown = |view: &mut TransfersView| {
            crate::golden::render_to_lines(60, 5, |frame| {
                let area = frame.area();
                view.draw(frame, area, &state, &Theme::default_dark(), now());
            })
        };
        assert_golden("transfers_confirm_cancel_short", 60, 5, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now());
        });
        assert!(!shown(&mut view).contains("n no"));
        view.handle_key(press(KeyCode::Char('G')), &state);
        let end = shown(&mut view);
        assert!(end.contains("n no") && end.contains("5 / 5"), "{end}");
    }
}
