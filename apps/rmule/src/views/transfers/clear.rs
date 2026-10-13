//! "Clear all completed" (ADR-0094, "Clearing a completed download"):
//! `C` asks once, then core forgets every completed download. The files stay
//! on disk and shared, so nothing here is destructive of work; the confirm is
//! for the list, which loses every completed row at once.

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use rmule_core::{CoreCommand, DownloadCommand, DownloadId};

use super::{Overlay, TransfersView};
use crate::action::Action;
use crate::state::{DownloadStatus, UiState};
use crate::theme::Theme;
use crate::views::ViewOutcome;
use crate::views::modal::{Modal, scroll_key};
use crate::wrap::wrapped_lines;

/// The downloads the list shows as completed, in id order.
pub(super) fn completed_ids(state: &UiState) -> Vec<DownloadId> {
    let mut ids: Vec<DownloadId> = state
        .downloads
        .iter()
        .filter(|(_, row)| row.status == DownloadStatus::Completed)
        .map(|(id, _)| *id)
        .collect();
    ids.sort();
    ids
}

impl TransfersView {
    /// `C`: ask before clearing every completed row, or say there is none.
    pub(super) fn clear_completed_key(&mut self, state: &UiState) -> ViewOutcome {
        let counted = completed_ids(state);
        if counted.is_empty() {
            return ViewOutcome::Emit(Action::Flash(crate::words::download::NOTHING_TO_CLEAR));
        }
        self.overlay = Overlay::ConfirmClearCompleted { counted };
        self.confirm_viewport.take();
        ViewOutcome::Redraw
    }

    /// The answer clears the downloads the question counted, never one that
    /// completed while it was up.
    pub(super) fn handle_confirm_clear(
        &mut self,
        key: KeyEvent,
        counted: &[DownloadId],
    ) -> ViewOutcome {
        match key.code {
            KeyCode::Char('y') => {
                self.overlay = Overlay::None;
                ViewOutcome::Emit(Action::Commands(
                    counted
                        .iter()
                        .map(|&download_id| {
                            CoreCommand::Download(DownloadCommand::ClearDownload { download_id })
                        })
                        .collect(),
                ))
            }
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('q') => {
                self.overlay = Overlay::None;
                ViewOutcome::Redraw
            }
            code => {
                scroll_key(&mut self.confirm_viewport, code);
                ViewOutcome::Redraw
            }
        }
    }

    pub(super) fn draw_confirm_clear(
        &self,
        frame: &mut Frame,
        area: Rect,
        counted: &[DownloadId],
        theme: &Theme,
    ) {
        let count = counted.len();
        let width = 46u16.min(area.width);
        let noun = if count == 1 { "download" } else { "downloads" };
        let lines = |width: u16| {
            let text_w = usize::from(width).saturating_sub(2).max(1);
            let mut lines: Vec<Line<'static>> = Vec::new();
            lines.extend(wrapped_lines(
                &format!("Clear {count} completed {noun} from the list?"),
                text_w,
                Style::new().fg(theme.fg),
            ));
            let kept = if count == 1 {
                "The file stays on disk and shared."
            } else {
                "The files stay on disk and shared."
            };
            lines.extend(wrapped_lines(kept, text_w, theme.dim_text()));
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                Span::styled(
                    "y",
                    Style::new().fg(theme.accent).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" clear    ", Style::new().fg(theme.fg)),
                Span::styled(
                    "Esc",
                    Style::new().fg(theme.accent).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" abort", Style::new().fg(theme.fg)),
            ]));
            lines
        };

        Modal::new(" Clear completed ", theme)
            .flash_title(theme)
            .at_least(6)
            .draw_scrolled(frame, area, width, theme, &self.confirm_viewport, lines);
    }
}

#[cfg(test)]
mod tests {
    use ratatui::crossterm::event::KeyCode;
    use rmule_core::DownloadId;

    use super::*;
    use crate::fixture::*;
    use crate::golden::assert_golden;

    fn clear_command(outcome: ViewOutcome) -> Option<DownloadCommand> {
        match outcome {
            ViewOutcome::Emit(Action::Command(CoreCommand::Download(command))) => Some(command),
            _ => None,
        }
    }

    fn cleared_ids(outcome: ViewOutcome) -> Vec<DownloadId> {
        let ViewOutcome::Emit(Action::Commands(commands)) = outcome else {
            panic!("expected the answer to send commands");
        };
        commands
            .into_iter()
            .map(|command| match command {
                CoreCommand::Download(DownloadCommand::ClearDownload { download_id }) => {
                    download_id
                }
                other => panic!("expected ClearDownload, got {other:?}"),
            })
            .collect()
    }

    /// The answer clears what the question counted: a download that completes
    /// while the question is up is left for the next one.
    #[test]
    fn a_download_completing_under_the_question_is_not_cleared() {
        let mut view = TransfersView::new();
        let mut state = three_downloads();
        view.handle_key(press(KeyCode::Char('C')), &state);
        state
            .downloads
            .get_mut(&download_id(1))
            .expect("row")
            .status = DownloadStatus::Completed;
        assert_eq!(
            cleared_ids(view.handle_key(press(KeyCode::Char('y')), &state)),
            vec![download_id(3)]
        );
    }

    #[test]
    fn capital_c_asks_then_clears_every_completed_download() {
        let mut view = TransfersView::new();
        let state = three_downloads();
        assert!(matches!(
            view.handle_key(press(KeyCode::Char('C')), &state),
            ViewOutcome::Redraw
        ));
        assert_eq!(
            view.overlay,
            Overlay::ConfirmClearCompleted {
                counted: vec![download_id(3)]
            }
        );
        assert_eq!(
            cleared_ids(view.handle_key(press(KeyCode::Char('y')), &state)),
            vec![download_id(3)]
        );
        assert_eq!(view.overlay, Overlay::None);

        view.handle_key(press(KeyCode::Char('C')), &state);
        assert!(clear_command(view.handle_key(press(KeyCode::Esc), &state)).is_none());
        assert_eq!(view.overlay, Overlay::None, "Esc aborts");
    }

    #[test]
    fn capital_c_with_nothing_completed_says_so_instead_of_asking() {
        let mut view = TransfersView::new();
        let mut state = three_downloads();
        state
            .downloads
            .retain(|_, row| row.status != DownloadStatus::Completed);
        assert!(matches!(
            view.handle_key(press(KeyCode::Char('C')), &state),
            ViewOutcome::Emit(Action::Flash(_))
        ));
        assert_eq!(view.overlay, Overlay::None);
    }

    /// The completed row's menu offers "Clear from list" first, greys Cancel
    /// with its reason, and Enter clears that one download.
    #[test]
    fn a_completed_rows_menu_clears_that_row_and_cancel_is_greyed() {
        let mut view = TransfersView::new();
        let state = three_downloads();
        let completed: DownloadId = download_id(3);
        let at = view
            .download_ids(&state)
            .iter()
            .position(|id| *id == completed)
            .unwrap();
        view.select_row(&state, at);
        view.handle_key(press(KeyCode::Char('m')), &state);
        let items = super::super::menu::menu_items(DownloadStatus::Completed, completed, &state);
        assert_eq!(items[0].label, "Clear from list");
        assert!(
            items[1].reason.is_some(),
            "Cancel is greyed with its reason"
        );
        match clear_command(view.handle_key(press(KeyCode::Enter), &state)) {
            Some(DownloadCommand::ClearDownload { download_id }) => {
                assert_eq!(download_id, completed);
            }
            other => panic!("expected ClearDownload, got {other:?}"),
        }
    }

    #[test]
    fn golden_confirm_clear_completed() {
        let mut view = TransfersView::new();
        view.overlay = Overlay::ConfirmClearCompleted {
            counted: vec![download_id(3)],
        };
        let state = three_downloads();
        assert_golden(
            "transfers_confirm_clear_completed",
            GOLDEN_W,
            GOLDEN_H,
            |frame| {
                let area = frame.area();
                view.draw(frame, area, &state, &Theme::default_dark(), now());
            },
        );
    }
}
