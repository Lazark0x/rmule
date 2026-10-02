//! The cancel confirm: the one download action that destroys work, so it is
//! the one action that asks first.

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use rmule_core::{CoreCommand, DownloadCommand, DownloadId};

use super::{Overlay, TransfersView, selected_id};
use crate::action::Action;
use crate::state::UiState;
use crate::theme::Theme;
use crate::views::ViewOutcome;
use crate::views::modal::Modal;
use crate::words::units::short_hash_or_dash;
use crate::wrap::wrapped_lines;

impl TransfersView {
    pub(super) fn handle_confirm(&mut self, key: KeyEvent, ids: &[DownloadId]) -> ViewOutcome {
        match key.code {
            KeyCode::Char('y') => {
                self.overlay = Overlay::None;
                match selected_id(ids, &self.table_state) {
                    Some(id) => ViewOutcome::Emit(Action::Command(CoreCommand::Download(
                        DownloadCommand::CancelDownload { download_id: id },
                    ))),
                    None => ViewOutcome::Redraw,
                }
            }
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('q') => {
                self.overlay = Overlay::None;
                ViewOutcome::Redraw
            }
            _ => ViewOutcome::Redraw,
        }
    }

    pub(super) fn draw_confirm(
        &self,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
        ids: &[DownloadId],
    ) {
        let short = selected_id(ids, &self.table_state).map_or_else(
            || "—".to_string(),
            |id| short_hash_or_dash(state.downloads.get(&id).and_then(|r| r.file_hash)),
        );
        let width = 42u16.min(area.width);
        let text_w = usize::from(width).saturating_sub(2).max(1);
        let mut lines: Vec<Line<'static>> = Vec::new();
        // Both prose lines wrap rather than clip.
        lines.extend(wrapped_lines(&short, text_w, Style::new().fg(theme.fg)));
        lines.extend(wrapped_lines(
            "This deletes the part file.",
            text_w,
            Style::new().fg(theme.bad),
        ));
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![
            Span::styled(
                "y",
                Style::new().fg(theme.accent).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" confirm    ", Style::new().fg(theme.fg)),
            Span::styled(
                "Esc",
                Style::new().fg(theme.accent).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" abort", Style::new().fg(theme.fg)),
        ]));

        Modal::new(" Cancel download ", theme)
            .flash_title(theme)
            .at_least(6)
            .draw(frame, area, width, theme, lines);
    }
}

#[cfg(test)]
mod tests {

    use ratatui::crossterm::event::KeyCode;

    use crate::golden::assert_golden;

    use super::*;
    use crate::fixture::*;

    #[test]
    fn cancel_flows_menu_to_confirm_to_command() {
        let mut view = TransfersView::new();
        let state = three_downloads();
        view.select_row(&state, 0);
        view.handle_key(press(KeyCode::Char('m')), &state);
        view.handle_key(press(KeyCode::Char('j')), &state); // cursor → Cancel…
        assert!(matches!(
            view.handle_key(press(KeyCode::Enter), &state),
            ViewOutcome::Redraw
        ));
        assert_eq!(view.overlay, Overlay::ConfirmCancel);
        match view.handle_key(press(KeyCode::Char('y')), &state) {
            ViewOutcome::Emit(Action::Command(CoreCommand::Download(
                DownloadCommand::CancelDownload { download_id },
            ))) => assert_eq!(download_id, crate::fixture::download_id(1)),
            _ => panic!("y must confirm the cancel"),
        }
        assert_eq!(view.overlay, Overlay::None);
    }

    #[test]
    fn esc_aborts_the_cancel_confirm_without_emitting() {
        let mut view = TransfersView::new();
        let state = three_downloads();
        view.select_row(&state, 0);
        view.overlay = Overlay::ConfirmCancel;
        assert!(matches!(
            view.handle_key(press(KeyCode::Esc), &state),
            ViewOutcome::Redraw
        ));
        assert_eq!(view.overlay, Overlay::None);
    }

    #[test]
    fn golden_confirm_cancel() {
        let mut view = TransfersView::new();
        view.overlay = Overlay::ConfirmCancel;
        let state = three_downloads();
        assert_golden("transfers_confirm_cancel", GOLDEN_W, GOLDEN_H, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now());
        });
    }
}
