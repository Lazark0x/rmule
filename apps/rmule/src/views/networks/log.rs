//! The core-event log pane (spec §3.4): a scrollable ring of every event the
//! session has seen, each dated by relative age against a draw-time `now`.
//!
//! A long line wraps under the age gutter instead of being cut — the gutter is
//! written once per line, and the text keeps every character.

use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};

use super::{NetworksView, Pane};
use crate::state::UiState;
use crate::theme::Theme;
use crate::wrap::labeled_lines;

/// Width of the log pane's relative-age gutter (`"{age:>7} "`); wrapped
/// continuation lines hang under it.
const AGE_GUTTER_W: usize = 9;

/// Fixed wall stamp for renders nobody clocked (goldens, tests): midday UTC,
/// keeping derived times readable and deterministic.
fn fallback_wall() -> chrono::DateTime<chrono::FixedOffset> {
    chrono::DateTime::parse_from_rfc3339("2026-01-01T12:00:00+00:00")
        .expect("static timestamp parses")
}

impl NetworksView {
    pub(super) fn max_log_offset(&self, state: &UiState) -> usize {
        let lines = if self.log_lines > 0 {
            self.log_lines
        } else {
            state.log.len()
        };
        lines.saturating_sub(self.log_rows.max(1))
    }

    pub(super) fn draw_log(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
        now: Instant,
    ) {
        let focused = self.focus == Pane::Log;
        let border = if focused { theme.accent } else { theme.dim };
        let block = crate::views::title::titled(
            Block::bordered().border_style(Style::new().fg(border)),
            area.width,
            (
                &format!(" Log ({}) ", state.log.len()),
                Style::new().fg(theme.fg),
            ),
            ("", theme.dim_text()),
        );
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if inner.height == 0 || inner.width == 0 {
            return;
        }
        let visible = inner.height as usize;
        self.log_rows = visible; // remembered for input-time scroll clamping

        if state.log.is_empty() {
            frame.render_widget(
                Paragraph::new(Line::styled("no core events yet", theme.dim_text())),
                inner,
            );
            return;
        }

        // Each entry wraps under its time gutter: a long event text
        // costs extra rows instead of being cut at the pane edge. Scrolling
        // therefore counts *display* lines, not entries. The gutter shows the
        // event's wall-clock time (a hands-on run's finding — a counter forced
        // the reader to do arithmetic): derived as `wall_now − age`, since
        // the state layer stays clock-free.
        let wall_now = self.wall_now.unwrap_or_else(fallback_wall);
        let text_w = usize::from(inner.width).saturating_sub(AGE_GUTTER_W).max(1);
        let lines: Vec<Line> = state
            .log
            .iter()
            .flat_map(|line| {
                let age = chrono::Duration::from_std(now.saturating_duration_since(line.at))
                    .unwrap_or_else(|_| chrono::Duration::zero());
                labeled_lines(
                    Span::styled(
                        format!(
                            "{:>width$} ",
                            (wall_now - age).format("%H:%M:%S"),
                            width = AGE_GUTTER_W - 1
                        ),
                        theme.dim_text(),
                    ),
                    line.text.as_str(),
                    Style::new().fg(theme.fg),
                    text_w,
                )
            })
            .collect();
        self.log_lines = lines.len();

        let offset = self.log_offset.min(lines.len().saturating_sub(visible));
        let end = lines.len() - offset;
        let start = end.saturating_sub(visible);
        frame.render_widget(Paragraph::new(lines[start..end].to_vec()), inner);
    }
}

#[cfg(test)]
mod tests {
    use crate::action::Action;
    use std::time::Duration;

    use rmule_core::{CoreEvent, DownloadEvent};

    use crate::golden::assert_golden;

    use crate::views::networks::*;

    use crate::fixture::*;
    #[test]
    fn log_focus_scrolls_and_g_bindings_jump_to_the_ends() {
        let mut state = UiState::default();
        let now = Instant::now();
        for part_index in 0..10u32 {
            state.apply(
                Action::Core(CoreEvent::Download(DownloadEvent::PartVerified {
                    download_id: download_id(1),
                    part_index,
                })),
                now,
            );
        }
        let mut view = NetworksView::new();
        view.handle_key(press(KeyCode::Tab), &state); // focus → Log
        assert_eq!(view.log_offset, 0, "starts pinned to the newest line");
        view.handle_key(press(KeyCode::Char('k')), &state);
        assert_eq!(view.log_offset, 1, "k scrolls one line older");
        // Default log_rows is 4 ⇒ oldest offset is 10 − 4.
        view.handle_key(press(KeyCode::Char('g')), &state);
        assert_eq!(view.log_offset, 6, "g jumps to the oldest window");
        view.handle_key(press(KeyCode::Char('G')), &state);
        assert_eq!(view.log_offset, 0, "G pins back to the newest");
    }

    #[test]
    fn golden_networks_log_focus() {
        let base = Instant::now();
        let mut state = UiState::default();
        for (offset, part_index) in [(560u64, 5u32), (585, 12), (598, 17)] {
            state.apply(
                Action::Core(CoreEvent::Download(DownloadEvent::PartVerified {
                    download_id: download_id(1),
                    part_index,
                })),
                base + Duration::from_secs(offset),
            );
        }
        let now = base + Duration::from_secs(600);
        let mut view = NetworksView::new();
        view.handle_key(press(KeyCode::Tab), &state); // focus → Log
        assert_golden("networks_log_focus", 78, 21, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now);
        });
    }

    #[test]
    fn golden_networks_wrap_long_log_line() {
        let (state, base) = long_failure();
        let now = base + Duration::from_secs(5);
        let mut view = NetworksView::new();
        assert_golden("networks_wrap_long_log", 78, 21, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now);
        });
    }

    #[test]
    fn a_long_log_line_wraps_under_the_age_gutter_instead_of_being_cut() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let (state, base) = long_failure();
        let mut view = NetworksView::new();
        let mut terminal = Terminal::new(TestBackend::new(78, 21)).expect("terminal");
        terminal
            .draw(|frame| {
                let area = frame.area();
                view.draw(frame, area, &state, &Theme::default_dark(), base);
            })
            .expect("draw");
        let buffer = terminal.backend().buffer();
        let area = buffer.area;
        let rendered: String = (area.top()..area.bottom())
            .map(|y| {
                (area.left()..area.right())
                    .map(|x| buffer.cell((x, y)).map_or(" ", |cell| cell.symbol()))
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            rendered.contains("already checked"),
            "the log tail was cut:\n{rendered}"
        );
        assert!(
            view.log_lines > state.log.len(),
            "the entry wrapped to more display lines than entries"
        );
    }
}
