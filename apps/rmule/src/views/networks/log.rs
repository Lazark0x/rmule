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
use crate::row_selection::viewport;
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
        if state.log.is_empty() {
            self.log_viewport.show(0, inner.height);
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
        let lines_at = |width: u16| -> Vec<Line> {
            let text_w = usize::from(width).saturating_sub(AGE_GUTTER_W).max(1);
            state
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
                .collect()
        };
        let bar = viewport::needs_bar(state.log.len(), inner.height, || {
            lines_at(inner.width).len() > usize::from(inner.height)
        });
        let (list, bar) = viewport::split(inner, bar);
        let lines = lines_at(list.width);
        let shown = self.log_viewport.show(lines.len(), list.height);
        frame.render_widget(Paragraph::new(lines[shown].to_vec()), list);
        self.log_viewport.draw(frame, area, bar, theme);
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
        for part_index in 0..30u32 {
            state.apply(
                Action::Core(CoreEvent::Download(DownloadEvent::PartVerified {
                    download_id: download_id(1),
                    part_index,
                })),
                now,
            );
        }
        let mut view = NetworksView::new();
        let draw = |view: &mut NetworksView| {
            crate::golden::render_to_lines(78, 21, |frame| {
                view.draw(frame, frame.area(), &state, &Theme::default_dark(), now);
            })
        };
        draw(&mut view);
        view.handle_key(press(KeyCode::Tab), &state); // focus → Log
        let end = view.log_viewport.first();
        assert!(end > 0, "opens on the newest line");
        view.handle_key(press(KeyCode::Char('k')), &state);
        assert_eq!(view.log_viewport.first(), end - 1, "k scrolls one line older");
        view.handle_key(press(KeyCode::Char('g')), &state);
        assert_eq!(view.log_viewport.first(), 0, "g jumps to the oldest window");
        view.handle_key(press(KeyCode::Char('G')), &state);
        assert_eq!(view.log_viewport.first(), end, "G pins back to the newest");
        assert!(
            draw(&mut view).contains(" 30 / 30 "),
            "resting on the end, the border counts the newest line"
        );
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
    }
}
