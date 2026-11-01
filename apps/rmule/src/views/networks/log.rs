//! The core-event log pane (spec §3.4): every event the session kept, each with
//! the time it was said and its severity as a glyph and a word, and a date line
//! at the start and wherever the day changes. `f` narrows it by severity.
//!
//! A long line wraps under the gutter instead of being cut — the gutter is
//! written once per line, and the text keeps every character.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::{NetworksView, Pane};
use crate::row_selection::viewport;
use crate::state::{LogLine, UiState};
use crate::theme::Theme;
use crate::views::ViewOutcome;
use crate::words::log as words;
use crate::words::severity::Severity;
use crate::wrap::labeled_lines;

/// Width of the time and the severity's glyph in the gutter, each with the
/// space after it; wrapped continuation lines hang under the gutter.
const TIME_W: usize = 9;
const GLYPH_W: usize = 2;

/// The next floor `f` gives: every line, warnings and up, failures, every line.
const fn next_floor(floor: Severity) -> Severity {
    match floor {
        Severity::Info => Severity::Warning,
        Severity::Warning => Severity::Failure,
        Severity::Failure => Severity::Info,
    }
}

fn tone(severity: Severity, theme: &Theme) -> Style {
    match severity {
        Severity::Info => theme.dim_text(),
        Severity::Warning => Style::new().fg(theme.warn),
        Severity::Failure => Style::new().fg(theme.bad),
    }
}

/// A line's display rows: the time and the severity's glyph on its first, then
/// the severity's word, the two in its colour, then the text, wrapping under
/// the gutter.
fn entry(line: &LogLine, width: u16, theme: &Theme) -> Vec<Line<'static>> {
    let time = format!("{:<TIME_W$}", line.wall.format("%H:%M:%S"));
    let toned = tone(line.severity, theme);
    let glyph = format!("{:<GLYPH_W$}", line.severity.glyph());
    let word = line.severity.word();
    let text = word.map_or_else(
        || line.text.to_string(),
        |word| words::worded(word, &line.text),
    );
    let text_style = Style::new().fg(theme.fg);
    let text_w = usize::from(width).saturating_sub(TIME_W + GLYPH_W).max(1);
    labeled_lines(Span::styled(glyph, toned), &text, text_style, text_w)
        .into_iter()
        .enumerate()
        .map(|(index, mut row)| {
            let gutter = if index == 0 {
                Span::styled(time.clone(), theme.dim_text())
            } else {
                Span::raw(" ".repeat(TIME_W))
            };
            row.spans.insert(0, gutter);
            let opens_with_word = word.filter(|_| index == 0).and_then(|word| {
                let body = row.spans.last()?;
                let rest = body.content.strip_prefix(word)?.to_string();
                Some((word, rest))
            });
            if let Some((word, rest)) = opens_with_word {
                row.spans.pop();
                row.spans.push(Span::styled(word, toned));
                row.spans.push(Span::styled(rest, text_style));
            }
            row
        })
        .collect()
}

impl NetworksView {
    /// `f` on the focused log: the next severity floor. The list shortens or
    /// grows, so the viewport goes back to the newest line.
    pub(super) fn narrow_log(&mut self) -> ViewOutcome {
        self.log_floor = next_floor(self.log_floor);
        self.log_viewport = crate::row_selection::viewport::Viewport::at_end();
        ViewOutcome::Redraw
    }

    pub(super) fn draw_log(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
    ) {
        let focused = self.focus == Pane::Log;
        let shown: Vec<&LogLine> = state
            .log
            .iter()
            .filter(|line| line.severity >= self.log_floor)
            .collect();
        let block = crate::views::title::titled(
            theme.pane(focused),
            area.width,
            (
                &words::title(shown.len(), state.log.len(), self.log_floor),
                Style::new().fg(theme.fg),
            ),
            (words::hint(focused), theme.dim_text()),
        );
        let inner = block.inner(area);
        frame.render_widget(block, area);
        self.log_caret = None;
        if inner.height == 0 || inner.width == 0 {
            return;
        }
        if shown.is_empty() {
            self.log_viewport.show(0, inner.height);
            frame.render_widget(
                Paragraph::new(Line::styled(
                    words::nothing_shown(self.log_floor),
                    theme.dim_text(),
                )),
                inner,
            );
            return;
        }

        let kept: Vec<&LogLine> = shown
            .iter()
            .copied()
            .filter(|line| self.log_filter.keeps([line.text.as_str()]))
            .collect();
        let (inner, filter_line) = self.log_filter.carve(inner);
        self.log_caret =
            self.log_filter
                .draw(frame, filter_line, (kept.len(), state.log.len()), theme);
        let day_style = theme.dim_text().add_modifier(Modifier::BOLD);
        // Each entry wraps under its gutter: a long event text costs extra rows
        // instead of being cut at the pane edge. Scrolling therefore counts
        // *display* lines, not entries.
        let lines_at = |width: u16| {
            let mut lines = Vec::with_capacity(kept.len() + 1);
            let mut days: Vec<(usize, String)> = Vec::new();
            for line in &kept {
                let date = line.wall.format("%Y-%m-%d").to_string();
                if days.last().is_none_or(|(_, day)| *day != date) {
                    days.push((lines.len(), date.clone()));
                    lines.push(Line::styled(date, day_style));
                }
                lines.extend(entry(line, width, theme));
            }
            (lines, days)
        };
        let bar = viewport::needs_bar(kept.len(), inner.height, || {
            lines_at(inner.width).0.len() > usize::from(inner.height)
        });
        let (list, bar) = viewport::split(inner, bar);
        let (lines, days) = lines_at(list.width);
        let on_screen = self.log_viewport.show(lines.len(), list.height);
        // Scrolled past its date line, the top row's day is on the border: a
        // time with no date in view is the ambiguity the date lines are for.
        let top_day = days
            .iter()
            .rfind(|(row, _)| *row < on_screen.start)
            .filter(|_| !days.iter().any(|(row, _)| *row == on_screen.start));
        frame.render_widget(Paragraph::new(lines[on_screen].to_vec()), list);
        self.log_viewport.draw(frame, area, bar, theme);
        if let Some((_, day)) = top_day {
            let edge = Rect {
                x: area.x.saturating_add(1),
                y: area.bottom().saturating_sub(1),
                width: u16::try_from(day.len() + 2).unwrap_or(0),
                height: 1,
            };
            frame.render_widget(
                Line::styled(format!(" {day} "), day_style),
                edge.intersection(area),
            );
        }
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
        assert_eq!(
            view.log_viewport.first(),
            end - 1,
            "k scrolls one line older"
        );
        view.handle_key(press(KeyCode::Char('g')), &state);
        assert_eq!(view.log_viewport.first(), 0, "g jumps to the oldest window");
        view.handle_key(press(KeyCode::Char('G')), &state);
        assert_eq!(view.log_viewport.first(), end, "G pins back to the newest");
        assert!(
            draw(&mut view).contains(" 31 / 31 "),
            "resting on the end, the border counts the newest line and the date line"
        );
    }

    /// A run across midnight: the day is said when it changes, and no earlier.
    #[test]
    fn the_date_is_said_at_the_start_and_when_the_day_changes() {
        let mut state = UiState::default();
        let base = Instant::now();
        state
            .log
            .set_wall(base, "2026-03-01T23:59:58+00:00".parse().unwrap());
        for second in 0..5u64 {
            state.apply(
                Action::Core(CoreEvent::Download(DownloadEvent::PartVerified {
                    download_id: download_id(1),
                    part_index: 7,
                })),
                base + Duration::from_secs(second),
            );
        }
        let mut view = NetworksView::new();
        let rendered = crate::golden::render_to_lines(100, 30, |frame| {
            view.draw(
                frame,
                frame.area(),
                &state,
                &Theme::default_dark(),
                base + Duration::from_secs(5),
            );
        });
        let rows: Vec<&str> = rendered
            .lines()
            .filter(|row| row.contains("2026-03-") || row.contains("part 7"))
            .map(|row| row.split('│').nth(1).unwrap_or(row).trim())
            .collect();
        assert_eq!(
            rows,
            [
                "2026-03-01",
                "23:59:58 · part 7 verified",
                "23:59:59 · part 7 verified",
                "2026-03-02",
                "00:00:00 · part 7 verified",
                "00:00:01 · part 7 verified",
                "00:00:02 · part 7 verified",
            ]
        );
    }

    /// `f` walks every line, warnings and up, failures, every line, and what a
    /// floor hides is counted beside what it keeps.
    #[test]
    fn f_narrows_the_focused_log_by_severity_and_wraps() {
        let mut state = UiState::default();
        let now = Instant::now();
        state.apply(
            Action::Core(CoreEvent::Download(DownloadEvent::PartVerified {
                download_id: download_id(1),
                part_index: 1,
            })),
            now,
        );
        state.apply(Action::Core(CoreEvent::EventsShed { count: 3 }), now);
        state.apply(
            Action::Core(CoreEvent::ClientUdpBindFailed {
                port: 4672,
                kind: std::io::ErrorKind::AddrInUse,
            }),
            now,
        );
        let mut view = NetworksView::new();
        let rendered = |view: &mut NetworksView| {
            crate::golden::render_to_lines(100, 30, |frame| {
                view.draw(frame, frame.area(), &state, &Theme::default_dark(), now);
            })
        };
        view.handle_key(press(KeyCode::Char('f')), &state);
        assert!(
            rendered(&mut view).contains("Log (3)"),
            "f is the focused log's key alone"
        );
        view.handle_key(press(KeyCode::Tab), &state); // focus → Log
        let all = rendered(&mut view);
        assert!(
            all.contains("· part 1") && all.contains("! warning:") && all.contains("✗ failure:")
        );

        view.handle_key(press(KeyCode::Char('f')), &state);
        let warnings = rendered(&mut view);
        assert!(warnings.contains("Log (2 of 3) · warnings and failures"));
        assert!(!warnings.contains("part 1") && warnings.contains("! warning:"));

        view.handle_key(press(KeyCode::Char('f')), &state);
        let failures = rendered(&mut view);
        assert!(failures.contains("Log (1 of 3) · failures"));
        assert!(!failures.contains("! warning:") && failures.contains("✗ failure:"));

        view.handle_key(press(KeyCode::Char('f')), &state);
        assert!(rendered(&mut view).contains("Log (3)"));
    }

    /// A log longer than its pane, scrolled back: no cursor, so the border
    /// counts the last line on screen of all of them, and the bar shows where.
    /// The log filters as the tables do: only the lines that hold the word.
    #[test]
    fn slash_over_the_log_keeps_the_lines_that_hold_it() {
        use crate::golden::render_to_lines;
        let mut state = UiState::default();
        for text in ["alpha one", "beta two"] {
            state.log_flash(crate::words::Sentence::for_test(text), now());
        }
        let mut view = NetworksView::new();
        view.handle_key(press(KeyCode::Tab), &state);
        view.handle_key(press(KeyCode::Char('/')), &state);
        for letter in "beta".chars() {
            view.handle_key(press(KeyCode::Char(letter)), &state);
        }
        let shown = render_to_lines(100, 30, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now());
        });
        assert!(shown.contains("beta two"), "{shown}");
        assert!(!shown.contains("alpha one"), "{shown}");
        assert!(shown.contains("1 of 2"), "{shown}");
    }

    #[test]
    fn golden_networks_log_overflow() {
        let base = Instant::now();
        let mut state = UiState::default();
        for part_index in 0..30u32 {
            state.apply(
                Action::Core(CoreEvent::Download(DownloadEvent::PartVerified {
                    download_id: download_id(1),
                    part_index,
                })),
                base + Duration::from_secs(u64::from(part_index)),
            );
        }
        let now = base + Duration::from_secs(60);
        let mut view = NetworksView::new();
        let theme = Theme::default_dark();
        crate::golden::render_to_lines(78, 21, |frame| {
            view.draw(frame, frame.area(), &state, &theme, now);
        });
        view.handle_key(press(KeyCode::Tab), &state); // focus → Log
        for _ in 0..8 {
            view.handle_key(press(KeyCode::Char('k')), &state);
        }
        assert_golden("networks_log_overflow", 78, 21, |frame| {
            view.draw(frame, frame.area(), &state, &theme, now);
        });
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
    fn a_long_log_line_wraps_under_the_gutter_instead_of_being_cut() {
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
