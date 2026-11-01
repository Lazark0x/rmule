//! The two rate graphs: one cell per history column, newest at the right.
//!
//! The window picks what a column stands for — a tick, a minute, an hour — and
//! the pane plots as many of the newest columns as it has cells for, so it never
//! interpolates: wider panes see further back. A metered zero keeps a floor so
//! a live-but-idle link reads differently from one nobody measured, and a span
//! no tick landed in stays blank; a stopped core freezes the graph on what was
//! observed and says so in the title.

use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, RenderDirection, Sparkline};

use crate::state::{RateWindow, Rates, UiState};
use crate::theme::Theme;
use crate::views::title::titled;
use crate::words::statistics as words;
use crate::words::units::rate;
use crate::wrap::{display_width, wrapped_lines};

/// Which meter a graph plots. Both series ride the *same* history column, so
/// the two graphs share an x-axis by construction — they cannot drift apart.
#[derive(Clone, Copy)]
pub(super) enum Series {
    Down,
    Up,
}

impl Series {
    /// Same arrows as the status bar's two meters, so the association is
    /// immediate.
    const fn label(self) -> &'static str {
        match self {
            Self::Down => words::GRAPH_DOWN,
            Self::Up => words::GRAPH_UP,
        }
    }

    const fn value(self, rates: Rates) -> f64 {
        match self {
            Self::Down => rates.down_bps,
            Self::Up => rates.up_bps,
        }
    }

    /// One tone per graph (never two tones inside one), and neither is an
    /// alarm colour: traffic is not a warning. Both roles are distinct in all
    /// three themes, including the hand-tuned Indexed-256 fallback.
    const fn tone(self, theme: &Theme) -> Color {
        match self {
            Self::Down => theme.good,
            Self::Up => theme.accent,
        }
    }
}

/// One rate graph: a bordered pane whose title carries the current and peak
/// readings and whose bottom border carries the visible time span; the
/// download graph, on top, says the window and its key.
pub(super) fn draw_graph(
    frame: &mut Frame,
    area: Rect,
    state: &UiState,
    theme: &Theme,
    now: Instant,
    (series, window): (Series, RateWindow),
) {
    let outline = Block::bordered().border_style(theme.chrome());
    let inner = outline.inner(area);
    if inner.width == 0 || inner.height == 0 {
        frame.render_widget(outline, area);
        return;
    }

    let visible = state.rate_history.newest(window, usize::from(inner.width));
    let peak = visible
        .iter()
        .filter_map(|column| column.rates)
        .map(|rates| series.value(rates))
        .fold(0.0_f64, f64::max);
    let latest = state.rate_history.latest().map(|rates| series.value(rates));

    let band = usize::from(area.width.saturating_sub(2));
    let hint = match series {
        Series::Down => words::window_hint(window),
        Series::Up => "",
    };
    let mut block = titled(
        outline,
        area.width,
        (
            &graph_title(series.label(), latest, (words::tallest(window), peak), band),
            Style::new().fg(theme.fg),
        ),
        (hint, theme.dim_text()),
    );

    // The x-axis lives on the bottom border: left edge = the oldest sample
    // still on screen, right edge = the newest tick — or an honest "stopped"
    // once the core's stream ended and the graph froze where it stood.
    if let Some(oldest) = visible.first() {
        let left = words::axis_age(now.saturating_duration_since(oldest.at));
        let (right, right_style) = if state.core_alive {
            (words::AXIS_NOW, theme.dim_text())
        } else {
            (words::AXIS_STOPPED, Style::new().fg(theme.bad))
        };
        // Both labels whole or neither (never truncate: drop a segment, never clip one).
        if display_width(&left) + display_width(right) <= band {
            block = block
                .title_bottom(Line::from(Span::styled(left, theme.dim_text())))
                .title_bottom(Line::from(Span::styled(right, right_style)).right_aligned());
        }
    }
    frame.render_widget(block, area);

    if visible.is_empty() {
        frame.render_widget(
            Paragraph::new(wrapped_lines(
                words::NO_SAMPLES,
                usize::from(inner.width),
                theme.dim_text(),
            )),
            inner,
        );
        return;
    }

    // Newest first + right-to-left ⇒ "now" is pinned to the right edge and a
    // half-filled history leaves the *left* blank, which is where the missing
    // past belongs.
    let ticks = u64::from(inner.height) * 8;
    let bars: Vec<u64> = visible
        .iter()
        .rev()
        .map(|column| {
            column
                .rates
                .map_or(0, |rates| bar_ticks(series.value(rates), peak, ticks))
        })
        .collect();
    frame.render_widget(
        Sparkline::default()
            .data(bars)
            .max(ticks)
            .direction(RenderDirection::RightToLeft)
            .style(Style::new().fg(series.tone(theme))),
        inner,
    );
}

/// One column's bar height in eighth-of-a-row ticks, against a window scaled
/// to its own `peak`.
///
/// A *metered* zero keeps a one-tick floor: an idle second must read as a
/// baseline the graph drew, never as the blank of a column that has no sample
/// in it. Auto-ranging per graph (rather than a shared scale) is what keeps
/// the upload graph legible while a download saturates the link; the peak in
/// the pane title is what stops the scale from being implicit.
fn bar_ticks(bps: f64, peak: f64, ticks: u64) -> u64 {
    if ticks == 0 {
        return 0;
    }
    if peak <= 0.0 || bps <= 0.0 {
        return 1;
    }
    let scaled = (bps / peak * (ticks - 1) as f64).round() as u64;
    scaled.min(ticks - 1) + 1
}

/// The graph header, priority-dropped to fit its pane (never truncate: drop a whole
/// segment, never clip one). The current reading outranks the peak; the label
/// alone is the floor. With no samples at all there is no reading to state.
fn graph_title(
    label: &str,
    now_bps: Option<f64>,
    (tallest, peak_bps): (&str, f64),
    band: usize,
) -> String {
    let Some(now_bps) = now_bps else {
        return format!(" {label} ");
    };
    let now = rate(now_bps);
    let full = words::graph_title_tallest(label, &now, tallest, &rate(peak_bps));
    if display_width(&full) <= band {
        return full;
    }
    let short = words::graph_title(label, &now);
    if display_width(&short) <= band {
        return short;
    }
    format!(" {label} ")
}

#[cfg(test)]
mod tests {
    use super::super::StatisticsView;
    use crate::golden::render_to_lines;
    use ratatui::crossterm::event::KeyCode;
    use std::time::Duration;

    use rmule_core::diagnostics::DiagnosticsSnapshot;

    use crate::action::Action;
    use crate::golden::assert_golden;

    use super::*;
    use crate::fixture::*;
    use crate::views::View;

    /// The distinction the whole graph rests on: a column the tick metered at
    /// zero is a baseline, a column with no sample is blank.
    #[test]
    fn a_metered_zero_keeps_a_floor_and_the_peak_fills_the_column() {
        let ticks = 5 * 8;
        assert_eq!(
            bar_ticks(0.0, 400.0, ticks),
            1,
            "an idle second still draws"
        );
        assert_eq!(bar_ticks(400.0, 400.0, ticks), ticks, "the peak fills");
        let half = bar_ticks(200.0, 400.0, ticks);
        assert!(
            (half as f64 - ticks as f64 / 2.0).abs() <= 1.0,
            "half the peak draws half the column, got {half} of {ticks}"
        );
        // No traffic at all in the window: a flat, honest baseline.
        assert_eq!(bar_ticks(0.0, 0.0, ticks), 1);
    }

    fn snapshot_at(taken_at: Instant) -> crate::bridge::BridgeSnapshot {
        crate::bridge::BridgeSnapshot {
            diagnostics: DiagnosticsSnapshot::default(),
            rates: crate::rates::TransferRates::default(),
            taken_at,
        }
    }

    /// Three days up: `w` walks the window, and the axis and the hint say which
    /// one is up.
    #[test]
    fn w_walks_the_graphs_from_seconds_to_days_and_back() {
        let base = Instant::now();
        let mut state = UiState::default();
        state.apply(Action::Snapshot(snapshot_at(base)), base);
        rate_ticks(
            &mut state,
            base,
            3 * 86_400,
            &DiagnosticsSnapshot::default(),
        );
        let now = base + Duration::from_secs(3 * 86_400);
        let mut view = StatisticsView::default();
        let drawn = |view: &mut StatisticsView| {
            render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
                view.draw(frame, frame.area(), &state, &Theme::default_dark(), now);
            })
        };
        let seconds = drawn(&mut view);
        assert!(seconds.contains("1 s a column"), "{seconds}");
        view.handle_key(press(KeyCode::Char('w')), &UiState::default());
        let hours = drawn(&mut view);
        assert!(hours.contains("1 min a column"), "{hours}");
        view.handle_key(press(KeyCode::Char('w')), &UiState::default());
        let days = drawn(&mut view);
        assert!(
            days.contains("1 h a column") && days.contains(" 3d ago "),
            "{days}"
        );
        assert!(
            days.contains("busiest hour") && days.contains("· up 3d 0h"),
            "{days}"
        );
        view.handle_key(press(KeyCode::Char('w')), &UiState::default());
        assert_eq!(drawn(&mut view), seconds);
    }

    /// The distinction a coarse window adds: a span no tick landed in is blank
    /// beside a metered idle one.
    #[test]
    fn a_gap_in_the_ticks_draws_blank_beside_a_metered_idle_column() {
        let base = Instant::now();
        let mut state = UiState::default();
        for secs in [0, 240] {
            state.apply_snapshot(snapshot_at(base), base + Duration::from_secs(secs));
        }
        let mut view = StatisticsView::default();
        view.handle_key(press(KeyCode::Char('w')), &UiState::default());
        let rendered = render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
            view.draw(
                frame,
                frame.area(),
                &state,
                &Theme::default_dark(),
                base + Duration::from_secs(240),
            );
        });
        assert!(rendered.contains("▁   ▁"), "floor, gap, floor:\n{rendered}");
    }

    #[test]
    fn the_graph_title_drops_whole_segments_as_the_pane_narrows() {
        let full = graph_title("▼ Download", Some(1024.0), ("peak", 4096.0), 60);
        assert_eq!(full, " ▼ Download · now 1.0 KB/s · peak 4.0 KB/s ");
        let narrow = graph_title("▼ Download", Some(1024.0), ("peak", 4096.0), 30);
        assert_eq!(narrow, " ▼ Download · now 1.0 KB/s ");
        assert_eq!(
            graph_title("▼ Download", Some(1024.0), ("peak", 4096.0), 14),
            " ▼ Download "
        );
        // No samples ⇒ no reading to state.
        assert_eq!(
            graph_title("▲ Upload", None, ("peak", 0.0), 60),
            " ▲ Upload "
        );
    }

    /// A stopped core stops appending samples; the graphs freeze on what was
    /// observed and the view says so — the right edge is no longer "now".
    #[test]
    fn a_stopped_core_freezes_the_graphs_and_labels_them() {
        let base = Instant::now();
        let mut state = busy(base);
        let before = state.rate_history.newest(RateWindow::Seconds, 1_000).len();
        state.apply(Action::CoreClosed, base + Duration::from_secs(90));
        assert_eq!(
            state.rate_history.newest(RateWindow::Seconds, 1_000).len(),
            before,
            "no tail is invented"
        );

        let rendered = render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
            StatisticsView::default().draw(
                frame,
                frame.area(),
                &state,
                &Theme::default_dark(),
                base + Duration::from_secs(120),
            );
        });
        assert!(
            rendered.contains("stopped"),
            "the axis marks the freeze:\n{rendered}"
        );
        assert!(
            rendered.contains("engine stopped"),
            "the session pane says why"
        );
    }

    #[test]
    fn golden_statistics_core_stopped() {
        let base = Instant::now();
        let mut state = busy(base);
        state.apply(Action::CoreClosed, base + Duration::from_secs(90));
        assert_golden("statistics_core_stopped", GOLDEN_W, GOLDEN_H, |frame| {
            StatisticsView::default().draw(
                frame,
                frame.area(),
                &state,
                &Theme::default_dark(),
                base + Duration::from_secs(120),
            );
        });
    }

    /// Single-tone per graph, and the two graphs are told apart by tone: the
    /// download bars carry `good`, the upload bars `accent`.
    #[test]
    fn each_graph_paints_its_bars_in_one_tone() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let base = Instant::now();
        let state = busy(base);
        let theme = Theme::default_dark();
        let mut terminal = Terminal::new(TestBackend::new(GOLDEN_W, GOLDEN_H)).expect("terminal");
        terminal
            .draw(|frame| {
                StatisticsView::default().draw(
                    frame,
                    Rect::new(0, 0, GOLDEN_W, GOLDEN_H),
                    &state,
                    &theme,
                    base + Duration::from_secs(90),
                );
            })
            .expect("draw");
        let buffer = terminal.backend().buffer();
        // The 13 rows above the 8-row facts strip hold two panes of 6 rows
        // each (border, 4 bars, border) and the odd row between them:
        // rows 1–4 are the download pane's interior, rows 8–11 the upload's.
        let tone_of = |y: u16| buffer.cell((GOLDEN_W - 2, y)).expect("bar cell").style().fg;
        assert_eq!(tone_of(4), Some(theme.good), "download bars are one tone");
        assert_eq!(tone_of(9), Some(theme.accent), "upload bars are the other");
    }
}
