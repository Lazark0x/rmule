//! The two rate graphs: one column per sample, newest at the right.
//!
//! The window is stated in *time* — the sample ring holds ten minutes at the
//! bridge's 1 Hz tick — and the pane plots as many of the newest samples as it
//! has columns for, so it never interpolates. A metered zero keeps a floor so
//! a live-but-idle link reads differently from one nobody measured; a stopped
//! core freezes the graph on what was observed and says so in the title.

use std::collections::VecDeque;
use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, RenderDirection, Sparkline};

use crate::rates::format_rate;
use crate::state::{RateSample, UiState};
use crate::theme::Theme;
use crate::views::relative_age;
use crate::wrap::wrapped_lines;

/// The graph body before the first data tick. It names *why* the pane is
/// empty, so a UI-only run does not read as a broken graph.
pub(super) const NO_SAMPLES: &str = "no samples yet — one lands per core data tick";

/// Which meter a graph plots. Both series ride the *same* [`RateSample`], so
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
            Self::Down => "▼ Download",
            Self::Up => "▲ Upload",
        }
    }

    const fn value(self, sample: &RateSample) -> f64 {
        match self {
            Self::Down => sample.down_bps,
            Self::Up => sample.up_bps,
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
/// readings and whose bottom border carries the visible time span.
pub(super) fn draw_graph(
    frame: &mut Frame,
    area: Rect,
    state: &UiState,
    theme: &Theme,
    now: Instant,
    series: Series,
) {
    let outline = Block::bordered().border_style(theme.chrome());
    let inner = outline.inner(area);
    if inner.width == 0 || inner.height == 0 {
        frame.render_widget(outline, area);
        return;
    }

    let visible = visible_samples(&state.rate_history, inner.width);
    let peak = visible
        .iter()
        .map(|sample| series.value(sample))
        .fold(0.0_f64, f64::max);
    let latest = visible.last().map(|sample| series.value(sample));

    let band = usize::from(area.width.saturating_sub(2));
    let mut block = outline.title_top(Line::from(Span::styled(
        graph_title(series.label(), latest, peak, band),
        Style::new().fg(theme.fg),
    )));

    // The x-axis lives on the bottom border: left edge = the oldest sample
    // still on screen, right edge = the newest tick — or an honest "stopped"
    // once the core's stream ended and the graph froze where it stood.
    if let Some(oldest) = visible.first() {
        let left = format!(" {} ", relative_age(oldest.at, now));
        let (right, right_style) = if state.core_alive {
            (" now ".to_string(), theme.dim_text())
        } else {
            (" stopped ".to_string(), Style::new().fg(theme.bad))
        };
        // Both labels whole or neither (never truncate: drop a segment, never clip one).
        if left.chars().count() + right.chars().count() <= band {
            block = block
                .title_bottom(Line::from(Span::styled(left, theme.dim_text())))
                .title_bottom(Line::from(Span::styled(right, right_style)).right_aligned());
        }
    }
    frame.render_widget(block, area);

    if visible.is_empty() {
        frame.render_widget(
            Paragraph::new(wrapped_lines(
                NO_SAMPLES,
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
        .map(|sample| bar_ticks(series.value(sample), peak, ticks))
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

/// The newest `width` samples, oldest first — exactly the ones a `width`-wide
/// graph has columns for. Older history stays in the ring for a wider pane.
fn visible_samples(history: &VecDeque<RateSample>, width: u16) -> Vec<&RateSample> {
    let skip = history.len().saturating_sub(usize::from(width));
    history.iter().skip(skip).collect()
}

/// One sample's bar height in eighth-of-a-row ticks, against a window scaled
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
fn graph_title(label: &str, now_bps: Option<f64>, peak_bps: f64, band: usize) -> String {
    let Some(now_bps) = now_bps else {
        return format!(" {label} ");
    };
    let full = format!(
        " {label} · now {} · peak {} ",
        format_rate(now_bps),
        format_rate(peak_bps)
    );
    if full.chars().count() <= band {
        return full;
    }
    let short = format!(" {label} · now {} ", format_rate(now_bps));
    if short.chars().count() <= band {
        return short;
    }
    format!(" {label} ")
}

#[cfg(test)]
mod tests {
    use super::super::draw;
    use crate::golden::render_to_lines;
    use std::time::Duration;

    use rmule_core::diagnostics::DiagnosticsSnapshot;

    use crate::action::Action;
    use crate::golden::assert_golden;

    use super::*;
    use crate::fixture::*;

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

    #[test]
    fn the_window_holds_the_newest_samples_the_pane_has_columns_for() {
        let mut state = UiState::default();
        let base = Instant::now();
        rate_ticks(&mut state, base, 40, &DiagnosticsSnapshot::default());
        let visible = visible_samples(&state.rate_history, 10);
        assert_eq!(visible.len(), 10);
        assert_eq!(
            visible[0].at,
            base + Duration::from_secs(30),
            "oldest on screen"
        );
        assert_eq!(
            visible[9].at,
            base + Duration::from_secs(39),
            "newest is now"
        );
        // A pane wider than the history draws all of it, and no more.
        assert_eq!(visible_samples(&state.rate_history, 200).len(), 40);
    }

    #[test]
    fn the_graph_title_drops_whole_segments_as_the_pane_narrows() {
        let full = graph_title("▼ Download", Some(1024.0), 4096.0, 60);
        assert_eq!(full, " ▼ Download · now 1.0 KB/s · peak 4.0 KB/s ");
        let narrow = graph_title("▼ Download", Some(1024.0), 4096.0, 30);
        assert_eq!(narrow, " ▼ Download · now 1.0 KB/s ");
        assert_eq!(
            graph_title("▼ Download", Some(1024.0), 4096.0, 14),
            " ▼ Download "
        );
        // No samples ⇒ no reading to state.
        assert_eq!(graph_title("▲ Upload", None, 0.0, 60), " ▲ Upload ");
    }

    /// A stopped core stops appending samples; the graphs freeze on what was
    /// observed and the view says so — the right edge is no longer "now".
    #[test]
    fn a_stopped_core_freezes_the_graphs_and_labels_them() {
        let base = Instant::now();
        let mut state = busy(base);
        let before = state.rate_history.len();
        state.apply(Action::CoreClosed, base + Duration::from_secs(90));
        assert_eq!(state.rate_history.len(), before, "no tail is invented");

        let rendered = render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
            draw(
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
            rendered.contains("core stopped"),
            "the session pane says why"
        );
    }

    #[test]
    fn golden_statistics_core_stopped() {
        let base = Instant::now();
        let mut state = busy(base);
        state.apply(Action::CoreClosed, base + Duration::from_secs(90));
        assert_golden("statistics_core_stopped", GOLDEN_W, GOLDEN_H, |frame| {
            draw(
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
                draw(
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
