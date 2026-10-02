//! The facts pane: the session totals and the activity counts, laid out as
//! label/value rows.
//!
//! Every figure is a fact core reported. A run that never metered a quantity
//! dashes it rather than printing a zero nobody observed, and the activity
//! counts are the same numbers the other views show — read off the same state,
//! so the two cannot disagree.
//!
//! **Kad in** / **Kad out** join the session byte totals: Kad
//! datagram counts, and a rate by the same means as every other meter here
//! ([`crate::rates`]). They live here rather than the Networks Kad panel
//! because that panel's 11-row band already draws Received/Sent bytes with
//! no room to spare (`views/networks.rs::BOTTOM_H`), and this is where the
//! operator already reads session traffic totals and rates side by side.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};

use crate::rates::format_rate;
use crate::state::{DownloadStatus, Ed2kConnection, UiState, UploadState};
use crate::theme::Theme;
use crate::views::human_size;
use crate::wrap::labeled_lines;

/// Label column of a fact row; values wrap under it.
const LABEL_W: usize = 13;

/// What every unobserved figure reads.
const DASH: &str = "—";

/// One row of a facts pane: what it says, plus whether it is a *reading* or an
/// *absence* — which is the whole of the row's styling decision.
struct Fact {
    label: &'static str,
    value: String,
    live: bool,
}

impl Fact {
    fn read(label: &'static str, value: impl Into<String>) -> Self {
        Self {
            label,
            value: value.into(),
            live: true,
        }
    }

    /// A fact the session does not have: rendered dim, never as a zero.
    fn absent(label: &'static str, value: impl Into<String>) -> Self {
        Self {
            label,
            value: value.into(),
            live: false,
        }
    }
}

/// The facts strip: session byte totals + current rates on the left, the live
/// activity counts on the right.
pub(super) fn draw_facts(frame: &mut Frame, area: Rect, state: &UiState, theme: &Theme) {
    let [session_area, activity_area] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area);

    // A run that never saw a tick has observed no counter — the honest figure
    // is absence, not the zero the default snapshot happens to carry.
    let metered = state.last_snapshot_at.is_some();
    let session = state.diagnostics.session;
    let bytes = |label, total: u64| {
        if metered {
            Fact::read(label, human_size(total))
        } else {
            Fact::absent(label, DASH)
        }
    };
    let rate = |label, bps: f64| {
        if metered {
            Fact::read(label, format_rate(bps))
        } else {
            Fact::absent(label, DASH)
        }
    };
    // Kad datagrams in and out: core counts them
    // (`KadRuntimeDiagnostics::traffic`) beside the wire bytes the Kad panel
    // already draws, but the panel's 11-row band has no slack left to draw
    // them too — this is where the operator reads Kad traffic otherwise.
    // Absent, not zero, while no Kad node runs; a node with no echo yet
    // shows its total with a dashed rate, the same honest half-degrade the
    // Kad panel's Received/Sent rows show.
    let dgrams = |label: &'static str, total: Option<u64>, bps: Option<f64>| match total {
        Some(total) => {
            let rate = bps.map_or_else(|| DASH.to_owned(), |bps| format!("{bps:.1}/s"));
            Fact::read(label, format!("{rate} · {total}"))
        }
        None => Fact::absent(label, DASH),
    };
    let kad = state.diagnostics.kad;
    let kad_rates = state.rates.kad;
    let session_rows = [
        bytes("Downloaded", session.down_bytes_total),
        bytes("Uploaded", session.up_bytes_total),
        rate("Down now", state.rates.down_total_bps),
        rate("Up now", state.rates.up_total_bps),
        dgrams(
            "Kad in",
            kad.map(|k| k.traffic.datagrams_in),
            kad_rates.map(|r| r.dgrams_in_bps),
        ),
        dgrams(
            "Kad out",
            kad.map(|k| k.traffic.datagrams_out),
            kad_rates.map(|r| r.dgrams_out_bps),
        ),
    ];

    // "Active" is the fold's own word: a download a slot grant or a part
    // assignment has put on the wire (`DownloadStatus::Downloading`). Upload
    // slots come off the levels lane — the same rows the byte counters above
    // were read from — and the queue off the edge fold, as in Shared.
    let active = state
        .downloads
        .values()
        .filter(|row| row.status == DownloadStatus::Downloading)
        .count();
    let queued = state
        .upload_peers
        .values()
        .filter(|peer| matches!(peer.state, UploadState::Queued { .. }))
        .count();
    let ed2k = match state.ed2k {
        Ed2kConnection::Connected { client_id } => {
            let class = if client_id.is_high_id() {
                "HighID"
            } else {
                "LowID"
            };
            Fact::read("eD2k", format!("connected ({class})"))
        }
        Ed2kConnection::Disconnected => Fact::absent("eD2k", "not connected"),
    };
    // The same three grades the Networks panel and the status dot report, off
    // the same one runtime fact — three renderings, one source.
    let kad = match state.diagnostics.kad {
        None => Fact::absent("Kad", "off"),
        Some(kad) if kad.contact_responded => Fact::read("Kad", "on · joined"),
        Some(_) => Fact::read("Kad", "on · no contact"),
    };
    let activity_rows = [
        Fact::read(
            "Downloads",
            format!("{} ({active} active)", state.downloads.len()),
        ),
        Fact::read(
            "Uploads",
            format!(
                "{} active · {queued} queued",
                state.diagnostics.uploads.len()
            ),
        ),
        // Each refusal is a Networks log line; this is their tally, from the
        // same session counters as the byte totals.
        if metered {
            Fact::read(
                crate::words::peer::HELLOS_LABEL,
                crate::words::peer::hellos_refused(session.peer_hellos_refused_total),
            )
        } else {
            Fact::absent(crate::words::peer::HELLOS_LABEL, DASH)
        },
        Fact::read("Shared files", state.shared.len().to_string()),
        ed2k,
        kad,
    ];

    draw_facts_pane(
        frame,
        session_area,
        theme,
        session_title(theme, state),
        &session_rows,
    );
    draw_facts_pane(
        frame,
        activity_area,
        theme,
        Line::from(Span::styled(" Activity ", Style::new().fg(theme.fg))),
        &activity_rows,
    );
}

/// The session pane's title, which is also where a stopped core is announced
/// inside the view (the status bar says it too — this is the in-view echo, so
/// a reader looking at the frozen graphs is told why).
fn session_title(theme: &Theme, state: &UiState) -> Line<'static> {
    let mut spans = vec![Span::styled(" Session ", Style::new().fg(theme.fg))];
    if !state.core_alive {
        spans.push(Span::styled("· core stopped ", Style::new().fg(theme.bad)));
    }
    Line::from(spans)
}

/// One bordered facts pane: label column, value wrapping under it, dim when
/// the value is an absence rather than a reading.
fn draw_facts_pane(
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
    title: Line<'static>,
    rows: &[Fact],
) {
    let block = Block::bordered()
        .border_style(theme.chrome())
        .title_top(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    let value_w = usize::from(inner.width).saturating_sub(LABEL_W).max(1);
    let lines: Vec<Line<'static>> = rows
        .iter()
        .flat_map(|fact| {
            let style = if fact.live {
                Style::new().fg(theme.fg)
            } else {
                theme.dim_text()
            };
            labeled_lines(
                Span::styled(format!("{:<w$}", fact.label, w = LABEL_W), theme.dim_text()),
                &fact.value,
                style,
                value_w,
            )
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::super::draw;
    use super::super::graph::NO_SAMPLES;
    use crate::golden::render_to_lines;
    use std::time::Duration;

    use crate::golden::assert_golden;

    use super::*;
    use crate::fixture::*;

    /// A UI-only run (or the window before the first tick) has observed no
    /// counter: every metered figure reads as absence, not as zero.
    #[test]
    fn an_unmetered_run_dashes_every_figure_it_never_observed() {
        let rendered = render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
            draw(
                frame,
                frame.area(),
                &UiState::default(),
                &Theme::default_dark(),
                Instant::now(),
            );
        });
        for label in ["Downloaded", "Uploaded", "Down now", "Up now"] {
            let row = rendered
                .lines()
                .find(|line| line.contains(label))
                .unwrap_or_else(|| panic!("no {label} row in\n{rendered}"));
            assert!(row.contains(DASH), "{label} claimed a figure: {row:?}");
        }
        assert!(
            rendered.contains(NO_SAMPLES),
            "the graphs say why they are empty"
        );
    }

    /// The counts are joins over the same state the other views render, so
    /// Statistics can never report a different session than Shared/Transfers.
    #[test]
    fn the_activity_pane_counts_what_the_other_views_show() {
        let rendered = render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
            draw(
                frame,
                frame.area(),
                &busy(Instant::now()),
                &Theme::default_dark(),
                Instant::now() + Duration::from_secs(90),
            );
        });
        for wanted in [
            "Downloads    2 (1 active)",
            "Uploads      1 active · 1 queued",
            "Shared files 2",
            "eD2k         connected (HighID)",
            "Kad          on · joined",
        ] {
            assert!(
                rendered.contains(wanted),
                "missing {wanted:?} in\n{rendered}"
            );
        }
    }

    #[test]
    fn golden_statistics_populated() {
        let base = Instant::now();
        let state = busy(base);
        assert_golden("statistics_populated", GOLDEN_W, GOLDEN_H, |frame| {
            draw(
                frame,
                frame.area(),
                &state,
                &Theme::default_dark(),
                base + Duration::from_secs(90),
            );
        });
    }

    #[test]
    fn golden_statistics_empty() {
        let state = UiState::default();
        assert_golden("statistics_empty", GOLDEN_W, GOLDEN_H, |frame| {
            draw(
                frame,
                frame.area(),
                &state,
                &Theme::default_dark(),
                Instant::now(),
            );
        });
    }

    /// Spec §5 acceptance, extended to the new pane: the sparkline bars
    /// and the facts strip must differ between themes in *tone only*. The
    /// Indexed-256 fallback therefore degrades honestly — same graph, no RGB.
    #[test]
    fn all_three_themes_render_the_same_statistics_glyphs() {
        let base = Instant::now();
        let state = busy(base);
        let dark = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/goldens/statistics_populated.txt"),
        )
        .expect("dark golden blessed");
        for theme in [Theme::light(), Theme::fallback_256()] {
            let lines = render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
                draw(
                    frame,
                    frame.area(),
                    &state,
                    &theme,
                    base + Duration::from_secs(90),
                );
            });
            assert_eq!(lines, dark, "theme changed glyphs, not just styles");
        }
    }
}
