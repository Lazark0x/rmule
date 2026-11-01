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

use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};

use crate::state::{DownloadStatus, Ed2kConnection, UiState, UploadState};
use crate::theme::Theme;
use crate::views::human_size;
use crate::words::statistics as words;
use crate::words::units::rate as format_rate;
use crate::words::{absent, networks};
use crate::wrap::{display_width, labeled_lines};

/// The label column two panes of facts share; values wrap under it.
fn label_w(rows: &[Fact]) -> usize {
    rows.iter()
        .map(|fact| display_width(fact.label))
        .max()
        .unwrap_or(0)
        + 1
}

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
pub(super) fn draw_facts(
    frame: &mut Frame,
    area: Rect,
    state: &UiState,
    theme: &Theme,
    now: Instant,
) {
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
            Fact::absent(label, absent::NOT_MEASURED)
        }
    };
    let rate = |label, bps: f64| {
        if metered {
            Fact::read(label, format_rate(bps))
        } else {
            Fact::absent(label, absent::NOT_MEASURED)
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
            let rate = bps.map_or_else(
                || absent::NOT_MEASURED.to_owned(),
                words::datagrams_per_second,
            );
            Fact::read(label, networks::traffic(&rate, &total.to_string()))
        }
        None => Fact::absent(label, absent::NOT_RUNNING),
    };
    let kad = state.diagnostics.kad;
    let kad_rates = state.rates.kad;
    let session_rows = [
        bytes(words::DOWNLOADED, session.down_bytes_total),
        bytes(words::UPLOADED, session.up_bytes_total),
        rate(words::DOWN_NOW, state.rates.down_total_bps),
        rate(words::UP_NOW, state.rates.up_total_bps),
        dgrams(
            words::KAD_IN,
            kad.map(|k| k.traffic.datagrams_in),
            kad_rates.map(|r| r.dgrams_in_bps),
        ),
        dgrams(
            words::KAD_OUT,
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
    let ed2k = match &state.ed2k {
        Ed2kConnection::Connected { client_id } => {
            Fact::read(words::ED2K, words::connected(client_id.is_high_id()))
        }
        Ed2kConnection::Connecting { .. } => Fact::absent(words::ED2K, words::CONNECTING),
        Ed2kConnection::Disconnected | Ed2kConnection::Lost => {
            Fact::absent(words::ED2K, words::NOT_CONNECTED)
        }
    };
    // The same three grades the Networks panel and the status dot report, off
    // the same one runtime fact — three renderings, one source.
    let kad = match state.diagnostics.kad {
        None => Fact::absent(words::KAD, words::KAD_OFF),
        Some(kad) if kad.contact_responded => Fact::read(words::KAD, words::KAD_JOINED),
        Some(_) => Fact::read(words::KAD, words::KAD_NO_CONTACT),
    };
    let activity_rows = [
        Fact::read(
            words::DOWNLOADS,
            words::downloads_row(state.downloads.len(), active),
        ),
        Fact::read(
            words::UPLOADS,
            words::uploads_row(state.diagnostics.uploads.len(), queued),
        ),
        // Each refusal is a Networks log line; this is their tally, from the
        // same session counters as the byte totals.
        if metered {
            Fact::read(
                crate::words::peer::HELLOS_LABEL,
                crate::words::peer::hellos_refused(session.peer_hellos_refused_total),
            )
        } else {
            Fact::absent(crate::words::peer::HELLOS_LABEL, absent::NOT_MEASURED)
        },
        Fact::read(words::SHARED_FILES, state.shared.len().to_string()),
        ed2k,
        kad,
    ];

    draw_facts_pane(
        frame,
        session_area,
        theme,
        session_title(
            theme,
            state,
            now,
            usize::from(session_area.width.saturating_sub(2)),
        ),
        &session_rows,
    );
    draw_facts_pane(
        frame,
        activity_area,
        theme,
        Line::from(Span::styled(
            words::ACTIVITY_TITLE,
            Style::new().fg(theme.fg),
        )),
        &activity_rows,
    );
}

/// The session pane's title, which is also where a stopped core is announced
/// inside the view (the status bar says it too — this is the in-view echo, so
/// a reader looking at the frozen graphs is told why).
fn session_title(theme: &Theme, state: &UiState, now: Instant, room: usize) -> Line<'static> {
    let mut spans = vec![Span::styled(
        words::SESSION_TITLE,
        Style::new().fg(theme.fg),
    )];
    if !state.core_alive {
        spans.push(Span::styled(
            words::ENGINE_STOPPED,
            Style::new().fg(theme.bad),
        ));
    }
    // A stopped core's uptime stops with its last tick, and a narrow pane
    // keeps the stop.
    let until = if state.core_alive {
        Some(now)
    } else {
        state.last_snapshot_at
    };
    if let (Some(started), Some(until)) = (state.started_at, until) {
        let up = words::uptime(until.saturating_duration_since(started));
        let used: usize = spans.iter().map(|span| display_width(&span.content)).sum();
        if used + display_width(&up) <= room {
            spans.insert(1, Span::styled(up, theme.dim_text()));
        }
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
    let label_w = label_w(rows);
    let value_w = usize::from(inner.width).saturating_sub(label_w).max(1);
    let lines: Vec<Line<'static>> = rows
        .iter()
        .flat_map(|fact| {
            let style = if fact.live {
                Style::new().fg(theme.fg)
            } else {
                theme.dim_text()
            };
            labeled_lines(
                Span::styled(format!("{:<label_w$}", fact.label), theme.dim_text()),
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

    use super::super::StatisticsView;
    use crate::golden::render_to_lines;
    use crate::words::statistics::NO_SAMPLES;
    use std::time::Duration;

    use crate::golden::assert_golden;

    use super::*;
    use crate::fixture::*;

    fn draw(frame: &mut Frame, area: Rect, state: &UiState, theme: &Theme, now: Instant) {
        StatisticsView::default().draw(frame, area, state, theme, now);
    }

    /// The window before the first tick has observed no counter: every metered figure reads as absence, not as zero.
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
            assert!(
                row.contains(absent::NOT_MEASURED),
                "{label} claimed a figure: {row:?}"
            );
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
        let glyphs = |theme: &Theme| {
            render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
                draw(
                    frame,
                    frame.area(),
                    &state,
                    theme,
                    base + Duration::from_secs(90),
                );
            })
        };
        let dark = glyphs(&Theme::default_dark());
        for theme in [Theme::light(), Theme::fallback_256()] {
            assert_eq!(
                glyphs(&theme),
                dark,
                "theme changed glyphs, not just styles"
            );
        }
    }
}
