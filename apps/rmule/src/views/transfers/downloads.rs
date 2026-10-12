//! The downloads table (spec §3.2) and its cell vocabulary.
//!
//! **File** and **Size** read the real name and exact byte size once a row's
//! `DownloadQueued`/`DownloadRecovered` edge has landed (ADR-0078) — from
//! [`crate::state::DownloadRow::metadata`], not a diagnostics-levels join, so a
//! recovered-but-not-yet-resumed download still shows its name. A row whose
//! edge has not landed falls back honestly to the short-hash stand-in instead
//! of inventing a name, and **Size** falls back to an estimate from the part
//! count in the same case.
//!
//! **Done %** divides verified bytes by the exact size when metadata supplies
//! one and falls back to the part-count ratio otherwise; **Speed** is the
//! download's own metered rate, never computed here. **ETA** divides by the
//! same bytes averaged over the last minute instead, and says *slow* where
//! that pace is too slow to estimate (ADR-0071, "Download ETA").

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::{Cell, HighlightSpacing, Row, Table};
use rmule_core::diagnostics::{DownloadDiagnostics, PartCounts, PartState, WorkerPhase};
use rmule_core::{DownloadId, DownloadMetadata, DownloadMetadataOrigin, SourceWait};
use rmule_primitives::{ED2K_PART_SIZE, FileHash};

use super::chunks::chunk_bar;
use super::sort::{DownloadLine, DownloadsTable};
use super::{COL_SPACING, Pane, SYMBOL_W, TransfersView, draw_centered, pane_block, table_widths};
use crate::row_selection::{MARKER, selection_style};
use crate::state::{DownloadRow, DownloadStatus, UiState};
use crate::table_sort::{SortedTable, arrow_floors, header_label, header_widths};
use crate::theme::Theme;
use crate::views::{DrawnRows, say_gave_way};
use crate::views::{human_size, rate_cell};
use crate::words::download::{ETA_TOO_SLOW, eta_time};
use crate::words::units::short_hash_or_dash;
use crate::wrap::{TableColumns, clamp_u16, gave_way, wrapped_cell};

/// Width of the in-table chunk map. Fixed so the golden is deterministic
/// regardless of the table's flex layout — and so the number of parts each
/// glyph buckets is a property of the file, not of the terminal.
const CHUNK_CELL_W: usize = 10;

/// Downloads table columns: File · Size · Done · Progress · Speed · ETA · Src
/// · Status. `File` is greedy — its declared width is ignored and it
/// takes every column the others leave over; when the pane is too narrow even
/// for those, they shrink and every cell wraps. Nothing is ever clipped.
const DOWNLOAD_COLS: [usize; 8] = [11, 10, 4, CHUNK_CELL_W, 10, 6, 5, 11];
const DOWNLOAD_FLEX: usize = 0;

/// The most each bounded column asks for beyond its floor when a value drawn is
/// wider (`None`: the name, which is greedy, and the fixed-width chunk bar).
const DOWNLOAD_CAPS: [Option<usize>; 8] = [
    None,
    Some(12),
    Some(7),
    None,
    Some(14),
    Some(10),
    Some(9),
    Some(14),
];

/// The order the downloads table's columns give way in when the pane cannot
/// hold every header: ETA, Src, Done, Size, Speed, Progress, then
/// Status. File never gives way.
const DOWNLOAD_GIVE_WAY: [usize; 7] = [5, 6, 2, 1, 4, 3, 7];

pub(super) fn diag_counts(diag: Option<&DownloadDiagnostics>) -> PartCounts {
    diag.map_or_else(PartCounts::default, DownloadDiagnostics::part_counts)
}

/// The row's positional part map (ADR-0079), or an empty slice when the row
/// has no diagnostics yet — the same "unknown" the empty vector means.
pub(super) fn diag_parts(diag: Option<&DownloadDiagnostics>) -> &[PartState] {
    diag.map_or(&[], |d| d.parts.as_slice())
}

/// The sources a running download knows, and how many of them are sending
/// now — aMule's source column. `None` without a diagnostics row: a download
/// that is not running holds no sources.
pub(super) fn source_counts(diag: Option<&DownloadDiagnostics>) -> Option<(u32, u32)> {
    let diag = diag?;
    let sending = diag
        .workers
        .values()
        .filter(|worker| matches!(worker.phase(), WorkerPhase::ReceivingPart { .. }))
        .count();
    Some((
        diag.known_sources,
        u32::try_from(sending).unwrap_or(u32::MAX),
    ))
}

/// Verified bytes in a positional part map (ADR-0079): every verified part's
/// length — each [`ED2K_PART_SIZE`], the last only as long as `size` leaves
/// it. Exact, never the part count times the part size.
pub(super) fn verified_bytes(parts: &[PartState], size: u64) -> u64 {
    parts
        .iter()
        .enumerate()
        .filter(|(_, part)| **part == PartState::Verified)
        .map(|(index, _)| {
            let start = (index as u64).saturating_mul(ED2K_PART_SIZE);
            size.saturating_sub(start).min(ED2K_PART_SIZE)
        })
        .sum()
}

/// Done (spec §3.2) as the exact ratio its cell rounds: verified
/// bytes over the exact size. A running download reads its positional part
/// map; one without a map yet — queued, paused, recovered and not resumed —
/// reads the bytes its edges stated (restored at recovery or resume, plus
/// each part verified since); a completed one is whole. Without an exact
/// size the part map's part ratio stands in. `None` when no fact exists.
pub(super) fn done_fraction(
    row: Option<&DownloadRow>,
    diag: Option<&DownloadDiagnostics>,
) -> Option<(u64, u64)> {
    let size = row
        .and_then(|row| row.metadata.as_ref())
        .map(|metadata| metadata.size)
        .filter(|size| *size > 0);
    let parts = diag_parts(diag);
    match (size, parts.is_empty()) {
        (Some(size), false) => Some((verified_bytes(parts, size), size)),
        (None, false) => {
            let counts = diag_counts(diag);
            Some((u64::from(counts.verified), u64::from(counts.total())))
        }
        (Some(size), true) => {
            let row = row?;
            let verified = if row.status == DownloadStatus::Completed {
                size
            } else {
                row.verified_bytes.min(size)
            };
            Some((verified, size))
        }
        (None, true) => None,
    }
}

/// Bytes still to verify: the exact size less the verified bytes, when the
/// size is known; else the unverified parts' nominal size, the one estimate
/// left before metadata lands.
fn remaining_bytes(row: Option<&DownloadRow>, diag: Option<&DownloadDiagnostics>) -> Option<u64> {
    let exact = row.and_then(|row| row.metadata.as_ref()).is_some();
    if exact {
        return done_fraction(row, diag).map(|(part, whole)| whole.saturating_sub(part));
    }
    let counts = diag_counts(diag);
    (counts.total() > 0)
        .then(|| u64::from(counts.in_flight + counts.missing).saturating_mul(ED2K_PART_SIZE))
}

/// The download's real name when metadata supplies a non-empty one; the
/// short-hash stand-in otherwise (spec §3.2 degrade — an `Unknown`-origin
/// row, or one whose `DownloadQueued`/`DownloadRecovered` edge has not
/// landed yet, honestly falls back instead of inventing a name). The second
/// element tells the caller whether the first is a real fact, for styling:
/// a stand-in stays dim, a real name reads plain like every other cell.
pub(super) fn display_name(
    metadata: Option<&DownloadMetadata>,
    hash: Option<FileHash>,
) -> (String, bool) {
    let real = metadata
        .map(|metadata| metadata.name.to_display_string())
        .filter(|name| !name.trim().is_empty());
    match real {
        Some(name) => (name, true),
        None => (short_hash_or_dash(hash), false),
    }
}

/// Human label for the details modal's `origin` row (ADR-0078's provenance
/// enum). `rmule-core` keeps `DownloadMetadataOrigin::as_str` crate-private,
/// so the view spells its own words for the three variants.
pub(super) fn origin_label(origin: DownloadMetadataOrigin) -> &'static str {
    match origin {
        DownloadMetadataOrigin::Link => "link",
        DownloadMetadataOrigin::RecoveredLink => "recovered link",
        DownloadMetadataOrigin::Unknown => "unknown",
    }
}

/// The averaged speed below which a download is too slow to estimate
/// (ADR-0071, "Download ETA").
const ETA_FLOOR_BPS: f64 = 1024.0;

/// The longest estimate worth showing; past it a download is too slow to
/// estimate (ADR-0071, "Download ETA").
const ETA_CEILING_SECS: u64 = 30 * 86_400;

/// What a download's ETA cell says, before its words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Eta {
    /// Nothing left to verify, or no run measured yet: the dash.
    Unknown,
    /// Moving too slowly to estimate: under the floor, or past the ceiling.
    TooSlow,
    /// Seconds left at the averaged speed.
    Left(u64),
}

impl Eta {
    /// The seconds the column sorts by; both kinds of no estimate are a
    /// missing value, which sorts last either way.
    pub(super) const fn seconds(self) -> Option<u64> {
        match self {
            Self::Left(secs) => Some(secs),
            Self::Unknown | Self::TooSlow => None,
        }
    }
}

/// The estimate from the bytes still to verify and the speed averaged over
/// [`crate::rates::ETA_WINDOW`] (`None` while the run has no measured
/// interval, or has no run).
pub(super) fn eta(remaining: Option<u64>, avg_bps: Option<f64>) -> Eta {
    let (Some(remaining), Some(avg_bps)) = (remaining.filter(|bytes| *bytes > 0), avg_bps) else {
        return Eta::Unknown;
    };
    if avg_bps < ETA_FLOOR_BPS {
        return Eta::TooSlow;
    }
    match (remaining as f64 / avg_bps) as u64 {
        secs if secs > ETA_CEILING_SECS => Eta::TooSlow,
        secs => Eta::Left(secs),
    }
}

/// [`eta`] for one download row.
pub(super) fn row_eta(
    row: Option<&DownloadRow>,
    diag: Option<&DownloadDiagnostics>,
    avg_bps: Option<f64>,
) -> Eta {
    eta(remaining_bytes(row, diag), avg_bps)
}

fn eta_cell(eta: Eta) -> String {
    match eta {
        Eta::Unknown => "—".to_string(),
        Eta::TooSlow => ETA_TOO_SLOW.to_string(),
        Eta::Left(secs) => eta_time(secs),
    }
}

pub(super) fn status_label(status: DownloadStatus) -> &'static str {
    match status {
        DownloadStatus::Waiting => "Waiting",
        // Waiting for a server session or Kad: the status column's eleven
        // cells hold "Downloading" and no more.
        DownloadStatus::NoConnection => "No network",
        DownloadStatus::Downloading => "Downloading",
        DownloadStatus::Paused => "Paused",
        DownloadStatus::Completed => "Completed",
        DownloadStatus::Failed => "Failed",
    }
}

fn status_style(status: DownloadStatus, theme: &Theme) -> Style {
    let color = match status {
        DownloadStatus::Downloading | DownloadStatus::Completed => theme.good,
        DownloadStatus::Waiting => theme.fg,
        DownloadStatus::NoConnection => theme.highlight,
        DownloadStatus::Paused => theme.highlight,
        DownloadStatus::Failed => theme.bad,
    };
    Style::new().fg(color)
}

impl TransfersView {
    pub(super) fn draw_downloads(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
        lines: &[DownloadLine],
    ) {
        let ids: Vec<DownloadId> = lines.iter().map(|line| line.id).collect();
        let ids = ids.as_slice();
        let focused = self.focus == Pane::Table;
        let title = format!(" Downloads ({}) ", ids.len());
        // Nothing to click until a table is drawn.
        self.header_area = Rect::default();
        self.rows = DrawnRows::default();

        if ids.is_empty() {
            let block = pane_block(area.width, (&title, " L add link "), focused, theme);
            let inner = block.inner(area);
            frame.render_widget(block, area);
            draw_centered(
                frame,
                inner,
                "no downloads — start one from Searches, or paste an eD2k link with L",
                theme.dim_text(),
            );
            return;
        }
        // `C` is offered while it has something to clear.
        let hint = if !super::clear::completed_ids(state).is_empty() {
            " s sort  S reverse  C clear completed  L add link "
        } else {
            " s sort  S reverse  L add link "
        };
        let block = pane_block(area.width, (&title, hint), focused, theme);
        let inner = block.inner(area);

        // The name column is greedy: it takes whatever the fixed columns leave
        // over, so nothing is ever cut while the pane has room. The
        // widths are computed here rather than left to `Constraint::Fill`, so
        // an over-narrow pane shrinks the fixed columns (their cells wrap)
        // instead of collapsing the name column to nothing.
        // The sorted column's floor holds its label and the arrow, so the
        // header stays one line; the name column pays for the arrow.
        let values: Vec<Vec<String>> = lines.iter().map(|line| line.values(theme)).collect();
        let mut wants = [0; 8];
        for (index, cap) in DOWNLOAD_CAPS.into_iter().enumerate() {
            if let Some(cap) = cap {
                let widest = values
                    .iter()
                    .map(|row| row[index].chars().count())
                    .max()
                    .unwrap_or(0);
                wants[index] = widest.min(cap);
            }
        }
        let floors = arrow_floors(&self.sort, &DOWNLOAD_COLS, DOWNLOAD_FLEX);
        let headers = header_widths(&self.sort);
        let cols = table_widths(
            area,
            &TableColumns {
                floors: &floors,
                headers: &headers,
                flex: DOWNLOAD_FLEX,
                wants: &wants,
                give_way: &DOWNLOAD_GIVE_WAY,
            },
        );
        let (header_cells, header_heights): (Vec<_>, Vec<u16>) = DownloadsTable::COLUMNS
            .iter()
            .zip(&cols)
            .map(|(column, width)| {
                let label = header_label(column.label, self.sort.arrow(column.column));
                wrapped_cell(&label, *width, theme.dim_text(), false)
            })
            .unzip();
        let header_h = header_heights.into_iter().max().unwrap_or(1);
        let header = Row::new(header_cells)
            .style(theme.dim_text())
            .height(header_h);
        let (rows, heights): (Vec<_>, Vec<u16>) = lines
            .iter()
            .map(|line| self.download_row(line, state, theme, &cols))
            .unzip();
        let widths = cols
            .iter()
            .map(|width| Constraint::Length(clamp_u16(*width)));
        let table = Table::new(rows, widths)
            .header(header)
            .column_spacing(COL_SPACING)
            .row_highlight_style(selection_style(theme, focused))
            .highlight_symbol(MARKER)
            // The symbol's gutter is always there, so the header's column
            // edges — and a click on them — do not move with the selection.
            .highlight_spacing(HighlightSpacing::Always);
        frame.render_widget(block, area);
        // The selected download's values in the columns that gave way.
        let off_screen = self
            .table_state
            .selected()
            .and_then(|at| values.get(at))
            .map_or_else(Vec::new, |values| {
                crate::views::off_screen::hidden(
                    DownloadsTable::COLUMNS.iter().map(|c| c.label),
                    values,
                    &cols,
                )
            });
        let inner = crate::views::off_screen::draw(frame, inner, &off_screen, theme);
        frame.render_stateful_widget(table, inner, &mut self.table_state);
        say_gave_way(
            frame,
            area,
            &gave_way(DownloadsTable::COLUMNS.iter().map(|c| c.label), &cols),
            theme,
        );

        self.header_area = Rect::new(
            inner.x.saturating_add(SYMBOL_W),
            inner.y,
            inner.width.saturating_sub(SYMBOL_W),
            header_h.min(inner.height),
        );
        self.header_cols = cols;
        let offset = self.table_state.offset().min(heights.len());
        self.rows = DrawnRows::new(
            Rect::new(
                inner.x,
                inner.y.saturating_add(header_h),
                inner.width,
                inner.height.saturating_sub(header_h),
            ),
            offset,
            heights[offset..].to_vec(),
        );
    }

    fn download_row(
        &self,
        line: &DownloadLine,
        state: &UiState,
        theme: &Theme,
        cols: &[usize],
    ) -> (Row<'static>, u16) {
        let diag = state.diagnostics.downloads.get(&line.id);
        let plain = Style::new().fg(theme.fg);
        let name_style = if line.name_real {
            plain
        } else {
            theme.dim_text()
        };
        let (speed_text, speed_style) = rate_cell(line.bps, theme);
        // Every cell wraps at its column instead of clipping; the row grows to
        // the tallest of them.
        let cells = [
            (line.name.clone(), cols[0], name_style, false),
            (line.size_cell(), cols[1], plain, false),
            (line.done_cell(), cols[2], plain, false),
            (speed_text, cols[4], speed_style, false),
            (eta_cell(line.eta), cols[5], plain, false),
            (line.sources_cell(), cols[6], plain, false),
            (
                line.status_text.to_string(),
                cols[7],
                status_style(line.status, theme),
                false,
            ),
        ];
        let built =
            cells.map(|(text, width, style, right)| wrapped_cell(&text, width, style, right));
        let height = built.iter().map(|(_, height)| *height).max().unwrap_or(1);
        let [file, size, done, speed, eta, src, status] = built.map(|(cell, _)| cell);

        let table_row = Row::new(vec![
            file,
            size,
            done,
            // The bar is sized to its actual column so it is never cut.
            Cell::from(Line::from(chunk_bar(diag_parts(diag), cols[3], theme))),
            speed,
            eta,
            src,
            status,
        ])
        .height(height);
        (table_row, height)
    }
}

/// A download's status as its cell words it: a download with no network
/// while core re-makes the operator's session waits for that, not for
/// nothing; one waiting with no server session while Kad runs says Kad is
/// who asks. Each wording keeps the rank of the status it words.
pub(super) fn status_text(
    status: DownloadStatus,
    wait: Option<SourceWait>,
    state: &UiState,
) -> &'static str {
    match (status, wait) {
        (DownloadStatus::NoConnection, _) if state.reconnect.is_some() => "Reconnecting",
        (DownloadStatus::Waiting, Some(SourceWait::KadAlone)) => "Asking Kad",
        _ => status_label(status),
    }
}

impl DownloadLine {
    /// The Size cell: the exact size when metadata supplies one (ADR-0078) —
    /// even an `Unknown`-origin row, which has no name yet — else the
    /// part-count estimate with `≈`, the best fact before metadata lands.
    pub(super) fn size_cell(&self) -> String {
        match (self.size, self.size_exact) {
            (Some(bytes), true) => human_size(bytes),
            (Some(bytes), false) => format!("≈ {}", human_size(bytes)),
            (None, _) => "—".to_string(),
        }
    }

    /// The Done cell: [`done_fraction`] as a whole percent, `—` without one.
    pub(super) fn done_cell(&self) -> String {
        self.done.map_or_else(
            || "—".to_string(),
            |(part, whole)| format!("{}%", part * 100 / whole.max(1)),
        )
    }

    /// The Src cell: the known sources, then the sending ones in parentheses
    /// when any are (aMule's `12 (3)`); `—` for a download that is not
    /// running.
    pub(super) fn sources_cell(&self) -> String {
        match self.sources {
            None => "—".to_string(),
            Some((known, 0)) => known.to_string(),
            Some((known, sending)) => format!("{known} ({sending})"),
        }
    }

    /// The cell texts, in [`DownloadsTable::COLUMNS`]' order — what the
    /// `Off-screen:` line says of a column that gave way. The Progress bar
    /// has no text of its own; it reads as the Done figure it draws.
    pub(super) fn values(&self, theme: &Theme) -> Vec<String> {
        let done = self.done_cell();
        vec![
            self.name.clone(),
            self.size_cell(),
            done.clone(),
            done,
            rate_cell(self.bps, theme).0,
            eta_cell(self.eta),
            self.sources_cell(),
            self.status_text.to_string(),
        ]
    }
}

#[cfg(test)]
mod tests;
