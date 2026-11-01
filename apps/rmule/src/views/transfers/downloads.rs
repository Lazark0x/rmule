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
use ratatui::layout::Rect;
use ratatui::style::Style;
use rmule_core::diagnostics::{DownloadDiagnostics, PartCounts, PartState, WorkerPhase};
use rmule_core::{DownloadMetadata, DownloadMetadataOrigin, SourceWait};
use rmule_primitives::{ED2K_PART_SIZE, FileHash};

use super::chunks::chunk_bar;
use super::sort::DownloadLine;
use super::{Pane, TransfersView, draw_centered, pane_block};
use crate::state::{DownloadRow, DownloadStatus, UiState};
use crate::table::{self, Cell, Rows, Table};
use crate::theme::Theme;
use crate::views::{human_size, rate_cell};
use crate::words::download::{
    ETA_TOO_SLOW, NO_NEEDED_PARTS_STATUS, completing_status, eta_time, part_check_status,
    volume_stop_status,
};
use crate::words::labels;
use crate::words::units::short_hash_or_dash;
use crate::wrap::display_width;

/// Downloads table columns: File · Size · Done · Progress · Speed · ETA · Src
/// · Status. `File` is greedy: its entry is the room it keeps before other
/// columns give way to it. Status is floored at `Downloading`, so no status
/// word is ever cut at the widths a row can be read at.
const DOWNLOAD_COLS: [usize; 8] = [30, 9, 4, CHUNK_CELL_W, 10, 6, 5, 11];
const DOWNLOAD_FLEX: usize = 0;

/// The chunk map's floor, and the most it grows to: the details modal's width.
const CHUNK_CELL_W: usize = 10;
const CHUNK_CELL_MAX: usize = 50;

/// The column holding the chunk map.
const PROGRESS_COL: usize = 3;

/// The most each bounded column asks for beyond its floor when a value drawn is
/// wider (`None`: the name, which is greedy, and the chunk bar, which asks by
/// the pane's width).
const DOWNLOAD_CAPS: [Option<usize>; 8] = [
    None,
    Some(12),
    Some(7),
    None,
    Some(14),
    Some(10),
    Some(9),
    Some(24),
];

/// The order the downloads table's columns give way in: ETA, Src, Done — the
/// chunk map draws what it says — then Size, Speed, Progress and Status. File
/// never gives way.
const DOWNLOAD_GIVE_WAY: [usize; 7] = [5, 6, 2, 1, 4, 3, 7];

/// The chunk map's width in a pane `pane_width` wide: its floor, growing with
/// a third of what the pane has past a hundred cells, so a large file buckets
/// fewer parts per cell where there is room for it.
fn chunk_width(pane_width: u16) -> usize {
    (usize::from(pane_width).saturating_sub(70) / 3).clamp(CHUNK_CELL_W, CHUNK_CELL_MAX)
}

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

/// A status's colour. Green says bytes are moving, so a stalled row and a
/// finished one read plain.
fn status_style(status: DownloadStatus, stalled: bool, theme: &Theme) -> Style {
    let color = match status {
        DownloadStatus::Downloading if stalled => theme.fg,
        DownloadStatus::Downloading => theme.good,
        DownloadStatus::Waiting | DownloadStatus::Completing | DownloadStatus::Completed => {
            theme.fg
        }
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
        let focused = self.focus == Pane::Table;
        let title = if self.tags.is_empty() {
            format!(" Downloads ({}) ", lines.len())
        } else {
            let tagged = crate::words::rows::tagged(self.tags.len());
            format!(" Downloads ({}) · {tagged} ", lines.len())
        };
        if lines.is_empty() && !self.filter.shown() {
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
        // The keys a person needs first; they give way from the end. `C` is
        // offered while it has something to clear.
        let hint = if !super::clear::completed_ids(state).is_empty() {
            " p pause  m menu  / filter  L add  Tab sources  Space tag  C clear  s sort  z zoom "
        } else {
            " p pause  m menu  / filter  L add  Tab sources  Space tag  s sort  z zoom "
        };
        let block = pane_block(area.width, (&title, hint), focused, theme);
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let cells =
            |index: usize, cols: &[usize]| download_cells(&lines[index], state, cols, theme);
        let values: Vec<Vec<String>> = lines.iter().map(|line| line.values(theme)).collect();
        let mut wants = [0; 8];
        for (index, cap) in DOWNLOAD_CAPS.into_iter().enumerate() {
            if let Some(cap) = cap {
                let widest = values
                    .iter()
                    .map(|row| display_width(&row[index]))
                    .max()
                    .unwrap_or(0);
                wants[index] = widest.min(cap);
            }
        }
        wants[PROGRESS_COL] = chunk_width(area.width);
        let table = Table::of(
            &self.sort,
            &DOWNLOAD_COLS,
            DOWNLOAD_FLEX,
            &DOWNLOAD_GIVE_WAY,
            theme.dim_text(),
        )
        .wants(&wants)
        .left(PROGRESS_COL)
        .empty(crate::words::rows::NO_MATCH);
        let tagged = |index: usize| self.tags.contains(&lines[index].id);
        let rows = Rows {
            count: lines.len(),
            selected: self.selected,
            focused,
            cells: &cells,
            marker: None,
            tagged: Some(&tagged),
            filter: Some((&self.filter, state.downloads.len())),
        };
        self.drawn = table::draw(
            frame,
            (area, inner),
            &table,
            &rows,
            &mut self.viewport,
            theme,
        );
    }
}

/// One download's cells, in `DownloadsTable::COLUMNS`' order. The Progress
/// bar has no text of its own; the Off-screen line reads it as the Done figure.
fn download_cells(
    line: &DownloadLine,
    state: &UiState,
    cols: &[usize],
    theme: &Theme,
) -> Vec<Cell> {
    let diag = state.diagnostics.downloads.get(&line.id);
    let plain = Style::new().fg(theme.fg);
    let name_style = if line.name_real {
        plain
    } else {
        theme.dim_text()
    };
    let (speed_text, speed_style) = rate_cell(line.bps, theme);
    let done = line.done_cell();
    vec![
        Cell::new(line.name.clone(), name_style),
        Cell::new(line.size_cell(), plain),
        Cell::new(done.clone(), plain),
        Cell::new(done, plain).drawn(chunk_bar(diag_parts(diag), cols[PROGRESS_COL], theme)),
        Cell::new(speed_text, speed_style),
        Cell::new(eta_cell(line.eta), plain),
        Cell::new(line.sources_cell(), plain),
        Cell::new(
            line.status_text.clone(),
            status_style(line.status, line.stalled, theme),
        ),
    ]
}

/// Whether `status` is a running download's and every source its run knows
/// holds no part the file lacks.
pub(super) fn swarm_exhausted(status: DownloadStatus, diag: Option<&DownloadDiagnostics>) -> bool {
    matches!(
        status,
        DownloadStatus::Waiting | DownloadStatus::Downloading
    ) && diag.is_some_and(DownloadDiagnostics::every_source_needs_nothing)
}

/// A download's status as its cell words it: a download with no network
/// while core re-makes the operator's session waits for that, not for
/// nothing; one waiting with no server session while Kad runs says Kad is
/// who asks; a running one no known source can feed says so, whatever it
/// last waited on; a completing one says what its move waits for or has
/// copied, from its diagnostics row. Each wording keeps the rank of the
/// status it words. A row the volume stopped says so where a Pause would, and a
/// run reading its parts back says how far, ahead of what it will wait on. A
/// Downloading row with nothing moving says **Stalled**.
pub(super) fn status_text(
    status: DownloadStatus,
    row: Option<&DownloadRow>,
    diag: Option<&DownloadDiagnostics>,
    stalled: bool,
    state: &UiState,
) -> String {
    let volume_stop = row.and_then(|row| row.volume_stop.as_ref());
    let check = diag.and_then(|diag| diag.part_check);
    match (status, row.and_then(|row| row.source_wait)) {
        // A run its stopped core no longer stands behind keeps its rank, not
        // its claim.
        (
            DownloadStatus::Waiting
            | DownloadStatus::NoConnection
            | DownloadStatus::Downloading
            | DownloadStatus::Completing,
            _,
        ) if !state.core_alive => crate::words::app::ROW_STOPPED.to_string(),
        (DownloadStatus::NoConnection, _) if state.reconnect.is_some() => {
            labels::RECONNECTING.to_string()
        }
        (DownloadStatus::Paused, _) if volume_stop.is_some() => volume_stop
            .map_or_else(String::new, |stopped| {
                volume_stop_status(stopped.stop).to_string()
            }),
        (DownloadStatus::Waiting | DownloadStatus::NoConnection, _) if check.is_some() => check
            .map_or_else(String::new, |level| {
                part_check_status(level.checked, level.of)
            }),
        _ if swarm_exhausted(status, diag) => NO_NEEDED_PARTS_STATUS.to_string(),
        (DownloadStatus::Downloading, _) if stalled => labels::STALLED.to_string(),
        (DownloadStatus::Waiting, Some(SourceWait::KadAlone)) => labels::ASKING_KAD.to_string(),
        (DownloadStatus::Waiting, Some(SourceWait::OnStanding)) => labels::QUEUED.to_string(),
        (DownloadStatus::Completing, _) => completing_status(diag.and_then(|diag| diag.completion)),
        _ => labels::status(status).to_string(),
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

    /// The cell texts, in the table's column order: what the columns ask
    /// their widths by. The Progress bar has no text of its own; it reads as
    /// the Done figure.
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
            self.status_text.clone(),
        ]
    }
}

#[cfg(test)]
mod tests;
