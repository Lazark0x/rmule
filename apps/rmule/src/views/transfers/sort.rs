//! The downloads table's **Table Sort** (ADR-0070): its
//! columns and how a download answers for each, the `s` / `S` keys and the
//! header click. The cursor is bound to the download id, so a row that moves
//! while it downloads keeps the selection.
//!
//! Every value is the fact the cell renders, taken before it is rendered: a
//! size in bytes, a share as an exact ratio, a rate in bytes per second. A
//! cell that renders a dash has no value and sorts last either way.

use std::borrow::Cow;

use rmule_core::DownloadId;
use rmule_primitives::ED2K_PART_SIZE;

use super::TransfersView;
use super::downloads::{diag_counts, display_name, done_fraction, row_eta, source_counts};
use crate::state::{DownloadStatus, UiState};
use crate::table_sort::{ColumnKind, ColumnSpec, SortValue, SortedTable};
use crate::views::ViewOutcome;

/// The downloads table, as the sort sees it.
pub(super) struct DownloadsTable;

/// The downloads table's visible columns, left to right.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DownloadColumn {
    File,
    Size,
    Done,
    Progress,
    Speed,
    Eta,
    Sources,
    Status,
}

/// One download's sortable facts, projected once per order.
pub(super) struct DownloadLine {
    id: DownloadId,
    /// The real name; the short-hash stand-in is not one.
    name: Option<String>,
    /// Exact, or the part-count estimate the cell shows with `≈`.
    size: Option<u64>,
    done: Option<(u64, u64)>,
    /// Parts the chunk bar lights — held or being fetched — over all parts.
    progress: Option<(u64, u64)>,
    speed: Option<u64>,
    eta: Option<u64>,
    /// Known, then sending; `None` for a download that is not running.
    sources: Option<(u32, u32)>,
    status: DownloadStatus,
}

impl DownloadLine {
    fn new(id: DownloadId, state: &UiState) -> Self {
        let row = state.downloads.get(&id);
        let diag = state.diagnostics.downloads.get(&id);
        let metadata = row.and_then(|row| row.metadata.as_ref());
        let counts = diag_counts(diag);
        let bps = state.download_speed(id);
        let (name, real) = display_name(metadata, row.and_then(|row| row.file_hash));
        let estimate = row
            .and_then(|row| row.part_count)
            .map(|parts| (parts as u64).saturating_mul(ED2K_PART_SIZE));
        Self {
            id,
            name: real.then_some(name),
            size: metadata.map(|metadata| metadata.size).or(estimate),
            done: done_fraction(row, diag),
            progress: (counts.total() > 0).then(|| {
                (
                    u64::from(counts.verified + counts.in_flight),
                    u64::from(counts.total()),
                )
            }),
            // Whole bytes per second: finer than the cell's one decimal of KB/s.
            speed: (bps > 0.0).then_some(bps as u64),
            eta: row_eta(row, diag, state.download_eta_speed(id)).seconds(),
            sources: source_counts(diag),
            status: row.map_or(DownloadStatus::Waiting, |row| row.status),
        }
    }
}

/// A status's place in aMule's download-status order
/// (`CPartFile::getPartfileStatusRang`, `amule-kno/src/PartFile.cpp:4638`):
/// moving bytes, then waiting for them, paused, complete, failed. The first
/// in that order ranks lowest, so the column's Natural Direction (ascending, a
/// rank's) opens on aMule's first click: the downloads moving bytes at the
/// top.
const fn status_rank(status: DownloadStatus) -> u64 {
    match status {
        DownloadStatus::Downloading => 0,
        // aMule has no such state: a file with no server and no Kad is one
        // of its waiting files, `getPartfileStatusRang`'s `1`.
        DownloadStatus::Waiting | DownloadStatus::NoConnection => 1,
        DownloadStatus::Paused => 2,
        DownloadStatus::Completed => 3,
        DownloadStatus::Failed => 4,
    }
}

/// The group a download falls in under Progress and Done, ahead of its share
/// (ADR-0070, "A column's order may be a rank"): the downloads moving bytes,
/// then the completed ones, then the rest — led by those whose run is alive
/// but moves no bytes (waiting for a source, a slot or a network), then
/// those with no run (paused, failed). The operator's reading of aMule: what
/// is happening now, what just finished, what waits on them.
const fn activity_rank(status: DownloadStatus) -> u8 {
    match status {
        DownloadStatus::Downloading => 0,
        DownloadStatus::Completed => 1,
        DownloadStatus::Waiting | DownloadStatus::NoConnection => 2,
        DownloadStatus::Paused | DownloadStatus::Failed => 3,
    }
}

impl SortedTable for DownloadsTable {
    type Row = DownloadLine;
    type Column = DownloadColumn;
    type Identity = DownloadId;
    const TABLE: &'static str = "transfers";
    const COLUMNS: &'static [ColumnSpec<DownloadColumn>] = &[
        ColumnSpec::new(DownloadColumn::File, "name", "File", ColumnKind::Text),
        ColumnSpec::new(DownloadColumn::Size, "size", "Size", ColumnKind::Quantity),
        ColumnSpec::new(DownloadColumn::Done, "done", "Done", ColumnKind::Quantity),
        ColumnSpec::new(
            DownloadColumn::Progress,
            "progress",
            "Progress",
            ColumnKind::Quantity,
        ),
        ColumnSpec::new(
            DownloadColumn::Speed,
            "speed",
            "Speed",
            ColumnKind::Quantity,
        ),
        ColumnSpec::new(DownloadColumn::Eta, "eta", "ETA", ColumnKind::Quantity),
        ColumnSpec::new(
            DownloadColumn::Sources,
            "sources",
            "Src",
            ColumnKind::Quantity,
        ),
        ColumnSpec::new(DownloadColumn::Status, "status", "Status", ColumnKind::Rank),
    ];
    const NAME: DownloadColumn = DownloadColumn::File;

    fn value(column: DownloadColumn, row: &DownloadLine) -> Option<SortValue<'_>> {
        let fraction = |(part, whole)| SortValue::Fraction { part, whole };
        match column {
            DownloadColumn::File => row
                .name
                .as_deref()
                .map(|name| SortValue::Text(Cow::Borrowed(name))),
            DownloadColumn::Size => row.size.map(SortValue::Quantity),
            DownloadColumn::Done => row.done.map(fraction),
            DownloadColumn::Progress => row.progress.map(fraction),
            DownloadColumn::Speed => row.speed.map(SortValue::Quantity),
            DownloadColumn::Eta => row.eta.map(SortValue::Quantity),
            // `known (sending)` orders by known, then sending, as aMule sorts
            // by source count.
            DownloadColumn::Sources => row.sources.map(|(known, sending)| SortValue::Pair {
                first: u64::from(known),
                second: u64::from(sending),
            }),
            DownloadColumn::Status => Some(SortValue::Quantity(status_rank(row.status))),
        }
    }

    fn rank(column: DownloadColumn, row: &DownloadLine) -> u8 {
        match column {
            DownloadColumn::Done | DownloadColumn::Progress => activity_rank(row.status),
            _ => 0,
        }
    }

    fn identity(row: &DownloadLine) -> DownloadId {
        row.id
    }
}

impl TransfersView {
    /// Every download's id, in display order.
    pub(super) fn download_ids(&self, state: &UiState) -> Vec<DownloadId> {
        let lines: Vec<DownloadLine> = state
            .downloads
            .keys()
            .map(|id| DownloadLine::new(*id, state))
            .collect();
        self.sort
            .order(&lines)
            .into_iter()
            .map(|at| lines[at].id)
            .collect()
    }

    /// Take up the downloads' sort as the durable preferences kept it.
    pub fn restore_sort(&mut self, sorts: &crate::table_sort::TableSorts) {
        self.sort = crate::table_sort::TableSort::restore(sorts);
        self.restore_source_sort(sorts);
    }

    /// A click on the header row: sort by the column under it. `None` when
    /// the click was not on a header cell.
    pub(super) fn header_click(&mut self, column: u16, row: u16) -> Option<ViewOutcome> {
        self.sort.header_click(
            self.header_area,
            &self.header_cols,
            usize::from(super::COL_SPACING),
            column,
            row,
        )
    }
}

#[cfg(test)]
mod tests;
