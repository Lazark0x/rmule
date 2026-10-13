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
use super::downloads::{
    Eta, diag_counts, display_name, done_fraction, row_eta, source_counts, status_text,
};
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

/// One download's facts, joined once per frame from its row, its
/// diagnostics and its meters: the sort orders by them, the cells and the
/// `Off-screen:` line word them. Nothing is derived twice, so a cell cannot
/// say what its order does not.
pub(super) struct DownloadLine {
    pub(super) id: DownloadId,
    /// The real name, or the short-hash stand-in when there is none.
    pub(super) name: String,
    /// Whether [`Self::name`] is a real fact; the stand-in is not one.
    pub(super) name_real: bool,
    /// Exact, or the part-count estimate the cell shows with `≈`.
    pub(super) size: Option<u64>,
    pub(super) size_exact: bool,
    pub(super) done: Option<(u64, u64)>,
    /// Parts the chunk bar lights — held or being fetched — over all parts.
    progress: Option<(u64, u64)>,
    /// Bytes per second as metered; `0` when nothing moves.
    pub(super) bps: f64,
    pub(super) eta: Eta,
    /// Known, then sending; `None` for a download that is not running.
    pub(super) sources: Option<(u32, u32)>,
    pub(super) status: DownloadStatus,
    /// The status as the cell words it; the same rank as [`Self::status`].
    pub(super) status_text: &'static str,
}

impl DownloadLine {
    pub(super) fn new(id: DownloadId, state: &UiState) -> Self {
        let row = state.downloads.get(&id);
        let diag = state.diagnostics.downloads.get(&id);
        let metadata = row.and_then(|row| row.metadata.as_ref());
        let counts = diag_counts(diag);
        let (name, name_real) = display_name(metadata, row.and_then(|row| row.file_hash));
        let estimate = row
            .and_then(|row| row.part_count)
            .map(|parts| (parts as u64).saturating_mul(ED2K_PART_SIZE));
        let status = row.map_or(DownloadStatus::Waiting, |row| row.status);
        Self {
            id,
            name,
            name_real,
            size: metadata.map(|metadata| metadata.size).or(estimate),
            size_exact: metadata.is_some(),
            done: done_fraction(row, diag),
            progress: (counts.total() > 0).then(|| {
                (
                    u64::from(counts.verified + counts.in_flight),
                    u64::from(counts.total()),
                )
            }),
            bps: state.download_speed(id),
            eta: row_eta(row, diag, state.download_eta_speed(id)),
            sources: source_counts(diag),
            status,
            status_text: status_text(status, row.and_then(|row| row.source_wait), state),
        }
    }

    /// Whole bytes per second: finer than the cell's one decimal of KB/s.
    fn speed(&self) -> Option<u64> {
        (self.bps > 0.0).then_some(self.bps as u64)
    }
}

/// A status's place in aMule's download-status order
/// (`CPartFile::getPartfileStatusRang`, `amule-kno/src/PartFile.cpp:4638`):
/// moving bytes, then waiting for them, paused, completing (`PS_COMPLETING`,
/// `:4649`), complete, failed. The first
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
        DownloadStatus::Completing => 3,
        DownloadStatus::Completed => 4,
        DownloadStatus::Failed => 5,
    }
}

/// The group a download falls in under Progress and Done, ahead of its share
/// (ADR-0070, "A column's order may be a rank"): the downloads moving bytes,
/// then those moving their finished file into place, then the completed
/// ones, then the rest — led by those whose run is alive
/// but moves no bytes (waiting for a source, a slot or a network), then
/// those with no run (paused, failed). The operator's reading of aMule: what
/// is happening now, what just finished, what waits on them.
const fn activity_rank(status: DownloadStatus) -> u8 {
    match status {
        DownloadStatus::Downloading => 0,
        DownloadStatus::Completing => 1,
        DownloadStatus::Completed => 2,
        DownloadStatus::Waiting | DownloadStatus::NoConnection => 3,
        DownloadStatus::Paused | DownloadStatus::Failed => 4,
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
                .name_real
                .then_some(SortValue::Text(Cow::Borrowed(row.name.as_str()))),
            DownloadColumn::Size => row.size.map(SortValue::Quantity),
            DownloadColumn::Done => row.done.map(fraction),
            DownloadColumn::Progress => row.progress.map(fraction),
            DownloadColumn::Speed => row.speed().map(SortValue::Quantity),
            DownloadColumn::Eta => row.eta.seconds().map(SortValue::Quantity),
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
    /// Every download's line, in display order.
    pub(super) fn sorted_lines(&self, state: &UiState) -> Vec<DownloadLine> {
        let lines: Vec<DownloadLine> = state
            .downloads
            .keys()
            .map(|id| DownloadLine::new(*id, state))
            .collect();
        let order = self.sort.order(&lines);
        let mut slots: Vec<Option<DownloadLine>> = lines.into_iter().map(Some).collect();
        order
            .into_iter()
            .filter_map(|at| slots[at].take())
            .collect()
    }

    /// Every download's id, in display order.
    pub(super) fn download_ids(&self, state: &UiState) -> Vec<DownloadId> {
        self.sorted_lines(state)
            .into_iter()
            .map(|line| line.id)
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
