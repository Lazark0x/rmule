//! The shared-files table's **Table Sort** (ADR-0070): its
//! columns and how a shared file answers for each, the `s` / `S` keys and the
//! header click. The cursor is bound to the file hash, so a row whose
//! counters move keeps the selection.
//!
//! Every value is the fact its cell renders, taken before it is rendered: the
//! registry's name and size off the row, the uploading count off the upload
//! peers, the request and byte counters off the level — this run's, the
//! figure a Requests or Transferred cell shows first. A cell that renders a
//! dash has no value and sorts last either way.

use std::borrow::Cow;

use rmule_core::diagnostics::ShareTotals;
use rmule_primitives::FileHash;

use super::SharedView;
use crate::state::{SharedRow, UiState, withheld_rank};
use crate::table_sort::{ColumnKind, ColumnSpec, SortValue, SortedTable, TableSort, TableSorts};
use crate::views::ViewOutcome;
use rmule_core::Withheld;

/// The shared-files table, as the sort sees it.
pub(super) struct SharedTable;

/// The shared-files table's visible columns, left to right. Requests,
/// Accepted, Transferred is aMule's own order
/// (`amule-kno/src/SharedFilesCtrl.cpp:158-160`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SharedColumn {
    File,
    State,
    Size,
    Uploading,
    Requests,
    Accepted,
    Transferred,
}

/// One shared file's cells, joined once per frame: the registry row and the
/// levels read beside it.
pub(super) struct SharedLine {
    pub(super) file_hash: FileHash,
    /// The name it is shared under; `None` until the registry's path is read.
    pub(super) name: Option<String>,
    /// Why nothing is offered for it now, and since when; `None` while
    /// offered.
    pub(super) withheld: Option<Withheld>,
    pub(super) size: Option<u64>,
    /// Peers holding a slot for it now.
    pub(super) uploading: u64,
    /// The run's counters, `None` before the first data tick — nothing has
    /// been read yet, which is not zero.
    pub(super) requests: Option<u64>,
    pub(super) accepted: Option<u64>,
    pub(super) transferred: Option<u64>,
    /// Every run's, this one included — shown beside this run's, in
    /// brackets, as aMule's Shared Files list does.
    pub(super) all_time: Option<ShareTotals>,
}

impl SharedLine {
    pub(super) fn new(row: &SharedRow, state: &UiState) -> Self {
        let counters = state.last_snapshot_at.map(|_| {
            state
                .diagnostics
                .shared_files
                .get(&row.file_hash)
                .copied()
                .unwrap_or_default()
        });
        Self {
            file_hash: row.file_hash,
            name: row.name(),
            withheld: row.withheld,
            size: row.file_size,
            uploading: state.uploading_now(row.file_hash) as u64,
            requests: counters.map(|counters| counters.requests),
            accepted: counters.map(|counters| counters.accepted),
            transferred: counters.map(|counters| counters.transferred),
            all_time: counters.map(|counters| counters.all_time),
        }
    }
}

impl SortedTable for SharedTable {
    type Row = SharedLine;
    type Column = SharedColumn;
    type Identity = FileHash;
    const TABLE: &'static str = "shared";
    const COLUMNS: &'static [ColumnSpec<SharedColumn>] = &[
        ColumnSpec::new(SharedColumn::File, "name", "File", ColumnKind::Text),
        ColumnSpec::new(SharedColumn::State, "state", "State", ColumnKind::Rank),
        ColumnSpec::new(SharedColumn::Size, "size", "Size", ColumnKind::Quantity),
        ColumnSpec::new(
            SharedColumn::Uploading,
            "uploading",
            "Uploading",
            ColumnKind::Quantity,
        ),
        ColumnSpec::new(
            SharedColumn::Requests,
            "requests",
            "Requests",
            ColumnKind::Quantity,
        ),
        ColumnSpec::new(
            SharedColumn::Accepted,
            "accepted",
            "Accepted",
            ColumnKind::Quantity,
        ),
        ColumnSpec::new(
            SharedColumn::Transferred,
            "transferred",
            "Transferred",
            ColumnKind::Quantity,
        ),
    ];
    const NAME: SharedColumn = SharedColumn::File;

    fn value(column: SharedColumn, row: &SharedLine) -> Option<SortValue<'_>> {
        let all_time = row.all_time.unwrap_or_default();
        match column {
            SharedColumn::File => row
                .name
                .as_deref()
                .map(|name| SortValue::Text(Cow::Borrowed(name))),
            // State renders words but is a rank (ADR-0070: nothing sorts by
            // the spelling of an enumeration).
            SharedColumn::State => Some(SortValue::Quantity(withheld_rank(
                row.withheld.map(|held| held.reason),
            ))),
            SharedColumn::Size => row.size.map(SortValue::Quantity),
            SharedColumn::Uploading => Some(SortValue::Quantity(row.uploading)),
            SharedColumn::Requests => row.requests.map(SortValue::Quantity),
            // Ties break on the all-time figure before the Tie Chain does:
            // a run of equal Accepted counts still orders by which
            // file's slot grants go back the furthest.
            SharedColumn::Accepted => row.accepted.map(|run| SortValue::Pair {
                first: run,
                second: all_time.accepted,
            }),
            SharedColumn::Transferred => row.transferred.map(SortValue::Quantity),
        }
    }

    fn identity(row: &SharedLine) -> FileHash {
        row.file_hash
    }
}

impl SharedView {
    /// The shared files' cells, one line per file, in the sort's order.
    pub(super) fn sorted_lines(&self, state: &UiState) -> Vec<SharedLine> {
        let filter = self.directory_filter(state);
        let lines: Vec<SharedLine> = state
            .shared
            .values()
            .filter(|row| {
                filter.is_none_or(|dir| {
                    row.path
                        .as_deref()
                        .is_some_and(|path| path.starts_with(dir))
                })
            })
            .map(|row| SharedLine::new(row, state))
            .collect();
        let order = self.sort.order(&lines);
        let mut slots: Vec<Option<SharedLine>> = lines.into_iter().map(Some).collect();
        order
            .into_iter()
            .filter_map(|at| slots[at].take())
            .collect()
    }

    /// The shared files in display order.
    pub(super) fn ordered<'a>(&self, state: &'a UiState) -> Vec<&'a SharedRow> {
        self.sorted_lines(state)
            .iter()
            .map(|line| &state.shared[&line.file_hash])
            .collect()
    }

    /// The shared files' hashes in display order — what the cursor is
    /// placed against.
    pub(super) fn file_ids(&self, state: &UiState) -> Vec<FileHash> {
        self.sorted_lines(state)
            .into_iter()
            .map(|line| line.file_hash)
            .collect()
    }

    /// Take up the shared files' sort as the durable preferences kept it.
    pub fn restore_sort(&mut self, sorts: &TableSorts) {
        self.sort = TableSort::restore(sorts);
        self.restore_peer_sort(sorts);
    }

    /// A click on the header row: sort by the column under it. `None` when
    /// the click was not on a header cell.
    pub(super) fn header_click(&mut self, column: u16, row: u16) -> Option<ViewOutcome> {
        self.sort
            .header_click(self.header_area, &self.header_cols, 1, column, row)
    }
}

#[cfg(test)]
mod tests;
