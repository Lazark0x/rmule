//! The sources pane's **Table Sort** (ADR-0070): its columns,
//! how a source answers for each, the `s` / `S` keys while the pane has focus
//! and the header click. The cursor is bound to the source's peer endpoint
//! (and its slot, for a slot that holds no peer yet), so a source that moves
//! as its phase or speed changes keeps the selection.
//!
//! Software sorts by the client's family rank, then its version, and Phase by
//! how far the source has got — neither by its words.

use std::borrow::Cow;

use rmule_core::DownloadId;
use rmule_core::diagnostics::WorkerEntry;

use super::super::{COL_SPACING, TransfersView};
pub(in crate::views::transfers) use super::row::SourceKey;
use super::row::{SourceRow, source_rows};
use crate::state::UiState;
use crate::table_sort::{ColumnKind, ColumnSpec, SortValue, SortedTable, TableSorts};
use crate::views::ViewOutcome;
use crate::views::software::SoftwareRanks;

/// The sources pane, as the sort sees it.
pub(in crate::views::transfers) struct SourcesTable;

/// The sources pane's visible columns, left to right.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::views::transfers) enum SourceColumn {
    Source,
    Software,
    Phase,
    Speed,
}

/// One source's sortable facts.
pub(in crate::views::transfers) struct SourceLine {
    key: SourceKey,
    endpoint: Option<String>,
    software: Option<u64>,
    phase: u64,
    /// Whole bytes per second; `None` while nothing is metered.
    speed: Option<u64>,
}

impl SourceLine {
    fn new(row: &SourceRow<'_>, id: DownloadId, state: &UiState, ranks: &SoftwareRanks) -> Self {
        let bps = row.bps(id, state);
        Self {
            key: row.key(),
            endpoint: row.peer().map(|peer| peer.to_string()),
            software: ranks.rank(row.software()),
            phase: row.phase_rank(),
            speed: (bps > 0.0).then_some(bps as u64),
        }
    }
}

impl SortedTable for SourcesTable {
    type Row = SourceLine;
    type Column = SourceColumn;
    type Identity = SourceKey;
    const TABLE: &'static str = "sources";
    const COLUMNS: &'static [ColumnSpec<SourceColumn>] = &[
        ColumnSpec::new(SourceColumn::Source, "source", "Source", ColumnKind::Text),
        ColumnSpec::new(
            SourceColumn::Software,
            "software",
            "Software",
            ColumnKind::Rank,
        ),
        ColumnSpec::new(SourceColumn::Phase, "phase", "Phase", ColumnKind::Rank),
        ColumnSpec::new(SourceColumn::Speed, "speed", "Speed", ColumnKind::Quantity),
    ];
    const NAME: SourceColumn = SourceColumn::Source;

    fn value(column: SourceColumn, row: &SourceLine) -> Option<SortValue<'_>> {
        match column {
            // An endpoint compares digit runs as numbers, so `10.0.0.9` comes
            // before `10.0.0.10`.
            SourceColumn::Source => row
                .endpoint
                .as_deref()
                .map(|endpoint| SortValue::Text(Cow::Borrowed(endpoint))),
            SourceColumn::Software => row.software.map(SortValue::Quantity),
            SourceColumn::Phase => Some(SortValue::Quantity(row.phase)),
            SourceColumn::Speed => row.speed.map(SortValue::Quantity),
        }
    }

    fn identity(row: &SourceLine) -> SourceKey {
        row.key
    }
}

impl TransfersView {
    /// The selected download's sources, by key, in display order.
    pub(in crate::views::transfers) fn source_keys(
        &self,
        state: &UiState,
        download: Option<DownloadId>,
    ) -> Vec<SourceKey> {
        let Some((id, diag)) =
            download.and_then(|id| Some((id, state.diagnostics.downloads.get(&id)?)))
        else {
            return Vec::new();
        };
        let rows = source_rows(diag);
        let ranks = SoftwareRanks::new(diag.workers.values().filter_map(WorkerEntry::software));
        let lines: Vec<SourceLine> = rows
            .iter()
            .map(|row| SourceLine::new(row, id, state, &ranks))
            .collect();
        self.source_sort
            .order(&lines)
            .into_iter()
            .map(|at| lines[at].key)
            .collect()
    }

    /// Take up the sources pane's sort as the durable preferences kept it.
    pub(in crate::views::transfers) fn restore_source_sort(&mut self, sorts: &TableSorts) {
        self.source_sort = crate::table_sort::TableSort::restore(sorts);
    }

    /// A click on the sources header: sort by the column under it. `None`
    /// when the click was not on a header cell.
    pub(in crate::views::transfers) fn source_header_click(
        &mut self,
        column: u16,
        row: u16,
    ) -> Option<ViewOutcome> {
        self.source_sort.header_click(
            self.source_header_area,
            &self.source_header_cols,
            usize::from(COL_SPACING),
            column,
            row,
        )
    }
}

#[cfg(test)]
mod tests {
    use ratatui::crossterm::event::KeyCode;
    use rmule_core::diagnostics::{WorkerPhase, WorkerSlot};

    use super::*;
    use crate::action::Action;
    use crate::config::PrefEdit;
    use crate::fixture::*;
    use crate::golden::render_to_lines;
    use crate::table_sort::Direction;
    use crate::theme::Theme;

    /// One download whose four sources disagree on every column: slot 0 is
    /// `10.0.0.10`, receiving, eMule, 50 KB/s; slot 1 `10.0.0.9`, queued,
    /// aMule; slot 2 `10.0.0.2`, connecting, no hello yet; slot 3
    /// `10.0.0.3`, receiving, aMule, 100 KB/s.
    fn four_sources() -> UiState {
        let mut state = UiState::default();
        let id = download_id(1);
        state.downloads.insert(
            id,
            download_row(crate::state::DownloadStatus::Downloading, 1, 4),
        );
        let receiving = WorkerPhase::ReceivingPart {
            part_index: 0,
            bytes_received: 1,
        };
        let workers = vec![
            identified(
                worker(0, receiving.clone(), Some(peer_endpoint(10))),
                emule_qt(),
            ),
            identified(
                worker(1, WorkerPhase::WaitingForSlot, Some(peer_endpoint(9))),
                amule_233(),
            ),
            worker(2, WorkerPhase::Connecting, Some(peer_endpoint(2))),
            identified(worker(3, receiving, Some(peer_endpoint(3))), amule_233()),
        ];
        state
            .diagnostics
            .downloads
            .insert(id, diag(id, 1, "MMMM", 0, workers));
        for (slot, kbps) in [(0, 50.0), (3, 100.0)] {
            state
                .rates
                .source_bps
                .insert((id, WorkerSlot::from_usize(slot)), kbps * 1024.0);
        }
        state
    }

    fn slots(view: &TransfersView, state: &UiState) -> Vec<usize> {
        view.source_keys(state, Some(download_id(1)))
            .into_iter()
            .filter_map(|key| match key {
                SourceKey::Slot(_, slot) => Some(slot.as_usize()),
                SourceKey::Ended(_) => None,
            })
            .collect()
    }

    fn draw(view: &mut TransfersView, state: &UiState) -> Vec<String> {
        render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
            view.draw(frame, frame.area(), state, &Theme::default_dark(), now());
        })
        .lines()
        .map(str::to_string)
        .collect()
    }

    #[test]
    fn every_source_column_orders_by_its_value_with_the_pane_focused() {
        let state = four_sources();
        let mut view = TransfersView::new();
        view.handle_key(press(KeyCode::Tab), &state);
        // Endpoints compare digit runs as numbers: .2, .3, .9, .10.
        assert_eq!(slots(&view, &state), [2, 3, 1, 0]);
        let expect = [
            // eMule before aMule by family rank, though "aMule" sorts first
            // as a word; no hello sorts last either way.
            (SourceColumn::Software, [0, 3, 1, 2], [3, 1, 0, 2]),
            // Receiving, queued, connecting; the Tie Chain never reverses.
            (SourceColumn::Phase, [3, 0, 1, 2], [2, 1, 3, 0]),
            (SourceColumn::Speed, [3, 0, 2, 1], [0, 3, 2, 1]),
            (SourceColumn::Source, [2, 3, 1, 0], [0, 1, 3, 2]),
        ];
        for (column, natural, reversed) in expect {
            let outcome = view.handle_key(press(KeyCode::Char('s')), &state);
            assert!(
                matches!(
                    outcome,
                    ViewOutcome::Emit(Action::Preference(PrefEdit::TableSort {
                        table: "sources",
                        ..
                    }))
                ),
                "{column:?}"
            );
            assert_eq!(view.source_sort.column(), column);
            assert_eq!(slots(&view, &state), natural, "{column:?} natural");
            view.handle_key(press(KeyCode::Char('S')), &state);
            assert_eq!(slots(&view, &state), reversed, "{column:?} reversed");
            view.handle_key(press(KeyCode::Char('S')), &state);
        }
        assert_eq!(
            view.sort.column(),
            super::super::super::sort::DownloadColumn::File,
            "the downloads table kept its own sort"
        );
    }

    #[test]
    fn the_source_cursor_follows_its_peer_and_a_header_click_sorts_the_pane() {
        let mut state = four_sources();
        let mut view = TransfersView::new();
        view.handle_key(press(KeyCode::Tab), &state);
        view.handle_key(press(KeyCode::Char('j')), &state); // onto 10.0.0.3
        let lines = draw(&mut view, &state);
        assert!(
            lines.iter().any(|line| line.contains("▸ 10.0.0.3:4662")),
            "{}",
            lines.join("\n")
        );

        // Click the Speed header: the pane sorts by speed, slot 3 first.
        let (x, y) = lines
            .iter()
            .enumerate()
            .skip(13)
            .find_map(|(y, line)| {
                let at = line.find("Speed")?;
                Some((line[..at].chars().count() as u16, y as u16))
            })
            .expect("sources header on screen");
        view.handle_click(x, y, &state);
        assert_eq!(view.source_sort.column(), SourceColumn::Speed);
        assert_eq!(view.source_sort.direction(), Direction::Descending);

        // Slot 3 slows below slot 0: the row moves and the cursor with it.
        state
            .rates
            .source_bps
            .insert((download_id(1), WorkerSlot::from_usize(3)), 1.0);
        let lines = draw(&mut view, &state);
        assert_eq!(slots(&view, &state), [0, 3, 2, 1]);
        assert!(
            lines.iter().any(|line| line.contains("▸ 10.0.0.3:4662")),
            "{}",
            lines.join("\n")
        );
    }
}
