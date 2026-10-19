//! The results table's **Table Sort** (ADR-0070): which
//! columns it has and how a result answers for each, the `s` / `S` keys and
//! the header click, and the cursor bound to a result's identity.
//!
//! Core publishes the result *set* and replaces it whole on every batch; the
//! order the operator sees is decided here, and the cursor survives a batch
//! because it names a file, not a position.

use std::borrow::Cow;

use rmule_primitives::{Ed2kFileClass, FileHash, SearchResult};

use super::SearchesView;
use super::results::result_source_count;
use crate::state::UiState;
use crate::table_sort::{ColumnKind, ColumnSpec, SortValue, SortedTable};
use crate::views::ViewOutcome;

/// A result's type as a rank: aMule's `EED2KFileType` value
/// (`amule-kno/src/OtherFunctions.h:288`) for a class, and one past the last
/// class for a `FT_FILETYPE` term rmule does not know — the cell shows the
/// counterparty's own word there, which is still a type. `None` for an
/// unclassifiable row, the cell's dash.
fn type_rank(result: &SearchResult) -> Option<u64> {
    let rank = match result.file_class() {
        Some(Ed2kFileClass::Audio) => 1,
        Some(Ed2kFileClass::Video) => 2,
        Some(Ed2kFileClass::Image) => 3,
        Some(Ed2kFileClass::Program) => 4,
        Some(Ed2kFileClass::Document) => 5,
        Some(Ed2kFileClass::Archive) => 6,
        Some(Ed2kFileClass::CdImage) => 7,
        None => {
            result.file_type()?;
            8
        }
    };
    Some(rank)
}

/// The results table, as the sort sees it.
pub(super) struct ResultsTable;

/// A result's identity: the result set's own key, hash and size — a hash
/// reported at two sizes is two rows.
pub(super) type ResultId = (FileHash, u64);

/// The results table's visible columns, left to right.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ResultColumn {
    Name,
    Size,
    Sources,
    Type,
}

impl SortedTable for ResultsTable {
    type Row = SearchResult;
    type Column = ResultColumn;
    type Identity = ResultId;
    const TABLE: &'static str = "search";
    const COLUMNS: &'static [ColumnSpec<ResultColumn>] = &[
        ColumnSpec::new(ResultColumn::Name, "name", "Name", ColumnKind::Text),
        ColumnSpec::new(ResultColumn::Size, "size", "Size", ColumnKind::Quantity),
        ColumnSpec::new(
            ResultColumn::Sources,
            "sources",
            "Sources",
            ColumnKind::Quantity,
        ),
        ColumnSpec::new(ResultColumn::Type, "type", "Type", ColumnKind::Rank),
    ];
    const NAME: ResultColumn = ResultColumn::Name;

    fn value(column: ResultColumn, row: &SearchResult) -> Option<SortValue<'_>> {
        Some(match column {
            ResultColumn::Name => {
                SortValue::Text(Cow::Owned(row.primary_name().to_display_string()))
            }
            ResultColumn::Size => SortValue::Quantity(row.file_size()),
            ResultColumn::Sources => SortValue::Quantity(u64::from(result_source_count(row))),
            // The em dash is a missing type, not a type named "—".
            ResultColumn::Type => SortValue::Quantity(type_rank(row)?),
        })
    }

    fn identity(row: &SearchResult) -> ResultId {
        (row.file_hash(), row.file_size())
    }
}

impl SearchesView {
    /// The current held search's results in display order.
    pub(super) fn ordered<'a>(&self, state: &'a UiState) -> Vec<&'a SearchResult> {
        let Some(pane) = self.held.current_pane(state) else {
            return Vec::new();
        };
        self.sort
            .order(&pane.results)
            .into_iter()
            .map(|at| &pane.results[at])
            .collect()
    }

    /// The identities of the current held search's results, in display order
    /// — what its cursor is placed against.
    pub(super) fn result_ids(&self, state: &UiState) -> Vec<ResultId> {
        self.ordered(state)
            .into_iter()
            .map(ResultsTable::identity)
            .collect()
    }

    /// The result under the cursor, pinning the cursor to it so a batch that
    /// lands before the action runs cannot slide another file beneath it.
    pub(super) fn selected_result<'a>(&mut self, state: &'a UiState) -> Option<&'a SearchResult> {
        let ids = self.result_ids(state);
        let id = self.held.current_mut()?.cursor.pin(&ids)?;
        let rows = self.ordered(state);
        rows.into_iter()
            .find(|row| ResultsTable::identity(row) == id)
    }

    /// A click on the header row: sort by the column under it. `None` when
    /// the click was not on a header cell.
    pub(super) fn header_click(&mut self, column: u16, row: u16) -> Option<ViewOutcome> {
        self.sort.header_click(
            self.header_area,
            &self.header_cols,
            super::results::COL_SPACING_CELLS,
            column,
            row,
        )
    }

    /// The display row a click on the table's rows region lands on, walking
    /// the drawn rows' heights — a wrapped name makes one row several lines.
    pub(super) fn row_at(&self, column: u16, row: u16) -> Option<usize> {
        let area = self.rows_area;
        let inside = column >= area.x
            && column < area.x.saturating_add(area.width)
            && row >= area.y
            && row < area.y.saturating_add(area.height);
        if !inside {
            return None;
        }
        let mut line = row - area.y;
        let first = self.viewport.first();
        for (index, height) in self.row_heights.iter().enumerate().skip(first) {
            if line < *height {
                return Some(index);
            }
            line -= height;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use ratatui::crossterm::event::KeyCode;

    use super::*;
    use crate::action::Action;
    use crate::config::PrefEdit;
    use crate::config::SharedConfig;
    use crate::fixture::*;
    use crate::golden::assert_golden;
    use crate::state::SearchStatus;
    use crate::table_sort::{Direction, TableSort, TableSorts};

    fn names(view: &mut SearchesView, state: &UiState) -> Vec<String> {
        view.held.bind(state);
        view.ordered(state)
            .into_iter()
            .map(|result| result.primary_name().to_display_string())
            .collect()
    }

    /// The screen cell of `label`'s first glyph on the header line.
    fn header_cell(lines: &[String], label: &str) -> (u16, u16) {
        lines
            .iter()
            .enumerate()
            .find_map(|(y, line)| {
                let header = line.contains("Name") && line.contains("Type");
                let x = line.chars().collect::<Vec<_>>();
                let at = header.then(|| {
                    (0..x.len()).find(|at| x[*at..].iter().collect::<String>().starts_with(label))
                })??;
                Some((u16::try_from(at).ok()?, u16::try_from(y).ok()?))
            })
            .expect("header on screen")
    }

    fn tiers() -> UiState {
        state_with(three_tier_results(), SearchStatus::Completed { total: 3 })
    }

    #[test]
    fn s_moves_the_sort_along_the_columns_and_capital_s_reverses_it() {
        let state = tiers();
        let mut view = SearchesView::new();
        assert_eq!(
            names(&mut view, &state),
            ["clip_low.avi", "distro_hot.iso", "song_mid.mp3"],
            "the default is name ascending, not core's source order"
        );

        match view.handle_key(press(KeyCode::Char('s')), &state) {
            ViewOutcome::Emit(Action::Preference(PrefEdit::TableSort {
                table,
                column,
                direction,
            })) => assert_eq!(
                (table, column, direction),
                ("search", "size", Direction::Descending)
            ),
            other => panic!("expected the sort kept as a preference, got {other:?}"),
        }
        assert_eq!(
            names(&mut view, &state),
            ["distro_hot.iso", "clip_low.avi", "song_mid.mp3"]
        );

        view.handle_key(press(KeyCode::Char('S')), &state);
        assert_eq!(
            names(&mut view, &state),
            ["song_mid.mp3", "clip_low.avi", "distro_hot.iso"]
        );
    }

    /// Type sorts by aMule's file-type value, not by the label the cell
    /// shows: sorted as text, the same labels give another order.
    #[test]
    fn type_sorts_by_rank_not_by_its_label() {
        use super::super::results::result_type;
        let state = state_with(
            vec![
                server_result(0x11, "e.txt", 1, 1, 0),
                server_result(0x22, "b.iso", 1, 1, 0),
                server_result(0x33, "d.exe", 1, 1, 0),
                server_result(0x44, "c.avi", 1, 1, 0),
                server_result(0x55, "a.mp3", 1, 1, 0),
                server_result(0x66, "f", 1, 1, 0),
            ],
            SearchStatus::Completed { total: 6 },
        );
        let mut view = SearchesView::new();
        while view.sort.column() != ResultColumn::Type {
            view.handle_key(press(KeyCode::Char('s')), &state);
        }
        assert_eq!(
            view.sort.direction(),
            Direction::Ascending,
            "a rank's first press runs ascending"
        );
        // Audio, Video, Program, Document, CD image; the unclassifiable last.
        assert_eq!(
            names(&mut view, &state),
            ["a.mp3", "c.avi", "d.exe", "e.txt", "b.iso", "f"]
        );
        let ordered = view.ordered(&state);
        let mut labels: Vec<String> = ordered.iter().filter_map(|r| result_type(r)).collect();
        let shown = labels.clone();
        labels.sort();
        assert_ne!(shown, labels, "the rank must not be the labels' order");
    }

    #[test]
    fn with_no_results_s_is_not_the_views_key() {
        let mut view = SearchesView::new();
        assert!(matches!(
            view.handle_key(press(KeyCode::Char('s')), &UiState::default()),
            ViewOutcome::Ignored
        ));
    }

    #[test]
    fn a_header_click_sorts_by_its_column_and_again_reverses_at_two_widths() {
        let state = tiers();
        for width in [78, 50] {
            let mut view = SearchesView::new();
            let lines = screen_lines(&draw_searches(&mut view, &state, width, GOLDEN_H));
            let (x, y) = header_cell(&lines, "Sources");
            assert!(matches!(
                view.handle_click(x, y, &state),
                ViewOutcome::Emit(Action::Preference(_))
            ));
            assert_eq!(
                (view.sort.column(), view.sort.direction()),
                (ResultColumn::Sources, Direction::Descending),
                "width {width}: a quantity arrives descending"
            );
            let lines = screen_lines(&draw_searches(&mut view, &state, width, GOLDEN_H));
            let (x, y) = header_cell(&lines, "Sources ▼");
            view.handle_click(x, y, &state);
            assert_eq!(
                view.sort.direction(),
                Direction::Ascending,
                "width {width}: the active header reverses"
            );
            let lines = screen_lines(&draw_searches(&mut view, &state, width, GOLDEN_H));
            let (x, y) = header_cell(&lines, "Type");
            view.handle_click(x, y, &state);
            assert_eq!(view.sort.column(), ResultColumn::Type, "width {width}");
        }
    }

    #[test]
    fn the_cursor_follows_its_result_when_a_batch_replaces_the_set() {
        let mut state = tiers();
        let mut view = SearchesView::new();
        screen_lines(&draw_searches(&mut view, &state, 78, GOLDEN_H));
        view.handle_key(press(KeyCode::Char('j')), &state); // onto distro_hot
        let search_id = search_id(1);

        // The next batch is the whole set again, grown by two files that sort
        // ahead of it.
        let mut batch = three_tier_results();
        batch.push(server_result(0x44, "alpha.mkv", 10, 2, 0));
        batch.push(server_result(0x55, "beta.mkv", 10, 2, 0));
        state.searches.get_mut(&search_id).expect("pane").results = batch;
        screen_lines(&draw_searches(&mut view, &state, 78, GOLDEN_H));
        assert_eq!(view.results_state.selected(), Some(3));
        assert_eq!(
            view.selected_result(&state)
                .map(|result| result.primary_name().to_display_string()),
            Some("distro_hot.iso".to_string())
        );
    }

    #[test]
    fn an_untouched_cursor_rests_on_the_first_row_as_batches_arrive() {
        let mut state = tiers();
        let mut view = SearchesView::new();
        screen_lines(&draw_searches(&mut view, &state, 78, GOLDEN_H));
        let search_id = search_id(1);
        state
            .searches
            .get_mut(&search_id)
            .expect("pane")
            .results
            .push(server_result(0x44, "alpha.mkv", 10, 2, 0));
        screen_lines(&draw_searches(&mut view, &state, 78, GOLDEN_H));
        assert_eq!(view.results_state.selected(), Some(0));
        assert_eq!(
            view.selected_result(&state)
                .map(|result| result.primary_name().to_display_string()),
            Some("alpha.mkv".to_string())
        );
    }

    #[test]
    fn the_sort_survives_a_restart_through_the_config_store() {
        let config = SharedConfig::open(rmule_testkit::memory_store());
        let state = tiers();
        let mut view = SearchesView::new();
        view.handle_key(press(KeyCode::Char('s')), &state);
        let ViewOutcome::Emit(Action::Preference(edit)) =
            view.handle_key(press(KeyCode::Char('s')), &state)
        else {
            panic!("the sort is kept");
        };
        config.commit(&edit).expect("commit");

        let mut restarted = SearchesView::new();
        restarted.restore_sort(&config.load(None).expect("load").table_sorts);
        assert_eq!(restarted.sort, view.sort);
        assert_eq!(
            names(&mut restarted, &state),
            ["distro_hot.iso", "song_mid.mp3", "clip_low.avi"],
            "sources descending"
        );
        // Nothing stored yet: the default.
        let mut fresh = SearchesView::new();
        fresh.restore_sort(&TableSorts::default());
        assert_eq!(fresh.sort, TableSort::default());
    }

    #[test]
    fn golden_searches_sorted_by_sources() {
        let state = tiers();
        let mut view = SearchesView::new().having_sent("ubuntu");
        view.handle_key(press(KeyCode::Char('s')), &state);
        view.handle_key(press(KeyCode::Char('s')), &state);
        assert_golden("searches_sorted_sources", GOLDEN_W, GOLDEN_H, |frame| {
            view.draw(frame, frame.area(), &state, &theme(), Instant::now());
        });
    }
}
