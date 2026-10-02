//! The sort at its seam: rows in, display order and cursor position out.

use std::borrow::Cow;

use super::*;

struct Row {
    id: u8,
    name: Option<&'static str>,
    size: Option<u64>,
    kind: Option<&'static str>,
}

fn row(id: u8, name: &'static str, size: Option<u64>, kind: Option<&'static str>) -> Row {
    Row {
        id,
        name: Some(name),
        size,
        kind,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Col {
    Name,
    Size,
    Kind,
}

struct Files;

impl SortedTable for Files {
    type Row = Row;
    type Column = Col;
    type Identity = u8;
    const TABLE: &'static str = "files";
    const COLUMNS: &'static [ColumnSpec<Col>] = &[
        ColumnSpec::new(Col::Name, "name", "Name", ColumnKind::Text),
        ColumnSpec::new(Col::Size, "size", "Size", ColumnKind::Quantity),
        ColumnSpec::new(Col::Kind, "kind", "Kind", ColumnKind::Text),
    ];
    const NAME: Col = Col::Name;

    fn value(column: Col, row: &Row) -> Option<SortValue<'_>> {
        match column {
            Col::Name => row.name.map(|name| SortValue::Text(Cow::Borrowed(name))),
            Col::Size => row.size.map(SortValue::Quantity),
            Col::Kind => row.kind.map(|kind| SortValue::Text(Cow::Borrowed(kind))),
        }
    }

    fn identity(row: &Row) -> u8 {
        row.id
    }
}

fn ids(sort: &TableSort<Files>, rows: &[Row]) -> Vec<u8> {
    sort.order(rows).into_iter().map(|at| rows[at].id).collect()
}

fn sorted_by(column: Col) -> TableSort<Files> {
    let mut sort = TableSort::<Files>::default();
    sort.click(column);
    sort
}

#[test]
fn the_default_is_name_ascending_and_names_fold_case_accents_and_digit_runs() {
    let rows = [
        row(1, "File10.avi", None, None),
        row(2, "file2.avi", None, None),
        row(3, "Éclair", None, None),
        row(4, "eclair", None, None),
        row(5, "dune", None, None),
        row(6, "file02.avi", None, None),
    ];
    // file2 before File10 (digit runs as numbers, case folded); Éclair beside
    // eclair (accent folded); file02 == file2 by name, so identity parts them.
    assert_eq!(ids(&TableSort::default(), &rows), [5, 3, 4, 2, 6, 1]);
}

#[test]
fn a_quantity_takes_the_sort_descending_and_compares_as_a_number() {
    let rows = [
        row(1, "a", Some(9_500_000), None),
        row(2, "b", Some(10_000_000_000), None),
        row(3, "c", Some(700), None),
    ];
    let sort = sorted_by(Col::Size);
    assert_eq!(sort.direction(), Direction::Descending, "Natural Direction");
    assert_eq!(ids(&sort, &rows), [2, 1, 3]);
}

#[test]
fn ties_fall_to_name_then_identity_and_reversing_leaves_the_chain_alone() {
    let rows = [
        row(4, "zeta", Some(5), None),
        row(3, "alpha", Some(5), None),
        row(2, "alpha", Some(5), None),
        row(1, "mid", Some(9), None),
    ];
    let mut sort = sorted_by(Col::Size);
    assert_eq!(ids(&sort, &rows), [1, 2, 3, 4]);
    sort.reverse();
    // The 5s move to the top as a block; inside it the order is unchanged.
    assert_eq!(ids(&sort, &rows), [2, 3, 4, 1]);
}

#[test]
fn a_missing_value_sorts_last_in_both_directions() {
    let rows = [
        row(1, "a", None, None),
        row(2, "b", Some(3), Some("Video")),
        row(3, "c", Some(8), Some("Audio")),
        Row {
            id: 4,
            name: None,
            size: Some(8),
            kind: None,
        },
    ];
    let mut size = sorted_by(Col::Size);
    // Row 4 ties row 3 on size and has no name: last among the 8s.
    assert_eq!(ids(&size, &rows), [3, 4, 2, 1]);
    size.reverse();
    assert_eq!(ids(&size, &rows), [2, 3, 4, 1]);

    let mut kind = sorted_by(Col::Kind);
    assert_eq!(ids(&kind, &rows), [3, 2, 1, 4]);
    kind.reverse();
    assert_eq!(ids(&kind, &rows), [2, 3, 1, 4]);
}

#[test]
fn s_walks_the_columns_and_wraps_and_a_click_on_the_active_header_reverses() {
    let mut sort = TableSort::<Files>::default();
    sort.next_column();
    assert_eq!(
        (sort.column(), sort.direction()),
        (Col::Size, Direction::Descending)
    );
    sort.next_column();
    assert_eq!(
        (sort.column(), sort.direction()),
        (Col::Kind, Direction::Ascending)
    );
    sort.next_column();
    assert_eq!(sort.column(), Col::Name, "wraps");

    sort.click(Col::Name);
    assert_eq!(
        sort.direction(),
        Direction::Descending,
        "same header reverses"
    );
    assert_eq!(sort.arrow(Col::Name), Some('▼'));
    assert_eq!(sort.arrow(Col::Size), None);
    sort.click(Col::Kind);
    assert_eq!(
        sort.direction(),
        Direction::Ascending,
        "a new header starts natural"
    );
}

#[test]
fn the_stored_text_round_trips_keeps_foreign_tables_and_skips_garbage() {
    let mut sorts = TableSorts::parse(Some("servers=ping:asc;broken;files=kind:sideways"));
    assert_eq!(TableSort::<Files>::restore(&sorts), TableSort::default());

    let mut sort = TableSort::<Files>::default();
    sort.next_column();
    let (column, direction) = sort.stored();
    sorts.set(Files::TABLE, column, direction);
    let reread = TableSorts::parse(Some(&sorts.text()));
    assert_eq!(TableSort::<Files>::restore(&reread), sort);
    assert_eq!(reread.get("servers"), Some(("ping", Direction::Ascending)));

    let renamed = TableSorts::parse(Some("files=weight:desc"));
    assert_eq!(
        TableSort::<Files>::restore(&renamed),
        TableSort::default(),
        "a column this table no longer has falls back to the default"
    );
}

#[test]
fn a_header_click_lands_on_the_column_under_it_and_a_gap_on_nothing() {
    let widths = [5, 3, 4];
    assert_eq!(column_at(0, &widths, 1), Some(0));
    assert_eq!(column_at(4, &widths, 1), Some(0));
    assert_eq!(column_at(5, &widths, 1), None);
    assert_eq!(column_at(6, &widths, 1), Some(1));
    assert_eq!(column_at(10, &widths, 1), Some(2));
    assert_eq!(column_at(14, &widths, 1), None);
}

#[test]
fn the_cursor_rests_on_the_first_row_until_moved_then_follows_its_row() {
    let mut cursor = RowCursor::default();
    assert_eq!(cursor.place(&[7, 8, 9]), Some(0));
    assert_eq!(
        cursor.place(&[9, 7, 8]),
        Some(0),
        "resting: first row, any row"
    );
    assert_eq!(cursor.place(&[] as &[u8]), None);

    cursor.step(&[9, 7, 8], 1);
    assert_eq!(cursor.place(&[9, 7, 8]), Some(1));
    // A replaced batch moves row 7 to the bottom: the cursor goes with it.
    assert_eq!(cursor.place(&[1, 9, 8, 7]), Some(3));
    // Row 7 leaves: the cursor holds its height and takes the row there.
    assert_eq!(cursor.place(&[1, 9, 8]), Some(2));
    assert_eq!(cursor.place(&[8, 1, 9]), Some(0), "now bound to row 8");

    cursor.reset();
    assert_eq!(cursor.place(&[8, 1, 9]), Some(0));
    assert_eq!(cursor.pin(&[1, 8, 9]), Some(1));
    assert_eq!(
        cursor.place(&[8, 9, 1]),
        Some(2),
        "pinned rows are followed"
    );
}

#[test]
fn a_fraction_compares_by_value_exactly_and_a_zero_whole_as_zero() {
    let key = |part, whole| Key::from(SortValue::Fraction { part, whole });
    // 42% of a big file against 40% of a small one: the terms disagree, the
    // values do not.
    assert!(key(42, 100) > key(4, 10));
    assert!(key(1, 3) < key(1, 2));
    assert!(key(2, 4) == key(1, 2), "equal ratios tie, to the Tie Chain");
    // Terms near u64::MAX cross-multiply without overflowing.
    assert!(key(u64::MAX - 1, u64::MAX) < key(u64::MAX, u64::MAX));
    assert!(key(7, 0) == key(0, 1));
    assert!(key(7, 0) < key(1, u64::MAX));
}

#[test]
fn a_pair_compares_its_first_figure_then_its_second_at_any_magnitude() {
    let key = |first, second| Key::from(SortValue::Pair { first, second });
    assert!(key(2, 0) > key(1, u64::MAX));
    assert!(key(1, 5) < key(1, 6));
    assert!(key(u64::from(u32::MAX) + 1, 0) > key(u64::from(u32::MAX), 9));
}
