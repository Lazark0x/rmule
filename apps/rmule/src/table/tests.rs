//! The table as drawn: one line per row, cut in the middle, clipped never
//! dropped, and the full value on the Off-screen line.

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::layout::Rect;
use ratatui::style::Style;

use super::*;
use crate::table_sort::{ColumnKind, ColumnSpec, SortValue};

struct Files;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Column {
    Name,
    Size,
}

impl SortedTable for Files {
    type Row = ();
    type Column = Column;
    type Identity = u8;
    const TABLE: &'static str = "test";
    const COLUMNS: &'static [ColumnSpec<Column>] = &[
        ColumnSpec::new(Column::Name, "name", "Name", ColumnKind::Text),
        ColumnSpec::new(Column::Size, "size", "Size", ColumnKind::Quantity),
    ];
    const NAME: Column = Column::Name;
    fn value(_: Column, (): &()) -> Option<SortValue<'_>> {
        None
    }
    fn identity((): &()) -> u8 {
        0
    }
}

/// Draw `names` at `width` × `height`, the cursor on `selected`: the screen's
/// lines, and where the table landed.
fn drawn(names: &[&str], selected: usize, width: u16, height: u16) -> (Vec<String>, Drawn) {
    let theme = Theme::default_dark();
    let sort = TableSort::<Files>::default();
    let table = Table::of(&sort, &[10, 6], 0, &[1], Style::new());
    let cells = |index: usize, _: &[usize]| {
        vec![
            Cell::new(names[index], Style::new()),
            Cell::new("1.0 MB", Style::new()),
        ]
    };
    let rows = Rows {
        count: names.len(),
        selected: Some(selected),
        focused: true,
        cells: &cells,
        marker: None,
        tagged: None,
        filter: None,
    };
    let mut viewport = Viewport::default();
    let mut landed = Drawn::default();
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
    terminal
        .draw(|frame| {
            let body = Rect::new(0, 0, width, height);
            landed = draw(
                frame,
                (Rect::default(), body),
                &table,
                &rows,
                &mut viewport,
                &theme,
            );
        })
        .expect("draw");
    let buffer = terminal.backend().buffer();
    let lines = (0..height)
        .map(|y| {
            (0..width)
                .map(|x| buffer.cell((x, y)).expect("cell").symbol())
                .collect::<String>()
                .trim_end()
                .to_string()
        })
        .collect();
    (lines, landed)
}

#[test]
fn a_long_name_takes_one_line_and_its_row_keeps_its_place() {
    let (lines, landed) = drawn(&["a", "a-very-long-name-of-a-file.iso", "c"], 0, 24, 8);
    assert_eq!(lines[0], "  Name ▲            Size");
    assert_eq!(lines[1], "▸ a               1.0 MB");
    assert_eq!(lines[2], "  a-very-lon….iso 1.0 MB");
    assert_eq!(lines[3], "  c               1.0 MB");
    assert_eq!(landed.hit(4, 2), Some(1));
    assert_eq!(landed.hit(4, 3), Some(2));
}

#[test]
fn the_selected_rows_full_name_rides_the_off_screen_line() {
    let (lines, _) = drawn(&["a", "a-very-long-name-of-a-file.iso"], 1, 44, 6);
    let said = lines.join("\n");
    assert!(!said.contains("Off-screen"), "it fits at 44:\n{said}");
    let (lines, _) = drawn(&["a", "a-very-long-name-of-a-file.iso"], 1, 24, 6);
    let said = lines.join(" ");
    assert!(said.contains("Off-screen: Name"), "{said}");
    assert!(said.contains("long-name"), "{said}");
    let (lines, _) = drawn(&["a", "a-very-long-name-of-a-file.iso"], 0, 24, 6);
    assert!(!lines.join(" ").contains("Off-screen"), "row a shows whole");
}

/// With one line for the table the row the keys act on stays in sight: the
/// header gives way, never the row.
#[test]
fn a_pane_of_one_line_still_shows_the_cursors_row() {
    let (lines, landed) = drawn(&["a", "b", "c"], 2, 24, 1);
    assert!(lines[0].starts_with("▸ c"), "{}", lines[0]);
    assert_eq!(landed.hit(4, 0), Some(2));
}

#[test]
fn a_cut_pads_by_cells_so_the_next_column_stays_put() {
    let (lines, _) = drawn(&["東京物語の完全版ディスク.mkv"], 0, 24, 3);
    assert!(lines[1].ends_with("1.0 MB"), "{}", lines[1]);
    assert!(lines[1].contains(".mkv"), "{}", lines[1]);
}

#[test]
fn a_narrow_pane_takes_a_column_away_and_says_which() {
    let (lines, landed) = drawn(&["a", "b"], 0, 16, 4);
    assert_eq!(landed.header().1[1], 0);
    assert!(lines[0].starts_with("  Name"), "{}", lines[0]);
    assert!(!lines[1].contains("MB") || lines[2].contains("Off-screen"));
    let said = lines.join(" ");
    assert!(said.contains("Off-screen: Size 1.0 MB"), "{said}");
}

/// The cursor walks from a row that fits onto one that is cut: the table's
/// bottom edge stands, for the Off-screen line kept its place.
#[test]
fn the_frame_does_not_move_as_the_cursor_enters_a_cut_row() {
    let names = ["short.iso", "a-very-long-name-that-cannot-fit-its-cell.iso"];
    let (fits, on_fits) = drawn(&names, 0, 24, 6);
    let (cut, on_cut) = drawn(&names, 1, 24, 6);
    assert_eq!(on_fits.line_of(1), on_cut.line_of(1), "{fits:?}\n{cut:?}");
    assert!(
        cut.iter().any(|line| line.contains("Off-screen")),
        "{cut:?}"
    );
    assert!(
        !fits.iter().any(|line| line.contains("Off-screen")),
        "{fits:?}"
    );
    assert_eq!(on_fits.rows_height(), on_cut.rows_height());
}
