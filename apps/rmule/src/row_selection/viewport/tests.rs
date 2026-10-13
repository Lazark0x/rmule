//! The Viewport's thumb, its bar, its following and its count.

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::style::Modifier;

use super::{TrackCell, Viewport};
use crate::table_sort::RowMove;
use crate::theme::Theme;

/// A list `total` items long showing `shown` from `first`, without a cursor.
fn at(first: usize, shown: usize, total: usize) -> Viewport {
    Viewport {
        first,
        shown,
        total,
        cursor: None,
        tail: false,
    }
}

#[test]
fn the_thumb_is_the_window_over_the_whole_list() {
    // (first, shown, total) on a ten-cell track → the thumb's whole cells.
    let cases = [
        ((0, 10, 100), 0..1),
        // The last page puts the thumb on the track's end.
        ((90, 10, 100), 9..10),
        ((45, 10, 100), 5..6),
        ((0, 5, 10), 0..5),
        ((5, 5, 10), 5..10),
        ((2, 6, 10), 2..8),
        // One item below the top is not the top, one above the end is not the end.
        ((1, 10, 100), 1..2),
        ((89, 10, 100), 8..9),
    ];
    for ((first, shown, total), thumb) in cases {
        assert_eq!(
            at(first, shown, total).thumb(10, 1),
            Some(thumb),
            "first {first}, shown {shown}, total {total}"
        );
    }
}

#[test]
fn a_list_that_fits_has_no_thumb_and_a_short_track_still_holds_one() {
    assert_eq!(at(0, 10, 10).thumb(10, 1), None);
    assert_eq!(at(0, 3, 1_000).thumb(1, 1), Some(0..1));
    assert_eq!(at(997, 3, 1_000).thumb(2, 1), Some(1..2));
}

/// A bar drawn as one glyph a cell, `║` the track and a reversed cell's
/// glyph followed by `~`.
fn picture(cells: impl Iterator<Item = (String, bool)>) -> String {
    cells
        .map(|(glyph, reversed)| if reversed { glyph + "~" } else { glyph })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The track `track` cells long under `first`, `shown` and `total`, the
/// thumb's edges in eighths.
fn track(first: usize, shown: usize, total: usize, track: u16) -> String {
    let cells = at(first, shown, total)
        .track(track, true)
        .expect("the list overflows");
    picture(cells.map(|cell| match cell {
        TrackCell::Rail => ("║".to_owned(), false),
        TrackCell::Thumb { glyph, reversed } => (glyph.to_owned(), reversed),
    }))
}

#[test]
fn the_thumb_moves_an_eighth_of_a_cell_at_a_time() {
    // Ten cells are eighty eighths: ten items of eighty on screen make a
    // thumb ten eighths long with seventy to travel, one an item.
    let cases = [
        (0, "█ ▆~ ║ ║ ║ ║ ║ ║ ║ ║"),
        (1, "▇ ▅~ ║ ║ ║ ║ ║ ║ ║ ║"),
        (2, "▆ ▄~ ║ ║ ║ ║ ║ ║ ║ ║"),
        (7, "▁ █ ▇~ ║ ║ ║ ║ ║ ║ ║"),
        (8, "║ █ ▆~ ║ ║ ║ ║ ║ ║ ║"),
        // One item above the end is not the end.
        (69, "║ ║ ║ ║ ║ ║ ║ ║ ▃ ▁~"),
        // The last page puts the thumb's end on the track's end.
        (70, "║ ║ ║ ║ ║ ║ ║ ║ ▂ █"),
    ];
    for (first, bar) in cases {
        assert_eq!(track(first, 10, 80, 10), bar, "first {first}");
    }
}

#[test]
fn the_last_page_ends_flush_where_the_shares_round_down() {
    // Forty of a hundred on three cells is 9.6 eighths, sixty above it 14.4:
    // the thumb ends on the track's last eighth all the same.
    assert_eq!(track(60, 40, 100, 3), "║ ▂ █");
    assert_eq!(track(0, 40, 100, 3), "█ ▆~ ║");
}

#[test]
fn a_thumb_shorter_than_a_cell_is_a_cell_long() {
    // Three of a thousand on ten cells is a quarter of an eighth.
    assert_eq!(track(0, 3, 1_000, 10), "█ ║ ║ ║ ║ ║ ║ ║ ║ ║");
    assert_eq!(track(500, 3, 1_000, 10), "║ ║ ║ ║ ▄ ▄~ ║ ║ ║ ║");
    assert_eq!(track(997, 3, 1_000, 10), "║ ║ ║ ║ ║ ║ ║ ║ ║ █");
    // A one-row track is all thumb wherever the list is.
    for first in [0, 500, 997] {
        assert_eq!(track(first, 3, 1_000, 1), "█", "first {first}");
    }
}

#[test]
fn a_thumb_inside_one_cell_takes_the_edge_glyph_that_overstates_it_less() {
    let cell = |thumb| match TrackCell::of(&thumb, 0) {
        TrackCell::Thumb { glyph, reversed } => (glyph, reversed),
        TrackCell::Rail => ("║", false),
    };
    assert_eq!(
        cell(4..7),
        ("▄", false),
        "the lower half overstates one eighth"
    );
    assert_eq!(cell(2..5), ("▃", true), "the upper five overstate two");
}

#[test]
fn the_bottom_edge_draws_reversed_and_a_theme_without_a_thumb_colour_whole_cells() {
    let drawn = |theme: Theme| {
        let mut terminal = Terminal::new(TestBackend::new(1, 12)).expect("test terminal");
        terminal
            .draw(|frame| at(45, 10, 100).draw_bar(frame, frame.area(), &theme))
            .expect("draw frame");
        let buffer = terminal.backend().buffer();
        picture((0..12).map(|y| {
            let cell = buffer.cell((0, y)).expect("in the bar");
            (
                cell.symbol().to_owned(),
                cell.modifier.contains(Modifier::REVERSED),
            )
        }))
    };
    let colour = Theme::default_dark();
    assert_eq!(drawn(colour), "▲ ║ ║ ║ ║ ▄ ▄~ ║ ║ ║ ║ ▼");
    let mono = Theme {
        dim: colour.fg,
        ..colour
    };
    assert_eq!(drawn(mono), "▲ ║ ║ ║ ║ ║ █ ║ ║ ║ ║ ▼");
}

#[test]
fn following_moves_no_further_than_keeps_the_cursor_on_screen() {
    let mut viewport = Viewport::default();
    let one = |_| 1;
    assert_eq!(viewport.follow(4, 20, 5, one), 0);
    assert_eq!(
        viewport.follow(7, 20, 5, one),
        3,
        "down pushes it just far enough"
    );
    assert_eq!(
        viewport.follow(5, 20, 5, one),
        3,
        "inside the window it stays"
    );
    assert_eq!(
        viewport.follow(1, 20, 5, one),
        1,
        "up pulls it to the cursor"
    );
    // Rows leave: what is left fills the room instead of hiding above.
    viewport.follow(19, 20, 5, one);
    assert_eq!(viewport.follow(7, 8, 5, one), 3);
}

#[test]
fn a_wrapped_row_costs_its_lines() {
    let heights = [1, 3, 1, 2, 1, 1];
    let mut viewport = Viewport::default();
    let first = viewport.follow(3, heights.len(), 4, |index| heights[index]);
    assert_eq!(first, 2, "row 1 would push the cursor's row off the bottom");
    assert_eq!(viewport.shown, 3, "rows 2 to 4 fill the four lines");
    assert_eq!(viewport.count().as_deref(), Some("4 / 6"));
}

#[test]
fn a_list_with_a_cursor_counts_even_when_it_fits() {
    let mut viewport = Viewport::default();
    viewport.follow(1, 3, 10, |_| 1);
    assert!(!viewport.overflows());
    assert_eq!(viewport.count().as_deref(), Some("2 / 3"));
}

#[test]
fn a_list_without_a_cursor_counts_its_last_line_only_while_it_overflows() {
    let mut viewport = Viewport::default();
    viewport.show(3, 10);
    assert_eq!(viewport.count(), None);
    viewport.show(30, 10);
    assert_eq!(viewport.count().as_deref(), Some("10 / 30"));
    assert!(viewport.scroll(RowMove::Step(5)));
    assert_eq!(viewport.show(30, 10), 5..15);
    assert_eq!(viewport.count().as_deref(), Some("15 / 30"));
}

#[test]
fn a_list_resting_on_its_end_keeps_it_in_view_until_scrolled_back() {
    let mut log = Viewport::at_end();
    assert_eq!(log.show(3, 4), 0..3);
    assert_eq!(log.show(10, 4), 6..10, "new lines keep the end in view");
    assert!(log.scroll(RowMove::Step(-1)));
    assert_eq!(log.show(12, 4), 5..9, "scrolled back, it stays put");
    assert!(log.scroll(RowMove::Last));
    assert_eq!(log.show(15, 4), 11..15, "G rests it on the end again");
    assert!(log.scroll(RowMove::First));
    assert!(
        !log.scroll(RowMove::Step(-1)),
        "nothing above the first line"
    );
}
