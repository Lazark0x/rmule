//! The Viewport's thumb, its following and its count.

use super::Viewport;
use crate::table_sort::RowMove;

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
    // (first, shown, total) on a ten-cell track → the thumb's cells.
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
            at(first, shown, total).thumb(10),
            Some(thumb),
            "first {first}, shown {shown}, total {total}"
        );
    }
}

#[test]
fn a_list_that_fits_has_no_thumb_and_a_short_track_still_holds_one() {
    assert_eq!(at(0, 10, 10).thumb(10), None);
    assert_eq!(at(0, 3, 1_000).thumb(1), Some(0..1));
    assert_eq!(at(997, 3, 1_000).thumb(2), Some(1..2));
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
