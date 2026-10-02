//! Unit tests for the de-truncation primitives: text wrapping, greedy column widths and header floors.

use super::*;

#[test]
fn short_text_stays_on_one_line_and_keeps_every_character() {
    assert_eq!(wrap_text("", 10), vec![""]);
    assert_eq!(wrap_text("bunny.avi", 10), vec!["bunny.avi"]);
    assert_eq!(wrap_text("exactlyten", 10), vec!["exactlyten"]);
}

#[test]
fn overlong_words_hard_break_and_lose_nothing() {
    let name = "A".repeat(25);
    let lines = wrap_text(&name, 10);
    assert_eq!(lines, vec!["A".repeat(10), "A".repeat(10), "A".repeat(5)]);
    assert_eq!(lines.concat(), name, "hard break drops no characters");
}

#[test]
fn wrapping_prefers_a_space_and_consumes_it_as_the_break() {
    // "peer 10.0.0.1 queued rank 3" at 13 breaks after the endpoint, and
    // the break space is not re-emitted at the head of the next line.
    assert_eq!(
        wrap_text("peer 10.0.0.1 queued rank 3", 13),
        vec!["peer 10.0.0.1", "queued rank 3"]
    );
}

/// A table with one-cell headers, so only the floors speak.
fn floors_only<'a>(floors: &'a [usize], flex: usize) -> TableColumns<'a> {
    TableColumns {
        floors,
        headers: &[],
        flex,
        wants: &[],
        give_way: &[],
    }
}

#[test]
fn the_greedy_column_absorbs_whatever_the_others_leave() {
    // 74 columns, four fixed (7+10+9+12 = 38), one gap column between the
    // five: the name column's declared 12 grows to the remaining 32.
    let widths = greedy_widths(74, &floors_only(&[12, 7, 10, 9, 12], 0), 1);
    assert_eq!(widths, vec![32, 7, 10, 9, 12]);
    assert_eq!(
        widths.iter().sum::<usize>() + 4,
        74,
        "the row fills the pane exactly"
    );
}

#[test]
fn a_pane_too_narrow_for_the_declared_set_shrinks_every_column() {
    let widths = greedy_widths(20, &floors_only(&[12, 7, 10, 9, 12], 0), 1);
    assert!(widths.iter().all(|width| *width >= 1), "no column vanishes");
    assert!(widths[0] > 1, "the name column keeps a usable share");
    assert!(widths.iter().sum::<usize>() + 4 <= 20, "the row still fits");
}

/// The Shared Files table's column floors: File · State · Size ·
/// Uploading · Requests · Accepted · Transferred.
const SHARED_FLOORS: [usize; 7] = [12, 14, 9, 10, 15, 15, 19];
const SHARED_HEADERS: [usize; 7] = [4, 5, 4, 9, 8, 8, 11];
const SHARED_GIVE_WAY: [usize; 6] = [5, 4, 6, 3, 2, 1];

fn shared() -> TableColumns<'static> {
    TableColumns {
        floors: &SHARED_FLOORS,
        headers: &SHARED_HEADERS,
        flex: 0,
        wants: &[],
        give_way: &SHARED_GIVE_WAY,
    }
}

#[test]
fn a_shrinking_column_stops_at_its_header_at_every_width_that_holds_the_headers() {
    // Headers 49 + six gaps: from 55 up nothing gives way and nothing
    // shrinks below its header — `Uploading` never becomes `Uploadin`/`g`.
    for total in 55usize..=120 {
        let widths = greedy_widths(total, &shared(), 1);
        let used = widths.iter().sum::<usize>() + 6;
        assert_eq!(used, total, "the row fills the pane at {total}");
        for (width, header) in widths.iter().zip(SHARED_HEADERS) {
            assert!(*width >= header, "{widths:?} splits a header at {total}");
        }
    }
}

#[test]
fn below_the_headers_columns_give_way_in_the_stated_order_and_say_so() {
    // 54 is one short of the headers: Accepted, first in the order, goes.
    let widths = greedy_widths(54, &shared(), 1);
    assert_eq!(widths[5], 0, "{widths:?}");
    assert!(
        widths
            .iter()
            .enumerate()
            .all(|(index, width)| index == 5 || *width >= SHARED_HEADERS[index])
    );
    // Narrower still: Requests next, then Transferred.
    let widths = greedy_widths(38, &shared(), 1);
    assert_eq!(
        widths.iter().map(|width| *width == 0).collect::<Vec<_>>(),
        [false, false, false, false, true, true, true]
    );
    let labels = [
        "File",
        "State",
        "Size",
        "Uploading",
        "Requests",
        "Accepted",
        "Transferred",
    ];
    let hidden = gave_way(labels, &widths);
    assert_eq!(hidden, ["Requests", "Accepted", "Transferred"]);
    assert!(gave_way(labels, &greedy_widths(80, &shared(), 1)).is_empty());
}

#[test]
fn the_gave_way_note_names_the_columns_or_counts_them_but_is_never_cut() {
    let hidden = ["Requests", "Accepted", "Transferred"];
    assert_eq!(
        gave_way_note(&hidden, 60).as_deref(),
        Some(" too narrow to show: Requests, Accepted, Transferred ")
    );
    assert_eq!(
        gave_way_note(&hidden, 30).as_deref(),
        Some(" 3 columns not shown ")
    );
    assert_eq!(gave_way_note(&hidden, 12).as_deref(), Some(" 3 hidden "));
    assert_eq!(
        gave_way_note(&["Type"], 20).as_deref(),
        Some(" 1 column not shown ")
    );
    assert_eq!(gave_way_note(&[], 60), None);
}

#[test]
fn a_column_that_gave_way_draws_nothing_but_keeps_its_gap() {
    let columns = [
        Column::left("name", Style::new()),
        Column::right("7", Style::new()),
        Column::right("42", Style::new()),
    ];
    let lines = column_lines(&columns, &[6, 0, 3], 1, &Span::raw("  "));
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].to_string(), "  name     42");
}

#[test]
fn a_wrapped_row_grows_down_with_a_gutter_only_on_its_first_line() {
    let columns = [
        Column::left("a-very-long-file-name.iso", Style::new()),
        Column::right("42", Style::new()),
    ];
    let lines = column_lines(&columns, &[10, 4], 1, &Span::raw("▸ "));
    assert_eq!(lines.len(), 3, "the name wraps to three lines");
    let text: Vec<String> = lines.iter().map(ToString::to_string).collect();
    assert_eq!(text[0], "▸ a-very-lon   42");
    assert_eq!(text[1], "  g-file-nam     ");
    assert_eq!(text[2], "  e.iso          ");
}

#[test]
fn a_greedy_row_never_asks_for_more_columns_than_it_has() {
    // The downloads table's declared set, swept across every plausible
    // pane width: the row must always fit, and no column may vanish.
    let declared = [11, 10, 4, 10, 10, 6, 5, 11];
    // 8 columns + 7 gaps = 15 is the physical floor for this row.
    for total in 15usize..=200 {
        let widths = greedy_widths(total, &floors_only(&declared, 0), 1);
        let used = widths.iter().sum::<usize>() + widths.len() - 1;
        assert!(used <= total, "row overflows at total {total}: {used}");
        assert!(
            widths.iter().all(|width| *width >= 1),
            "column vanished at {total}"
        );
    }
}

#[test]
fn bounded_columns_are_served_before_the_greedy_one() {
    // Peer · Software · Speed · File: 74 cells, three gaps. The floors hold
    // 46; the 25 cells left go first to the columns that want more — Peer to
    // its 15, Speed to 11 — and File takes what remains.
    let table = TableColumns {
        floors: &[12, 12, 10, 12],
        headers: &[],
        flex: 3,
        wants: &[15, 12, 11, 0],
        give_way: &[1, 2, 0],
    };
    assert_eq!(greedy_widths(74, &table, 1), vec![15, 12, 11, 33]);
    // Slack for one want only: the column that gives way last is served first.
    assert_eq!(greedy_widths(52, &table, 1), vec![15, 12, 10, 12]);
}
