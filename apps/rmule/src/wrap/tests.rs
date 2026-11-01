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
fn wide_glyphs_measure_and_break_in_cells() {
    assert_eq!(display_width("ペガサス"), 8);
    assert_eq!(
        display_width("e\u{301}"),
        1,
        "a combining mark takes no cell"
    );
    assert_eq!(wrap_text("ペガサス幻想", 8), vec!["ペガサス", "幻想"]);
    assert_eq!(
        wrap_text("ペガ", 1),
        vec!["ペ", "ガ"],
        "a glyph wider than the column"
    );
    assert_eq!(first_cells("ペガサス", 5), "ペガ");
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
