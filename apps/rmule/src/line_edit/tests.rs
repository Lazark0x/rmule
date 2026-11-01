//! The line editor at its keys and at its cells.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::style::Style;

use super::*;

fn chord(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
    KeyEvent::new(code, modifiers)
}

fn ctrl(letter: char) -> KeyEvent {
    chord(KeyCode::Char(letter), KeyModifiers::CONTROL)
}

fn alt(letter: char) -> KeyEvent {
    chord(KeyCode::Char(letter), KeyModifiers::ALT)
}

fn plain(code: KeyCode) -> KeyEvent {
    chord(code, KeyModifiers::NONE)
}

fn typed(edit: &mut LineEdit, text: &str) {
    for c in text.chars() {
        edit.key(&plain(KeyCode::Char(c)));
    }
}

/// The line as a test reads it: the caret a `|`.
fn at_caret(edit: &LineEdit) -> String {
    let (head, tail) = edit.text().split_at(edit.caret);
    format!("{head}|{tail}")
}

/// The field's cells with the caret's column.
fn shown(edit: &LineEdit, width: usize) -> (String, u16) {
    let shown = edit.show(width, Style::new(), Style::new());
    let cells: String = shown.spans.iter().map(|s| s.content.as_ref()).collect();
    (cells, shown.caret)
}

#[test]
fn typing_lands_at_the_caret_not_at_the_end() {
    let mut edit = LineEdit::new("/home/op/dwnload");
    for _ in 0..6 {
        edit.key(&plain(KeyCode::Left));
    }
    typed(&mut edit, "o");
    assert_eq!(at_caret(&edit), "/home/op/do|wnload");
}

#[test]
fn readline_keys_edit_the_line() {
    let mut edit = LineEdit::new("big buck bunny");
    edit.key(&ctrl('a'));
    assert_eq!(at_caret(&edit), "|big buck bunny");
    edit.key(&ctrl('f'));
    edit.key(&ctrl('d'));
    assert_eq!(at_caret(&edit), "b|g buck bunny");
    edit.key(&ctrl('k'));
    assert_eq!(at_caret(&edit), "b|");
    edit.key(&ctrl('y'));
    assert_eq!(at_caret(&edit), "bg buck bunny|");
    edit.key(&ctrl('w'));
    assert_eq!(at_caret(&edit), "bg buck |");
    edit.key(&ctrl('u'));
    assert_eq!(at_caret(&edit), "|");
    edit.key(&ctrl('y'));
    assert_eq!(at_caret(&edit), "bg buck |", "a cut stays until the next");
    edit.key(&ctrl('e'));
    edit.key(&ctrl('h'));
    assert_eq!(at_caret(&edit), "bg buck|");
}

#[test]
fn word_moves_stop_at_every_word_of_a_path() {
    let mut edit = LineEdit::new("/srv/my-films/old");
    edit.key(&alt('b'));
    assert_eq!(at_caret(&edit), "/srv/my-films/|old");
    edit.key(&chord(KeyCode::Left, KeyModifiers::CONTROL));
    assert_eq!(at_caret(&edit), "/srv/my-|films/old");
    edit.key(&chord(KeyCode::Backspace, KeyModifiers::ALT));
    assert_eq!(at_caret(&edit), "/srv/|films/old");
    edit.key(&alt('f'));
    assert_eq!(at_caret(&edit), "/srv/films|/old");
    edit.key(&alt('d'));
    assert_eq!(at_caret(&edit), "/srv/films|");
}

#[test]
fn ctrl_w_takes_the_whole_path_back_to_a_space() {
    let mut edit = LineEdit::new("vlc --fullscreen  /tmp/x  ");
    edit.key(&ctrl('w'));
    assert_eq!(at_caret(&edit), "vlc --fullscreen  |");
}

#[test]
fn the_caret_moves_by_what_a_reader_calls_a_character() {
    let mut edit = LineEdit::new("cafe\u{301}日本");
    edit.key(&plain(KeyCode::Left));
    edit.key(&plain(KeyCode::Left));
    edit.key(&plain(KeyCode::Left));
    assert_eq!(
        at_caret(&edit),
        "caf|e\u{301}日本",
        "the accent goes with its e"
    );
    edit.key(&plain(KeyCode::Delete));
    assert_eq!(at_caret(&edit), "caf|日本");
}

#[test]
fn a_paste_lands_at_the_caret_on_one_line() {
    let mut edit = LineEdit::new("ab");
    edit.key(&plain(KeyCode::Left));
    edit.paste("x\ny");
    assert_eq!(at_caret(&edit), "ax y|b");
}

#[test]
fn altgr_is_text_and_an_unbound_chord_is_not() {
    let mut edit = LineEdit::new("");
    let alt_gr = chord(
        KeyCode::Char('@'),
        KeyModifiers::CONTROL | KeyModifiers::ALT,
    );
    assert!(LineEdit::claims(&alt_gr));
    edit.key(&alt_gr);
    assert_eq!(edit.text(), "@");
    assert!(LineEdit::claims(&ctrl('w')));
    assert!(LineEdit::claims(&alt('b')));
    assert!(!LineEdit::claims(&ctrl('p')));
    assert!(!LineEdit::claims(&alt('q')));
    assert!(!LineEdit::claims(&plain(KeyCode::Enter)));
    assert!(!edit.key(&ctrl('p')));
    assert_eq!(edit.text(), "@");
}

#[test]
fn a_line_that_fits_shows_whole_with_the_caret_in_it() {
    let mut edit = LineEdit::new("rmule");
    edit.key(&plain(KeyCode::Left));
    assert_eq!(shown(&edit, 10), ("rmule".to_string(), 4));
}

#[test]
fn a_long_line_scrolls_around_the_caret_and_marks_the_cut_ends() {
    let mut edit = LineEdit::new("0123456789abcdefghij");
    assert_eq!(
        shown(&edit, 10),
        ("‹cdefghij".to_string(), 9),
        "the end of the line, the caret past it"
    );
    edit.key(&plain(KeyCode::Home));
    assert_eq!(shown(&edit, 10), ("012345678›".to_string(), 0));
    for _ in 0..8 {
        edit.key(&plain(KeyCode::Right));
    }
    assert_eq!(
        shown(&edit, 10),
        ("012345678›".to_string(), 8),
        "the text holds still while the caret stays clear of the mark"
    );
    edit.key(&plain(KeyCode::Right));
    let (cells, caret) = shown(&edit, 10);
    assert_eq!(cells, "‹23456789›");
    assert_eq!(caret, 8);
}

#[test]
fn scrolling_back_keeps_the_caret_off_the_left_mark() {
    let mut edit = LineEdit::new("0123456789abcdefghij");
    let _ = shown(&edit, 10);
    for _ in 0..20 {
        edit.key(&plain(KeyCode::Left));
        let (cells, caret) = shown(&edit, 10);
        assert!(
            caret > 0 || !cells.starts_with('‹'),
            "the caret on the mark at {cells}"
        );
    }
}

#[test]
fn the_field_measures_cells_not_characters() {
    let mut edit = LineEdit::new("日本語のファイル");
    let (cells, caret) = shown(&edit, 8);
    assert_eq!(cells, "‹ァイル");
    assert_eq!(
        display_width(&cells),
        7,
        "and the caret takes the eighth cell"
    );
    assert_eq!(caret, 7);
    edit.key(&plain(KeyCode::Home));
    let (cells, caret) = shown(&edit, 8);
    assert_eq!(cells, "日本語 ›", "half a wide glyph is a blank");
    assert_eq!(caret, 0);
}
