//! Unit tests for the form machine: field editing, validation, notes and its width contract.

use super::*;
use crate::fixture::press;

fn form() -> Form {
    Form::new(vec![
        Field::display("Minted", "0a1b"),
        Field::text("Name", "rmule"),
        Field::choice("Theme", vec!["auto", "dark", "light"], 0),
    ])
}

#[test]
fn focus_starts_and_stays_off_display_rows() {
    let mut form = form();
    assert_eq!(form.focus, 1, "the display row is not a resting spot");
    form.step_focus(true);
    assert_eq!(form.focus, 2);
    form.step_focus(true);
    assert_eq!(form.focus, 1, "wrapping skips it too");
    form.step_focus(false);
    assert_eq!(form.focus, 2);
    // …and neither jump can land on one either, whichever end it comes at.
    form.focus_first();
    assert_eq!(form.focus, 1);
    form.focus_last();
    assert_eq!(form.focus, 2);
}

#[test]
fn typing_lands_in_text_fields_and_never_in_a_selector() {
    let mut form = form();
    assert_eq!(
        form.handle_key(press(KeyCode::Char('!'))),
        FormKey::Consumed
    );
    assert_eq!(form.text(1), "rmule!");
    form.handle_key(press(KeyCode::Backspace));
    assert_eq!(form.text(1), "rmule");

    form.step_focus(true);
    form.handle_key(press(KeyCode::Char('x')));
    assert_eq!(form.choice(2), 0, "a selector is stepped, never typed into");
    assert_eq!(form.handle_key(press(KeyCode::Right)), FormKey::Consumed);
    assert_eq!(form.choice(2), 1);
    form.handle_key(press(KeyCode::Left));
    form.handle_key(press(KeyCode::Left));
    assert_eq!(form.choice(2), 2, "stepping wraps");
    form.handle_key(press(KeyCode::Backspace));
    assert_eq!(form.choice(2), 0, "backspace is the selector's clear");
}

/// `←`/`→` and space step a selector and edit a text field.
#[test]
fn a_text_field_takes_the_arrows_a_selector_steps_with() {
    let mut form = form();
    assert_eq!(form.handle_key(press(KeyCode::Left)), FormKey::Consumed);
    assert_eq!(
        form.handle_key(press(KeyCode::Char(' '))),
        FormKey::Consumed
    );
    assert_eq!(form.fields[1].value().0, "rmul e");
}

#[test]
fn a_one_field_edit_stays_on_its_field() {
    let mut form = form();
    for code in [KeyCode::Tab, KeyCode::BackTab, KeyCode::Up, KeyCode::Down] {
        assert_eq!(form.field_key(press(code)), FormKey::Ignored);
        assert_eq!(form.focus, 1, "{code:?} left the field");
    }
    assert_eq!(form.text(1), "rmule");
}

#[test]
fn a_directory_field_completes_on_tab_and_says_what_is_left() {
    let root = tempfile::tempdir().expect("a directory");
    std::fs::create_dir(root.path().join("anime-new")).expect("a directory");
    std::fs::create_dir(root.path().join("anime-old")).expect("a directory");
    let typed = format!("{}{}a", root.path().display(), std::path::MAIN_SEPARATOR);
    let mut form = Form::new(vec![Field::directory("Dir", typed)]);
    assert_eq!(form.handle_key(press(KeyCode::Tab)), FormKey::Consumed);
    assert_eq!(form.focus, 0, "Tab completes, it does not move");
    assert!(form.text(0).ends_with("anime-"), "{}", form.text(0));
    let note = form.note.as_deref().expect("the choices are said");
    assert!(note.contains("anime-old"), "{note}");
    form.handle_key(press(KeyCode::Char('o')));
    assert_eq!(form.note, None, "the next key clears it");
}

#[test]
fn a_placeholder_is_not_typed_text_and_the_caret_stands_before_it() {
    let form = Form::new(vec![Field::text("Size", "").with_placeholder("any")]);
    let rendered = form.render(40, &Theme::default_dark(), true);
    assert_eq!(rendered.caret, Some((0, 6)), "at the start of the value");
    assert!(rendered.lines[0].to_string().contains("any"));
}

#[test]
fn commit_and_cancel_are_reported_not_acted_on() {
    let mut form = form();
    assert_eq!(form.handle_key(press(KeyCode::Enter)), FormKey::Commit);
    assert_eq!(form.handle_key(press(KeyCode::Esc)), FormKey::Cancel);
    assert_eq!(form.text(1), "rmule", "neither key touched the entry");
}

/// The de-truncation rule holds for a form too: no rendered line
/// may exceed the width it was given, at any width, with or without the
/// caret and note that ride the value's last line.
#[test]
fn no_rendered_line_ever_exceeds_the_width_it_was_given() {
    let theme = Theme::default_dark();
    let mut form = Form::new(vec![
        Field::text(
            "Download dir",
            "/home/somebody/a/rather/long/downloads/path",
        )
        .with_note("(on restart)"),
        Field::choice("Theme", vec!["auto", "dark"], 0)
            .with_note("auto = RMULE_THEME / COLORTERM")
            .in_section("Appearance"),
        Field::display("User hash", "2a".repeat(16)),
    ]);
    form.error = Some(crate::words::Sentence::for_test(
        "a rejection long enough to need wrapping of its own",
    ));
    for width in form.min_width()..=120 {
        for caret in [false, true] {
            for line in form.render(width, &theme, caret).lines {
                assert!(
                    line.width() <= width,
                    "line {:?} is {} wide at width {width}",
                    line.to_string(),
                    line.width()
                );
            }
        }
    }
}

#[test]
fn the_render_reports_where_the_focused_field_landed() {
    let mut form = form();
    form.error = Some(crate::words::Sentence::for_test("nope"));
    let rendered = form.render(40, &Theme::default_dark(), true);
    let text: Vec<String> = rendered.lines.iter().map(ToString::to_string).collect();
    let focused = &text[rendered.focus.clone()];
    assert_eq!(focused.len(), 1);
    assert!(focused[0].starts_with(" Name "), "{focused:?}");
    assert_eq!(rendered.caret, Some((rendered.focus.start, 8 + 5)));
    assert!(text.last().unwrap().contains("nope"), "{text:?}");
}
