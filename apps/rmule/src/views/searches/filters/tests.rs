//! Unit tests for the search-options editor and its summary line.

use crate::action::Action;
use crate::state::SearchStatus;
use ratatui::crossterm::event::KeyCode;
use rmule_core::{CoreCommand, SearchCommand};
use std::time::Instant;

use rmule_primitives::Ed2kText;

use crate::golden::assert_golden;

use super::*;
use crate::fixture::*;

#[test]
fn the_options_editor_opens_on_o_and_esc_keeps_what_was_typed() {
    let (mut view, state) = view_with_filters(&[
        KeyCode::Tab, // → Min size
        KeyCode::Char('7'),
        KeyCode::Char('0'),
        KeyCode::Char('0'),
        KeyCode::Char(' '),
        KeyCode::Char('M'),
        KeyCode::Char('B'),
    ]);
    assert_eq!(view.filters.form.focus, Filters::MIN_SIZE);
    assert_eq!(view.filters.text(Filters::MIN_SIZE), "700 MB");
    view.handle_key(press(KeyCode::Esc), &state);
    assert!(!view.filters_open, "Esc closes the editor");
    assert_eq!(
        view.filters.text(Filters::MIN_SIZE),
        "700 MB",
        "the typing survives"
    );
}

/// Every constraint the operator set reaches the `KeywordQuery` the command
/// carries — the front half of the end-to-end search-options path.
#[test]
fn the_typed_filters_reach_the_start_search_query() {
    let (mut view, state) = view_with_filters(&[
        KeyCode::Right, // Type: Any → Audio
        KeyCode::Right, // → Video
        KeyCode::Tab,   // → Min size
        KeyCode::Char('7'),
        KeyCode::Char('0'),
        KeyCode::Char('0'),
        KeyCode::Char('M'),
        KeyCode::Char('B'),
        KeyCode::Tab, // → Max size
        KeyCode::Char('2'),
        KeyCode::Char('G'),
        KeyCode::Char('B'),
        KeyCode::Tab, // → Min sources
        KeyCode::Char('1'),
        KeyCode::Char('0'),
        KeyCode::Tab, // → Extension
        KeyCode::Char('.'),
        KeyCode::Char('a'),
        KeyCode::Char('v'),
        KeyCode::Char('i'),
        KeyCode::Esc,
    ]);
    view.handle_key(press(KeyCode::Char('/')), &state);
    for c in "bunny".chars() {
        view.handle_key(press(KeyCode::Char(c)), &state);
    }
    match view.handle_key(press(KeyCode::Enter), &state) {
        ViewOutcome::Emit(Action::Command(CoreCommand::Search(SearchCommand::StartSearch {
            query: rmule_primitives::SearchQuery::Keywords(query),
            ..
        }))) => {
            assert_eq!(query.phrase().to_display_string(), "bunny");
            assert_eq!(query.file_type(), Some(Ed2kFileClass::Video));
            assert_eq!(query.min_size(), Some(700 * 1024 * 1024));
            assert_eq!(query.max_size(), Some(2 * 1024 * 1024 * 1024));
            assert_eq!(query.min_availability(), Some(10));
            assert_eq!(
                query
                    .extension()
                    .map(Ed2kText::to_display_string)
                    .as_deref(),
                Some("avi"),
                "the leading dot people type is not part of FT_FILEFORMAT"
            );
        }
        other => panic!("expected a constrained StartSearch, got {other:?}"),
    }
}

/// `Enter` inside the editor is aMule's extension-field `Enter`: it applies
/// and runs the search.
#[test]
fn enter_in_the_editor_applies_and_searches() {
    let state = session_state();
    let mut view = SearchesView::new();
    view.handle_key(press(KeyCode::Char('/')), &state);
    for c in "bunny".chars() {
        view.handle_key(press(KeyCode::Char(c)), &state);
    }
    view.handle_key(press(KeyCode::Esc), &state);
    view.handle_key(press(KeyCode::Char('o')), &state);
    view.handle_key(press(KeyCode::Right), &state); // Type → Audio
    match view.handle_key(press(KeyCode::Enter), &state) {
        ViewOutcome::Emit(Action::Command(CoreCommand::Search(SearchCommand::StartSearch {
            query: rmule_primitives::SearchQuery::Keywords(query),
            ..
        }))) => assert_eq!(query.file_type(), Some(Ed2kFileClass::Audio)),
        other => panic!("expected StartSearch, got {other:?}"),
    }
    assert!(!view.filters_open, "a committed editor closes");
}

/// A rejection keeps the editor up with the entry intact (the Networks form
/// rule) instead of searching on a bound it could not read.
#[test]
fn an_unreadable_bound_is_refused_in_the_editor() {
    let (view, _) = view_with_filters(&[
        KeyCode::Tab,
        KeyCode::Char('7'),
        KeyCode::Char('0'),
        KeyCode::Char('0'),
        KeyCode::Char('X'),
        KeyCode::Enter,
    ]);
    assert_eq!(view.filters.form.focus, Filters::MIN_SIZE, "still open");
    assert!(
        view.filters
            .form
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("size unit"),
        "got {:?}",
        view.filters.form.error
    );
    assert_eq!(
        view.filters.text(Filters::MIN_SIZE),
        "700X",
        "the entry survives"
    );
}

/// aMule warns and drops the max bound; rmule refuses, because a dropped
/// bound is a different search than the one asked for.
#[test]
fn a_max_below_the_min_is_refused_rather_than_dropped() {
    let (view, _) = view_with_filters(&[
        KeyCode::Tab,
        KeyCode::Char('2'),
        KeyCode::Char('G'),
        KeyCode::Char('B'),
        KeyCode::Tab,
        KeyCode::Char('1'),
        KeyCode::Char('M'),
        KeyCode::Char('B'),
        KeyCode::Enter,
    ]);
    assert!(view.filters_open, "the editor stays up");
    assert_eq!(
        view.filters.form.error.as_deref(),
        Some("max size must not be below min size")
    );
}

/// An empty options row leaves the query exactly as it was — the
/// byte-identical guarantee, seen from the front end.
#[test]
fn untouched_options_add_no_constraints() {
    let state = session_state();
    let mut view = SearchesView::new();
    view.handle_key(press(KeyCode::Char('/')), &state);
    for c in "bunny".chars() {
        view.handle_key(press(KeyCode::Char(c)), &state);
    }
    match view.handle_key(press(KeyCode::Enter), &state) {
        ViewOutcome::Emit(Action::Command(CoreCommand::Search(SearchCommand::StartSearch {
            query: rmule_primitives::SearchQuery::Keywords(query),
            ..
        }))) => assert_eq!(
            query,
            KeywordQuery::new(Ed2kText::from_utf8("bunny")).unwrap()
        ),
        other => panic!("expected StartSearch, got {other:?}"),
    }
}

/// The selector is a ring with "Any" at its head, exactly where aMule's
/// dropdown puts it — so ← from Any is the *last* class, and → past the
/// last class is Any again rather than a constraint nobody chose.
#[test]
fn the_type_selector_cycles_through_any_and_all_seven_classes() {
    let mut filters = Filters::default();
    assert_eq!(filters.class(), None, "Any leads");
    let mut seen = Vec::new();
    for _ in 0..Ed2kFileClass::ALL.len() {
        filters.form.step_choice(true);
        seen.push(filters.class().expect("a class"));
    }
    assert_eq!(seen, Ed2kFileClass::ALL.to_vec());
    filters.form.step_choice(true);
    assert_eq!(filters.class(), None, "past the last class is Any");
    filters.form.step_choice(false);
    assert_eq!(filters.class(), Some(Ed2kFileClass::CdImage));
}

#[test]
fn size_bounds_parse_on_amules_binary_multipliers() {
    assert_eq!(parse_size(""), Ok(None));
    assert_eq!(
        parse_size("0"),
        Ok(None),
        "aMule reads a zero spin as absent"
    );
    assert_eq!(parse_size("512"), Ok(Some(512)), "a bare number is bytes");
    assert_eq!(parse_size("2KB"), Ok(Some(2048)));
    assert_eq!(parse_size("700 MB"), Ok(Some(700 * 1024 * 1024)));
    assert_eq!(parse_size("1.5 gb"), Ok(Some(1024 * 1024 * 1024 * 3 / 2)));
    // The unit past aMule's dropdown, and the one that needs a 0x08 term.
    assert_eq!(parse_size("5 TB"), Ok(Some(5 * 1024_u64.pow(4))));
    assert!(parse_size("5 TB").unwrap().unwrap() > u64::from(u32::MAX));
    assert!(parse_size("700X").is_err());
    assert!(parse_size("big").is_err());
}

#[test]
fn the_summary_row_names_only_the_constraints_that_are_set() {
    let mut filters = Filters::default();
    assert_eq!(filters.summary(), "none");
    // Driven the way an operator does, through the same key routing the
    // editor uses: two steps of the type ring, then two typed fields.
    let press_into = |filters: &mut Filters, code| {
        filters.form.handle_key(press(code));
    };
    press_into(&mut filters, KeyCode::Right); // Any → Audio
    press_into(&mut filters, KeyCode::Right); // → Videos
    press_into(&mut filters, KeyCode::Tab);
    for code in "700 MB".chars().map(KeyCode::Char) {
        press_into(&mut filters, code);
    }
    filters.form.focus = Filters::EXTENSION;
    for code in ".avi".chars().map(KeyCode::Char) {
        press_into(&mut filters, code);
    }
    assert_eq!(filters.summary(), "Videos · ≥700 MB · .avi");
}

#[test]
fn golden_searches_options_editor() {
    let state = UiState::default();
    let theme = Theme::default_dark();
    let mut view = SearchesView::new();
    view.handle_key(press(KeyCode::Char('/')), &state);
    for c in "big buck bunny".chars() {
        view.handle_key(press(KeyCode::Char(c)), &state);
    }
    view.handle_key(press(KeyCode::Esc), &state);
    view.handle_key(press(KeyCode::Char('o')), &state);
    view.handle_key(press(KeyCode::Right), &state); // Type → Audio
    view.handle_key(press(KeyCode::Right), &state); // → Video
    view.handle_key(press(KeyCode::Tab), &state);
    for c in "700 MB".chars() {
        view.handle_key(press(KeyCode::Char(c)), &state);
    }
    assert_golden("searches_options_editor", 78, 21, |frame| {
        view.draw(frame, frame.area(), &state, &theme, Instant::now());
    });
}

/// The collapsed row: a compact statement of the active constraints, over
/// the results table it narrowed.
#[test]
fn golden_searches_options_summary() {
    let state = state_with(three_tier_results(), SearchStatus::Completed { total: 3 });
    let theme = Theme::default_dark();
    let mut view = SearchesView::new().having_sent("ubuntu");
    view.handle_key(press(KeyCode::Char('o')), &state);
    view.handle_key(press(KeyCode::Right), &state); // Type → Audio
    view.handle_key(press(KeyCode::Tab), &state);
    for c in "4 MB".chars() {
        view.handle_key(press(KeyCode::Char(c)), &state);
    }
    view.handle_key(press(KeyCode::Tab), &state);
    view.handle_key(press(KeyCode::Tab), &state);
    for c in "25".chars() {
        view.handle_key(press(KeyCode::Char(c)), &state);
    }
    view.handle_key(press(KeyCode::Tab), &state);
    for c in "mp3".chars() {
        view.handle_key(press(KeyCode::Char(c)), &state);
    }
    view.handle_key(press(KeyCode::Esc), &state);
    assert_golden("searches_options_summary", 78, 21, |frame| {
        view.draw(frame, frame.area(), &state, &theme, Instant::now());
    });
}
