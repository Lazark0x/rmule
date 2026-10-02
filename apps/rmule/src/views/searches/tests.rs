//! Unit tests for the Searches view: the query input, the method selector and options row, the Held Search strip, and their goldens.

use crate::golden::assert_golden;

use super::*;
use crate::fixture::*;
use crate::state::SearchStatus;

#[test]
fn slash_focuses_the_input_and_esc_returns_to_the_results() {
    let state = UiState::default();
    let mut view = SearchesView::new();
    assert!(!view.input_focused);
    assert!(matches!(
        view.handle_key(press(KeyCode::Char('/')), &state),
        ViewOutcome::Redraw
    ));
    assert!(view.input_focused);
    assert!(matches!(
        view.handle_key(press(KeyCode::Esc), &state),
        ViewOutcome::Redraw
    ));
    assert!(!view.input_focused);
}

#[test]
fn tab_cycles_focus_between_results_and_input_and_shift_tab_agrees() {
    // Two panes only: Tab and Shift-Tab both cross the boundary, the same
    // convention as Shared Files.
    let state = UiState::default();
    let mut view = SearchesView::new();
    assert!(!view.input_focused);

    assert!(matches!(
        view.handle_key(press(KeyCode::Tab), &state),
        ViewOutcome::Redraw
    ));
    assert!(view.input_focused, "Tab from results focuses the input");

    assert!(matches!(
        view.handle_key(press(KeyCode::Tab), &state),
        ViewOutcome::Redraw
    ));
    assert!(!view.input_focused, "Tab from the input returns to results");

    assert!(matches!(
        view.handle_key(press(KeyCode::BackTab), &state),
        ViewOutcome::Redraw
    ));
    assert!(
        view.input_focused,
        "Shift-Tab from results focuses the input too"
    );

    assert!(matches!(
        view.handle_key(press(KeyCode::BackTab), &state),
        ViewOutcome::Redraw
    ));
    assert!(
        !view.input_focused,
        "Shift-Tab from the input returns to results too"
    );
}

#[test]
fn tab_leaves_the_input_without_being_typed() {
    let state = UiState::default();
    let mut view = SearchesView::new();
    view.handle_key(press(KeyCode::Char('/')), &state);
    for c in "eels".chars() {
        view.handle_key(press(KeyCode::Char(c)), &state);
    }
    view.handle_key(press(KeyCode::Tab), &state);
    assert!(!view.input_focused);
    // The query is untouched — Tab left the field, it did not edit it.
    assert_eq!(view.query, "eels");
}

#[test]
fn a_focused_input_captures_printables_including_binding_letters() {
    let state = UiState::default();
    let mut view = SearchesView::new();
    view.handle_key(press(KeyCode::Char('/')), &state);
    // h/l/q/j/1 are bindings when unfocused but plain text here.
    for c in "h l q j 1".chars().filter(|c| *c != ' ') {
        assert!(matches!(
            view.handle_key(press(KeyCode::Char(c)), &state),
            ViewOutcome::Redraw
        ));
    }
    assert_eq!(view.query, "hlqj1");
    // Backspace edits the buffer.
    assert!(matches!(
        view.handle_key(press(KeyCode::Backspace), &state),
        ViewOutcome::Redraw
    ));
    assert_eq!(view.query, "hlqj");
}

#[test]
fn enter_without_a_session_degrades_to_a_flash_and_keeps_the_typed_query() {
    let state = UiState::default();
    let mut view = SearchesView::new();
    view.handle_key(press(KeyCode::Char('/')), &state);
    for c in "big buck bunny".chars() {
        view.handle_key(press(KeyCode::Char(c)), &state);
    }
    match view.handle_key(press(KeyCode::Enter), &state) {
        ViewOutcome::Emit(Action::Flash(text)) => {
            assert!(
                text.contains("no credentials"),
                "degrade names what is missing: {text}"
            );
        }
        _ => panic!("expected a degrade flash"),
    }
    // The query survives the degrade, and focus is kept for editing.
    assert_eq!(view.query, "big buck bunny");
    assert!(view.input_focused);
}

#[test]
fn a_search_needs_no_server() {
    // No server configured and none connected — a Kad-only operator.
    // The search is sent; core sends its Kad leg and holds the server leg.
    let mut state = session_state();
    state.session.as_mut().expect("session").server = None;

    let mut view = SearchesView::new();
    view.handle_key(press(KeyCode::Char('/')), &state);
    for c in "bunny".chars() {
        view.handle_key(press(KeyCode::Char(c)), &state);
    }
    match view.handle_key(press(KeyCode::Enter), &state) {
        ViewOutcome::Emit(Action::Command(CoreCommand::Search(SearchCommand::StartSearch {
            ..
        }))) => {}
        other => panic!("expected StartSearch, got {other:?}"),
    }
}

/// With no server configured or connected, a result still downloads —
/// with no source hint; core finds its sources over Kad.
#[test]
fn a_download_needs_no_server() {
    let mut state = state_with(three_tier_results(), SearchStatus::Completed { total: 3 });
    state.session = session_state().session;
    state.session.as_mut().expect("session").server = None;
    state.connected_server = None;
    let mut view = SearchesView::new();
    view.handle_key(press(KeyCode::Char('g')), &state);
    view.handle_key(press(KeyCode::Char('m')), &state);
    match view.handle_key(press(KeyCode::Enter), &state) {
        ViewOutcome::Emit(Action::Command(CoreCommand::Download(
            rmule_core::DownloadCommand::StartDownload { source_hint, .. },
        ))) => assert_eq!(source_hint, None),
        other => panic!("expected StartDownload, got {other:?}"),
    }
}

#[test]
fn enter_with_a_session_emits_the_real_start_search() {
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
        }))) => {
            assert_eq!(query.phrase().to_display_string(), "bunny");
        }
        other => panic!("expected StartSearch, got {other:?}"),
    }
}

#[test]
fn unfocused_binding_keys_bubble_to_the_globals() {
    let state = UiState::default();
    let mut view = SearchesView::new();
    // With no input focused and no results, h/l/1/q are the app's, not the
    // view's — the view must ignore them so the globals fire.
    for code in [
        KeyCode::Char('h'),
        KeyCode::Char('l'),
        KeyCode::Char('1'),
        KeyCode::Char('q'),
    ] {
        assert!(matches!(
            view.handle_key(press(code), &state),
            ViewOutcome::Ignored
        ));
    }
}

#[test]
fn golden_searches_empty() {
    let state = UiState::default();
    let theme = Theme::default_dark();
    let mut view = SearchesView::new();
    assert_golden("searches_empty", 78, 21, |frame| {
        view.draw(frame, frame.area(), &state, &theme, Instant::now());
    });
}

#[test]
fn clicks_focus_the_input_or_select_a_result_row() {
    let state = state_with(three_tier_results(), SearchStatus::Completed { total: 3 });
    let mut view = SearchesView::new();
    draw_golden(&mut view, &state);
    // Input block occupies the top rows; clicking it focuses the query.
    assert!(matches!(
        view.handle_click(4, 1, &state),
        ViewOutcome::Redraw
    ));
    assert!(view.input_focused);
    // Results table: block starts under the input; header +1; row 1 next.
    let rows = crate::views::table_rows(view.results_area);
    assert!(matches!(
        view.handle_click(4, rows.y + 1, &state),
        ViewOutcome::Redraw
    ));
    assert!(!view.input_focused, "a result click unfocuses the input");
    // Second row in name order: clip_low, distro_hot, song_mid.
    assert_eq!(
        view.selected_result(&state)
            .map(|result| result.primary_name().to_display_string()),
        Some("distro_hot.iso".to_string())
    );
}
