//! Unit tests for the Searches view: the query input, the method selector and options row, the Held Search strip, and their goldens.

use crate::golden::{assert_golden, render_to_lines};

use super::*;
use crate::fixture::*;
use crate::state::{SearchStatus, fold};

fn typed(view: &mut SearchesView, state: &UiState, text: &str) {
    for c in text.chars() {
        view.handle_key(press(KeyCode::Char(c)), state);
    }
}

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
    assert_eq!(view.query.text(), "eels");
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
    assert_eq!(view.query.text(), "hlqj1");
    // Backspace edits the buffer.
    assert!(matches!(
        view.handle_key(press(KeyCode::Backspace), &state),
        ViewOutcome::Redraw
    ));
    assert_eq!(view.query.text(), "hlqj");
}

/// The keys of the first search: `Enter` sends and moves to the results, so
/// a second one opens the row menu and never a twin.
#[test]
fn enter_sends_the_search_and_moves_to_its_results() {
    let mut state = session_state();
    let mut view = SearchesView::new();
    view.handle_key(press(KeyCode::Char('/')), &state);
    typed(&mut view, &state, "bunny");
    assert!(matches!(
        view.handle_key(press(KeyCode::Enter), &state),
        ViewOutcome::Emit(Action::Command(_))
    ));
    assert!(view.results_focused());
    assert_eq!(view.query.text(), "bunny", "the query stays in view");
    let opened = view.held.entries.len();
    let id = view.held.current_id().expect("the search");
    assert!(
        !matches!(
            view.handle_key(press(KeyCode::Enter), &state),
            ViewOutcome::Emit(Action::Command(_))
        ),
        "a second Enter sends nothing"
    );
    assert_eq!(view.held.entries.len(), opened, "no twin");
    fold(
        &mut state,
        search_event(rmule_core::SearchEvent::SearchStarted { search_id: id }),
    );
    fold(
        &mut state,
        search_event(rmule_core::SearchEvent::SearchResultsReceived {
            search_id: id,
            results: vec![search_result("bunny.mkv", 3)],
        }),
    );
    view.handle_key(press(KeyCode::Enter), &state);
    assert!(view.menu.is_some(), "Enter on a result is its menu");
}

#[test]
fn down_from_the_query_is_the_way_to_the_results() {
    let state = UiState::default();
    let mut view = SearchesView::new();
    view.handle_key(press(KeyCode::Char('/')), &state);
    typed(&mut view, &state, "eels");
    view.handle_key(press(KeyCode::Down), &state);
    assert!(view.results_focused());
    assert_eq!(view.query.text(), "eels");
}

#[test]
fn a_refused_query_stays_typed_with_the_reason_under_it() {
    let state = session_state();
    let mut view = SearchesView::new();
    view.handle_key(press(KeyCode::Char('o')), &state);
    view.handle_key(press(KeyCode::Down), &state);
    typed(&mut view, &state, "lots");
    view.handle_key(press(KeyCode::Esc), &state);
    view.handle_key(press(KeyCode::Char('/')), &state);
    typed(&mut view, &state, "bunny");
    assert!(matches!(
        view.handle_key(press(KeyCode::Enter), &state),
        ViewOutcome::Redraw
    ));
    assert!(view.input_focused, "still in the query");
    assert_eq!(view.query.text(), "bunny");
    assert!(view.refusal.is_some());
    let screen = render_to_lines(78, 21, |frame| {
        view.draw(
            frame,
            frame.area(),
            &state,
            &Theme::default_dark(),
            Instant::now(),
        )
    });
    assert!(screen.contains('✗'), "under the field: {screen}");
    view.handle_key(press(KeyCode::Backspace), &state);
    assert!(view.refusal.is_none(), "the typing changed");
}

/// Arriving by digit, the digits, `?` and `Esc` are still the app's; a typed
/// letter is text, `q` included, and after a `/` a digit is too.
#[test]
fn arrival_leaves_the_navigation_keys_with_the_app() {
    let state = UiState::default();
    let mut view = SearchesView::new();
    view.arrive(&state);
    assert!(view.input_focused);
    for code in [KeyCode::Char('3'), KeyCode::Char('?')] {
        assert!(matches!(
            view.handle_key(press(code), &state),
            ViewOutcome::Ignored
        ));
    }
    assert_eq!(view.query.text(), "");
    view.handle_key(press(KeyCode::Char('/')), &state);
    view.handle_key(press(KeyCode::Char('1')), &state);
    assert_eq!(view.query.text(), "1", "a `/` first, and the digit is text");
    view.handle_key(press(KeyCode::Backspace), &state);
    view.handle_key(press(KeyCode::Char('/')), &state);
    assert_eq!(view.query.text(), "/", "a second `/` is text");

    let mut view = SearchesView::new();
    view.arrive(&state);
    view.handle_key(press(KeyCode::Char('q')), &state);
    view.handle_key(press(KeyCode::Char('3')), &state);
    assert_eq!(view.query.text(), "q3", "typing has begun");

    let mut view = SearchesView::new();
    view.arrive(&state);
    view.handle_key(press(KeyCode::Esc), &state);
    assert!(!view.input_focused);
}

#[test]
fn a_draft_stays_with_its_search_across_a_step() {
    let state = UiState::default();
    let mut view = SearchesView::new().having_sent("alpha").having_sent("beta");
    view.handle_key(press(KeyCode::Char('/')), &state);
    view.handle_key(press(KeyCode::End), &state);
    typed(&mut view, &state, " max");
    view.handle_key(press(KeyCode::Esc), &state);
    view.handle_key(press(KeyCode::Char('[')), &state);
    assert_eq!(view.query.text(), "alpha");
    view.handle_key(press(KeyCode::Char(']')), &state);
    assert_eq!(
        view.query.text(),
        "beta max",
        "what was typed is still there"
    );
}

#[test]
fn the_real_cursor_sits_at_the_caret_of_the_query_and_only_there() {
    let state = UiState::default();
    let mut view = SearchesView::new();
    let area = |view: &mut SearchesView| {
        let mut caret = None;
        render_to_lines(78, 21, |frame| {
            caret = view.draw(
                frame,
                frame.area(),
                &state,
                &Theme::default_dark(),
                Instant::now(),
            );
        });
        caret
    };
    assert_eq!(area(&mut view), None, "nothing is being typed");
    view.handle_key(press(KeyCode::Char('/')), &state);
    typed(&mut view, &state, "日本");
    assert_eq!(
        area(&mut view).map(|at| (at.x, at.y)),
        Some((1 + 2 + 4, 1)),
        "two wide glyphs past the prompt"
    );
    view.handle_key(press(KeyCode::Home), &state);
    assert_eq!(area(&mut view).map(|at| (at.x, at.y)), Some((3, 1)));
}

#[test]
fn a_search_needs_no_server() {
    // No server configured and none connected — a Kad-only operator.
    // The search is sent; core sends its Kad leg and holds the server leg.
    let mut state = session_state();
    state.session.server = None;

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
    state.session.server = None;
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

/// A name in wide glyphs keeps Size, Sources and Type on screen.
#[test]
fn golden_searches_wide_names() {
    let results = vec![
        server_result(
            0x11,
            "聖闘士星矢ペガサス幻想オープニング完全版テーマ曲集.mp3",
            4_194_304,
            42,
            7,
        ),
        server_result(0x22, "plain_name.avi", 512, 5, 0),
    ];
    let state = state_with(results, SearchStatus::Running);
    let theme = Theme::default_dark();
    let mut view = SearchesView::new().having_sent("ペガサス");
    assert_golden("searches_wide_names", 78, 21, |frame| {
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

/// A row a Kad answer qualified an AICH root for starts its download with
/// that root, beside the link and never in it (ADR-0038).
#[test]
fn a_download_started_from_a_kad_rooted_row_carries_its_root() {
    let root = rmule_primitives::AichRootHash::from_bytes([0xA1; 20]);
    let mut results = three_tier_results();
    for result in &mut results {
        *result = result.clone().with_kad_aich_root(root);
    }
    let mut state = state_with(results, SearchStatus::Completed { total: 3 });
    state.session = session_state().session;
    let mut view = SearchesView::new();
    view.handle_key(press(KeyCode::Char('g')), &state);
    view.handle_key(press(KeyCode::Char('m')), &state);
    match view.handle_key(press(KeyCode::Enter), &state) {
        ViewOutcome::Emit(Action::Command(CoreCommand::Download(
            rmule_core::DownloadCommand::StartDownload {
                file,
                kad_aich_root,
                ..
            },
        ))) => {
            assert_eq!(kad_aich_root, Some(root));
            assert_eq!(file.aich_root, None);
        }
        other => panic!("expected StartDownload, got {other:?}"),
    }
}
