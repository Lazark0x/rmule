//! Held Searches at the view's seam: keys and clicks in; the current entry,
//! the strip's order and the selected result out.

use std::time::Instant;

use ratatui::crossterm::event::KeyCode;
use rmule_core::{SearchEvent, SearchFailure};
use rmule_primitives::SearchResult;

use super::*;
use crate::fixture::*;
use crate::golden::{assert_golden, render_to_lines};
use crate::state::fold;

/// Commit `query` from the focused input, as the operator would; the id the
/// view sent it under.
fn send(view: &mut SearchesView, state: &UiState, query: &str) -> SearchId {
    view.input_focused = true;
    view.query.clear();
    for c in query.chars() {
        view.handle_key(press(KeyCode::Char(c)), state);
    }
    let outcome = view.handle_key(press(KeyCode::Enter), state);
    view.handle_key(press(KeyCode::Esc), state);
    match outcome {
        ViewOutcome::Emit(Action::Command(CoreCommand::Search(SearchCommand::StartSearch {
            search_id,
            ..
        }))) => search_id,
        other => panic!("the query is sent, got {other:?}"),
    }
}

/// Core's answer to the `StartSearch` sent under `id`.
fn started(state: &mut UiState, id: SearchId) {
    fold(
        state,
        search_event(SearchEvent::SearchStarted { search_id: id }),
    );
}

fn results(state: &mut UiState, id: SearchId, results: Vec<SearchResult>) {
    fold(
        state,
        search_event(SearchEvent::SearchResultsReceived {
            search_id: id,
            results,
        }),
    );
}

/// A view that sent each of `queries` in turn, each started by core; the ids
/// they went under, in order.
fn holding(queries: &[&str]) -> (SearchesView, UiState, Vec<SearchId>) {
    let mut state = session_state();
    let mut view = SearchesView::new();
    let mut ids = Vec::new();
    for query in queries {
        let id = send(&mut view, &state, query);
        started(&mut state, id);
        ids.push(id);
    }
    view.held.bind(&state);
    (view, state, ids)
}

fn queries(view: &SearchesView) -> Vec<&str> {
    view.held
        .entries
        .iter()
        .map(|entry| entry.query.as_str())
        .collect()
}

fn current(view: &SearchesView) -> (SearchId, &str) {
    let entry = view.held.current().expect("a current entry");
    (entry.id, entry.query.as_str())
}

fn key(view: &mut SearchesView, state: &UiState, code: KeyCode) -> ViewOutcome {
    view.handle_key(press(code), state)
}

#[test]
fn every_query_opens_a_new_entry_at_the_right_end_and_makes_it_current() {
    let (mut view, mut state, _) = holding(&["alpha"]);
    // The same text twice is two entries, current from the moment it is sent.
    let second = send(&mut view, &state, "alpha");
    assert_eq!(current(&view), (second, "alpha"));
    started(&mut state, second);
    let third = send(&mut view, &state, "beta");
    started(&mut state, third);
    view.held.bind(&state);

    assert_eq!(queries(&view), ["alpha", "alpha", "beta"]);
    assert_eq!(current(&view), (third, "beta"));
    assert_eq!(view.held.entries[1].id, second);
}

/// Outcomes are matched by the id they name, never by arrival order: a later
/// search's start arriving first names its own entry.
#[test]
fn an_outcome_settles_the_entry_it_names_whatever_the_order() {
    let mut state = session_state();
    let mut view = SearchesView::new();
    let first = send(&mut view, &state, "alpha");
    let second = send(&mut view, &state, "beta");
    started(&mut state, second);
    results(
        &mut state,
        second,
        vec![server_result(0x77, "beta.iso", 10, 1, 0)],
    );
    view.held.bind(&state);
    assert_eq!(current(&view), (second, "beta"));
    assert_eq!(
        view.selected_result(&state)
            .map(|result| result.primary_name().to_display_string()),
        Some("beta.iso".to_string())
    );
    key(&mut view, &state, KeyCode::Char('['));
    assert_eq!(current(&view), (first, "alpha"));
    assert_eq!(view.selected_result(&state), None, "alpha has not started");
}

#[test]
fn brackets_walk_the_strip_and_the_input_follows_the_current_query() {
    let (mut view, state, ids) = holding(&["alpha", "beta", "gamma"]);
    key(&mut view, &state, KeyCode::Char('['));
    assert_eq!(current(&view), (ids[1], "beta"));
    assert_eq!(view.query, "beta");
    key(&mut view, &state, KeyCode::Char('['));
    key(&mut view, &state, KeyCode::Char('['));
    assert_eq!(current(&view).1, "alpha", "clamped at the left end");
    key(&mut view, &state, KeyCode::Char(']'));
    assert_eq!(view.query, "beta");
}

#[test]
fn results_for_an_entry_out_of_view_land_in_it_and_show_on_the_strip() {
    let (mut view, mut state, ids) = holding(&["alpha", "beta"]);
    results(&mut state, ids[0], three_tier_results());
    results(
        &mut state,
        ids[1],
        vec![server_result(0x77, "beta.iso", 10, 1, 0)],
    );

    let strip = render_to_lines(78, 21, |frame| {
        view.draw(
            frame,
            frame.area(),
            &state,
            &Theme::default_dark(),
            Instant::now(),
        );
    });
    assert!(strip.contains(" alpha · 3… [beta · 1…]"), "{strip}");
    assert_eq!(
        view.selected_result(&state)
            .map(|result| result.primary_name().to_display_string()),
        Some("beta.iso".to_string())
    );

    key(&mut view, &state, KeyCode::Char('['));
    assert_eq!(
        view.selected_result(&state)
            .map(|result| result.primary_name().to_display_string()),
        Some("clip_low.avi".to_string()),
        "alpha's own results, first by name"
    );
}

#[test]
fn each_entry_keeps_its_own_cursor() {
    let (mut view, mut state, ids) = holding(&["alpha", "beta"]);
    results(&mut state, ids[0], three_tier_results());
    results(&mut state, ids[1], three_tier_results());
    key(&mut view, &state, KeyCode::Char('j'));
    key(&mut view, &state, KeyCode::Char('j'));
    key(&mut view, &state, KeyCode::Char('['));
    key(&mut view, &state, KeyCode::Char(']'));
    assert_eq!(
        view.selected_result(&state)
            .map(|result| result.primary_name().to_display_string()),
        Some("song_mid.mp3".to_string()),
        "beta's cursor waited where it was"
    );
    key(&mut view, &state, KeyCode::Char('['));
    assert_eq!(
        view.selected_result(&state)
            .map(|result| result.primary_name().to_display_string()),
        Some("clip_low.avi".to_string()),
        "alpha's cursor never moved"
    );
}

#[test]
fn x_stops_a_running_search_then_closes_it() {
    let (mut view, mut state, ids) = holding(&["alpha", "beta", "gamma"]);
    key(&mut view, &state, KeyCode::Char('['));
    match key(&mut view, &state, KeyCode::Char('x')) {
        ViewOutcome::Emit(Action::Command(CoreCommand::Search(SearchCommand::CancelSearch {
            search_id,
        }))) => assert_eq!(search_id, ids[1]),
        other => panic!("x stops the running search, got {other:?}"),
    }
    assert_eq!(
        queries(&view),
        ["alpha", "beta", "gamma"],
        "a stop keeps the entry"
    );
    fold(
        &mut state,
        search_event(SearchEvent::SearchCancelled { search_id: ids[1] }),
    );

    match key(&mut view, &state, KeyCode::Char('x')) {
        ViewOutcome::Emit(Action::ForgetSearch(id)) => assert_eq!(id, ids[1]),
        other => panic!("x closes the stopped search, got {other:?}"),
    }
    assert_eq!(queries(&view), ["alpha", "gamma"]);
    assert_eq!(current(&view).1, "gamma", "the right neighbour");
    assert_eq!(view.query, "gamma");
}

#[test]
fn closing_the_rightmost_moves_left_and_closing_the_last_empties_the_tab() {
    let (mut view, mut state, ids) = holding(&["alpha", "beta"]);
    for id in ids {
        fold(
            &mut state,
            search_event(SearchEvent::SearchFailed {
                search_id: id,
                reason: SearchFailure::ServerDisconnected,
            }),
        );
    }
    key(&mut view, &state, KeyCode::Char('x'));
    assert_eq!(
        current(&view).1,
        "alpha",
        "no right neighbour: the left one"
    );
    key(&mut view, &state, KeyCode::Char('x'));
    assert!(view.held.is_empty());
    assert!(view.query.is_empty(), "the empty prompt");
    assert!(matches!(
        key(&mut view, &state, KeyCode::Char('x')),
        ViewOutcome::Ignored
    ));
}

#[test]
fn editing_the_query_opens_a_new_entry_and_leaves_the_old_one_as_it_was() {
    let (mut view, mut state, _) = holding(&["alpha"]);
    key(&mut view, &state, KeyCode::Char('/'));
    for c in " beta".chars() {
        key(&mut view, &state, KeyCode::Char(c));
    }
    let ViewOutcome::Emit(Action::Command(CoreCommand::Search(SearchCommand::StartSearch {
        search_id: second,
        ..
    }))) = key(&mut view, &state, KeyCode::Enter)
    else {
        panic!("Enter sends the edited query");
    };
    started(&mut state, second);
    view.held.bind(&state);
    assert_eq!(queries(&view), ["alpha", "alpha beta"]);
    assert_eq!(current(&view), (second, "alpha beta"));
}

#[test]
fn a_click_on_an_entry_selects_it() {
    let (mut view, state, _) = holding(&["alpha", "beta"]);
    let lines = render_to_lines(78, 21, |frame| {
        view.draw(
            frame,
            frame.area(),
            &state,
            &Theme::default_dark(),
            Instant::now(),
        );
    });
    let (y, line) = lines
        .lines()
        .enumerate()
        .find(|(_, line)| line.contains("alpha ·"))
        .expect("the strip is drawn");
    let x = line.chars().position(|c| c == 'a').expect("alpha's label");
    let outcome = view.handle_click(
        u16::try_from(x).expect("column"),
        u16::try_from(y).expect("row"),
        &state,
    );
    assert!(matches!(outcome, ViewOutcome::Redraw));
    assert_eq!(current(&view).1, "alpha");
    assert_eq!(view.query, "alpha");
}

#[test]
fn a_label_is_capped_at_twenty_characters() {
    assert_eq!(label("a query of exactly 20"), "a query of exactly 2…");
    assert_eq!(label("twenty characters ok"), "twenty characters ok");
    assert_eq!(label(""), "—");
}

#[test]
fn a_related_files_search_is_labelled_by_its_file_with_a_tilde() {
    let mut state = session_state();
    let mut view = SearchesView::new();
    let related = rmule_primitives::RelatedFilesQuery::new(
        rmule_primitives::FileHash::from_bytes([7; 16]),
        rmule_primitives::Ed2kText::from_utf8("abcdefghijklmnopqrstuvwxyz.avi"),
    );
    view.held
        .open(&related.into(), SearchMethod::default(), search_id(1));
    started(&mut state, search_id(1));
    let strip = render_to_lines(78, 21, |frame| {
        view.draw(
            frame,
            frame.area(),
            &state,
            &Theme::default_dark(),
            Instant::now(),
        );
    });
    assert!(strip.contains("[~abcdefghijklmnopqrst… · 0…]"), "{strip}");
}

/// Eight searches on a 78-column strip, the current one in the middle: the
/// strip scrolls to it and marks both hidden ends.
#[test]
fn golden_searches_held_strip() {
    let (mut view, mut state, ids) = holding(&[
        "ubuntu",
        "debian netinst",
        "a much longer query than twenty characters",
        "arch",
        "fedora workstation",
        "mint",
        "gentoo stage3",
        "void",
    ]);
    results(&mut state, ids[0], three_tier_results());
    fold(
        &mut state,
        search_event(SearchEvent::SearchCompleted {
            search_id: ids[0],
            total_results: 3,
        }),
    );
    for _ in 0..3 {
        key(&mut view, &state, KeyCode::Char('['));
    }
    assert_golden("searches_held_strip", 78, 12, |frame| {
        view.draw(
            frame,
            frame.area(),
            &state,
            &Theme::default_dark(),
            Instant::now(),
        );
    });
}

/// The rows core dropped for answering no running search are said on the
/// strip — only once there are some.
#[test]
fn the_strip_says_how_many_rows_answered_no_running_search_only_when_some_did() {
    let (mut view, mut state, _) = holding(&["alpha"]);
    let draw = |view: &mut SearchesView, state: &UiState| {
        render_to_lines(100, 12, |frame| {
            view.draw(
                frame,
                frame.area(),
                state,
                &Theme::default_dark(),
                Instant::now(),
            );
        })
    };
    assert!(!draw(&mut view, &state).contains("answered no running search"));
    state.diagnostics.session.search_rows_unattributed_total = 7;
    let lines = draw(&mut view, &state);
    assert!(
        lines.contains("7 rows answered no running search and were dropped"),
        "{lines}"
    );
    assert!(lines.contains("[alpha · 0…]"), "the entry keeps its place");
}

/// A search closed before `bind` saw its id stays closed when core's late
/// event for it arrives.
#[test]
fn a_late_event_for_a_closed_search_opens_no_entry() {
    let mut state = session_state();
    let mut view = SearchesView::new();
    let id = send(&mut view, &state, "alpha");
    assert_eq!(view.held.close_current(), Some(id));
    started(&mut state, id);
    view.held.bind(&state);
    assert!(view.held.is_empty(), "the closed search was held again");
}
