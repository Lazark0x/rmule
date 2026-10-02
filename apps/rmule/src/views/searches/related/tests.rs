//! The Related-Files Search at the Search tab's seam: a menu choice or a core
//! answer in; the command sent, the strip, the query line and the results
//! pane's words out.

use std::time::Instant;

use ratatui::crossterm::event::KeyCode;
use rmule_core::{RelatedSearchRefusal, SearchEvent, SearchFailure, SearchId};
use rmule_primitives::{Ed2kText, FileHash};

use super::*;
use crate::fixture::*;
use crate::golden::{assert_golden, render_to_lines};
use crate::state::fold;
use crate::theme::Theme;

fn query(byte: u8, name: &str) -> RelatedFilesQuery {
    RelatedFilesQuery::new(FileHash::from_bytes([byte; 16]), Ed2kText::from_utf8(name))
}

fn render(view: &mut SearchesView, state: &UiState, width: u16) -> String {
    render_to_lines(width, 21, |frame| {
        view.draw(
            frame,
            frame.area(),
            state,
            &Theme::default_dark(),
            Instant::now(),
        );
    })
}

/// The id a `StartSearch` went under.
fn sent(outcome: ViewOutcome) -> SearchId {
    match outcome {
        ViewOutcome::Emit(Action::Command(CoreCommand::Search(SearchCommand::StartSearch {
            search_id,
            ..
        }))) => search_id,
        other => panic!("a StartSearch, got {other:?}"),
    }
}

fn started(state: &mut UiState, id: SearchId) {
    fold(
        state,
        search_event(SearchEvent::SearchStarted { search_id: id }),
    );
}

fn completed_empty(state: &mut UiState, id: SearchId) {
    fold(
        state,
        search_event(SearchEvent::SearchCompleted {
            search_id: id,
            total_results: 0,
        }),
    );
}

fn refused(state: &mut UiState, id: SearchId, reason: RelatedSearchRefusal) {
    fold(
        state,
        search_event(SearchEvent::SearchRefused {
            search_id: id,
            reason,
        }),
    );
}

/// The search result menu at the row the cursor rests on, and `Enter` on the
/// third item, *Search related*.
fn choose_related(view: &mut SearchesView, state: &UiState) -> ViewOutcome {
    view.handle_key(press(KeyCode::Char('g')), state);
    view.handle_key(press(KeyCode::Char('m')), state);
    view.handle_key(press(KeyCode::Char('j')), state);
    view.handle_key(press(KeyCode::Char('j')), state);
    view.handle_key(press(KeyCode::Enter), state)
}

fn results_state(granted: Option<bool>) -> UiState {
    let state = state_with(
        vec![server_result(0xAB, "video.avi", 1000, 42, 0)],
        crate::state::SearchStatus::Completed { total: 1 },
    );
    match granted {
        Some(granted) => connected_granting(state, granted),
        None => state,
    }
}

#[test]
fn the_result_menu_dims_search_related_with_each_reason_and_sends_nothing() {
    for (state, reason) in [
        (results_state(None), "Search related (not connected)"),
        (
            results_state(Some(false)),
            "Search related (server does not offer it)",
        ),
    ] {
        let mut view = SearchesView::new().having_sent("video");
        view.handle_key(press(KeyCode::Char('m')), &state);
        assert!(render(&mut view, &state, 78).contains(reason), "{reason}");
        view.menu = None;
        // j, j wraps past the dimmed item back to Download: nothing to send.
        view.handle_key(press(KeyCode::Char('g')), &state);
        view.handle_key(press(KeyCode::Char('m')), &state);
        view.handle_key(press(KeyCode::Char('j')), &state);
        view.handle_key(press(KeyCode::Char('j')), &state);
        assert_eq!(view.menu, Some(0), "{reason}");
    }
}

#[test]
fn the_result_menu_offers_search_related_for_the_row_when_the_server_grants_it() {
    let state = results_state(Some(true));
    let mut view = SearchesView::new().having_sent("video");
    match choose_related(&mut view, &state) {
        ViewOutcome::Emit(Action::SearchRelated(query)) => {
            assert_eq!(query.file_hash(), FileHash::from_bytes([0xAB; 16]));
            assert_eq!(query.file_name().to_display_string(), "video.avi");
        }
        other => panic!("expected SearchRelated, got {other:?}"),
    }
    assert_eq!(view.menu, None);
}

#[test]
fn the_item_follows_a_server_switch_under_the_open_menu() {
    let granted = results_state(Some(true));
    let mut view = SearchesView::new().having_sent("video");
    view.handle_key(press(KeyCode::Char('g')), &granted);
    view.handle_key(press(KeyCode::Char('m')), &granted);
    view.handle_key(press(KeyCode::Char('j')), &granted);
    view.handle_key(press(KeyCode::Char('j')), &granted);
    assert_eq!(view.menu, Some(2), "resting on Search related");

    // The next server does not grant it: the same open menu dims it, and
    // Enter sends nothing.
    let switched = results_state(Some(false));
    assert!(render(&mut view, &switched, 78).contains("Search related (server does not offer it)"));
    assert!(matches!(
        view.handle_key(press(KeyCode::Enter), &switched),
        ViewOutcome::Redraw
    ));
}

#[test]
fn starting_one_sends_the_related_query_and_focuses_the_results() {
    let state = connected_granting(UiState::default(), true);
    let mut view = SearchesView::new();
    view.input_focused = true;
    match view.start_related(query(0x42, "debian.iso"), &state) {
        ViewOutcome::Emit(Action::Command(CoreCommand::Search(SearchCommand::StartSearch {
            query: SearchQuery::RelatedFiles(sent),
            ..
        }))) => assert_eq!(sent, query(0x42, "debian.iso")),
        other => panic!("expected a related StartSearch, got {other:?}"),
    }
    assert!(!view.input_focused, "focus is on the results");
    assert_eq!(view.query, "", "the file is no keywords to edit");
    let screen = render(&mut view, &state, 78);
    assert!(screen.contains("❯ related to: debian.iso"), "{screen}");
    assert!(screen.contains("[~debian.iso · —…]"), "{screen}");
}

#[test]
fn a_dimmed_level_at_send_time_sends_nothing_and_opens_nothing() {
    let state = connected_granting(UiState::default(), false);
    let mut view = SearchesView::new();
    match view.start_related(query(0x42, "debian.iso"), &state) {
        ViewOutcome::Emit(Action::Flash(text)) => {
            assert_eq!(text, "search related: server does not offer it");
        }
        other => panic!("expected the reason, got {other:?}"),
    }
    assert!(view.held.is_empty());
}

#[test]
fn a_file_whose_name_is_not_known_is_named_by_its_hash() {
    let state = connected_granting(UiState::default(), true);
    let mut view = SearchesView::new();
    view.start_related(query(0x5C, ""), &state);
    let screen = render(&mut view, &state, 78);
    assert!(
        screen.contains("related to: the file with hash 5C5C5C5C5C… — its name"),
        "{screen}"
    );
    assert!(screen.contains("[~5C5C5C5C5C… · —…]"), "{screen}");
}

#[test]
fn enter_in_the_input_while_a_related_entry_is_current_starts_a_keyword_search() {
    let state = connected_granting(UiState::default(), true);
    let mut view = SearchesView::new();
    view.start_related(query(0x42, "debian.iso"), &state);
    view.handle_key(press(KeyCode::Char('/')), &state);
    // Nothing typed: nothing to send, and the related entry stays.
    assert!(matches!(
        view.handle_key(press(KeyCode::Enter), &state),
        ViewOutcome::Redraw
    ));
    for c in "debian".chars() {
        view.handle_key(press(KeyCode::Char(c)), &state);
    }
    assert!(matches!(
        view.handle_key(press(KeyCode::Enter), &state),
        ViewOutcome::Emit(Action::Command(CoreCommand::Search(
            SearchCommand::StartSearch {
                query: SearchQuery::Keywords(_),
                ..
            }
        )))
    ));
    assert_eq!(
        view.held.entries.len(),
        2,
        "a new entry beside the related one"
    );
}

#[test]
fn an_empty_answer_says_what_rmule_knows() {
    let mut state = connected_granting(UiState::default(), true);
    let mut view = SearchesView::new();
    let id = sent(view.start_related(query(0x42, "debian.iso"), &state));
    started(&mut state, id);
    completed_empty(&mut state, id);
    let screen = render(&mut view, &state, 110);
    assert!(screen.contains(NO_RELATED_FILES), "{screen}");
}

#[test]
fn a_refusal_before_starting_reads_as_its_reason_and_closes_by_its_id() {
    let mut state = connected_granting(UiState::default(), true);
    let mut view = SearchesView::new();
    let id = sent(view.start_related(query(0x42, "debian.iso"), &state));
    refused(&mut state, id, RelatedSearchRefusal::NotConnected);
    assert_eq!(
        state.notable.as_deref(),
        Some("related search refused: not connected")
    );
    let screen = render(&mut view, &state, 78);
    assert!(screen.contains("refused: not connected"), "{screen}");
    assert!(
        screen.contains("[~debian.iso · —]"),
        "not running: {screen}"
    );

    // `x` closes the refused entry and forgets the refusal.
    assert!(matches!(
        view.handle_key(press(KeyCode::Char('x')), &state),
        ViewOutcome::Emit(Action::ForgetSearch(closed)) if closed == id
    ));
    assert!(view.held.is_empty());
}

/// Two searches pending: core refuses the later one and starts the earlier
/// after it. Each outcome settles the entry it names — by order, the refusal
/// would have settled the older entry.
#[test]
fn a_refusal_settles_the_entry_it_names_with_two_pending() {
    let mut state = connected_granting(UiState::default(), true);
    let mut view = SearchesView::new();
    let one = sent(view.start_related(query(0x01, "one.iso"), &state));
    let two = sent(view.start_related(query(0x02, "two.iso"), &state));
    refused(&mut state, two, RelatedSearchRefusal::NotOffered);
    started(&mut state, one);
    view.held.bind(&state);
    assert_eq!(view.held.entries[0].id, one);
    assert_eq!(view.held.entries[0].kind.refused(), None);
    assert_eq!(view.held.entries[1].id, two);
    assert_eq!(
        view.held.entries[1].kind.refused(),
        Some(RelatedSearchRefusal::NotOffered)
    );
    assert_eq!(view.held.entries.len(), 2, "no entry for an unknown id");
}

#[test]
fn a_refusal_after_sending_reads_as_its_reason_in_the_entry_and_the_status_bar() {
    let mut state = connected_granting(UiState::default(), true);
    let mut view = SearchesView::new();
    let id = sent(view.start_related(query(0x42, "debian.iso"), &state));
    started(&mut state, id);
    fold(
        &mut state,
        search_event(SearchEvent::SearchFailed {
            search_id: id,
            reason: SearchFailure::RelatedSearchNotOffered,
        }),
    );
    assert_eq!(
        state.notable.as_deref(),
        Some("related search refused: server does not offer it")
    );
    let screen = render(&mut view, &state, 78);
    assert!(
        screen.contains("refused: server does not offer it"),
        "{screen}"
    );
    assert!(screen.contains("Results · Refused"), "{screen}");
}

#[test]
fn golden_searches_related_query_line() {
    let mut state = connected_granting(UiState::default(), true);
    let mut view = SearchesView::new().having_sent("ubuntu");
    let related = sent(view.start_related(query(0x42, "debian-12.5.0-amd64-netinst.iso"), &state));
    started(&mut state, search_id(1));
    started(&mut state, related);
    completed_empty(&mut state, related);
    assert_golden("searches_related_query", 78, 12, |frame| {
        view.draw(
            frame,
            frame.area(),
            &state,
            &Theme::default_dark(),
            Instant::now(),
        );
    });
}
