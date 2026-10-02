//! The Search tab with no core attached, at the view's seam: a UI-only run
//! (the state a failed attach leaves) and a run whose core stopped. Keys in;
//! what the entry says, what stays in the input, and that nothing was sent out.

use std::time::Instant;

use ratatui::crossterm::event::KeyCode;
use rmule_primitives::{Ed2kText, FileHash, RelatedFilesQuery};

use super::super::{SearchesView, ViewOutcome};
use crate::action::Action;
use crate::fixture::*;
use crate::golden::{assert_golden, render_to_lines};
use crate::state::{SearchStatus, UiState};
use crate::view::ViewId;

/// A UI-only run: no session, no core, and the reason the attach failed.
fn ui_only() -> UiState {
    UiState {
        ui_only: Some(crate::state::AttachFailure::OpenStore),
        ..UiState::default()
    }
}

fn render(view: &mut SearchesView, state: &UiState) -> String {
    render_to_lines(90, 12, |frame| {
        view.draw(frame, frame.area(), state, &theme(), Instant::now());
    })
}

#[test]
fn a_query_with_no_core_is_held_as_not_sent_and_stays_in_the_input() {
    let state = ui_only();
    let mut view = SearchesView::new();
    view.handle_key(press(KeyCode::Char('/')), &state);
    for c in "big buck bunny".chars() {
        view.handle_key(press(KeyCode::Char(c)), &state);
    }
    assert!(
        matches!(
            view.handle_key(press(KeyCode::Enter), &state),
            ViewOutcome::Redraw
        ),
        "nothing is sent and nothing flashes a wrong cause"
    );
    assert_eq!(view.shown_query(), "big buck bunny");
    assert!(!view.results_focused(), "the input keeps focus");
    assert_golden("searches_not_sent_no_core", 90, 12, |frame| {
        view.draw(frame, frame.area(), &state, &theme(), Instant::now());
    });

    // Moving off and back finds the query where it was.
    view.handle_key(press(KeyCode::Esc), &state);
    let closed = view.handle_key(press(KeyCode::Char('x')), &state);
    assert!(matches!(closed, ViewOutcome::Emit(Action::ForgetSearch(_))));
    assert!(render(&mut view, &state).contains("press / and type a query"));
}

#[test]
fn a_related_search_with_no_core_opens_a_not_sent_entry_in_view() {
    // The level last read lit the item; the core has stopped since.
    let mut state = session_state();
    state.core_alive = false;
    let mut view = SearchesView::new();
    let query = RelatedFilesQuery::new(
        FileHash::from_bytes([0x5A; FileHash::BYTE_LEN]),
        Ed2kText::from_utf8("a.avi"),
    );
    assert!(matches!(
        view.start_related(query, &state),
        ViewOutcome::Emit(Action::SwitchView(ViewId::Searches))
    ));
    let screen = render(&mut view, &state);
    assert!(screen.contains("Results · Not sent"), "{screen}");
    assert!(
        screen.contains("not sent — the core has stopped"),
        "{screen}"
    );
    assert_eq!(
        crate::views::related::unavailable(&state),
        Some("the core has stopped"),
        "and the row menus dim the item with the reason"
    );
    assert_eq!(
        crate::views::related::unavailable(&ui_only()),
        Some("no core attached")
    );
}

#[test]
fn golden_a_running_search_stops_with_the_core() {
    let mut state = state_with(
        vec![search_result("linux-1.iso", 40)],
        SearchStatus::Running,
    );
    state.core_alive = false;
    let mut view = SearchesView::new().having_sent("linux");
    assert_golden("searches_stopped_with_the_core", 90, 12, |frame| {
        view.draw(frame, frame.area(), &state, &theme(), Instant::now());
    });
}
