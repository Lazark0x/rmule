//! More results on a Held Search, at the view's seam: `n` asks only where the
//! server holds more for the current entry, says why not everywhere else, and
//! the status line and hints say what is on offer.

use std::time::Instant;

use ratatui::crossterm::event::KeyCode;
use rmule_core::{CoreCommand, SearchCommand, ServerMoreResults};

use super::super::SearchesView;
use crate::action::Action;
use crate::fixture::*;
use crate::golden::assert_golden;
use crate::state::{MORE_REFUSED, SearchStatus, UiState};
use crate::views::ViewOutcome;

fn completed_linux() -> (SearchesView, UiState) {
    let state = state_with(
        vec![search_result("linux-1.iso", 40)],
        SearchStatus::Completed { total: 1 },
    );
    (SearchesView::new().having_sent("linux"), state)
}

fn offer(state: &mut UiState, asks_left: u8) {
    state.diagnostics.search_more_results = Some(ServerMoreResults {
        search_id: search_id(1),
        asks_left,
    });
}

#[test]
fn n_asks_for_the_next_page_only_where_the_server_holds_more() {
    let (mut view, mut state) = completed_linux();
    match view.handle_key(press(KeyCode::Char('n')), &state) {
        ViewOutcome::Emit(Action::Flash(text)) => assert_eq!(text, MORE_REFUSED),
        other => panic!("nothing on offer is said, got {other:?}"),
    }

    offer(&mut state, 5);
    match view.handle_key(press(KeyCode::Char('n')), &state) {
        ViewOutcome::Emit(Action::Command(CoreCommand::Search(SearchCommand::MoreResults {
            search_id: id,
        }))) => assert_eq!(id, search_id(1)),
        other => panic!("expected MoreResults, got {other:?}"),
    }

    offer(&mut state, 0);
    match view.handle_key(press(KeyCode::Char('n')), &state) {
        ViewOutcome::Emit(Action::Flash(text)) => {
            assert!(text.contains("stops after 5"), "{text}");
        }
        other => panic!("the limit is said, got {other:?}"),
    }
}

#[test]
fn golden_searches_the_server_has_more() {
    let (mut view, mut state) = completed_linux();
    offer(&mut state, 5);
    let theme = theme();
    assert_golden("searches_server_has_more", 96, 12, |frame| {
        view.draw(frame, frame.area(), &state, &theme, Instant::now());
    });
}

/// The level of which search the server holds more for, delivered as the
/// bridge delivers it.
fn snapshot_more(state: &mut UiState, more: Option<ServerMoreResults>) {
    let mut diagnostics = state.diagnostics.clone();
    diagnostics.search_more_results = more;
    state.apply_snapshot(
        crate::bridge::BridgeSnapshot {
            diagnostics,
            rates: state.rates.clone(),
            taken_at: Instant::now(),
        },
        Instant::now(),
    );
}

fn status_of(view: &mut SearchesView, state: &UiState) -> String {
    let theme = theme();
    let mut terminal =
        ratatui::Terminal::new(ratatui::backend::TestBackend::new(160, 12)).expect("terminal");
    terminal
        .draw(|frame| view.draw(frame, frame.area(), state, &theme, Instant::now()))
        .expect("draw");
    let buffer = terminal.backend().buffer();
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .find(|line| line.contains("Results ·"))
        .unwrap_or_default()
}

/// A newer search took the rows the server kept for this one, so the
/// entry stops offering more — and its status line says why, as `n` does.
#[test]
fn a_held_search_whose_kept_rows_another_search_replaced_says_why() {
    let (mut view, mut state) = completed_linux();
    snapshot_more(
        &mut state,
        Some(ServerMoreResults {
            search_id: search_id(1),
            asks_left: 5,
        }),
    );
    assert!(status_of(&mut view, &state).contains("server has more"));

    snapshot_more(
        &mut state,
        Some(ServerMoreResults {
            search_id: search_id(2),
            asks_left: 5,
        }),
    );
    let status = status_of(&mut view, &state);
    assert!(
        status.contains("a newer search replaced the rows the server kept"),
        "{status}"
    );
    match view.handle_key(press(KeyCode::Char('n')), &state) {
        ViewOutcome::Emit(Action::Flash(text)) => {
            assert!(text.contains("a newer search replaced"), "{text}");
        }
        other => panic!("why is said, got {other:?}"),
    }
}

/// The server sending its last page is not a replacement: no newer search
/// exists, so the entry says the server sent all it had.
#[test]
fn a_held_search_whose_server_ran_out_says_so() {
    let (mut view, mut state) = completed_linux();
    state.diagnostics.connected_server =
        Some(rmule_primitives::ServerEndpoint::new("127.0.0.1", 4661).expect("endpoint"));
    snapshot_more(
        &mut state,
        Some(ServerMoreResults {
            search_id: search_id(1),
            asks_left: 4,
        }),
    );
    snapshot_more(&mut state, None);
    let status = status_of(&mut view, &state);
    assert!(status.contains("the server sent all it had"), "{status}");
}

/// With no server connected, the rows went with the connection.
#[test]
fn a_held_search_whose_server_disconnected_says_so() {
    let (mut view, mut state) = completed_linux();
    snapshot_more(
        &mut state,
        Some(ServerMoreResults {
            search_id: search_id(1),
            asks_left: 4,
        }),
    );
    snapshot_more(&mut state, None);
    let status = status_of(&mut view, &state);
    assert!(
        status.contains("the server that kept them disconnected"),
        "{status}"
    );
}
