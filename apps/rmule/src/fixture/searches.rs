//! The Searches tab's fixtures: result rows, filter states and the search views over them.

use std::collections::BTreeMap;

use ratatui::crossterm::event::KeyCode;
use rmule_primitives::{Ed2kText, FileHash, SearchResult};

use crate::state::{SearchPane, SearchStatus, SessionConfig, UiState};
use crate::views::searches::SearchesView;

use super::{endpoint, press, search_id};

/// A server-shaped result row: the two counts a real `OP_SEARCHRESULT`
/// carries and **no** `FT_FILETYPE` tag — neither Lugdunum nor eserver
/// ever emits one (capture-pinned in `rmule-ed2k`), so the Type column has
/// to come out of the file name.
pub(crate) fn server_result(
    hash: u8,
    name: &str,
    size: u64,
    sources: u32,
    complete: u32,
) -> SearchResult {
    SearchResult::new(
        FileHash::from_bytes([hash; 16]),
        size,
        vec![Ed2kText::from_utf8(name)],
        Vec::new(),
    )
    .expect("valid result")
    .with_reported_availability(sources)
    .with_complete_sources(complete)
}

/// One search pane holding `results` at `status`, keyed by the first id.
pub(crate) fn state_with(results: Vec<SearchResult>, status: SearchStatus) -> UiState {
    let mut searches = BTreeMap::new();
    searches.insert(
        search_id(1),
        SearchPane {
            status,
            results,
            skipped: 0,
            waiting_for_turn: None,
            more_ended: None,
            legs: None,
        },
    );
    UiState {
        searches,
        ..UiState::default()
    }
}

/// A sweep that asked twelve servers, seven of which answered.
pub(crate) const fn swept_servers() -> rmule_core::SweepTally {
    rmule_core::SweepTally {
        asked: 12,
        answered: 7,
    }
}

/// [`three_tier_results`] in a running search whose server answered, whose
/// sweep asked twelve servers and heard from seven, and whose Kad walk is
/// still out.
pub(crate) fn swept_state() -> UiState {
    use rmule_core::{SearchEvent, SearchLegState as L, SearchLegs};
    let mut state = state_with(three_tier_results(), SearchStatus::Running);
    crate::state::fold(
        &mut state,
        super::search_event(SearchEvent::SearchLegsChanged {
            search_id: search_id(1),
            legs: SearchLegs {
                server: L::Settled,
                sweep: L::Settled,
                kad: L::Sent,
                sweep_servers: swept_servers(),
            },
        }),
    );
    state
}

/// One result per source-count tier, so a tint test covers the whole ladder.
pub(crate) fn three_tier_results() -> Vec<SearchResult> {
    vec![
        server_result(0x11, "clip_low.avi", 734_003_200, 5, 0), // dim tier (<10)
        server_result(0x22, "song_mid.mp3", 4_194_304, 42, 7),  // normal tier (≥10)
        server_result(0x33, "distro_hot.iso", 3_221_225_472, 1234, 900), // good tier (≥100)
    ]
}

/// A state whose session config is complete, so a search commits for real
/// instead of flashing the honest reason.
pub(crate) fn session_state() -> UiState {
    UiState {
        session: Some(SessionConfig {
            server: Some(endpoint("srv.example", 4661)),
            download_dir: Some(std::path::PathBuf::from("/tmp/dl")),
        }),
        ..UiState::default()
    }
}

/// `state` with a session, connected to a server that grants the
/// **Related-Files Search** or not — on the level the menus read.
pub(crate) fn connected_granting(mut state: UiState, related_search: bool) -> UiState {
    state.session = session_state().session;
    state.diagnostics.connected_server = Some(endpoint("srv.example", 4661));
    state.diagnostics.connected_server_grants = rmule_core::ServerGrants {
        related_search,
        ..rmule_core::ServerGrants::default()
    };
    state
}

/// Drive `o`, then a scripted key sequence, on a fresh view.
pub(crate) fn view_with_filters(keys: &[KeyCode]) -> (SearchesView, UiState) {
    let state = session_state();
    let mut view = SearchesView::new();
    view.handle_key(press(KeyCode::Char('o')), &state);
    for code in keys {
        view.handle_key(press(*code), &state);
    }
    (view, state)
}
