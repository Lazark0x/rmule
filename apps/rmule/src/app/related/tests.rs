//! *Search related* from each tab's row menu, at the app's seam: keys in; the
//! command queued for core, the current tab and focus out.

use std::time::Instant;

use ratatui::crossterm::event::KeyCode;
use rmule_core::{CoreCommand, SearchCommand};
use rmule_primitives::{FileHash, SearchQuery};
use tokio::sync::mpsc;

use super::*;
use crate::fixture::*;
use crate::state::{SearchStatus, UiState};
use crate::theme::Theme;

/// An app attached to a real core, so a command is queued rather than
/// answered with "core not attached".
fn attached(state: UiState) -> App {
    let core = rmule_core::Core::builder(
        rmule_core::CoreConfig::default(),
        rmule_testkit::memory_store(),
    )
    .build();
    let (actions_tx, _actions_rx) = mpsc::channel(64);
    let handle = crate::bridge::spawn(core, actions_tx, crate::bridge::BridgeConfig::default());
    let mut app = App::new(Theme::default_dark()).with_client(handle);
    app.state = state;
    app
}

fn keys(app: &mut App, codes: &[KeyCode]) {
    for code in codes {
        app.reduce(key_action(*code), Instant::now());
    }
}

/// The one Related-Files `StartSearch` queued, as (hash, name).
fn sent(app: &App) -> Vec<(FileHash, String)> {
    app.pending_commands
        .iter()
        .filter_map(|command| match command {
            CoreCommand::Search(SearchCommand::StartSearch {
                query: SearchQuery::RelatedFiles(query),
                ..
            }) => Some((query.file_hash(), query.file_name().to_display_string())),
            _ => None,
        })
        .collect()
}

fn assert_landed(app: &App, hash: FileHash, name: &str) {
    assert_eq!(sent(app), [(hash, name.to_string())]);
    assert_eq!(app.chrome.active, ViewId::Searches);
    assert!(app.views.searches.results_focused());
}

const DOWN: KeyCode = KeyCode::Char('j');

#[tokio::test(flavor = "multi_thread")]
async fn from_a_search_result() {
    let state = connected_granting(
        state_with(three_tier_results(), SearchStatus::Completed { total: 3 }),
        true,
    );
    let mut app = attached(state);
    app.chrome.active = ViewId::Searches;
    // g: first row by name, clip_low.avi.
    keys(
        &mut app,
        &[
            KeyCode::Char('g'),
            KeyCode::Char('m'),
            DOWN,
            DOWN,
            KeyCode::Enter,
        ],
    );
    assert_landed(&app, file_hash(0x11), "clip_low.avi");
}

#[tokio::test(flavor = "multi_thread")]
async fn from_a_download() {
    let mut app = attached(connected_granting(three_downloads(), true));
    app.chrome.active = ViewId::Transfers;
    keys(
        &mut app,
        &[KeyCode::Char('m'), DOWN, DOWN, DOWN, DOWN, KeyCode::Enter],
    );
    assert_landed(&app, file_hash(0x07), "bunny.mp4");
}

#[tokio::test(flavor = "multi_thread")]
async fn from_a_download_whose_name_is_not_known() {
    let mut app = attached(connected_granting(three_downloads(), true));
    app.chrome.active = ViewId::Transfers;
    keys(
        &mut app,
        &[
            DOWN,
            DOWN,
            KeyCode::Char('m'),
            DOWN,
            DOWN,
            DOWN,
            DOWN,
            KeyCode::Enter,
        ],
    );
    assert_landed(&app, file_hash(0x5C), "");
}

#[tokio::test(flavor = "multi_thread")]
async fn from_a_shared_file() {
    let mut app = attached(connected_granting(served_files(), true));
    app.chrome.active = ViewId::SharedFiles;
    keys(&mut app, &[KeyCode::Char('m'), KeyCode::Enter]);
    assert_landed(&app, file_hash(1), "");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dimmed_item_sends_nothing_and_stays_on_its_tab() {
    let mut app = attached(connected_granting(three_downloads(), false));
    app.chrome.active = ViewId::Transfers;
    keys(
        &mut app,
        &[KeyCode::Char('m'), DOWN, DOWN, DOWN, DOWN, KeyCode::Enter],
    );
    assert!(sent(&app).is_empty());
    assert_eq!(app.chrome.active, ViewId::Transfers);
}

/// A UI-only run — no client attached — dims the item with its
/// reason even where the level last said the server grants it; nothing is
/// queued and the tab stays.
#[tokio::test(flavor = "multi_thread")]
async fn with_no_core_attached_the_item_is_dimmed_and_nothing_is_queued() {
    let mut app = App::new(Theme::default_dark());
    app.state = connected_granting(three_downloads(), true);
    app.state.ui_only = Some(crate::state::AttachFailure::OpenStore);
    app.chrome.active = ViewId::Transfers;
    keys(
        &mut app,
        &[KeyCode::Char('m'), DOWN, DOWN, DOWN, DOWN, KeyCode::Enter],
    );
    assert!(app.pending_commands.is_empty());
    assert_eq!(app.chrome.active, ViewId::Transfers);
    assert_eq!(
        crate::views::related::unavailable(&app.state),
        Some("no core attached")
    );
}
