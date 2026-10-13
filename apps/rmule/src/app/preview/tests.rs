//! Unit tests for a Preview's launch: what the reducer puts on the player
//! lane, and what it says when it cannot.

use super::*;
use crate::fixture::{download_id, preview_ready, rooted};
use crate::theme::Theme;

#[test]
fn a_ready_row_puts_exactly_one_launch_with_the_players_words_and_the_path() {
    let (player, mut launches) = crate::player::lane();
    let mut app = App::new(Theme::default_dark()).with_player(player);
    app.state = preview_ready();
    app.reduce(Action::Preview(download_id(1)), Instant::now());
    assert_eq!(
        launches.try_recv().expect("one launch"),
        Launch {
            start: Start::Command(vec![
                "mpv".into(),
                "--fs".into(),
                rooted("films/film.mkv.part").into_os_string(),
            ]),
            name: "film.mkv".to_string(),
        }
    );
    assert!(launches.try_recv().is_err(), "exactly one");
}

/// With no Player Command a ready row still launches: the lane looks the
/// Default App up by the extension of the name, not of the `.part`.
#[test]
fn without_a_player_command_a_ready_row_puts_one_default_app_launch_by_its_names_extension() {
    let (player, mut launches) = crate::player::lane();
    let mut app = App::new(Theme::default_dark()).with_player(player);
    app.state = preview_ready();
    app.state.preferences.player_command = None;
    app.reduce(Action::Preview(download_id(1)), Instant::now());
    assert_eq!(
        launches.try_recv().expect("one launch"),
        Launch {
            start: Start::DefaultApp {
                extension: "mkv".to_string(),
                file: rooted("films/film.mkv.part"),
            },
            name: "film.mkv".to_string(),
        }
    );
    assert!(launches.try_recv().is_err(), "exactly one");
}

#[test]
fn without_a_player_lane_a_ready_preview_flashes_that_no_core_is_attached() {
    let mut app = App::new(Theme::default_dark());
    app.state = preview_ready();
    let now = Instant::now();
    app.reduce(Action::Preview(download_id(1)), now);
    assert_eq!(
        app.chrome.flash_text(now),
        Some(app_words::CORE_NOT_ATTACHED.as_str())
    );
}

/// A Preview of a row the menu greys flashes the reason it greys it with,
/// and puts nothing on the player lane: `v` on a blocked row lands here.
#[test]
fn a_blocked_preview_flashes_the_reason_the_menu_greys_it_with() {
    let (player, mut launches) = crate::player::lane();
    let mut app = App::new(Theme::default_dark()).with_player(player);
    app.state = preview_ready();
    app.state.diagnostics.downloads.remove(&download_id(1));
    let now = Instant::now();
    app.reduce(Action::Preview(download_id(1)), now);
    assert_eq!(
        app.chrome.flash_text(now),
        Some(words::blocked(crate::player::PreviewBlock::NoPartMap).as_str())
    );
    assert!(launches.try_recv().is_err(), "nothing launched");
}
