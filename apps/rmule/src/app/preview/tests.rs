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
            argv: vec![
                "mpv".into(),
                "--fs".into(),
                rooted("films/film.mkv.part").into_os_string(),
            ],
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
