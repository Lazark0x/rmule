//! Unit tests for the download row-action menu: what each status offers, what is greyed and why, and the commands it emits.

use ratatui::crossterm::event::KeyCode;

use crate::golden::assert_golden;

use super::*;
use crate::fixture::*;

#[test]
fn p_on_an_active_row_emits_a_real_pause_command() {
    let mut view = TransfersView::new();
    let state = three_downloads();
    view.handle_key(press(KeyCode::Char('j')), &state); // ensure a selection
    view.select_row(&state, 0); // download_id(1), Downloading
    match view.handle_key(press(KeyCode::Char('p')), &state) {
        ViewOutcome::Emit(Action::Command(CoreCommand::Download(
            DownloadCommand::PauseDownload { download_id },
        ))) => assert_eq!(download_id, crate::fixture::download_id(1)),
        _ => panic!("expected a PauseDownload command"),
    }
}

#[test]
fn p_on_a_paused_row_flashes_without_a_session_and_resumes_with_one() {
    let mut view = TransfersView::new();
    let mut state = three_downloads();
    view.select_row(&state, 1); // download_id(2), Paused
    match view.handle_key(press(KeyCode::Char('p')), &state) {
        ViewOutcome::Emit(Action::Flash(message)) => {
            assert!(
                message.contains("core not attached"),
                "honest resume gap, got {message:?}"
            );
        }
        other => panic!("expected a Flash without a session, got {other:?}"),
    }

    // With a session the real ResumeDownload goes out.
    state.session = Some(crate::state::SessionConfig {
        server: Some(rmule_primitives::ServerEndpoint::new("srv.example", 4661).expect("endpoint")),
        download_dir: None,
    });
    match view.handle_key(press(KeyCode::Char('p')), &state) {
        ViewOutcome::Emit(Action::Command(CoreCommand::Download(
            DownloadCommand::ResumeDownload { download_id, .. },
        ))) => {
            assert_eq!(download_id, crate::fixture::download_id(2));
        }
        other => panic!("expected ResumeDownload, got {other:?}"),
    }
}

/// A failed row offers Restart, the same fresh run of the same
/// download — never a Pause core would refuse for a download with no run.
#[test]
fn a_failed_row_offers_restart_and_resumes_the_same_download() {
    let mut state = three_downloads();
    let items = menu_items(DownloadStatus::Failed, None, &state);
    assert_eq!(items[0].label, "Restart");
    state.session = Some(crate::fixture::session_state().session.expect("session"));
    match pause_toggle_action(
        DownloadStatus::Failed,
        crate::fixture::download_id(2),
        &state,
    ) {
        Action::Command(CoreCommand::Download(DownloadCommand::ResumeDownload {
            download_id,
            ..
        })) => assert_eq!(download_id, crate::fixture::download_id(2)),
        other => panic!("expected ResumeDownload, got {other:?}"),
    }
}

#[test]
fn the_menu_cursor_skips_greyed_items_and_clamps() {
    let mut view = TransfersView::new();
    let state = three_downloads();
    // download_id(2) carries no metadata, so Copy eD2k link stays greyed here too
    // (a row with real metadata has a fourth enabled stop — covered by
    // `copy_link_is_enabled_once_metadata_names_the_file`).
    view.select_row(&state, 1);
    view.handle_key(press(KeyCode::Char('m')), &state);
    assert_eq!(
        view.overlay,
        Overlay::Menu {
            cursor: MenuAction::Resume
        }
    );
    // Down walks the three enabled items and then clamps — never landing on
    // a greyed item.
    use MenuAction::{Cancel, Details, Resume};
    for expected in [Cancel, Details, Details, Details] {
        view.handle_key(press(KeyCode::Char('j')), &state);
        assert_eq!(view.overlay, Overlay::Menu { cursor: expected });
    }
    for expected in [Cancel, Resume, Resume] {
        view.handle_key(press(KeyCode::Char('k')), &state);
        assert_eq!(view.overlay, Overlay::Menu { cursor: expected });
    }
}

#[test]
fn menu_pause_entry_emits_and_closes() {
    let mut view = TransfersView::new();
    let state = three_downloads();
    view.select_row(&state, 0);
    view.handle_key(press(KeyCode::Enter), &state); // open menu (cursor 0 = Pause)
    match view.handle_key(press(KeyCode::Enter), &state) {
        ViewOutcome::Emit(Action::Command(CoreCommand::Download(
            DownloadCommand::PauseDownload { download_id },
        ))) => assert_eq!(download_id, crate::fixture::download_id(1)),
        _ => panic!("expected PauseDownload from the menu"),
    }
    assert_eq!(view.overlay, Overlay::None, "menu closes after acting");
}

#[test]
fn an_open_modal_swallows_stray_keys_but_a_closed_view_bubbles_them() {
    let mut view = TransfersView::new();
    let state = three_downloads();
    // Closed: an unclaimed key bubbles to the globals.
    assert!(matches!(
        view.handle_key(press(KeyCode::Char('2')), &state),
        ViewOutcome::Ignored
    ));
    // Open menu: the same key is captured (modal is exclusive).
    view.select_row(&state, 0);
    view.handle_key(press(KeyCode::Char('m')), &state);
    assert!(matches!(
        view.handle_key(press(KeyCode::Char('2')), &state),
        ViewOutcome::Redraw
    ));
    assert_eq!(
        view.overlay,
        Overlay::Menu {
            cursor: MenuAction::Pause
        },
        "unchanged, just swallowed"
    );
}

#[test]
fn menu_wont_open_on_an_empty_view() {
    let mut view = TransfersView::new();
    let empty = UiState::default();
    assert!(matches!(
        view.handle_key(press(KeyCode::Char('m')), &empty),
        ViewOutcome::Ignored
    ));
    assert_eq!(view.overlay, Overlay::None);
    assert!(matches!(
        view.handle_key(press(KeyCode::Char('p')), &empty),
        ViewOutcome::Ignored
    ));
}

fn menu_screen(view: &mut TransfersView, state: &UiState) -> String {
    crate::golden::render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
        let area = frame.area();
        view.draw(frame, area, state, &Theme::default_dark(), now());
    })
}

/// `m`, then down to *Search related* — the fifth item, under *Copy eD2k
/// link* — and `Enter`.
fn choose_related(view: &mut TransfersView, state: &UiState, row: usize) -> ViewOutcome {
    view.select_row(state, row);
    view.handle_key(press(KeyCode::Char('m')), state);
    for _ in 0..4 {
        view.handle_key(press(KeyCode::Char('j')), state);
    }
    view.handle_key(press(KeyCode::Enter), state)
}

#[test]
fn search_related_is_dimmed_with_each_reason_and_sends_nothing() {
    for (state, reason) in [
        (three_downloads(), "Search related  not connected"),
        (
            connected_granting(three_downloads(), false),
            "Search related  server does not offer it",
        ),
    ] {
        let mut view = TransfersView::new();
        assert!(
            !matches!(
                choose_related(&mut view, &state, 0),
                ViewOutcome::Emit(Action::SearchRelated(_))
            ),
            "{reason}"
        );
        view.overlay = Overlay::Menu {
            cursor: MenuAction::Pause,
        };
        let screen = menu_screen(&mut view, &state);
        assert!(screen.contains(reason), "{screen}");
    }
}

#[test]
fn search_related_asks_about_the_download_by_hash_and_name() {
    let state = connected_granting(three_downloads(), true);
    let mut view = TransfersView::new();
    match choose_related(&mut view, &state, 0) {
        ViewOutcome::Emit(Action::SearchRelated(query)) => {
            assert_eq!(query.file_hash(), file_hash(0x07));
            assert_eq!(query.file_name().to_display_string(), "bunny.mp4");
        }
        other => panic!("expected SearchRelated, got {other:?}"),
    }
    assert_eq!(view.overlay, Overlay::None, "menu closes after acting");
}

/// download_id(3)'s metadata landed with no name: the query carries none,
/// and the Search tab names the file by its hash.
#[test]
fn a_download_whose_name_is_not_known_asks_by_hash_alone() {
    let state = connected_granting(three_downloads(), true);
    let mut view = TransfersView::new();
    match choose_related(&mut view, &state, 2) {
        ViewOutcome::Emit(Action::SearchRelated(query)) => {
            assert_eq!(query.file_hash(), file_hash(0x5C));
            assert_eq!(query.file_name().to_display_string(), "");
        }
        other => panic!("expected SearchRelated, got {other:?}"),
    }
}

#[test]
fn golden_menu_open() {
    let mut view = TransfersView::new();
    view.overlay = Overlay::Menu {
        cursor: MenuAction::Pause,
    };
    let state = three_downloads();
    assert_golden("transfers_menu_open", GOLDEN_W, GOLDEN_H, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now());
    });
}

/// A failed download offers one Restart whatever it failed on — here a
/// missing part file, where core starts over — and nothing beside it that
/// acts on the run; core, not the operator, picks between continuing and
/// starting over.
#[test]
fn golden_menu_of_a_download_failed_on_a_missing_part_file() {
    use rmule_core::{DownloadFailure, StorageIntegrityFault};
    let mut state = three_downloads();
    let mut row = download_row(DownloadStatus::Failed, 0x3C, 4);
    row.failure = Some(DownloadFailure::StorageIntegrityFailed(
        StorageIntegrityFault::PartFileMissing,
    ));
    state.downloads.insert(download_id(9), row);
    let mut view = TransfersView::new();
    let index = view
        .download_ids(&state)
        .iter()
        .position(|id| *id == download_id(9))
        .expect("the failed row is listed");
    view.select_row(&state, index);
    view.overlay = Overlay::Menu {
        cursor: MenuAction::Restart,
    };
    assert_golden("transfers_menu_failed", GOLDEN_W, GOLDEN_H, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now());
    });
}

/// The cursor names its action: a status change under an open menu closes it
/// instead of running whatever now sits at the same place.
#[test]
fn a_status_change_under_an_open_menu_never_runs_another_action() {
    let mut view = TransfersView::new();
    let mut state = three_downloads();
    view.select_row(&state, 0); // download_id(1), Downloading
    view.handle_key(press(KeyCode::Char('m')), &state);
    assert_eq!(
        view.overlay,
        Overlay::Menu {
            cursor: MenuAction::Pause
        }
    );
    state
        .downloads
        .get_mut(&crate::fixture::download_id(1))
        .expect("row")
        .status = DownloadStatus::Completed;
    let outcome = view.handle_key(press(KeyCode::Enter), &state);
    assert!(matches!(outcome, ViewOutcome::Redraw), "got {outcome:?}");
    assert_eq!(view.overlay, Overlay::None);
}
