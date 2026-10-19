//! The "Shared directories" section: the list with each entry's state and
//! what lies under it, the add row, the remove confirm and the add's
//! question, all asked in Settings.

use std::path::PathBuf;
use std::time::Instant;

use ratatui::crossterm::event::KeyCode;
use rmule_core::{
    CoreEvent, DirectoryOffer, DirectoryRole, DirectoryState, ScanEvent, ScanPhase,
    SharedDirectoryDiagnostics,
};
use rmule_primitives::FileHash;

use super::super::SettingsView;
use super::Slot;
use crate::action::Action;
use crate::fixture::press;
use crate::golden::assert_golden;
use crate::state::{SharedRow, UiState};
use crate::theme::Theme;
use crate::views::ViewOutcome;

const FILM: FileHash = FileHash::from_bytes([
    0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8A, 0x9B, 0xAC, 0xBD, 0xCE, 0xDF, 0xE0, 0xF1, 0x02,
]);

/// The download directory, still hashing, and one added directory holding
/// one shared file.
fn listed() -> UiState {
    let mut state = UiState::default();
    // A named data directory, so no frame draws the platform's own
    // "set RMULE_DATA or HOME / LOCALAPPDATA" words.
    state.preferences.data_dir = Some(crate::args::DataDir {
        path: PathBuf::from("/srv/rmule"),
        source: crate::args::DataDirSource::Flag,
    });
    state.diagnostics.shared_directories = vec![
        SharedDirectoryDiagnostics {
            dir: PathBuf::from("/home/u/Downloads"),
            role: DirectoryRole::DownloadDirectory,
            state: DirectoryState::Scan(ScanPhase::Hashing {
                done: 2,
                total: 8,
                current: PathBuf::from("/home/u/Downloads/clip.mkv"),
            }),
        },
        SharedDirectoryDiagnostics {
            dir: PathBuf::from("/srv/media"),
            role: DirectoryRole::Added,
            state: DirectoryState::Scan(ScanPhase::Watching { settling: 0 }),
        },
    ];
    state.shared.insert(
        FILM,
        SharedRow {
            file_hash: FILM,
            path: Some(PathBuf::from("/srv/media/films/film.mkv")),
            file_size: Some(734_003_200),
            withheld: None,
        },
    );
    state
}

fn focus(view: &mut SettingsView, state: &UiState, slot: &Slot) {
    view.handle_key(press(KeyCode::Char('g')), state);
    view.form.focus = view.slots.iter().position(|s| s == slot).expect("slot");
}

fn command(outcome: ViewOutcome) -> Option<rmule_core::ScanCommand> {
    match outcome {
        ViewOutcome::Emit(Action::Command(rmule_core::CoreCommand::Scan(command))) => Some(command),
        _ => None,
    }
}

#[test]
fn a_typed_path_is_sent_for_core_to_guard_count_and_ask() {
    let state = listed();
    let mut view = SettingsView::new();
    focus(&mut view, &state, &Slot::AddDir);
    view.handle_key(press(KeyCode::Enter), &state);
    for c in "media".chars() {
        view.handle_key(press(KeyCode::Char(c)), &state);
    }
    assert!(matches!(
        view.handle_key(press(KeyCode::Enter), &state),
        ViewOutcome::Redraw
    ));
    assert_eq!(
        view.form.error.as_deref(),
        Some(crate::words::scan::ADD_RELATIVE)
    );
    for _ in 0.."media".len() {
        view.handle_key(press(KeyCode::Backspace), &state);
    }
    let books = crate::fixture::rooted("srv/books");
    for c in books.display().to_string().chars() {
        view.handle_key(press(KeyCode::Char(c)), &state);
    }
    assert_eq!(
        command(view.handle_key(press(KeyCode::Enter), &state)),
        Some(rmule_core::ScanCommand::AddSharedDirectory { path: books })
    );
}

#[test]
fn x_asks_before_it_stops_sharing_and_the_download_directory_is_not_removed() {
    let state = listed();
    let mut view = SettingsView::new();
    focus(
        &mut view,
        &state,
        &Slot::Dir {
            dir: PathBuf::from("/home/u/Downloads"),
            role: DirectoryRole::DownloadDirectory,
        },
    );
    view.handle_key(press(KeyCode::Char('x')), &state);
    assert!(view.removing.is_none());
    assert!(view.form.error.is_some(), "why it cannot be removed");

    focus(
        &mut view,
        &state,
        &Slot::Dir {
            dir: PathBuf::from("/srv/media"),
            role: DirectoryRole::Added,
        },
    );
    view.handle_key(press(KeyCode::Char('x')), &state);
    assert_eq!(view.removing, Some(PathBuf::from("/srv/media")));
    assert!(command(view.handle_key(press(KeyCode::Char('j')), &state)).is_none());
    assert_eq!(
        command(view.handle_key(press(KeyCode::Char('y')), &state)),
        Some(rmule_core::ScanCommand::RemoveSharedDirectory {
            path: PathBuf::from("/srv/media")
        })
    );
    assert!(view.removing.is_none());
}

#[test]
fn an_add_is_asked_here_and_the_download_directorys_first_share_is_not() {
    let mut state = listed();
    let ask = |dir: &str, adding| {
        CoreEvent::Scan(ScanEvent::ConsentRequested {
            dir: PathBuf::from(dir),
            offer: DirectoryOffer {
                files: 12,
                bytes: 8_000_000,
                unread: 0,
            },
            adding,
            replaces: Vec::new(),
        })
    };
    crate::state::fold(&mut state, ask("/home/u/Downloads", false));
    let mut view = SettingsView::new();
    assert!(matches!(
        view.handle_key(press(KeyCode::Char('j')), &state),
        ViewOutcome::Redraw
    ));
    crate::state::fold(&mut state, ask("/srv/books", true));
    assert_eq!(
        command(view.handle_key(press(KeyCode::Char('y')), &state)),
        Some(rmule_core::ScanCommand::Answer {
            dir: PathBuf::from("/srv/books"),
            share: true
        })
    );
}

#[test]
fn golden_settings_lists_the_shared_directories_with_state_and_counts() {
    let state = listed();
    let mut view = SettingsView::new();
    assert_golden("settings_shared_directories", 78, 14, |frame| {
        view.draw(
            frame,
            frame.area(),
            &state,
            &Theme::default_dark(),
            Instant::now(),
        );
    });
}

#[test]
fn golden_settings_remove_confirm_names_the_count() {
    let state = listed();
    let mut view = SettingsView::new();
    focus(
        &mut view,
        &state,
        &Slot::Dir {
            dir: PathBuf::from("/srv/media"),
            role: DirectoryRole::Added,
        },
    );
    view.handle_key(press(KeyCode::Char('x')), &state);
    assert_golden("settings_remove_shared_directory", 78, 16, |frame| {
        view.draw(
            frame,
            frame.area(),
            &state,
            &Theme::default_dark(),
            Instant::now(),
        );
    });
}

#[test]
fn golden_settings_remove_confirm_scrolls_in_a_short_frame() {
    let state = listed();
    let mut view = SettingsView::new();
    focus(
        &mut view,
        &state,
        &Slot::Dir {
            dir: PathBuf::from("/srv/media"),
            role: DirectoryRole::Added,
        },
    );
    view.handle_key(press(KeyCode::Char('x')), &state);
    let area = ratatui::layout::Rect::new(0, 0, 60, 6);
    let shown = |view: &mut SettingsView| {
        crate::golden::render_to_lines(area.width, area.height, |frame| {
            view.draw(frame, area, &state, &Theme::default_dark(), Instant::now());
        })
    };
    assert_golden(
        "settings_remove_shared_directory_short",
        area.width,
        area.height,
        |frame| {
            view.draw(frame, area, &state, &Theme::default_dark(), Instant::now());
        },
    );
    view.handle_key(press(KeyCode::Char('G')), &state);
    assert!(shown(&mut view).contains("keep it"), "{}", shown(&mut view));
}
