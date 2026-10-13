//! The strip: every listed directory with its state and what lies under it,
//! and `[` / `]` filtering the files table to one.

use std::path::PathBuf;
use std::time::Instant;

use ratatui::crossterm::event::KeyCode;

use crate::fixture::{golden_area, press, shared_directories, theme};
use crate::golden::assert_golden;
use crate::views::ViewOutcome;
use crate::views::shared_files::SharedView;

#[test]
fn the_brackets_step_through_all_and_each_directory_filtering_the_table() {
    let state = shared_directories();
    let mut view = SharedView::default();
    assert_eq!(view.file_ids(&state).len(), 2, "all shared files");
    assert!(matches!(
        view.handle_key(press(KeyCode::Char(']')), &state),
        ViewOutcome::Redraw
    ));
    assert_eq!(
        view.directory_filter(&state),
        Some(PathBuf::from("/home/u/Downloads").as_path())
    );
    assert_eq!(view.file_ids(&state), [crate::fixture::file_hash(1)]);
    view.handle_key(press(KeyCode::Char(']')), &state);
    assert_eq!(view.file_ids(&state), [crate::fixture::file_hash(2)]);
    view.handle_key(press(KeyCode::Char(']')), &state);
    assert!(
        view.file_ids(&state).is_empty(),
        "nothing under the one being added yet"
    );
    view.handle_key(press(KeyCode::Char(']')), &state);
    assert_eq!(view.directory_filter(&state), None, "wraps to all");
    view.handle_key(press(KeyCode::Char('[')), &state);
    assert_eq!(
        view.directory_filter(&state),
        Some(PathBuf::from("/srv/books").as_path())
    );
}

#[test]
fn golden_shared_strip_names_each_directory_with_state_and_counts() {
    let state = shared_directories();
    let mut view = SharedView::default();
    view.handle_key(press(KeyCode::Char(']')), &state);
    view.handle_key(press(KeyCode::Char(']')), &state);
    assert_golden(
        "shared_strip",
        golden_area().width,
        golden_area().height,
        |frame| view.draw(frame, golden_area(), &state, &theme(), Instant::now()),
    );
}

/// A pane too short for every directory: the strip scrolls to the selected
/// one, its bar beside it, and its hint line counts which it is.
#[test]
fn golden_shared_strip_overflow() {
    let state = shared_directories();
    let mut view = SharedView::default();
    for _ in 0..3 {
        view.handle_key(press(KeyCode::Char(']')), &state);
    }
    assert_golden("shared_strip_overflow", golden_area().width, 14, |frame| {
        view.draw(
            frame,
            ratatui::layout::Rect::new(0, 0, golden_area().width, 14),
            &state,
            &theme(),
            Instant::now(),
        );
    });
}

#[test]
fn a_missing_directory_says_since_when() {
    let since = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_790_000_000);
    let words = crate::words::scan::state_words(&rmule_core::DirectoryState::Scan(
        rmule_core::ScanPhase::Missing { since },
    ));
    assert_eq!(
        words,
        format!("missing since {}", crate::words::scan::moment(since))
    );
}

#[test]
fn a_partial_share_is_listed_under_the_directory_its_part_file_lies_in() {
    use rmule_core::{CoreEvent, DownloadEvent, DownloadMetadataOrigin, ServeEvent};

    let mut state = shared_directories();
    let partial = crate::fixture::file_hash(3);
    crate::state::fold(
        &mut state,
        CoreEvent::Download(DownloadEvent::DownloadQueued {
            download_id: crate::fixture::download_id(3),
            file_hash: partial,
            metadata: crate::fixture::metadata(
                "album.flac",
                52_428_800,
                DownloadMetadataOrigin::Link,
            ),
            file_path: PathBuf::from("/srv/media/album.flac.part"),
        }),
    );
    crate::state::fold(
        &mut state,
        CoreEvent::Serve(ServeEvent::PartialOffered { file_hash: partial }),
    );
    let mut view = SharedView::default();
    assert_eq!(view.file_ids(&state).len(), 3, "all shared files");
    view.handle_key(press(KeyCode::Char(']')), &state);
    assert_eq!(view.file_ids(&state), [crate::fixture::file_hash(1)]);
    view.handle_key(press(KeyCode::Char(']')), &state);
    assert_eq!(
        view.directory_filter(&state),
        Some(PathBuf::from("/srv/media").as_path())
    );
    let mut under_media = view.file_ids(&state);
    under_media.sort_unstable();
    assert_eq!(under_media, [crate::fixture::file_hash(2), partial]);
    view.handle_key(press(KeyCode::Char(']')), &state);
    assert!(view.file_ids(&state).is_empty());
}
