//! Known-File Marks at the view's seam: a marked row's look, a mark appearing
//! on a live change in every held search, and each re-add path from the row
//! menu to the command core receives.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};
use rmule_core::file_history::{Ed2kIdentity, FileHistory, HadFile, SharedFileFact};
use rmule_core::{DownloadEvent, DownloadMetadata, DownloadMetadataOrigin, SearchEvent};
use rmule_primitives::{Ed2kText, FileHash};

use super::*;
use crate::fixture::*;
use crate::golden::assert_golden;
use crate::state::fold;

/// Two rows: `clip_low.avi` (hash 0x11, 5 sources: the dim tint) and
/// `distro_hot.iso` (hash 0x33).
const CLIP: u8 = 0x11;
const CLIP_SIZE: u64 = 734_003_200;

/// A connected session downloading into `dir`, with one held search, `alpha`,
/// listing the three tiers.
fn searching(dir: &Path) -> (SearchesView, UiState) {
    let mut state = session_state();
    state.session.as_mut().expect("session").download_dir = Some(dir.to_path_buf());
    let mut view = SearchesView::new().having_sent("alpha");
    fold(
        &mut state,
        search_event(SearchEvent::SearchResultsReceived {
            search_id: search_id(1),
            results: three_tier_results(),
        }),
    );
    view.held.bind(&state);
    (view, state)
}

fn clip_hash() -> FileHash {
    FileHash::from_bytes([CLIP; 16])
}

/// When the had clip left the disk.
fn left() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000)
}

fn clip_identity() -> Ed2kIdentity {
    Ed2kIdentity::new(clip_hash(), CLIP_SIZE)
}

fn history(shared: Option<PathBuf>, had: bool, cancelled: bool) -> FileHistory {
    FileHistory {
        had: had
            .then(|| HadFile {
                identity: clip_identity(),
                name: "clip as kept.avi".into(),
                found_gone: left(),
            })
            .into_iter()
            .collect(),
        shared: shared
            .into_iter()
            .map(|path| SharedFileFact {
                identity: clip_identity(),
                path,
                withheld: None,
            })
            .collect(),
        cancelled: cancelled.then_some(clip_identity()).into_iter().collect(),
        unread: Vec::new(),
    }
}

/// The clip shared at `path`, withheld since [`left`] because its folder is
/// missing, and in the Had Set too: the withheld row outranks Had.
fn withheld(path: PathBuf) -> FileHistory {
    let mut history = history(Some(path), true, true);
    history.shared[0].withheld = Some(rmule_core::Withheld {
        reason: rmule_core::WithheldReason::FolderMissing,
        since: left(),
    });
    history
}

fn queue_clip(state: &mut UiState) {
    fold(
        state,
        download_event(DownloadEvent::DownloadQueued {
            download_id: download_id(9),
            file_hash: clip_hash(),
            metadata: DownloadMetadata {
                name: Ed2kText::from_utf8("clip_low.avi"),
                size: CLIP_SIZE,
                origin: DownloadMetadataOrigin::Link,
            },
            file_path: crate::fixture::part_file(),
        }),
    );
}

/// The colour and attributes of the first glyph of `text` on screen.
fn look(buffer: &Buffer, text: &str) -> (Color, Modifier) {
    for y in 0..buffer.area.height {
        let line: String = (0..buffer.area.width)
            .map(|x| buffer[(x, y)].symbol().to_string())
            .collect();
        if let Some(at) = line.find(text) {
            let x = u16::try_from(line[..at].chars().count()).expect("column");
            let cell = &buffer[(x, y)];
            return (cell.fg, cell.modifier);
        }
    }
    panic!("{text} not on screen");
}

/// Open the row menu on `clip_low.avi` (first by name) and press Download.
fn download_clip(view: &mut SearchesView, state: &UiState) -> ViewOutcome {
    view.handle_key(press(KeyCode::Char('g')), state);
    view.handle_key(press(KeyCode::Char('m')), state);
    view.handle_key(press(KeyCode::Enter), state)
}

/// The name a start gives its file, and what it does when that name is
/// taken in the download directory.
fn started(outcome: ViewOutcome) -> (String, NameTaken) {
    match outcome {
        ViewOutcome::Emit(Action::Command(CoreCommand::Download(
            DownloadCommand::StartDownload { name, if_taken, .. },
        ))) => (name.as_str().to_owned(), if_taken),
        other => panic!("expected StartDownload, got {other:?}"),
    }
}

#[test]
fn each_mark_takes_its_colour_and_attribute_in_place_of_the_source_tint() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut view, mut state) = searching(dir.path());
    let t = theme();
    assert_eq!(
        look(&draw_golden(&mut view, &state), "clip_low"),
        (t.dim, Modifier::BOLD),
        "unmarked: the source tint (the cursor row is bold)"
    );
    assert_eq!(
        look(&draw_golden(&mut view, &state), "song_mid").0,
        t.fg,
        "unmarked, off the cursor"
    );

    view.handle_key(press(KeyCode::Char('G')), &state); // cursor off the clip
    state.file_history = Some(history(None, false, true));
    assert_eq!(
        look(&draw_golden(&mut view, &state), "clip_low"),
        (t.mark_cancelled, Modifier::CROSSED_OUT)
    );
    state.file_history = Some(history(None, true, true));
    assert_eq!(
        look(&draw_golden(&mut view, &state), "clip_low"),
        (t.mark_had, Modifier::ITALIC)
    );
    state.file_history = Some(withheld(dir.path().join("clip_low.avi")));
    assert_eq!(
        look(&draw_golden(&mut view, &state), "clip_low"),
        (t.mark_withheld, Modifier::UNDERLINED),
        "shared but unreadable now: neither Have nor Had"
    );
    state.file_history = Some(history(Some(dir.path().join("clip_low.avi")), true, true));
    assert_eq!(
        look(&draw_golden(&mut view, &state), "clip_low"),
        (t.mark_have, Modifier::DIM)
    );
    queue_clip(&mut state);
    assert_eq!(
        look(&draw_golden(&mut view, &state), "clip_low"),
        (t.mark_downloading, Modifier::BOLD)
    );
}

/// A download started from the table marks its row as soon as core queues
/// it — in every held search that lists the file, not only the one in view.
#[test]
fn a_download_marks_its_file_in_every_held_search() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut view, mut state) = searching(dir.path());
    view.held.open(
        &rmule_primitives::KeywordQuery::new(Ed2kText::from_utf8("beta"))
            .expect("a valid query")
            .into(),
        super::super::method::SearchMethod::default(),
        search_id(2),
    );
    fold(
        &mut state,
        search_event(SearchEvent::SearchStarted {
            search_id: search_id(2),
        }),
    );
    fold(
        &mut state,
        search_event(SearchEvent::SearchResultsReceived {
            search_id: search_id(2),
            results: vec![server_result(CLIP, "clip_low.avi", CLIP_SIZE, 5, 0)],
        }),
    );
    view.held.bind(&state);
    view.handle_key(press(KeyCode::Char('[')), &state);
    view.handle_key(press(KeyCode::Char('G')), &state);

    started(download_clip(&mut view, &state));
    queue_clip(&mut state);
    view.handle_key(press(KeyCode::Char('G')), &state);
    let t = theme();
    assert_eq!(
        look(&draw_golden(&mut view, &state), "clip_low").0,
        t.mark_downloading
    );
    view.handle_key(press(KeyCode::Char(']')), &state);
    view.handle_key(press(KeyCode::Char('G')), &state);
    assert_eq!(
        look(&draw_golden(&mut view, &state), "clip_low").0,
        t.mark_downloading,
        "the other held search marks it too"
    );
}

#[test]
fn a_file_already_downloading_is_refused_with_where_it_is() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut view, mut state) = searching(dir.path());
    queue_clip(&mut state);
    match download_clip(&mut view, &state) {
        ViewOutcome::Emit(Action::Flash(text)) => {
            assert!(
                text.contains("already downloading as clip_low.avi"),
                "{text}"
            );
            assert!(text.contains("Transfers"), "{text}");
        }
        other => panic!("a second download is refused, got {other:?}"),
    }
    assert!(view.readd.is_none());
}

#[test]
fn a_file_they_have_asks_naming_its_path_and_a_yes_starts_it_beside_the_copy() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut view, mut state) = searching(dir.path());
    let copy = dir.path().join("clip_low.avi");
    std::fs::write(&copy, b"x").expect("the copy on disk");
    state.file_history = Some(history(Some(copy), false, false));

    assert!(matches!(
        download_clip(&mut view, &state),
        ViewOutcome::Redraw
    ));
    assert!(view.readd.is_some(), "a confirm, not a download");
    assert_eq!(
        started(view.handle_key(press(KeyCode::Char('y')), &state)),
        ("clip_low.avi".to_owned(), NameTaken::Number),
        "the copy on disk is never written over"
    );
    assert!(view.readd.is_none());
}

/// The screen as text, one line per row.
fn screen(buffer: &Buffer) -> String {
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol().to_string())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn a_file_they_had_asks_naming_its_old_name_and_day_and_a_yes_starts_it() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut view, mut state) = searching(dir.path());
    state.file_history = Some(history(None, true, false));

    download_clip(&mut view, &state);
    let shown = screen(&draw_golden(&mut view, &state));
    let day = chrono::DateTime::<chrono::Local>::from(left())
        .format("%Y-%m-%d")
        .to_string();
    for text in [
        "You had this file, as",
        "clip as kept.avi",
        &format!("rmule found it gone on {day}."),
    ] {
        assert!(
            shown.contains(text),
            "{text:?} not in the confirm:\n{shown}"
        );
    }
    assert_eq!(
        started(view.handle_key(press(KeyCode::Char('y')), &state)),
        ("clip_low.avi".to_owned(), NameTaken::Number),
    );
}

#[test]
fn a_file_shared_but_unreadable_asks_naming_its_path_why_and_since_when() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut view, mut state) = searching(dir.path());
    state.file_history = Some(withheld(PathBuf::from("/Volumes/Backup/clip.avi")));

    download_clip(&mut view, &state);
    let shown = screen(&draw_golden(&mut view, &state));
    let day = chrono::DateTime::<chrono::Local>::from(left())
        .format("%Y-%m-%d")
        .to_string();
    for text in [
        "You share this file, at",
        "/Volumes/Backup/clip.avi",
        "rmule cannot read it now",
        "(folder missing)",
        &day,
    ] {
        assert!(
            shown.contains(text),
            "{text:?} not in the confirm:\n{shown}"
        );
    }
    assert_eq!(
        started(view.handle_key(press(KeyCode::Char('y')), &state)),
        ("clip_low.avi".to_owned(), NameTaken::Number),
    );
}

/// A file whose download failed is marked Failed, not Downloading; its
/// confirm names the failure, and a yes restarts that same download rather
/// than starting a second one the store would refuse.
#[test]
fn a_failed_download_asks_naming_why_and_a_yes_restarts_it_in_place() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut view, mut state) = searching(dir.path());
    queue_clip(&mut state);
    fold(
        &mut state,
        download_event(DownloadEvent::DownloadFailed {
            download_id: download_id(9),
            reason: rmule_core::DownloadFailure::StorageIntegrityFailed(
                rmule_core::StorageIntegrityFault::PartFileMissing,
            ),
        }),
    );
    assert_eq!(
        look(&draw_golden(&mut view, &state), "clip_low.avi"),
        (theme().mark_failed, Modifier::BOLD | Modifier::UNDERLINED)
    );

    download_clip(&mut view, &state);
    let shown = screen(&draw_golden(&mut view, &state));
    assert!(shown.contains("Restart download?"), "{shown}");
    assert!(shown.contains("failed, as"), "{shown}");
    assert!(
        shown.contains("It failed because the file on disk"),
        "{shown}"
    );
    // One Restart: core picks, and the confirm says it may start over.
    assert!(shown.contains("starts over when nothing"), "{shown}");
    match view.handle_key(press(KeyCode::Char('y')), &state) {
        ViewOutcome::Emit(Action::Command(CoreCommand::Download(
            DownloadCommand::ResumeDownload {
                download_id: id, ..
            },
        ))) => assert_eq!(id, download_id(9)),
        other => panic!("expected ResumeDownload, got {other:?}"),
    }
}

/// A row failed before the store kept reasons (store version 6) recovers
/// with none: its confirm says the reason was not kept, rather than inventing one.
#[test]
fn a_failed_download_from_before_reasons_were_kept_says_so() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut view, mut state) = searching(dir.path());
    fold(
        &mut state,
        download_event(DownloadEvent::DownloadRecovered {
            download_id: download_id(9),
            state: rmule_core::DownloadLifecycle::Failed,
            failure: None,
            file_hash: clip_hash(),
            metadata: DownloadMetadata {
                name: Ed2kText::from_utf8("clip_low.avi"),
                size: CLIP_SIZE,
                origin: DownloadMetadataOrigin::Link,
            },
            file_path: crate::fixture::part_file(),
        }),
    );

    download_clip(&mut view, &state);
    let shown = screen(&draw_golden(&mut view, &state));
    assert!(shown.contains("Restart download?"), "{shown}");
    assert!(shown.contains("not recorded"), "{shown}");
    assert!(!shown.contains("failed because"), "{shown}");
}

#[test]
fn a_cancelled_file_asks_esc_keeps_it_and_a_yes_starts_it_at_its_place() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut view, mut state) = searching(dir.path());
    state.file_history = Some(history(None, false, true));

    download_clip(&mut view, &state);
    assert!(matches!(
        view.handle_key(press(KeyCode::Esc), &state),
        ViewOutcome::Redraw
    ));
    assert!(view.readd.is_none(), "Esc keeps things as they are");

    download_clip(&mut view, &state);
    assert_eq!(
        started(view.handle_key(press(KeyCode::Char('y')), &state)),
        ("clip_low.avi".to_owned(), NameTaken::Number)
    );
}

#[test]
fn golden_searches_readd_have() {
    let mut view = SearchesView::new().having_sent("alpha");
    let mut state = session_state();
    fold(
        &mut state,
        search_event(SearchEvent::SearchResultsReceived {
            search_id: search_id(1),
            results: three_tier_results(),
        }),
    );
    state.file_history = Some(history(
        Some(PathBuf::from("/home/me/Downloads/clip_low.avi")),
        false,
        false,
    ));
    view.held.bind(&state);
    download_clip(&mut view, &state);
    assert_golden("searches_readd_have", 78, 21, |frame| {
        view.draw(frame, frame.area(), &state, &theme(), Instant::now());
    });
}
