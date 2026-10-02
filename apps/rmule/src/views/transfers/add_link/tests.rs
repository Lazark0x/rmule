//! The Add-link form: what a pasted link sends, what it refuses, and how
//! both look.

use std::path::PathBuf;
use std::time::Instant;

use ratatui::crossterm::event::KeyCode;
use rmule_core::{CoreCommand, DownloadCommand};

use super::super::TransfersView;
use crate::action::Action;
use crate::fixture::*;
use crate::golden::assert_golden;
use crate::state::UiState;
use crate::theme::Theme;
use crate::views::ViewOutcome;

/// A link carrying two fields no client reads (`x=1`, `comment`), an AICH
/// root and one classic source — the reader's own skipped-field fixture.
const SKIPPING_LINK: &str = "ed2k://|file|hello.txt|11|AA010FBC1D14C795D86EF98C95479D17|x=1|h=A2NWOTYURUU3P3GCUB6KCNW3FTYYELQB|comment|/|sources,192.0.2.44:4662|/";

fn typed(view: &mut TransfersView, state: &UiState, text: &str) {
    for c in text.chars() {
        view.handle_key(press(KeyCode::Char(c)), state);
    }
}

/// [`three_downloads`] under a session that can start a download.
fn with_session() -> UiState {
    let mut state = three_downloads();
    let mut config = session();
    config.download_dir = Some(PathBuf::from("/srv/downloads"));
    state.session = Some(config);
    state
}

fn refusal(view: &TransfersView) -> Option<&str> {
    view.add_link.as_ref()?.form.error.as_deref()
}

#[test]
fn a_pasted_link_starts_its_download_and_names_the_fields_it_skipped() {
    let state = with_session();
    let mut view = TransfersView::new();
    view.handle_key(press(KeyCode::Char('L')), &state);
    typed(&mut view, &state, SKIPPING_LINK);
    match view.handle_key(press(KeyCode::Enter), &state) {
        ViewOutcome::Emit(Action::Actions(actions)) => match actions.as_slice() {
            [
                Action::Command(CoreCommand::Download(DownloadCommand::StartDownload {
                    file,
                    output_path,
                    ..
                })),
                Action::Note(note),
            ] => {
                assert_eq!(
                    file.file_hash.to_hex_upper(),
                    "AA010FBC1D14C795D86EF98C95479D17"
                );
                assert_eq!(
                    file.sources.peers().len(),
                    1,
                    "the link's source rides along"
                );
                assert_eq!(output_path, &PathBuf::from("/srv/downloads/hello.txt"));
                assert_eq!(
                    note.as_str(),
                    "ignored the fields `x`, `comment` the link carried, which no client reads"
                );
            }
            other => panic!("expected the start and its note, got {other:?}"),
        },
        other => panic!("expected actions, got {other:?}"),
    }
    assert!(view.add_link.is_none(), "an accepted link closes the form");
}

#[test]
fn what_cannot_be_added_is_refused_in_the_form_with_the_typing_kept() {
    let state = with_session();
    let mut view = TransfersView::new();
    view.handle_key(press(KeyCode::Char('L')), &state);

    view.handle_key(press(KeyCode::Enter), &state);
    assert_eq!(
        refusal(&view),
        Some("paste an eD2k file link: ed2k://|file|name|size|hash|/")
    );

    // `q` and `h` are text here, never the globals.
    typed(&mut view, &state, "quick hello");
    view.handle_key(press(KeyCode::Enter), &state);
    assert_eq!(
        refusal(&view),
        Some("not a readable eD2k link — check that it was copied whole")
    );
    assert_eq!(view.add_link.as_ref().unwrap().form.text(0), "quick hello");

    clear(&mut view, &state);
    typed(&mut view, &state, "ed2k://|server|10.1.2.3|4661|/");
    view.handle_key(press(KeyCode::Enter), &state);
    assert_eq!(
        refusal(&view),
        Some("a server link, not a file link — add servers in Networks (1)")
    );

    clear(&mut view, &state);
    typed(
        &mut view,
        &state,
        "ed2k://|file|x.bin|11|AA010FBC1D14C795D86EF98C95479D1|/",
    );
    view.handle_key(press(KeyCode::Enter), &state);
    assert_eq!(
        refusal(&view),
        Some("the link's hash does not read — check that it was copied whole")
    );

    assert!(matches!(
        view.handle_key(press(KeyCode::Esc), &state),
        ViewOutcome::Redraw
    ));
    assert!(view.add_link.is_none(), "Esc abandons the form");
}

fn clear(view: &mut TransfersView, state: &UiState) {
    let len = view.add_link.as_ref().unwrap().form.text(0).chars().count();
    for _ in 0..len {
        view.handle_key(press(KeyCode::Backspace), state);
    }
}

/// The file bunny.mp4 already downloads under, with no source in its link.
fn bunny_link() -> String {
    format!(
        "ed2k://|file|bunny.mp4|92000000|{}|/",
        file_hash(0x07).to_hex_upper()
    )
}

#[test]
fn a_link_for_a_download_already_in_transfers_is_refused_by_name() {
    let state = with_session();
    let mut view = TransfersView::new();
    view.handle_key(press(KeyCode::Char('L')), &state);
    typed(&mut view, &state, &bunny_link());
    view.handle_key(press(KeyCode::Enter), &state);
    assert_eq!(
        refusal(&view),
        Some("already downloading as bunny.mp4; the link names no source to add")
    );
}

#[test]
fn a_second_link_with_sources_is_sent_for_core_to_add_them() {
    let state = with_session();
    let mut view = TransfersView::new();
    view.handle_key(press(KeyCode::Char('L')), &state);
    let link = format!(
        "ed2k://|file|bunny.mp4|92000000|{}|/|sources,198.51.100.23:4662|/",
        file_hash(0x07).to_hex_upper()
    );
    typed(&mut view, &state, &link);
    match view.handle_key(press(KeyCode::Enter), &state) {
        ViewOutcome::Emit(Action::Command(CoreCommand::Download(
            DownloadCommand::StartDownload { file, .. },
        ))) => assert_eq!(file.sources.peers().len(), 1),
        other => panic!("expected the start carrying the source, got {other:?}"),
    }
}

#[test]
fn golden_transfers_add_link_form() {
    let state = with_session();
    let mut view = TransfersView::new();
    view.handle_key(press(KeyCode::Char('L')), &state);
    let now = Instant::now();
    assert_golden("transfers_add_link_form", 100, 24, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now);
    });
}

#[test]
fn golden_transfers_add_link_refused() {
    let state = with_session();
    let mut view = TransfersView::new();
    view.handle_key(press(KeyCode::Char('L')), &state);
    typed(&mut view, &state, &bunny_link());
    view.handle_key(press(KeyCode::Enter), &state);
    let now = Instant::now();
    assert_golden("transfers_add_link_refused", 100, 24, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now);
    });
}
