//! The Add-link form: what a pasted link sends, what it refuses, and how
//! both look.

use std::path::PathBuf;
use std::time::Instant;

use ratatui::crossterm::event::KeyCode;
use rmule_core::{CoreCommand, DownloadCommand, NameTaken};

use super::super::TransfersView;
use crate::action::Action;
use crate::fixture::*;
use crate::golden::assert_golden_caret;
use crate::state::UiState;
use crate::theme::Theme;
use crate::views::ViewOutcome;
use crate::words::download::{self as words, LinkRefusal};

/// A link carrying two fields no client reads (`x=1`, `comment`), an AICH
/// root and one classic source — the reader's own skipped-field fixture.
const SKIPPING_LINK: &str = "ed2k://|file|hello.txt|11|AA010FBC1D14C795D86EF98C95479D17|x=1|h=A2NWOTYURUU3P3GCUB6KCNW3FTYYELQB|comment|/|sources,192.0.2.44:4662|/";

const OTHER_LINK: &str = "ed2k://|file|other.bin|11|BB010FBC1D14C795D86EF98C95479D17|/";

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
    state.session = config;
    state
}

fn refusal(view: &TransfersView) -> Option<&str> {
    view.add_link.as_ref()?.form.error.as_deref()
}

/// The sent `StartDownload`s of a paste's outcome.
fn asked(outcome: ViewOutcome) -> usize {
    match outcome {
        ViewOutcome::Emit(Action::Actions(actions)) => actions.len(),
        _ => panic!("a paste of several links emits what it asked for"),
    }
}

/// Two links in one paste are two downloads; before bracketed paste the second
/// ran as keys.
#[test]
fn a_paste_of_several_links_asks_for_each() {
    let state = with_session();
    let mut view = TransfersView::by_name();
    view.open_add_link(&state);
    let paste = format!("{SKIPPING_LINK}\r\n{OTHER_LINK}\n");
    assert_eq!(asked(view.handle_paste(&paste, &state)), 2);
    assert!(view.add_link.is_none(), "nothing left to answer");
}

/// A refused link of a paste is never lost: each comes up in the field with
/// its refusal, and the form closes when the last is dealt with.
#[test]
fn links_refused_in_a_paste_come_up_in_turn() {
    let state = with_session();
    let mut view = TransfersView::by_name();
    view.open_add_link(&state);
    let paste = format!("not a link\n{SKIPPING_LINK}\nnor this\n");
    assert_eq!(asked(view.handle_paste(&paste, &state)), 1);
    let field = |view: &TransfersView| {
        view.add_link
            .as_ref()
            .map(|entry| entry.form.text(0).to_string())
    };
    assert_eq!(field(&view).as_deref(), Some("not a link"));
    assert!(refusal(&view).is_some());
    clear(&mut view, &state);
    typed(&mut view, &state, SKIPPING_LINK);
    view.handle_key(press(KeyCode::Enter), &state);
    assert_eq!(field(&view).as_deref(), Some("nor this"));
    clear(&mut view, &state);
    typed(&mut view, &state, OTHER_LINK);
    view.handle_key(press(KeyCode::Enter), &state);
    assert!(view.add_link.is_none());
}

#[test]
fn a_pasted_link_starts_its_download_and_names_the_fields_it_skipped() {
    let state = with_session();
    let mut view = TransfersView::by_name();
    view.handle_key(press(KeyCode::Char('L')), &state);
    typed(&mut view, &state, SKIPPING_LINK);
    match view.handle_key(press(KeyCode::Enter), &state) {
        ViewOutcome::Emit(Action::Actions(actions)) => match actions.as_slice() {
            [
                Action::Command(CoreCommand::Download(DownloadCommand::StartDownload {
                    file,
                    name,
                    if_taken,
                    ..
                })),
                Action::Note(_, note),
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
                assert_eq!(
                    (name.as_str(), if_taken),
                    ("hello.txt", &NameTaken::Refuse),
                    "a fresh add never lands on a file it did not make"
                );
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
    let mut view = TransfersView::by_name();
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
    let mut view = TransfersView::by_name();
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
    let mut view = TransfersView::by_name();
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
    let mut view = TransfersView::by_name();
    view.handle_key(press(KeyCode::Char('L')), &state);
    let now = Instant::now();
    assert_golden_caret("transfers_add_link_form", 100, 24, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now)
    });
}

#[test]
fn golden_transfers_add_link_refused() {
    let state = with_session();
    let mut view = TransfersView::by_name();
    view.handle_key(press(KeyCode::Char('L')), &state);
    typed(&mut view, &state, &bunny_link());
    view.handle_key(press(KeyCode::Enter), &state);
    let now = Instant::now();
    assert_golden_caret("transfers_add_link_refused", 100, 24, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now)
    });
}

/// A one-line frame has no room for the key legend; the page keys reach it
/// and typing pulls the field back.
#[test]
fn golden_transfers_add_link_scrolls_in_a_short_frame() {
    let state = with_session();
    let mut view = TransfersView::by_name();
    view.handle_key(press(KeyCode::Char('L')), &state);
    let shown = |view: &mut TransfersView| {
        crate::golden::render_to_lines(70, 4, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), Instant::now());
        })
    };
    assert_golden_caret("transfers_add_link_short", 70, 4, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), Instant::now())
    });
    assert!(!shown(&mut view).contains("cancel"));
    view.handle_key(press(KeyCode::PageDown), &state);
    assert!(shown(&mut view).contains("cancel"));
    typed(&mut view, &state, "e");
    assert!(shown(&mut view).contains("Link"), "{}", shown(&mut view));
}

/// With no download dir there is nowhere to land: the link stays typed with
/// the reason under it, and outlives the form, since setting one means
/// leaving it.
#[test]
fn a_link_with_no_download_dir_is_kept_until_there_is_one() {
    let mut state = three_downloads();
    state.session.download_dir = None;
    let mut view = TransfersView::new();
    view.open_add_link(&state);
    view.handle_paste(SKIPPING_LINK, &state);
    assert!(matches!(
        view.handle_key(press(KeyCode::Enter), &state),
        ViewOutcome::Redraw
    ));
    assert_eq!(
        refusal(&view),
        Some(words::link_refused(&LinkRefusal::NoDownloadDir).as_str())
    );

    view.handle_key(press(KeyCode::Esc), &state);
    assert!(view.add_link.is_none());
    state.session.download_dir = Some(PathBuf::from("/srv/downloads"));
    view.open_add_link(&state);
    let entry = view.add_link.as_ref().expect("the form");
    assert_eq!(entry.form.text(0), SKIPPING_LINK, "L brings the link back");
    assert_eq!(entry.form.error, None, "the reason has gone");
    assert!(matches!(
        view.handle_key(press(KeyCode::Enter), &state),
        ViewOutcome::Emit(_)
    ));
}

#[test]
fn a_form_cancelled_for_any_other_reason_leaves_nothing() {
    let state = with_session();
    let mut view = TransfersView::new();
    view.open_add_link(&state);
    view.handle_paste("not a link", &state);
    view.handle_key(press(KeyCode::Enter), &state);
    view.handle_key(press(KeyCode::Esc), &state);
    view.open_add_link(&state);
    assert_eq!(view.add_link.as_ref().expect("the form").form.text(0), "");
}
