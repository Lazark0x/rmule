//! Unit tests for the shared-files table: its columns, the run-and-all-time pairs, the Off-screen note and goldens.

use std::time::Instant;

use ratatui::crossterm::event::KeyCode;
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DurableSharedFileRegistry, ShareSource,
    SharedFileEntry, SharedFileRegistry, open_durable_store,
};

use super::*;
use crate::action::Action;
use crate::fixture::{GOLDEN_H, GOLDEN_W, file_hash, press, theme};
use crate::golden::{assert_golden, render_to_lines};
use crate::state::SharedRow;

fn screen(view: &mut SharedView, state: &UiState, width: u16, height: u16) -> String {
    render_to_lines(width, height, |frame| {
        view.draw(frame, frame.area(), state, &theme(), Instant::now());
    })
}

/// Wide enough that every column keeps its declared floor (the
/// Requests/Transferred pair floors alone need 88, and Accepted
/// raises that to 104) — tests here are about scrolling and restart
/// behaviour, not about how a narrow pane gives way.
const WIDE_W: u16 = 110;

/// The restart the human names: files an earlier run shared — as the
/// Download Directory Scan leaves them, never announced to this run —
/// are rows once the core over the same store answers the ask the app
/// sends at attach, each with its name and size.
#[tokio::test(flavor = "multi_thread")]
async fn files_shared_in_an_earlier_run_are_rows_after_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let film = dir.path().join("dl").join("film.mkv");
    {
        let registry = DurableSharedFileRegistry::new(
            open_durable_store(dir.path()).expect("store, first run"),
        );
        for (byte, path, size) in [
            (1, film.clone(), 734_003_200),
            (2, dir.path().join("dl/song.mp3"), 4_194_304),
        ] {
            registry
                .share(SharedFileEntry {
                    file_hash: file_hash(byte),
                    file_size: size,
                    name: path.file_name().unwrap().to_string_lossy().into_owned(),
                    path,
                    source: ShareSource::DownloadDirectory,
                    part_hashes: Vec::new(),
                    modified: None,
                })
                .expect("share");
        }
    }

    let mut core = Core::builder(
        CoreConfig::default(),
        open_durable_store(dir.path()).expect("store, second run"),
    )
    .settings(rmule_core::CoreSettings::default())
    .build();
    core.send(CoreCommand::DumpFileHistory).await.expect("ask");
    let mut state = UiState::default();
    loop {
        let event = core.next_event().await.expect("core answers");
        let answered = matches!(event, CoreEvent::FileHistory { .. });
        state.apply(Action::Core(event), Instant::now());
        if answered {
            break;
        }
    }
    core.shutdown().await;

    let mut view = SharedView::default();
    let drawn = screen(&mut view, &state, WIDE_W, GOLDEN_H);
    assert!(drawn.contains("2 files"), "{drawn}");
    for (name, size) in [("film.mkv", 734_003_200), ("song.mp3", 4_194_304)] {
        let row = drawn
            .lines()
            .find(|line| line.contains(name))
            .unwrap_or_else(|| panic!("{name} not a row:\n{drawn}"));
        assert!(row.contains(&human_size(size)), "{row}");
    }
}

/// More files than the pane has lines: moving the selection past the
/// bottom scrolls the table so the selected row is always drawn, and
/// moving back up past the top scrolls it back.
#[test]
fn the_table_scrolls_to_keep_the_selection_on_screen() {
    let mut state = UiState::default();
    for byte in 1..=30u8 {
        state.shared.insert(
            file_hash(byte),
            SharedRow {
                file_hash: file_hash(byte),
                path: Some(format!("/dl/file-{byte:02}.bin").into()),
                file_size: Some(u64::from(byte)),
                withheld: None,
            },
        );
    }
    let mut view = SharedView::default();
    for _ in 0..29 {
        view.handle_key(press(KeyCode::Char('j')), &state);
        let drawn = screen(&mut view, &state, WIDE_W, GOLDEN_H);
        let marked = drawn.lines().find(|line| line.contains('▸'));
        let expected = format!("file-{:02}.bin", view.files_selected + 1);
        assert!(
            marked.is_some_and(|line| line.contains(&expected)),
            "{expected} selected but not drawn:\n{drawn}"
        );
    }
    view.handle_key(press(KeyCode::Char('g')), &state);
    let drawn = screen(&mut view, &state, WIDE_W, GOLDEN_H);
    assert!(
        drawn
            .lines()
            .any(|line| line.contains('▸') && line.contains("file-01.bin")),
        "{drawn}"
    );
}

#[test]
fn golden_shared_named() {
    let mut state = crate::fixture::served_files();
    for (byte, path, size) in [
        (1, "/dl/film.mkv", 734_003_200),
        (2, "/dl/song.mp3", 4_194_304),
    ] {
        let row = state.shared.get_mut(&file_hash(byte)).expect("shared");
        row.path = Some(path.into());
        row.file_size = Some(size);
    }
    let mut view = SharedView::default();
    assert_golden("shared_named", GOLDEN_W, GOLDEN_H, |frame| {
        view.draw(frame, frame.area(), &state, &theme(), Instant::now());
    });
}

/// A file at its realistic widest (six-digit requests and
/// accepted counts, a near-terabyte transfer) — the pair that must not
/// split across two lines.
fn wide_figures_state() -> UiState {
    let mut state = crate::fixture::served_files();
    let row = state.shared.get_mut(&file_hash(1)).expect("shared");
    row.path = Some("/dl/film.mkv".into());
    row.file_size = Some(734_003_200);
    state.diagnostics.shared_files.insert(
        file_hash(1),
        rmule_core::diagnostics::SharedFileCounters {
            requests: 123_456,
            accepted: 111_222,
            transferred: 500 * 1_073_741_824,
            all_time: rmule_core::diagnostics::ShareTotals {
                requests: 654_321,
                accepted: 333_444,
                transferred: 999 * 1_073_741_824,
            },
        },
    );
    state
}

/// At 80 columns the declared floors (94 + 6 gaps + the gutter + the
/// border = 104) do not fit: the run-and-all-time pair drops its
/// all-time figure rather than wrapping, and the dropped
/// figures reprint in full, wrapped, on the "Off-screen:" note under the
/// header.
#[test]
fn golden_shared_wide_figures_too_narrow() {
    let state = wide_figures_state();
    let mut view = SharedView::default();
    assert_golden("shared_wide_figures_too_narrow", 80, GOLDEN_H, |frame| {
        view.draw(frame, frame.area(), &state, &theme(), Instant::now());
    });
}

/// At 120 columns every floor fits: the same pair stays whole, on one
/// line, right-aligned, never a wrapped, overprinted pair.
#[test]
fn golden_shared_wide_figures_fit_one_line() {
    let state = wide_figures_state();
    let mut view = SharedView::default();
    assert_golden("shared_wide_figures_fit_one_line", 120, GOLDEN_H, |frame| {
        view.draw(frame, frame.area(), &state, &theme(), Instant::now());
    });
}
