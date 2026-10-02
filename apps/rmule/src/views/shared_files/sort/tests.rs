//! Unit tests for the shared-files table's Table Sort: its ranks, directions, clicks and cursor.

use std::time::Instant;

use ratatui::crossterm::event::KeyCode;

use super::*;
use crate::action::Action;
use crate::config::PrefEdit;
use crate::fixture::*;
use crate::golden::{assert_golden, render_to_lines};
use crate::table_sort::Direction;
use crate::views::human_size;

fn draw(view: &mut SharedView, state: &UiState, width: u16) -> Vec<String> {
    render_to_lines(width, GOLDEN_H, |frame| {
        view.draw(frame, frame.area(), state, &theme(), Instant::now());
    })
    .lines()
    .map(str::to_string)
    .collect()
}

fn cell_of(lines: &[String], needle: &str) -> (u16, u16) {
    lines
        .iter()
        .enumerate()
        .find_map(|(y, line)| {
            let at = line.find(needle)?;
            let x = line[..at].chars().count();
            Some((u16::try_from(x).ok()?, u16::try_from(y).ok()?))
        })
        .unwrap_or_else(|| panic!("{needle} not on screen:\n{}", lines.join("\n")))
}

/// One shared file as the table reads it: its registry name and size
/// (`None` for a row an edge opened since the last File History answer),
/// its slot holders, and the run's request and byte counters.
struct File {
    hash: u8,
    named: Option<(&'static str, u64)>,
    uploading: u8,
    requests: u64,
    accepted: u64,
    transferred: u64,
}

fn shared(files: &[File]) -> UiState {
    let mut state = UiState {
        last_snapshot_at: Some(Instant::now()),
        ..UiState::default()
    };
    for file in files {
        let hash = file_hash(file.hash);
        state.shared.insert(
            hash,
            SharedRow {
                file_hash: hash,
                path: file
                    .named
                    .map(|(name, _)| std::path::Path::new("/dl").join(name)),
                file_size: file.named.map(|(_, size)| size),
                withheld: None,
            },
        );
        for slot in 0..file.uploading {
            let peer = peer_endpoint(file.hash * 10 + slot);
            state.upload_peers.insert(
                peer,
                crate::state::UploadPeer {
                    peer,
                    state: crate::state::UploadState::Uploading { file: hash },
                    software: None,
                },
            );
        }
        state.diagnostics.shared_files.insert(
            hash,
            rmule_core::diagnostics::SharedFileCounters {
                requests: file.requests,
                accepted: file.accepted,
                transferred: file.transferred,
                ..rmule_core::diagnostics::SharedFileCounters::default()
            },
        );
    }
    state
}

/// The first byte of each hash, in display order.
fn order(view: &SharedView, state: &UiState) -> Vec<u8> {
    view.file_ids(state)
        .into_iter()
        .map(|hash| hash.as_bytes()[0])
        .collect()
}

fn sort_to(view: &mut SharedView, state: &UiState, column: SharedColumn) {
    while view.sort.column() != column {
        view.handle_key(press(KeyCode::Char('s')), state);
    }
}

/// Three named files and one whose name is not known yet (4).
fn four() -> UiState {
    shared(&[
        File {
            hash: 3,
            named: Some(("charlie.image.name.iso", 300)),
            uploading: 2,
            requests: 5,
            accepted: 2,
            transferred: 1000,
        },
        File {
            hash: 1,
            named: Some(("alpha.film.name.mkv", 100)),
            uploading: 0,
            requests: 9,
            accepted: 6,
            transferred: 0,
        },
        File {
            hash: 2,
            named: Some(("bravo.song.name.mp3", 200)),
            uploading: 2,
            requests: 0,
            accepted: 0,
            transferred: 50,
        },
        File {
            hash: 4,
            named: None,
            uploading: 0,
            requests: 0,
            accepted: 0,
            transferred: 0,
        },
    ])
}

#[test]
fn every_column_orders_by_its_value_and_an_unknown_one_sorts_last() {
    let state = four();
    let mut view = SharedView::default();
    assert_eq!(order(&view, &state), [1, 2, 3, 4], "name ascending");
    view.handle_key(press(KeyCode::Char('S')), &state);
    assert_eq!(
        order(&view, &state),
        [3, 2, 1, 4],
        "nameless last both ways"
    );

    let expect = [
        (SharedColumn::Size, [3, 2, 1, 4], [1, 2, 3, 4]),
        // The two 2s tie and fall to the name, whichever way.
        (SharedColumn::Uploading, [2, 3, 1, 4], [1, 4, 2, 3]),
        (SharedColumn::Requests, [1, 3, 2, 4], [2, 4, 3, 1]),
        // The two 0s (hash 2 and the nameless hash 4) tie; the nameless
        // one is last regardless, as an unknown name always is.
        (SharedColumn::Accepted, [1, 3, 2, 4], [2, 4, 3, 1]),
        (SharedColumn::Transferred, [3, 2, 1, 4], [1, 4, 2, 3]),
    ];
    for (column, natural, reversed) in expect {
        sort_to(&mut view, &state, column);
        assert_eq!(view.sort.direction(), Direction::Descending, "{column:?}");
        assert_eq!(order(&view, &state), natural, "{column:?} natural");
        view.handle_key(press(KeyCode::Char('S')), &state);
        assert_eq!(order(&view, &state), reversed, "{column:?} reversed");
    }
}

/// Each cell is the fact core reported, rendered: the registry's name and
/// size, the slot holders, the run's counters — and the file whose name
/// is not known yet shows its hash and dashes, not a zero size.
#[test]
fn a_row_shows_the_registrys_name_and_size_and_the_runs_counters() {
    let state = four();
    let mut view = SharedView::default();
    // Wide enough that every column keeps its declared floor (the
    // seven-column set needs 104), so all four rows fit without
    // scrolling — this test is about cell content, not column widths.
    let lines = draw(&mut view, &state, 110);
    let row = |needle: &str| -> Vec<String> {
        let line = lines
            .iter()
            .find(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("{needle} not drawn:\n{}", lines.join("\n")));
        line.split_whitespace().map(str::to_string).collect()
    };
    let charlie = row("charlie").join(" ");
    for cell in [human_size(300), "2 5".to_string(), human_size(1000)] {
        assert!(charlie.contains(&cell), "{cell} in {charlie}");
    }
    let unknown = row("0404");
    assert!(unknown.contains(&"—".to_string()), "{unknown:?}");
    assert!(
        lines[0].contains("4 files · —"),
        "a total needs every size: {}",
        lines[0]
    );
}

fn withhold(state: &mut UiState, byte: u8, reason: rmule_core::WithheldReason) {
    state
        .shared
        .get_mut(&file_hash(byte))
        .expect("a row")
        .withheld = Some(Withheld {
        reason,
        // Noon UTC, so the local day drawn is the same in almost every
        // zone a golden runs in.
        since: std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_789_992_000),
    });
}

/// State renders words but sorts by rank: offered, missing, changed,
/// folder missing, unreadable — not "folder…", "missing", "shared",
/// "unreadable" as the words would.
#[test]
fn state_sorts_by_rank_not_by_its_words() {
    use rmule_core::WithheldReason as R;
    let mut state = four();
    withhold(
        &mut state,
        1,
        R::Unreadable(std::io::ErrorKind::PermissionDenied),
    );
    withhold(&mut state, 2, R::FolderMissing);
    withhold(&mut state, 3, R::Missing);
    let mut view = SharedView::default();
    sort_to(&mut view, &state, SharedColumn::State);
    assert_eq!(view.sort.direction(), Direction::Ascending);
    assert_eq!(order(&view, &state), [4, 3, 2, 1]);
}

/// Accepted orders by this run's count, then the all-time one — before
/// the Tie Chain's name. Two files tie on the run figure; the
/// all-time figure breaks it in the OPPOSITE order name-ascending would,
/// proving the tie is not falling through to the Tie Chain.
#[test]
fn accepted_ties_break_on_the_all_time_figure_before_the_name() {
    let mut state = shared(&[
        File {
            hash: 1,
            named: Some(("aaa.txt", 10)),
            uploading: 0,
            requests: 0,
            accepted: 3,
            transferred: 0,
        },
        File {
            hash: 2,
            named: Some(("zzz.txt", 10)),
            uploading: 0,
            requests: 0,
            accepted: 3,
            transferred: 0,
        },
    ]);
    state
        .diagnostics
        .shared_files
        .get_mut(&file_hash(1))
        .expect("counted")
        .all_time
        .accepted = 1;
    state
        .diagnostics
        .shared_files
        .get_mut(&file_hash(2))
        .expect("counted")
        .all_time
        .accepted = 10;
    let mut view = SharedView::default();
    sort_to(&mut view, &state, SharedColumn::Accepted);
    assert_eq!(view.sort.direction(), Direction::Descending);
    // "zzz" (all-time 10) orders before "aaa" (all-time 1) though name
    // ascending would say the opposite.
    assert_eq!(order(&view, &state), [2, 1]);
    view.handle_key(press(KeyCode::Char('S')), &state);
    assert_eq!(order(&view, &state), [1, 2]);
}

#[test]
fn golden_shared_withheld() {
    let mut state = four();
    withhold(&mut state, 2, rmule_core::WithheldReason::FolderMissing);
    let mut view = SharedView::default();
    assert_golden("shared_withheld", GOLDEN_W, GOLDEN_H, |frame| {
        view.draw(frame, frame.area(), &state, &theme(), Instant::now());
    });
}

#[test]
fn the_cursor_follows_its_file_as_rows_arrive_leave_and_reorder() {
    let mut state = four();
    state.shared.remove(&file_hash(4));
    let mut view = SharedView::default();
    view.handle_key(press(KeyCode::Char('j')), &state); // onto 2
    let selected = |view: &mut SharedView, state: &UiState| {
        view.clamp_selection(state);
        order(view, state)[view.files_selected]
    };

    // A file that sorts ahead of every row arrives.
    state.shared.insert(
        file_hash(0),
        SharedRow {
            file_hash: file_hash(0),
            path: Some("/dl/aaa.txt".into()),
            file_size: Some(1),
            withheld: None,
        },
    );
    draw(&mut view, &state, GOLDEN_W);
    assert_eq!(view.files_selected, 2);
    assert_eq!(selected(&mut view, &state), 2);

    state.shared.remove(&file_hash(1));
    draw(&mut view, &state, GOLDEN_W);
    assert_eq!(selected(&mut view, &state), 2);

    // Its request count climbs past every other: a requests sort puts it
    // on top.
    sort_to(&mut view, &state, SharedColumn::Requests);
    state
        .diagnostics
        .shared_files
        .get_mut(&file_hash(2))
        .expect("counted")
        .requests = 50;
    draw(&mut view, &state, GOLDEN_W);
    assert_eq!(view.files_selected, 0);
    assert_eq!(selected(&mut view, &state), 2);
}

#[test]
fn a_header_click_sorts_by_its_column_and_again_reverses_at_two_widths() {
    let state = four();
    for width in [GOLDEN_W, 66] {
        let mut view = SharedView::default();
        let lines = draw(&mut view, &state, width);
        let (x, y) = cell_of(&lines, "Request");
        assert!(matches!(
            view.handle_click(x, y, &state),
            ViewOutcome::Emit(Action::Preference(PrefEdit::TableSort {
                table: "shared",
                column: "requests",
                direction: Direction::Descending,
            }))
        ));
        view.handle_click(x, y, &state);
        assert_eq!(view.sort.direction(), Direction::Ascending, "width {width}");
        let lines = draw(&mut view, &state, width);
        // The gutter's two blanks tell the header from the title's "Files".
        let (x, y) = cell_of(&lines, "  File");
        view.handle_click(x + 2, y, &state);
        assert_eq!(view.sort.column(), SharedColumn::File, "width {width}");
    }
}

#[test]
fn a_click_on_any_line_of_a_wrapped_row_selects_that_row() {
    let state = four();
    let mut view = SharedView::default();
    // At 64 columns the File column is too narrow for a name: every
    // named row wraps over several lines. A taller pane than the usual
    // golden height keeps every row on screen despite the wrap — this
    // test is about wrapped-row clicking, not scrolling.
    let lines = render_to_lines(64, 40, |frame| {
        view.draw(frame, frame.area(), &state, &theme(), Instant::now());
    })
    .lines()
    .map(str::to_string)
    .collect::<Vec<_>>();
    let (x, y) = cell_of(&lines, "charli");
    view.handle_click(x, y + 1, &state);
    assert_eq!(view.files_selected, 2, "{}", lines.join("\n"));
    let (x, y) = cell_of(&lines, "bravo");
    view.handle_click(x, y + 1, &state);
    assert_eq!(view.files_selected, 1);
}

#[test]
fn golden_shared_sorted_by_requests() {
    let state = four();
    let mut view = SharedView::default();
    sort_to(&mut view, &state, SharedColumn::Requests);
    assert_golden("shared_sorted_requests", GOLDEN_W, GOLDEN_H, |frame| {
        view.draw(frame, golden_area(), &state, &theme(), Instant::now());
    });
}
