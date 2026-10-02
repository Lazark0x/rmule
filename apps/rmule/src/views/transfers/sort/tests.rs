//! Unit tests for the downloads table's Table Sort: its ranks, directions, clicks and the cursor that follows its row.

use ratatui::crossterm::event::KeyCode;

use super::*;
use crate::action::Action;
use crate::config::PrefEdit;
use crate::fixture::*;
use crate::golden::{assert_golden, render_to_lines};
use crate::table_sort::Direction;
use crate::theme::Theme;

/// Draw at `width` × `height` and return the screen, so a click can aim
/// at what is actually on it.
fn draw(view: &mut TransfersView, state: &UiState, width: u16, height: u16) -> Vec<String> {
    render_to_lines(width, height, |frame| {
        view.draw(frame, frame.area(), state, &Theme::default_dark(), now());
    })
    .lines()
    .map(str::to_string)
    .collect()
}

/// The screen cell of `needle`'s first glyph, on the first line holding it.
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

fn order(view: &TransfersView, state: &UiState) -> Vec<u64> {
    let ids: Vec<DownloadId> = (1..=9).map(download_id).collect();
    view.download_ids(state)
        .into_iter()
        .map(|id| {
            ids.iter()
                .position(|known| *known == id)
                .map_or(0, |at| at as u64 + 1)
        })
        .collect()
}

fn sort_to(view: &mut TransfersView, state: &UiState, column: DownloadColumn) {
    while view.sort.column() != column {
        view.handle_key(press(KeyCode::Char('s')), state);
    }
}

fn selected(view: &mut TransfersView, state: &UiState) -> Option<DownloadId> {
    let ids = view.download_ids(state);
    view.cursor.place(&ids).map(|at| ids[at])
}

/// 1 is `bunny.mp4`, named, 42 % done, 6 of 10 parts lit, metered; 2 has
/// no name, no exact size and no part map; 3 has an exact size but no
/// name, and is complete.
#[test]
fn every_column_orders_by_its_value_and_a_dash_sorts_last_both_ways() {
    let state = three_downloads();
    let mut view = TransfersView::new();
    assert_eq!(
        order(&view, &state),
        [1, 2, 3],
        "name ascending, nameless last"
    );
    view.handle_key(press(KeyCode::Char('S')), &state);
    assert_eq!(order(&view, &state), [1, 2, 3], "and still last descending");

    let expect = [
        // Exact 92 MB, exact 45 MB, then the ≈ 27.8 MB estimate.
        (DownloadColumn::Size, [1, 3, 2], [2, 3, 1]),
        // The download moving bytes, then the completed one, then the
        // paused one with no share at all, whichever way.
        (DownloadColumn::Done, [1, 3, 2], [1, 3, 2]),
        (DownloadColumn::Progress, [1, 3, 2], [1, 3, 2]),
        // Only 1 moves; the dashes keep the bottom either way.
        (DownloadColumn::Speed, [1, 2, 3], [1, 2, 3]),
        (DownloadColumn::Eta, [1, 2, 3], [1, 2, 3]),
        // 3/8 over 1/1 over 0/2: usable first.
        (DownloadColumn::Sources, [1, 3, 2], [2, 3, 1]),
        // aMule's rank, its first click first: downloading, paused,
        // complete.
        (DownloadColumn::Status, [1, 2, 3], [3, 2, 1]),
    ];
    for (column, natural, reversed) in expect {
        sort_to(&mut view, &state, column);
        assert_eq!(
            view.sort.direction(),
            DownloadsTable::kind(column).natural_direction(),
            "{column:?}"
        );
        assert_eq!(order(&view, &state), natural, "{column:?} natural");
        view.handle_key(press(KeyCode::Char('S')), &state);
        assert_eq!(order(&view, &state), reversed, "{column:?} reversed");
    }
}

/// Status sorts by aMule's rank, which is not the order of its words in
/// any language this build ships: the labels, sorted as text, disagree.
#[test]
fn status_sorts_by_rank_not_by_its_label() {
    use super::super::downloads::status_label;
    let statuses = [
        DownloadStatus::Failed,
        DownloadStatus::Paused,
        DownloadStatus::Completed,
        DownloadStatus::Waiting,
        DownloadStatus::Downloading,
    ];
    let mut state = UiState::default();
    for (at, status) in statuses.iter().enumerate() {
        let id = download_id(at as u64 + 1);
        state
            .downloads
            .insert(id, download_row(*status, at as u8 + 1, 1));
    }
    let mut view = TransfersView::new();
    sort_to(&mut view, &state, DownloadColumn::Status);
    let shown: Vec<DownloadStatus> = view
        .download_ids(&state)
        .iter()
        .map(|id| state.downloads[id].status)
        .collect();
    assert_eq!(
        shown,
        [
            DownloadStatus::Downloading,
            DownloadStatus::Waiting,
            DownloadStatus::Paused,
            DownloadStatus::Completed,
            DownloadStatus::Failed,
        ]
    );
    let mut by_label = shown.clone();
    by_label.sort_by_key(|status| status_label(*status));
    assert_ne!(shown, by_label, "the rank must not be the labels' order");
}

/// One download in each state, each with a share that would put it
/// elsewhere if the number alone decided: Progress and Done group the
/// downloads moving bytes, then the completed, then the running ones
/// moving none (waiting, no network), then those at rest (paused,
/// failed), and `S` reverses the share inside each group, never the
/// groups.
#[test]
fn progress_and_done_rank_the_activity_before_the_share_in_both_directions() {
    // (id, status, parts: `V` held, `I` in flight, `M` missing)
    let rows = [
        (1, DownloadStatus::Downloading, "VIMMMMMMMM"),
        (2, DownloadStatus::Downloading, "VVVVVVVIMM"),
        (3, DownloadStatus::Completed, "VVVVVVVVVV"),
        (4, DownloadStatus::Waiting, "VVVVVVVVMM"),
        (5, DownloadStatus::Paused, "VVVVVVVVVM"),
        (6, DownloadStatus::Failed, "VVMMMMMMMM"),
        (7, DownloadStatus::NoConnection, "VVVMMMMMMM"),
    ];
    let mut state = UiState::default();
    for (n, status, parts) in rows {
        let id = download_id(n);
        let mut row = download_row(status, n as u8, parts.len());
        row.metadata = Some(metadata(
            &format!("file{n}"),
            parts.len() as u64 * ED2K_PART_SIZE,
            rmule_core::DownloadMetadataOrigin::Link,
        ));
        state.downloads.insert(id, row);
        state
            .diagnostics
            .downloads
            .insert(id, diag(id, n as u8, parts, 0, Vec::new()));
    }
    let mut view = TransfersView::new();
    for column in [DownloadColumn::Progress, DownloadColumn::Done] {
        sort_to(&mut view, &state, column);
        assert_eq!(view.sort.direction(), Direction::Descending);
        assert_eq!(
            order(&view, &state),
            [2, 1, 3, 4, 7, 5, 6],
            "{column:?} natural"
        );
        view.handle_key(press(KeyCode::Char('S')), &state);
        assert_eq!(
            order(&view, &state),
            [1, 2, 3, 7, 4, 6, 5],
            "{column:?} reversed"
        );
    }
}

/// ETA sorts by the estimate in seconds. A download too slow to estimate
/// (`file2`, named between the others) and one with no measured run
/// (`file4`) have no estimate, and sit at the bottom in both directions, in
/// the Tie Chain's name order.
#[test]
fn eta_sorts_by_seconds_and_no_estimate_sits_last_both_ways() {
    // (id, speed averaged over the window, bytes/sec)
    let rows = [
        (1, Some(100.0 * 1024.0)),
        (2, Some(500.0)),
        (3, Some(1024.0 * 1024.0)),
        (4, None),
    ];
    let mut state = UiState::default();
    for (n, avg) in rows {
        let id = download_id(n);
        let mut row = download_row(DownloadStatus::Downloading, n as u8, 10);
        row.metadata = Some(metadata(
            &format!("file{n}"),
            10 * ED2K_PART_SIZE,
            rmule_core::DownloadMetadataOrigin::Link,
        ));
        state.downloads.insert(id, row);
        state
            .diagnostics
            .downloads
            .insert(id, diag(id, n as u8, "MMMMMMMMMM", 0, Vec::new()));
        if let Some(avg) = avg {
            state.rates.download_avg_bps.insert(id, avg);
        }
    }
    let mut view = TransfersView::new();
    sort_to(&mut view, &state, DownloadColumn::Eta);
    assert_eq!(view.sort.direction(), Direction::Descending);
    assert_eq!(order(&view, &state), [1, 3, 2, 4], "longest first");
    view.handle_key(press(KeyCode::Char('S')), &state);
    assert_eq!(order(&view, &state), [3, 1, 2, 4], "shortest first");
}

#[test]
fn the_cursor_follows_its_download_as_rows_arrive_leave_and_reorder() {
    let mut state = three_downloads();
    let mut view = TransfersView::new();
    view.handle_key(press(KeyCode::Char('j')), &state); // onto 2
    assert_eq!(selected(&mut view, &state), Some(download_id(2)));

    // A download that sorts ahead of every row arrives.
    let mut early = download_row(DownloadStatus::Waiting, 0x11, 1);
    early.metadata = Some(metadata(
        "aardvark.iso",
        1,
        rmule_core::DownloadMetadataOrigin::Link,
    ));
    state.downloads.insert(download_id(4), early);
    draw(&mut view, &state, GOLDEN_W, GOLDEN_H);
    assert_eq!(view.table_state.selected(), Some(2));
    assert_eq!(selected(&mut view, &state), Some(download_id(2)));

    // The row above it leaves.
    state.downloads.remove(&download_id(1));
    draw(&mut view, &state, GOLDEN_W, GOLDEN_H);
    assert_eq!(selected(&mut view, &state), Some(download_id(2)));

    // A new sort moves it to the bottom: 3 is done, and neither 4 nor 2
    // has a share, so the Tie Chain puts the named 4 first.
    sort_to(&mut view, &state, DownloadColumn::Done);
    draw(&mut view, &state, GOLDEN_W, GOLDEN_H);
    assert_eq!(view.table_state.selected(), Some(2));
    assert_eq!(selected(&mut view, &state), Some(download_id(2)));

    // Its own departure leaves the cursor as low as the table now goes.
    state.downloads.remove(&download_id(2));
    draw(&mut view, &state, GOLDEN_W, GOLDEN_H);
    assert_eq!(selected(&mut view, &state), Some(download_id(4)));
}

#[test]
fn a_header_click_sorts_by_its_column_and_again_reverses_at_two_widths() {
    let state = three_downloads();
    for (width, height) in [(GOLDEN_W, GOLDEN_H), (62, 18)] {
        let mut view = TransfersView::new();
        let lines = draw(&mut view, &state, width, height);
        let (x, y) = cell_of(&lines, "Size");
        assert!(matches!(
            view.handle_click(x, y, &state),
            ViewOutcome::Emit(Action::Preference(PrefEdit::TableSort {
                table: "transfers",
                column: "size",
                direction: Direction::Descending,
            }))
        ));
        let lines = draw(&mut view, &state, width, height);
        let (x, y) = cell_of(&lines, "Size ▼");
        view.handle_click(x, y, &state);
        assert_eq!(view.sort.direction(), Direction::Ascending, "width {width}");
        let lines = draw(&mut view, &state, width, height);
        let (x, y) = cell_of(&lines, "Status");
        view.handle_click(x, y, &state);
        assert_eq!(view.sort.column(), DownloadColumn::Status, "width {width}");
    }
}

/// At the narrowest supported frame the header is one line whichever
/// column holds the sort, either way: the arrow never wraps a label.
#[test]
fn the_header_is_one_line_whichever_column_holds_the_sort() {
    let state = three_downloads();
    let mut view = TransfersView::new();
    for column in DownloadsTable::COLUMNS {
        sort_to(&mut view, &state, column.column);
        for _ in 0..2 {
            draw(&mut view, &state, 80, GOLDEN_H);
            assert_eq!(view.header_area.height, 1, "{column:?}");
            view.handle_key(press(KeyCode::Char('S')), &state);
        }
    }
}

#[test]
fn a_click_on_any_line_of_a_wrapped_row_selects_that_row() {
    let state = three_downloads();
    let mut view = TransfersView::new();
    // At 62 columns every row wraps onto a second line.
    let lines = draw(&mut view, &state, 62, 18);
    let (x, y) = cell_of(&lines, "5C5C5C5C");
    view.handle_click(x, y, &state);
    assert_eq!(selected(&mut view, &state), Some(download_id(3)));
    let (x, y) = cell_of(&lines, "ABABABAB");
    view.handle_click(x, y + 1, &state);
    assert_eq!(selected(&mut view, &state), Some(download_id(2)));
}

#[test]
fn golden_transfers_sorted_by_size() {
    let state = three_downloads();
    let mut view = TransfersView::new();
    sort_to(&mut view, &state, DownloadColumn::Size);
    assert_golden("transfers_sorted_size", GOLDEN_W, GOLDEN_H, |frame| {
        view.draw(frame, frame.area(), &state, &Theme::default_dark(), now());
    });
}
