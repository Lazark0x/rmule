//! Unit tests for the downloads table and its cell vocabulary, with goldens.

use crate::golden::assert_golden;

use super::super::sort::{DownloadColumn, DownloadLine};
use super::*;
use crate::fixture::*;
use rmule_core::DownloadEvent;

/// The line a row reads with the diagnostics beside it, as a table would
/// draw it.
fn line_of(row: Option<&DownloadRow>, diag: Option<&DownloadDiagnostics>) -> DownloadLine {
    let mut state = UiState::default();
    let id = download_id(1);
    state.downloads.extend(row.map(|row| (id, row.clone())));
    state
        .diagnostics
        .downloads
        .extend(diag.map(|diag| (id, diag.clone())));
    DownloadLine::new(id, &state)
}

fn done_cell(row: Option<&DownloadRow>, diag: Option<&DownloadDiagnostics>) -> String {
    line_of(row, diag).done_cell()
}

/// Both Speed columns are real: the download's from its own
/// monotonic total, a source's from the level its slot carries. A worker
/// that is not receiving has no meter, so its cell stays an honest dash.
#[test]
fn both_speed_columns_meter_what_is_moving_and_dash_what_is_not() {
    let mut view = TransfersView::new();
    let state = three_downloads();
    let rendered = crate::golden::render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
        view.draw(frame, frame.area(), &state, &Theme::default_dark(), now());
    });
    let row = |needle: &str| {
        rendered
            .lines()
            .find(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("no row for {needle} in\n{rendered}"))
            .to_string()
    };
    // Downloads table: the active row carries its per-download rate, the
    // two rows with no rate carry dashes. download_id(1) has real metadata, so it
    // is found by its name now, not the hash stub.
    let active = row("bunny.mp4");
    assert!(active.contains("123.4 KB/s"), "download meter: {active}");
    let paused = row("ABABABABAB…");
    assert!(
        !paused.contains("KB/s"),
        "no rate ⇒ no invented one: {paused}"
    );
    // Sources pane: the receiving worker is metered, the queued one is not.
    let receiving = row("10.0.0.1:4662");
    assert!(receiving.contains("98.7 KB/s"), "source meter: {receiving}");
    let waiting = row("10.0.0.2:4662");
    assert!(
        !waiting.contains("KB/s"),
        "an idle slot has no meter: {waiting}"
    );
}

/// The fallback matrix: real metadata (id 1), no metadata yet
/// (id 2), and metadata known but nameless (id 3) each render honestly —
/// nothing invented, nothing left on the stale approximation once the
/// real fact exists.
#[test]
fn download_rows_show_real_names_exact_sizes_and_byte_based_done_percent() {
    let mut view = TransfersView::new();
    let state = three_downloads();
    let rendered = crate::golden::render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
        view.draw(frame, frame.area(), &state, &Theme::default_dark(), now());
    });
    let row = |needle: &str| {
        rendered
            .lines()
            .find(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("no row for {needle} in\n{rendered}"))
            .to_string()
    };
    // download_id(1): real name, exact size (not the old ≈ part-count estimate),
    // and a byte-based Done % — 42%, not the old 40% part-count ratio,
    // because the file's last part is short of a full ED2K_PART_SIZE.
    let named = row("bunny.mp4");
    assert!(
        named.contains("87.7 MB") && !named.contains('≈'),
        "exact size: {named}"
    );
    assert!(named.contains("42%"), "byte-based done: {named}");
    // download_id(2): no metadata edge landed — honest fallbacks survive unchanged.
    // Its part map has not landed either, so Done has nothing to divide:
    // `—`, not a 0% that would read as "started and getting nowhere".
    let stub = row("ABABABABAB…");
    assert!(stub.contains("≈ 27.8 MB"), "approx size fallback: {stub}");
    assert!(
        !stub.contains('%'),
        "no part map, so no done reading: {stub}"
    );
    // download_id(3): metadata known but nameless (Unknown origin) — the name
    // still falls back to the hash stub, but the size is exact (still a
    // real fact) and Done % is byte-based (100%: every part verified).
    let unnamed = row("5C5C5C5C5C…");
    assert!(
        unnamed.contains("42.9 MB") && !unnamed.contains('≈'),
        "exact size, no name: {unnamed}"
    );
    assert!(
        unnamed.contains("100%"),
        "byte-based done reaches 100 exactly: {unnamed}"
    );
}

/// Done and ETA read exact bytes. A running download's short last part
/// counts only its own length (the part count times the part size said
/// 80 % here); a paused one, with no part map, reads what its edges
/// restored and verified since; a completed one is whole; and a row with
/// neither a size nor a map has no reading.
#[test]
fn done_and_eta_read_exact_bytes_with_or_without_a_live_part_map() {
    use rmule_core::DownloadMetadataOrigin::Link;
    let half = ED2K_PART_SIZE / 2;
    let size = 2 * ED2K_PART_SIZE + half;
    let mut running = download_row(DownloadStatus::Downloading, 0x07, 3);
    running.metadata = Some(metadata("film.mkv", size, Link));
    let map = diag(download_id(1), 0x07, "VMV", 0, vec![]);
    assert_eq!(
        done_fraction(Some(&running), Some(&map)),
        Some((ED2K_PART_SIZE + half, size))
    );
    assert_eq!(done_cell(Some(&running), Some(&map)), "60%");
    // One part left at one part a second.
    assert_eq!(
        row_eta(Some(&running), Some(&map), Some(ED2K_PART_SIZE as f64)),
        Eta::Left(1)
    );

    let mut state = UiState::default();
    let id = download_id(2);
    for event in [
        DownloadEvent::DownloadRecovered {
            download_id: id,
            state: rmule_core::DownloadLifecycle::Paused,
            failure: None,
            file_hash: file_hash(0x08),
            metadata: metadata("song.mp3", size, Link),
            file_path: crate::fixture::part_file(),
        },
        DownloadEvent::DownloadProgressRestored {
            download_id: id,
            verified_parts: 1,
            verified_bytes: ED2K_PART_SIZE,
        },
        DownloadEvent::PartVerified {
            download_id: id,
            part_index: 2,
        },
    ] {
        crate::state::fold(&mut state, download_event(event));
    }
    let paused = state.downloads.get(&id);
    assert_eq!(
        done_cell(paused, None),
        "60%",
        "restored + the short last part"
    );

    let mut completed = download_row(DownloadStatus::Completed, 0x09, 3);
    completed.metadata = Some(metadata("done.iso", size, Link));
    assert_eq!(done_cell(Some(&completed), None), "100%");
    assert_eq!(
        row_eta(Some(&completed), None, Some(1_000_000.0)),
        Eta::Unknown
    );

    let bare = DownloadRow {
        metadata: None,
        ..download_row(DownloadStatus::Waiting, 0x0A, 3)
    };
    assert_eq!(done_cell(Some(&bare), None), "—");
    let ratio = diag(download_id(3), 0x0A, "VMM", 0, vec![]);
    assert_eq!(
        done_cell(Some(&bare), Some(&ratio)),
        "33%",
        "the part ratio without a size"
    );
}

/// Src is the level core republishes — every source the run knows, from
/// any surface — with the ones sending now in parentheses; a download
/// that is not running holds none and dashes, rather than repeating the
/// last server answer.
#[test]
fn the_sources_cell_counts_what_the_run_knows_and_who_is_sending() {
    let receiving = WorkerPhase::ReceivingPart {
        part_index: 0,
        bytes_received: 1,
    };
    let mut running = diag(
        download_id(1),
        0x07,
        "MM",
        0,
        vec![
            worker(0, receiving, Some(peer_endpoint(1))),
            worker(1, WorkerPhase::WaitingForSlot, Some(peer_endpoint(2))),
        ],
    );
    running.known_sources = 12;
    assert_eq!(line_of(None, Some(&running)).sources_cell(), "12 (1)");
    running.workers.clear();
    assert_eq!(line_of(None, Some(&running)).sources_cell(), "12");
    assert_eq!(line_of(None, None).sources_cell(), "—");
}

/// A paused download draws the parts it holds and the ones it
/// misses, nothing in flight — core keeps its part picture at rest — and a
/// completed one beside it is a solid bar, where any partial one shows at
/// least one `░` (a bucket reads held only when every part in it is). The
/// two shapes differ without colour.
#[test]
fn golden_a_paused_partial_bar_beside_a_completed_one() {
    let mut view = TransfersView::new();
    let mut state = three_downloads();
    let paused = download_id(2);
    state
        .downloads
        .get_mut(&paused)
        .expect("paused row")
        .part_count = Some(10);
    state
        .diagnostics
        .downloads
        .insert(paused, diag(paused, 0xAB, "VVMVMMVVMM", 0, vec![]));
    let rendered = crate::golden::render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
        view.draw(frame, frame.area(), &state, &Theme::default_dark(), now());
    });
    let row = |needle: &str| {
        rendered
            .lines()
            .find(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("no row for {needle} in\n{rendered}"))
            .to_string()
    };
    assert!(row("ABABABABAB…").contains("██░█░░██░░"), "{rendered}");
    let completed = row("Completed");
    assert!(completed.contains("██████████"), "{completed}");
    assert!(!completed.contains('░'), "{completed}");
    assert_golden(
        "transfers_paused_beside_completed",
        GOLDEN_W,
        GOLDEN_H,
        |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now());
        },
    );
}

/// Under 1 KiB/s averaged, or past 30 days, there is no estimate worth a
/// number; nothing left, or no measured run, keeps the dash.
#[test]
fn an_eta_too_slow_to_mean_anything_says_so() {
    let day = 86_400;
    let kib = 1024.0;
    assert_eq!(
        eta(Some(1024 * 60), Some(kib)),
        Eta::Left(60),
        "the floor itself estimates"
    );
    assert_eq!(eta(Some(1024 * 60), Some(kib - 1.0)), Eta::TooSlow);
    assert_eq!(
        eta(Some(1024 * 60), Some(0.0)),
        Eta::TooSlow,
        "a stalled run"
    );
    assert_eq!(
        eta(Some(1024 * 30 * day), Some(kib)),
        Eta::Left(30 * day),
        "the ceiling itself estimates"
    );
    assert_eq!(eta(Some(1024 * (30 * day + 1)), Some(kib)), Eta::TooSlow);
    assert_eq!(eta(Some(0), Some(kib)), Eta::Unknown, "nothing left");
    assert_eq!(eta(Some(1024), None), Eta::Unknown, "no measured run");
    assert_eq!(eta_cell(Eta::TooSlow), ETA_TOO_SLOW);
    assert_eq!(eta_cell(Eta::Unknown), "—");
    assert_eq!(Eta::TooSlow.seconds(), None, "sorts as a missing value");
}

/// The status is the fact, not the meter: the tick a download is paused, its
/// Speed reads 0 and its ETA the dash, though its meter and its minute's
/// average still hold the bytes it moved a moment ago.
#[test]
fn a_download_paused_this_tick_reads_no_speed_and_no_eta() {
    let mut state = three_downloads();
    let active = download_id(1);
    assert!(state.download_speed(active) > 0.0);
    assert!(state.download_eta_speed(active).is_some());

    crate::state::fold(
        &mut state,
        download_event(DownloadEvent::DownloadPaused {
            download_id: active,
        }),
    );
    assert!(
        state.rates.download_bps[&active] > 0.0,
        "the meter still holds bytes"
    );
    assert_eq!(state.download_speed(active), 0.0);
    assert_eq!(state.download_eta_speed(active), None);
    let values = DownloadLine::new(active, &state).values(&Theme::default_dark());
    assert_eq!(values[5], "—", "ETA: {values:?}");
    assert!(!values[4].contains("KB/s"), "Speed: {values:?}");

    for stopped in [download_id(2), download_id(3)] {
        state.rates.download_bps.insert(stopped, 50.0 * 1024.0);
        state.rates.download_avg_bps.insert(stopped, 50.0 * 1024.0);
        assert_eq!(state.download_speed(stopped), 0.0);
        assert_eq!(state.download_eta_speed(stopped), None);
    }
}

/// A download paused a moment ago, its meter still full: the row reads no
/// speed and no estimate, the same as a row paused for an hour.
#[test]
fn golden_transfers_just_paused_row() {
    let mut view = TransfersView::new();
    let mut state = three_downloads();
    crate::state::fold(
        &mut state,
        download_event(DownloadEvent::DownloadPaused {
            download_id: download_id(1),
        }),
    );
    assert_golden("transfers_just_paused_row", GOLDEN_W, GOLDEN_H, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now());
    });
}

/// The active download's sources went quiet: its minute-long average fell
/// under the floor, so its ETA says so instead of a count of days.
#[test]
fn golden_transfers_stalled_row() {
    let mut view = TransfersView::new();
    let mut state = three_downloads();
    state.rates.download_bps.insert(download_id(1), 0.0);
    state.rates.download_avg_bps.insert(download_id(1), 300.0);
    assert_golden("transfers_stalled_row", GOLDEN_W, GOLDEN_H, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now());
    });
}

#[test]
fn golden_wrap_narrow_frame_grows_rows_instead_of_cutting_cells() {
    // A pane too narrow for the name column and a rate too wide for the
    // Speed column: both wrap down rather than being clipped.
    let mut view = TransfersView::new();
    let mut state = three_downloads();
    state
        .rates
        .download_bps
        .insert(download_id(1), 12_345.6 * 1024.0);
    assert_golden("transfers_wrap_narrow", 62, 18, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now());
    });
}

/// Both panes too narrow for every header give columns away in
/// their stated orders and say which, rather than splitting a header.
#[test]
fn golden_transfers_narrow_headers_whole() {
    let mut view = TransfersView::new();
    let state = three_downloads();
    assert_golden("transfers_narrow_headers", 30, 18, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now());
    });
}

#[test]
fn an_overwide_cell_grows_the_row_and_keeps_every_character() {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    let mut view = TransfersView::new();
    let mut state = three_downloads();
    // 12345.6 KB/s is 12 chars in a 10-wide Speed column.
    state
        .rates
        .download_bps
        .insert(download_id(1), 12_345.6 * 1024.0);
    let mut terminal = Terminal::new(TestBackend::new(GOLDEN_W, GOLDEN_H)).expect("terminal");
    terminal
        .draw(|frame| view.draw(frame, frame.area(), &state, &Theme::default_dark(), now()))
        .expect("draw");
    let buffer = terminal.backend().buffer();
    let rows: Vec<String> = (0..GOLDEN_H)
        .map(|y| {
            (0..GOLDEN_W)
                .map(|x| buffer.cell((x, y)).map_or(" ", |cell| cell.symbol()))
                .collect::<String>()
        })
        .collect();
    // The rate wraps at its space: "12345.6" then "KB/s" on the row below.
    let head = rows
        .iter()
        .position(|row| row.contains("12345.6"))
        .unwrap_or_else(|| panic!("rate head missing:\n{}", rows.join("\n")));
    assert!(
        rows[head + 1].contains("KB/s"),
        "the rate tail was clipped, not wrapped:\n{}",
        rows.join("\n")
    );
}

#[test]
fn golden_wrap_long_download_name() {
    let mut view = TransfersView::new();
    let state = state_with_named_download(&long_name());
    assert_golden(
        "transfers_wrap_long_name",
        WRAP_LONG_NAME_W,
        WRAP_LONG_NAME_H,
        |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now());
        },
    );
}

#[test]
fn a_long_real_name_wraps_whole_instead_of_being_cut() {
    let name = long_name();
    assert_eq!(name.chars().count(), 200);
    let mut view = TransfersView::new();
    let state = state_with_named_download(&name);
    let rendered = crate::golden::render_to_lines(WRAP_LONG_NAME_W, WRAP_LONG_NAME_H, |frame| {
        view.draw(frame, frame.area(), &state, &Theme::default_dark(), now());
    });
    // Scoped to the downloads box: the unrelated
    // Sources pane title still renders its own short-hash stand-in,
    // ellipsis and all — that is not the truncation this test guards.
    let downloads_box: String = rendered
        .lines()
        .take_while(|line| !line.contains("Sources"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        downloads_box.contains("END-OF-NAME.iso"),
        "the 200-char name was cut:\n{rendered}"
    );
    assert!(
        !downloads_box.contains('…'),
        "an ellipsis crept back in:\n{rendered}"
    );
}

/// Downloads waiting for sources say who can still find them one: the first,
/// once its server session ended with Kad off, reads "No network" and its
/// Sources pane says it waits for a session or Kad; the second, with Kad
/// asking alone, reads "Asking Kad". Folded from the events core sends.
#[test]
fn golden_transfers_waiting_with_no_session() {
    let mut view = TransfersView::new();
    let state = waiting_downloads();
    assert_golden(
        "transfers_waiting_no_session",
        GOLDEN_W,
        GOLDEN_H,
        |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now());
        },
    );
}

/// A `DownloadLine`'s sort values and its cell text say the same thing
/// about a row, edge case by edge case: an unknown size,
/// the part-count estimate, a nameless exact size, a share the row cannot
/// exceed, and every status the cell can word, a completing move's steps
/// among them.
#[test]
fn sort_values_and_cell_text_agree_for_every_edge_case() {
    use crate::table_sort::SortValue;
    use rmule_core::DownloadMetadataOrigin::{Link, Unknown};
    use rmule_core::diagnostics::CompletionProgress;
    use rmule_core::{CompletionStep, SourceWait};

    let size = 2 * ED2K_PART_SIZE + 1_000;
    let mut state = UiState::default();
    let mut add = |n: u64, row: DownloadRow| state.downloads.insert(download_id(n), row);
    add(
        1,
        DownloadRow {
            part_count: None,
            ..download_row(DownloadStatus::Waiting, 1, 0)
        },
    );
    add(2, download_row(DownloadStatus::Waiting, 2, 3));
    add(
        3,
        DownloadRow {
            metadata: Some(metadata("", size, Unknown)),
            ..download_row(DownloadStatus::Paused, 3, 3)
        },
    );
    add(
        4,
        DownloadRow {
            metadata: Some(metadata("over.bin", size, Link)),
            verified_bytes: size * 10,
            ..download_row(DownloadStatus::Paused, 4, 3)
        },
    );
    add(
        5,
        DownloadRow {
            metadata: Some(metadata("done.bin", size, Link)),
            ..download_row(DownloadStatus::Completed, 5, 3)
        },
    );
    add(
        6,
        DownloadRow {
            metadata: Some(metadata("empty.bin", 0, Link)),
            ..download_row(DownloadStatus::Waiting, 6, 3)
        },
    );
    add(7, download_row(DownloadStatus::NoConnection, 7, 3));
    add(
        8,
        DownloadRow {
            source_wait: Some(SourceWait::KadAlone),
            ..download_row(DownloadStatus::Waiting, 8, 3)
        },
    );
    add(9, download_row(DownloadStatus::Failed, 9, 3));
    add(
        10,
        DownloadRow {
            metadata: Some(metadata("live.bin", size, Link)),
            ..download_row(DownloadStatus::Downloading, 10, 3)
        },
    );
    state
        .diagnostics
        .downloads
        .insert(download_id(10), diag(download_id(10), 10, "VMM", 0, vec![]));
    // Completing at three steps: renaming, held by a program, and 46 MiB
    // into its copy.
    for (n, step, copied) in [
        (11, CompletionStep::Moving, 0),
        (12, CompletionStep::WaitingForRelease, 0),
        (13, CompletionStep::Copying, 46 << 20),
    ] {
        state.downloads.insert(
            download_id(n),
            DownloadRow {
                metadata: Some(metadata("film.mkv", 92 << 20, Link)),
                ..download_row(DownloadStatus::Completing, n as u8, 10)
            },
        );
        let mut row = diag(download_id(n), n as u8, "VVVVVVVVVV", 0, vec![]);
        row.completion = Some(CompletionProgress { step, copied });
        state.diagnostics.downloads.insert(download_id(n), row);
    }

    let check = |state: &UiState, want: &[(u64, &str, u64)]| {
        for n in 1..=13 {
            let id = download_id(n);
            let line = DownloadLine::new(id, state);
            let cells = line.values(&Theme::default_dark());
            let value = |column| DownloadsTable::value(column, &line);

            match value(DownloadColumn::Done) {
                Some(SortValue::Fraction { part, whole }) => {
                    assert!(part <= whole, "row {n}: a share past the whole");
                    assert_eq!(cells[2], format!("{}%", part * 100 / whole), "row {n} Done");
                }
                None => assert_eq!(cells[2], "—", "row {n} Done"),
                other => panic!("row {n}: Done sorts as {other:?}"),
            }
            match value(DownloadColumn::Size) {
                Some(SortValue::Quantity(bytes)) => assert!(
                    [human_size(bytes), format!("≈ {}", human_size(bytes))].contains(&cells[1]),
                    "row {n} Size {} vs {bytes}",
                    cells[1]
                ),
                None => assert_eq!(cells[1], "—", "row {n} Size"),
                other => panic!("row {n}: Size sorts as {other:?}"),
            }
            if let Some(&(_, text, rank)) = want.iter().find(|(at, ..)| *at == n) {
                assert_eq!(cells[7], text, "row {n} Status");
                assert!(
                    matches!(value(DownloadColumn::Status), Some(SortValue::Quantity(r)) if r == rank),
                    "row {n}: {text} sorts at the wrong rank"
                );
            }
        }
    };
    let statuses = [
        (2, "Waiting", 1),
        (4, "Paused", 2),
        (5, "Completed", 4),
        (7, "No network", 1),
        (8, "Asking Kad", 1),
        (9, "Failed", 5),
        (10, "Downloading", 0),
        (11, "Completing", 3),
        (12, "Completing: waiting for the file to be released", 3),
        (13, "Completing: 46.0 MB copied", 3),
    ];
    check(&state, &statuses);

    state.reconnect = Some(crate::state::Reconnect {
        server: crate::fixture::server_endpoint(),
        step: crate::words::server::ReconnectStep {
            attempt: 1,
            bound: None,
            delay: std::time::Duration::from_secs(5),
            steady: false,
        },
        at: std::time::Instant::now(),
        said: crate::words::server::NO_SERVER_LISTED,
    });
    check(&state, &[(7, "Reconnecting", 1)]);
}
