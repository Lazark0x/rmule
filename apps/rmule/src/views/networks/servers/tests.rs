//! Unit tests for the managed-server table: its widths, row projection, dynamics and goldens.

use crate::action::Action;
use ratatui::crossterm::event::KeyCode;
use std::time::Instant;

use rmule_core::diagnostics::DiagnosticsSnapshot;
use rmule_core::{CoreEvent, DownloadEvent, ServerConnectionEvent};
use rmule_primitives::ClientId;

use crate::golden::assert_golden;

use super::*;
use crate::fixture::*;
#[test]
fn the_greedy_pair_share_the_slack_and_the_row_always_fits() {
    let headers: Vec<usize> = ServersTable::COLUMNS
        .iter()
        .map(|column| column.label.len())
        .collect();
    for pane in 30usize..=200 {
        let widths = server_widths(pane, &SERVER_COLS, &headers);
        let used = widths.iter().sum::<usize>() + widths.len() - 1 + SERVER_GUTTER_W;
        assert!(used <= pane, "row overflows a {pane}-wide pane: {used}");
        assert!(
            widths
                .iter()
                .zip(&headers)
                .all(|(width, header)| *width == 0 || width >= header),
            "a header is split in a {pane}-wide pane: {widths:?}"
        );
        assert!(widths[SERVER_NAME_COL] >= 4, "Name gave way at {pane}");
    }
    // With room to spare both identity columns grow, not just the first.
    let wide = server_widths(140, &SERVER_COLS, &headers);
    assert!(wide[SERVER_NAME_COL] > SERVER_COLS[SERVER_NAME_COL]);
    assert!(wide[SERVER_DESC_COL] > SERVER_COLS[SERVER_DESC_COL]);
}

/// Each Ping State renders its own cell: the round trip, or the word for
/// why there is none — never a bare dash — and a missing count says the
/// same word as the row's ping, or that the answer left it unset.
#[test]
fn each_ping_state_renders_its_own_cell_and_counts_follow_it() {
    let unanswered = PingState::Unanswered {
        since: Duration::from_secs(600),
    };
    for (ping, cell, count) in [
        (
            PingState::Measured(Duration::from_millis(42)),
            "42ms",
            "unset",
        ),
        (
            PingState::Measured(Duration::from_millis(2_500)),
            "2.5s",
            "unset",
        ),
        (PingState::NotAskedYet, "soon", "soon"),
        (PingState::Awaiting, "asked", "asked"),
        (unanswered, "lost", "lost"),
    ] {
        assert_eq!(format_ping(&ping), cell);
        assert!(
            cell.chars().count() <= SERVER_COLS[4],
            "{cell} overflows Ping"
        );
        assert_eq!(count_cell(None, &ping), count);
        assert_eq!(count_cell(Some(431_004), &ping), "431k");
    }
}

#[test]
fn dynamics_render_as_dashes_until_a_server_reports_them() {
    assert_eq!(format_age(None), "—", "never answered");
    for (secs, cell) in [
        (0, "0s"),
        (59, "59s"),
        (60, "1m"),
        (3_599, "59m"),
        (3_600, "1h"),
        (172_799, "47h"),
        (172_800, "2d"),
        (8_639_999, "99d"),
        (8_640_000, "14w"),
    ] {
        assert_eq!(format_age(Some(Duration::from_secs(secs))), cell);
    }
    assert_eq!(short_count(None), "—");
    assert_eq!(short_count(Some(0)), "0", "zero users is a measurement");
    assert_eq!(short_count(Some(9_999)), "9999");
    assert_eq!(short_count(Some(431_004)), "431k");
    assert_eq!(short_count(Some(24_507_112)), "24M");
    for count in [0u32, 9_999, 10_000, 999_999, 1_000_000, u32::MAX] {
        assert!(
            short_count(Some(count)).chars().count() <= 5,
            "{count} overflows the cell"
        );
    }
}

/// The connected row is marked by a glyph in the gutter, never by colour
/// alone (spec §5) — and the selection arrow is a second, independent mark.
#[test]
fn the_connected_row_is_marked_by_a_glyph_beside_the_selection_arrow() {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    // Short names so each row is one display line and the gutter reads
    // straight down.
    let state = UiState {
        diagnostics: DiagnosticsSnapshot {
            servers: vec![
                listed("10.0.0.1", 4661, "One"),
                listed("10.0.0.2", 4242, "Two"),
            ],
            connected_server: Some(endpoint("10.0.0.2", 4242)),
            ..DiagnosticsSnapshot::default()
        },
        ..UiState::default()
    };
    let theme = Theme::default_dark();
    let mut view = NetworksView::new();
    let mut terminal = Terminal::new(TestBackend::new(78, 21)).expect("terminal");
    terminal
        .draw(|frame| {
            view.draw(
                frame,
                Rect::new(0, 0, 78, 21),
                &state,
                &theme,
                Instant::now(),
            )
        })
        .expect("draw");
    let buffer = terminal.backend().buffer();
    let y0 = view.server_rows.line_of(0).expect("row 0 drawn");
    let gutter = |y: u16| -> String {
        (1u16..4)
            .map(|x| buffer.cell((x, y)).map_or(" ", |cell| cell.symbol()))
            .collect()
    };
    // Row 0 is selected but not connected; row 1 is connected, not selected.
    assert_eq!(gutter(y0), "▸  ", "selection arrow only");
    assert_eq!(gutter(y0 + 1), " ● ", "connected dot only");
    let dot = buffer.cell((2u16, y0 + 1)).expect("connected dot");
    assert_eq!(dot.style().fg, Some(theme.good));
}

#[test]
fn golden_networks_empty_list() {
    let state = UiState::default();
    let mut view = NetworksView::new();
    let now = Instant::now();
    assert_golden("networks_empty", 78, 21, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now);
    });
}

/// At 21 rows the detail pane would take over half the table's body, so
/// this frame is also the golden of its collapsed one-line form.
#[test]
fn golden_networks_populated_table() {
    let state = listed_servers();
    let mut view = NetworksView::new();
    let now = Instant::now();
    assert_golden("networks_populated", 78, 21, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now);
    });
}

/// A pane too narrow for every header gives columns away in the
/// stated order and says which, rather than splitting a header.
#[test]
fn golden_networks_narrow_headers_whole() {
    let state = listed_servers();
    let mut view = NetworksView::new();
    let now = Instant::now();
    assert_golden("networks_narrow_headers", 44, 21, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now);
    });
}

#[test]
fn golden_networks_connected_with_log() {
    // A sequence of real events at increasing instants → an authentic log
    // with mixed ages when drawn at a fixed `now`.
    let base = Instant::now();
    let mut state = listed_servers();
    let hi = ClientId::from_u32(ClientId::LOW_ID_THRESHOLD);
    let events: [(u64, CoreEvent); 4] = [
        (
            0,
            CoreEvent::ServerConnection(ServerConnectionEvent::Connected {
                server: endpoint("10.0.0.1", 4661),
                client_id: hi,
            }),
        ),
        (
            300,
            CoreEvent::Download(DownloadEvent::SourcesFound {
                download_id: download_id(1),
                total: 42,
                usable_high_id: 12,
            }),
        ),
        (
            585,
            CoreEvent::Download(DownloadEvent::PeerQueued {
                download_id: download_id(1),
                peer: peer_at(10, 0, 0, 1, 4662),
                rank: 3,
            }),
        ),
        (
            595,
            CoreEvent::Download(DownloadEvent::PartVerified {
                download_id: download_id(1),
                part_index: 17,
            }),
        ),
    ];
    for (offset, event) in events {
        state.apply(Action::Core(event), base + Duration::from_secs(offset));
    }
    let now = base + Duration::from_secs(600);
    let mut view = NetworksView::new();
    assert_golden("networks_connected_with_log", 78, 21, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now);
    });
}

#[test]
fn golden_networks_wrap_long_row() {
    let state = long_row();
    let mut view = NetworksView::new();
    let now = Instant::now();
    assert_golden("networks_wrap_long_row", 78, 21, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now);
    });
}

#[test]
fn a_wrapped_row_keeps_every_character_and_maps_its_lines_back_to_the_row() {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    let state = long_row();
    let mut view = NetworksView::new();
    // 30 rows, not the golden's 21: the narrower Name floor
    // (Address widened) wraps this fixture's row taller, and a
    // row extending past the pane edge is a viewport property, not a
    // truncation — the assertion needs the whole row on screen.
    let mut terminal = Terminal::new(TestBackend::new(78, 30)).expect("terminal");
    terminal
        .draw(|frame| {
            view.draw(
                frame,
                Rect::new(0, 0, 78, 30),
                &state,
                &Theme::default_dark(),
                Instant::now(),
            )
        })
        .expect("draw");
    let buffer = terminal.backend().buffer();
    let rendered: String = (0..30u16)
        .map(|y| {
            (0..78u16)
                .map(|x| buffer.cell((x, y)).map_or(" ", |cell| cell.symbol()))
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        rendered.contains("Nummer"),
        "the name's tail was cut:\n{rendered}"
    );
    assert!(
        rendered.contains("clock"),
        "the description's tail was cut:\n{rendered}"
    );
    assert!(
        !rendered.contains('…'),
        "no renderer in this crate truncates"
    );
    let (first, second) = (
        view.server_rows.line_of(0).expect("row 0 drawn"),
        view.server_rows.line_of(1).expect("row 1 drawn"),
    );
    assert!(
        second - first > 1,
        "the first row occupies several display lines"
    );
    view.handle_click(4, second, &state);
    assert_eq!(view.server_sel, 1);
    view.handle_click(4, first + 1, &state);
    assert_eq!(view.server_sel, 0);
}

/// A table taller than its pane scrolls by whole rows, and the selection
/// is always on screen.
#[test]
fn a_long_list_scrolls_the_selected_row_into_view() {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    let servers: Vec<ServerDiagnostics> = (0..40u8)
        .map(|n| listed(&format!("10.0.0.{n}"), 4661, &format!("Server {n}")))
        .collect();
    let state = UiState {
        diagnostics: DiagnosticsSnapshot {
            servers,
            ..DiagnosticsSnapshot::default()
        },
        ..UiState::default()
    };
    let mut view = NetworksView::new();
    let mut terminal = Terminal::new(TestBackend::new(78, 21)).expect("terminal");
    let mut draw = |view: &mut NetworksView| {
        terminal
            .draw(|frame| {
                view.draw(
                    frame,
                    Rect::new(0, 0, 78, 21),
                    &state,
                    &Theme::default_dark(),
                    Instant::now(),
                )
            })
            .expect("draw");
    };
    draw(&mut view);
    assert_eq!(view.viewport.first(), 0);
    view.handle_key(press(KeyCode::Char('G')), &state);
    draw(&mut view);
    assert!(
        view.viewport.first() > 0,
        "the table scrolled to the last row"
    );
    assert!(
        view.server_rows.line_of(39).is_some(),
        "the selected row is on screen"
    );
    view.handle_key(press(KeyCode::Char('g')), &state);
    draw(&mut view);
    assert_eq!(view.viewport.first(), 0, "g scrolls back to the top");
}

/// Everything on screen, one string per row.
fn screen(view: &mut NetworksView, state: &UiState, width: u16, height: u16) -> String {
    crate::golden::render_to_lines(width, height, |frame| {
        view.draw(
            frame,
            frame.area(),
            state,
            &Theme::default_dark(),
            Instant::now(),
        );
    })
}

/// The selected server's detail pane at the 80-column floor, one golden per
/// state: `j` presses move the cursor down the Name-sorted rows (eDonkey
/// Prime, Flaky Mirror, Static Pin, the unnamed row).
fn detail_golden(name: &str, state: &UiState, down: usize) {
    let mut view = NetworksView::new();
    for _ in 0..down {
        view.handle_key(press(KeyCode::Char('j')), state);
    }
    let now = Instant::now();
    assert_golden(name, 80, 34, |frame| {
        let area = frame.area();
        view.draw(frame, area, state, &Theme::default_dark(), now);
    });
}

/// A server never logged into says so for its grants, and that no status
/// answer has come, rather than showing nothing.
#[test]
fn golden_detail_pane_never_logged_in() {
    detail_golden("networks_detail_never_logged_in", &listed_servers(), 3);
}

/// A dead server's pane says when it died, its tally and the limit; the row
/// itself stays dimmed with `dead` in Fail.
#[test]
fn golden_detail_pane_dead_server() {
    let mut state = listed_servers();
    state.diagnostics.servers[2].age = Some(Duration::from_secs(3 * 86_400));
    detail_golden("networks_detail_dead", &state, 1);
}

/// The connected server whose shares are withheld says so, and why.
#[test]
fn golden_detail_pane_withheld_shares() {
    let mut state = listed_servers();
    state.diagnostics.share_announcement = Some(rmule_core::diagnostics::ShareAnnouncement {
        server: endpoint("10.0.0.1", 4661),
        shares: rmule_core::diagnostics::SharesToServer::Withheld,
    });
    detail_golden("networks_detail_withheld", &state, 0);
}

/// Where the pane would take more than half the table's body, it collapses
/// to the one wrapped line of grants and UDP flags — the frame the
/// `networks_populated` golden draws — and the Health and Shares sentences
/// are the pane's alone.
#[test]
fn the_detail_pane_collapses_where_the_table_would_lose_half_its_rows() {
    let state = listed_servers();
    let mut view = NetworksView::new();
    let flat = |shown: String| {
        shown
            .lines()
            .map(|line| line.trim_matches(|c| c == '│' || c == ' ').to_string())
            .collect::<Vec<_>>()
            .join(" ")
    };
    let short = flat(screen(&mut view, &state, 80, 21));
    assert!(short.contains("Grants at login (14m ago)"), "{short}");
    assert!(!short.contains("Health:"), "{short}");
    let tall = flat(screen(&mut view, &state, 80, 34));
    assert!(
        tall.contains("Health: answering — its last answer came 12s ago"),
        "{tall}"
    );
    assert!(
        tall.contains("Shares: not announced to this session yet"),
        "{tall}"
    );
}

/// A server list longer than its pane: the bar runs down the header and the
/// rows, and the border counts the cursor's row of the forty.
#[test]
fn golden_networks_servers_overflow() {
    let servers: Vec<ServerDiagnostics> = (0..40u8)
        .map(|n| listed(&format!("10.0.0.{n}"), 4661, &format!("Server {n}")))
        .collect();
    let state = UiState {
        diagnostics: DiagnosticsSnapshot {
            servers,
            ..DiagnosticsSnapshot::default()
        },
        ..UiState::default()
    };
    let mut view = NetworksView::new();
    for _ in 0..25 {
        view.handle_key(press(KeyCode::Char('j')), &state);
    }
    assert_golden("networks_servers_overflow", 78, 24, |frame| {
        view.draw(
            frame,
            frame.area(),
            &state,
            &Theme::default_dark(),
            Instant::now(),
        );
    });
}
