//! Unit tests for the results table: columns, tints, wrapping and goldens.

use ratatui::crossterm::event::KeyCode;
use std::time::Instant;

use ratatui::style::Color;

use rmule_primitives::{Ed2kText, FileHash};

use crate::golden::assert_golden;

use super::*;
use crate::fixture::*;

#[test]
fn source_tint_matches_the_inventory_thresholds() {
    let theme = Theme::default_dark();
    assert_eq!(source_tint(0, &theme), theme.dim);
    assert_eq!(source_tint(9, &theme), theme.dim);
    assert_eq!(source_tint(10, &theme), theme.fg);
    assert_eq!(source_tint(99, &theme), theme.fg);
    assert_eq!(source_tint(100, &theme), theme.good);
    assert_eq!(source_tint(1234, &theme), theme.good);
}

#[test]
fn file_size_renders_binary_units() {
    assert_eq!(format_size(0), "0 B");
    assert_eq!(format_size(1000), "1000 B");
    assert_eq!(format_size(4_194_304), "4.0 MB");
    assert_eq!(format_size(734_003_200), "700.0 MB");
    assert_eq!(format_size(3_221_225_472), "3.0 GB");
}

#[test]
fn sources_cell_shows_availability_and_the_complete_count_in_parentheses() {
    assert_eq!(
        result_sources_text(&server_result(0x11, "a.avi", 10, 42, 7)),
        "42 (7)"
    );
    assert_eq!(
        result_sources_text(&server_result(0x11, "a.avi", 10, 42, 0)),
        "42",
        "a zero complete-source count is a fact about the file, not a \
             number worth a pair of parentheses (aMule suppresses it too)"
    );

    // No FT_SOURCES at all: the concrete reporting peers are what is known.
    let untagged = SearchResult::new(
        FileHash::from_bytes([0x11; 16]),
        10,
        vec![Ed2kText::from_utf8("a.avi")],
        vec![rmule_primitives::PeerSource::new(
            rmule_primitives::ClientId::from_u32(0x0100_007f),
            4662,
        )],
    )
    .unwrap();
    assert_eq!(result_sources_text(&untagged), "1");
}

#[test]
fn type_cell_classifies_by_name_then_tag_then_falls_back_to_an_em_dash() {
    assert_eq!(
        result_type_text(&server_result(0x11, "clip_low.avi", 10, 1, 0)),
        "Videos"
    );
    assert_eq!(
        result_type_text(
            &server_result(0x11, "payload", 10, 1, 0).with_file_type(Ed2kText::from_utf8("Audio"))
        ),
        "Audio",
        "an extension-less name falls through to the tag"
    );
    // A term rmule does not know still beats an em dash: the server said it.
    assert_eq!(
        result_type_text(
            &server_result(0x11, "payload", 10, 1, 0)
                .with_file_type(Ed2kText::from_utf8("EmuleCollection"))
        ),
        "EmuleCollection"
    );
    assert_eq!(
        result_type_text(&server_result(0x11, "payload", 10, 1, 0)),
        "—"
    );
}

#[test]
fn result_rows_are_tinted_by_their_source_count() {
    let theme = Theme::default_dark();
    let state = state_with(three_tier_results(), SearchStatus::Completed { total: 3 });
    let mut view = SearchesView::new();
    let buffer = draw_golden(&mut view, &state);
    let area = buffer.area;
    // Find each row by its unique name, then read the first content cell's
    // fg (the row tint), skipping the border glyph and padding.
    let row_tint = |needle: &str| -> Option<Color> {
        for y in area.top()..area.bottom() {
            let line: String = (area.left()..area.right())
                .map(|x| buffer.cell((x, y)).map_or(" ", |cell| cell.symbol()))
                .collect();
            if line.contains(needle) {
                for x in (area.left() + 1)..(area.right() - 1) {
                    let cell = buffer.cell((x, y))?;
                    let symbol = cell.symbol();
                    if symbol != " " && symbol != "│" {
                        return cell.style().fg;
                    }
                }
            }
        }
        None
    };
    assert_eq!(row_tint("clip_low.avi"), Some(theme.dim));
    assert_eq!(row_tint("song_mid.mp3"), Some(theme.fg));
    assert_eq!(row_tint("distro_hot.iso"), Some(theme.good));
}

#[test]
fn golden_searches_results() {
    let state = state_with(three_tier_results(), SearchStatus::Completed { total: 3 });
    let theme = Theme::default_dark();
    let mut view = SearchesView::new().having_sent("ubuntu");
    view.handle_key(press(KeyCode::Char('g')), &state); // select the first row
    assert_golden("searches_results", 78, 21, |frame| {
        view.draw(frame, frame.area(), &state, &theme, Instant::now());
    });
}

/// A pane too narrow for every header gives columns away in the
/// stated order and says which, rather than splitting a header.
#[test]
fn golden_searches_narrow_headers_whole() {
    let state = state_with(three_tier_results(), SearchStatus::Completed { total: 3 });
    let theme = Theme::default_dark();
    let mut view = SearchesView::new().having_sent("ubuntu");
    view.handle_key(press(KeyCode::Char('g')), &state);
    assert_golden("searches_narrow_headers", 26, 21, |frame| {
        view.draw(frame, frame.area(), &state, &theme, Instant::now());
    });
}

#[test]
fn golden_wrap_overlong_result_name() {
    let state = state_with(
        vec![
            server_result(0x44, &long_name(), 1_073_741_824, 250, 12),
            server_result(0x22, "song_mid.mp3", 4_194_304, 42, 7),
        ],
        SearchStatus::Completed { total: 2 },
    );
    let theme = Theme::default_dark();
    let mut view = SearchesView::new().having_sent("ubuntu");
    view.handle_key(press(KeyCode::Char('g')), &state);
    assert_golden("searches_wrap_long_name", 80, 24, |frame| {
        view.draw(frame, frame.area(), &state, &theme, Instant::now());
    });
}

#[test]
fn an_overlong_result_name_wraps_whole_instead_of_being_cut() {
    let name = long_name();
    assert_eq!(name.chars().count(), 200);
    let state = state_with(
        vec![server_result(0x44, &name, 1_073_741_824, 250, 12)],
        SearchStatus::Completed { total: 1 },
    );
    let mut view = SearchesView::new();
    let rows = screen_lines(&draw_searches(&mut view, &state, 80, 24));
    // The name's tail reaches the screen, and no line carries a
    // truncation ellipsis.
    assert!(
        rows.iter().any(|row| row.contains("END-OF-NAME.iso")),
        "the 200-char name was cut:\n{}",
        rows.join("\n")
    );
    assert!(
        !rows.iter().any(|row| row.contains('…')),
        "an ellipsis crept back in"
    );
    // Its 200 characters occupy several rows of the one result row.
    let name_rows = rows.iter().filter(|row| row.contains("long-long")).count();
    assert!(name_rows >= 4, "the name wrapped over {name_rows} rows");
}

/// A search held back by the search spacing says so on its status
/// line, with the wait, and stops once core reports it sent.
#[test]
fn a_search_waiting_its_turn_says_so_until_it_is_sent() {
    let mut state = state_with(Vec::new(), SearchStatus::Running);
    let id = search_id(1);
    crate::state::fold(
        &mut state,
        search_event(rmule_core::SearchEvent::SearchWaitingForTurn {
            search_id: id,
            send_in: std::time::Duration::from_millis(1800),
        }),
    );
    assert_eq!(
        results_title(state.searches.get(&id), None, true, false, false),
        " Results · Waiting its turn on this server · sent in 2 s "
    );
    crate::state::fold(
        &mut state,
        search_event(rmule_core::SearchEvent::SearchSentToServer { search_id: id }),
    );
    assert_eq!(
        results_title(state.searches.get(&id), None, true, false, false),
        " Results · Running… "
    );
}

/// A search with Kad running and no session names each leg: Kad
/// finished, the server and the other servers waiting for a connection —
/// not "Completed", and not one undivided "Running…".
#[test]
fn a_search_on_kad_alone_names_the_legs_that_wait() {
    use rmule_core::{SearchLegState as L, SearchLegs};
    let mut state = state_with(Vec::new(), SearchStatus::Running);
    let id = search_id(1);
    crate::state::fold(
        &mut state,
        search_event(rmule_core::SearchEvent::SearchLegsChanged {
            search_id: id,
            legs: SearchLegs {
                server: L::WaitingForSession,
                sweep: L::WaitingForSession,
                kad: L::Settled,
                sweep_servers: rmule_core::SweepTally::default(),
            },
        }),
    );
    assert_eq!(
        results_title(state.searches.get(&id), None, true, false, false),
        " Results · Running… · server: waiting for a connection · other servers: waiting for a connection · Kad: done "
    );
}

/// A search that completed without Kad says Kad did not run for it, so the
/// count does not read as the whole network's.
#[test]
fn a_search_completed_without_kad_says_so() {
    use rmule_core::{SearchLegState as L, SearchLegs};
    let mut state = state_with(Vec::new(), SearchStatus::Running);
    let id = search_id(1);
    crate::state::fold(
        &mut state,
        search_event(rmule_core::SearchEvent::SearchLegsChanged {
            search_id: id,
            legs: SearchLegs {
                server: L::Settled,
                sweep: L::Settled,
                kad: L::NotRun,
                sweep_servers: swept_servers(),
            },
        }),
    );
    crate::state::fold(
        &mut state,
        search_event(rmule_core::SearchEvent::SearchCompleted {
            search_id: id,
            total_results: 3,
        }),
    );
    assert!(
        results_title(state.searches.get(&id), None, true, false, false)
            .contains("Kad: not running"),
        "{:?}",
        results_title(state.searches.get(&id), None, true, false, false)
    );
}

/// A Kad-only search with no server to send to completes on Kad, and its
/// entry says the server legs were not sent (ADR-0034, "A server leg's
/// states").
#[test]
fn a_search_completed_with_no_server_says_its_server_legs_were_not_sent() {
    use rmule_core::{LegNotSent, SearchLegState as L, SearchLegs};
    let mut state = state_with(Vec::new(), SearchStatus::Running);
    let id = search_id(1);
    crate::state::fold(
        &mut state,
        search_event(rmule_core::SearchEvent::SearchLegsChanged {
            search_id: id,
            legs: SearchLegs {
                server: L::NotSent(LegNotSent::NoServer),
                sweep: L::NotSent(LegNotSent::NoServer),
                kad: L::Settled,
                sweep_servers: rmule_core::SweepTally::default(),
            },
        }),
    );
    crate::state::fold(
        &mut state,
        search_event(rmule_core::SearchEvent::SearchCompleted {
            search_id: id,
            total_results: 1,
        }),
    );
    assert_eq!(
        results_title(state.searches.get(&id), None, true, false, false),
        " Results · Completed · 1 · server: not sent — no server · other servers: not sent — no server · Kad: done "
    );
}

/// A running search whose sweep asked twelve servers and heard from seven
/// says both, not "done" (ADR-0034's amendment).
#[test]
fn golden_searches_legs_counted() {
    let state = swept_state();
    let theme = Theme::default_dark();
    let mut view = SearchesView::new().having_sent("ubuntu");
    view.handle_key(press(KeyCode::Char('g')), &state);
    assert!(
        results_title(state.searches.get(&search_id(1)), None, true, false, false)
            .contains("other servers: 12 asked, 7 answered"),
    );
    assert_golden("searches_legs_counted", 110, 14, |frame| {
        view.draw(frame, frame.area(), &state, &theme, Instant::now());
    });
}
