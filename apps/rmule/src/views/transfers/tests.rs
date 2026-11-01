//! Unit tests for the Transfers view: panes, focus, keys, modals and their goldens.

use ratatui::crossterm::event::KeyCode;

use crate::golden::assert_golden;

use super::*;
use crate::fixture::*;

#[test]
fn selection_starts_at_the_top_and_clamps_when_rows_vanish() {
    let mut view = TransfersView::by_name();
    let state = three_downloads();
    // A first key selects row 0 (clamp seeds it) and G jumps to the last.
    view.handle_key(press(KeyCode::Char('G')), &state);
    assert_eq!(view.selected, Some(2));

    // Data shrinks to a single row: the next key clamps the stale index.
    let mut small = UiState {
        revision: 1,
        ..UiState::default()
    };
    small.downloads.insert(
        download_id(9),
        download_row(DownloadStatus::Waiting, 0x11, 1),
    );
    view.handle_key(press(KeyCode::Char('j')), &small);
    assert_eq!(view.selected, Some(0));
}

#[test]
fn up_and_down_walk_the_rows_within_bounds() {
    let mut view = TransfersView::by_name();
    let state = three_downloads();
    view.handle_key(press(KeyCode::Down), &state);
    assert_eq!(view.selected, Some(1));
    view.handle_key(press(KeyCode::Char('j')), &state);
    assert_eq!(view.selected, Some(2));
    // Past the bottom stays put.
    view.handle_key(press(KeyCode::Char('j')), &state);
    assert_eq!(view.selected, Some(2));
    view.handle_key(press(KeyCode::Char('k')), &state);
    assert_eq!(view.selected, Some(1));
}

#[test]
fn tab_cycles_focus_between_the_two_panes() {
    let mut view = TransfersView::by_name();
    let state = three_downloads();
    assert_eq!(view.focus, Pane::Table);
    assert!(matches!(
        view.handle_key(press(KeyCode::Tab), &state),
        ViewOutcome::Redraw
    ));
    assert_eq!(view.focus, Pane::Sources);
    view.handle_key(press(KeyCode::BackTab), &state);
    assert_eq!(view.focus, Pane::Table);
}

#[test]
fn focus_on_sources_moves_the_source_selection_not_the_table() {
    let mut view = TransfersView::by_name();
    let state = three_downloads();
    view.handle_key(press(KeyCode::Tab), &state); // focus sources
    view.handle_key(press(KeyCode::Char('j')), &state);
    assert_eq!(view.source_selected, Some(1), "second of two workers");
    assert_eq!(view.selected, Some(0), "table selection unmoved");
}

#[test]
fn the_focused_pane_wears_the_accent_border() {
    // Colors never reach the glyph-only goldens, so prove the focus
    // border directly (chrome's tab-accent test is the precedent). The
    // sources pane's top-left corner sits at row 13 (62% of 21 rows).
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    let theme = Theme::default_dark();
    let state = three_downloads();
    let sources_corner = (0u16, 13u16);

    let border_fg = |focus: Pane| {
        let mut view = TransfersView::by_name();
        view.focus = focus;
        let mut terminal = Terminal::new(TestBackend::new(GOLDEN_W, GOLDEN_H)).expect("terminal");
        terminal
            .draw(|frame| {
                let area = frame.area();
                view.draw(frame, area, &state, &theme, now());
            })
            .expect("draw");
        terminal
            .backend()
            .buffer()
            .cell(sources_corner)
            .expect("sources corner cell")
            .style()
            .fg
    };

    assert_eq!(
        border_fg(Pane::Sources),
        Some(theme.accent),
        "focused pane border is accent"
    );
    assert_eq!(
        border_fg(Pane::Table),
        Some(theme.dim),
        "unfocused pane border is dim"
    );
}

#[test]
fn golden_empty_state() {
    let mut view = TransfersView::by_name();
    let state = UiState::default();
    assert_golden("transfers_empty", GOLDEN_W, GOLDEN_H, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now());
    });
}

#[test]
fn golden_populated() {
    let mut view = TransfersView::by_name();
    let state = three_downloads();
    assert_golden("transfers_populated", GOLDEN_W, GOLDEN_H, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now());
    });
}

#[test]
fn a_click_on_a_table_row_selects_it_and_focuses_the_pane() {
    use ratatui::{Terminal, backend::TestBackend};
    let mut view = TransfersView::by_name();
    let state = three_downloads();
    let mut terminal = Terminal::new(TestBackend::new(78, 21)).expect("terminal");
    terminal
        .draw(|f| {
            view.draw(
                f,
                Rect::new(0, 0, 78, 21),
                &state,
                &Theme::default_dark(),
                Instant::now(),
            );
        })
        .expect("draw");
    view.focus = Pane::Sources; // prove the click refocuses
    // Table pane: border y=0, header y=1, first row y=2.
    assert!(matches!(
        view.handle_click(5, 3, &state),
        ViewOutcome::Redraw
    ));
    assert_eq!(view.focus, Pane::Table);
    assert_eq!(view.selected, Some(1));
    // A click past both panes is nobody's.
    assert!(matches!(
        view.handle_click(5, 60, &state),
        ViewOutcome::Ignored
    ));
}

/// `z` gives the focused pane the tab, the other draws nothing and takes no
/// click, and `Tab` carries the zoom to the other pane.
#[test]
fn z_zooms_the_focused_pane_and_tab_carries_it_across() {
    let state = three_downloads();
    let mut view = TransfersView::by_name();
    view.handle_key(press(KeyCode::Char('z')), &state);
    let shown = crate::golden::render_to_lines(78, 22, |frame| {
        view.draw(frame, frame.area(), &state, &Theme::default_dark(), now());
    });
    assert!(shown.contains("Downloads"), "{shown}");
    assert!(!shown.contains("Sources ·"), "{shown}");
    assert_eq!(view.sources_area, Rect::default());

    view.handle_key(press(KeyCode::Tab), &state);
    let shown = crate::golden::render_to_lines(78, 22, |frame| {
        view.draw(frame, frame.area(), &state, &Theme::default_dark(), now());
    });
    assert!(shown.contains("Sources ·"), "{shown}");
    assert!(!shown.contains("Downloads ("), "{shown}");

    view.handle_key(press(KeyCode::Char('z')), &state);
    let shown = crate::golden::render_to_lines(78, 22, |frame| {
        view.draw(frame, frame.area(), &state, &Theme::default_dark(), now());
    });
    assert!(
        shown.contains("Downloads (") && shown.contains("Sources ·"),
        "{shown}"
    );
}

/// A pane with no source to list takes the lines it says that in, and the
/// downloads keep the rest of the tab.
#[test]
fn an_idle_sources_pane_gives_its_rows_to_the_downloads() {
    let state = waiting_downloads();
    let mut view = TransfersView::by_name();
    crate::golden::render_to_lines(78, 22, |frame| {
        view.draw(frame, frame.area(), &state, &Theme::default_dark(), now());
    });
    assert!(view.sources_area.height <= 4, "{:?}", view.sources_area);
    assert_eq!(view.table_area.height + view.sources_area.height, 22);
}

fn typed(view: &mut TransfersView, state: &UiState, text: &str) {
    view.handle_key(press(KeyCode::Char('/')), state);
    for letter in text.chars() {
        view.handle_key(press(KeyCode::Char(letter)), state);
    }
}

/// `/` narrows as it is typed, the letters are text, not the view's keys, and
/// `Esc` brings every row back.
#[test]
fn slash_filters_the_downloads_as_typed_and_esc_clears() {
    let state = three_downloads();
    let mut view = TransfersView::by_name();
    let every = view.download_ids(&state).len();
    typed(&mut view, &state, "bunny");
    assert!(view.text_open());
    assert_eq!(view.download_ids(&state).len(), 1);
    let shown = crate::golden::render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now());
    });
    assert!(shown.contains("/ bunny"), "{shown}");
    assert!(shown.contains(&format!("1 of {every}")), "{shown}");
    view.handle_key(press(KeyCode::Esc), &state);
    assert_eq!(view.download_ids(&state).len(), every);
    assert!(!view.text_open());
}

/// A filter that keeps nothing still shows its line, so the way out is seen.
#[test]
fn a_filter_that_keeps_nothing_says_so_and_stays_on_show() {
    let state = three_downloads();
    let mut view = TransfersView::by_name();
    typed(&mut view, &state, "zzzz");
    let shown = crate::golden::render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now());
    });
    assert!(shown.contains("/ zzzz"), "{shown}");
    assert!(shown.contains(crate::words::rows::NO_MATCH), "{shown}");
}

/// Tagged rows are the targets: `p` acts on them all, and the cancel confirm
/// counts them.
#[test]
fn space_tags_rows_and_p_and_x_act_on_the_tagged_set() {
    use rmule_core::{CoreCommand, DownloadCommand};
    let mut state = three_downloads();
    for row in state.downloads.values_mut() {
        row.status = crate::state::DownloadStatus::Downloading;
    }
    let mut view = TransfersView::by_name();
    view.handle_key(press(KeyCode::Char(' ')), &state);
    view.handle_key(press(KeyCode::Char(' ')), &state);
    let ViewOutcome::Emit(Action::Commands(commands)) =
        view.handle_key(press(KeyCode::Char('p')), &state)
    else {
        panic!("p acts on the tagged rows");
    };
    assert_eq!(commands.len(), 2);
    assert!(commands.iter().all(|command| matches!(
        command,
        CoreCommand::Download(DownloadCommand::PauseDownload { .. })
    )));
    view.handle_key(press(KeyCode::Char('x')), &state);
    let Overlay::ConfirmCancel { targets } = &view.overlay else {
        panic!("x asks");
    };
    assert_eq!(targets.len(), 2);
}

/// `P`: every download on show, one key.
#[test]
fn capital_p_pauses_every_download_on_show() {
    use rmule_core::{CoreCommand, DownloadCommand};
    let mut state = three_downloads();
    for row in state.downloads.values_mut() {
        row.status = crate::state::DownloadStatus::Downloading;
    }
    let mut view = TransfersView::by_name();
    let ViewOutcome::Emit(Action::Commands(commands)) =
        view.handle_key(press(KeyCode::Char('P')), &state)
    else {
        panic!("P acts on every row");
    };
    assert_eq!(commands.len(), state.downloads.len());
    assert!(matches!(
        commands[0],
        CoreCommand::Download(DownloadCommand::PauseDownload { .. })
    ));
}
