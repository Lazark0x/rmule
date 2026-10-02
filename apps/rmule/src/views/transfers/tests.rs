//! Unit tests for the Transfers view: panes, focus, keys, modals and their goldens.

use ratatui::crossterm::event::KeyCode;

use crate::golden::assert_golden;

use super::*;
use crate::fixture::*;

#[test]
fn selection_starts_at_the_top_and_clamps_when_rows_vanish() {
    let mut view = TransfersView::new();
    let state = three_downloads();
    // A first key selects row 0 (clamp seeds it) and G jumps to the last.
    view.handle_key(press(KeyCode::Char('G')), &state);
    assert_eq!(view.table_state.selected(), Some(2));

    // Data shrinks to a single row: the next key clamps the stale index.
    let mut small = UiState::default();
    small.downloads.insert(
        download_id(9),
        download_row(DownloadStatus::Waiting, 0x11, 1),
    );
    view.handle_key(press(KeyCode::Char('j')), &small);
    assert_eq!(view.table_state.selected(), Some(0));
}

#[test]
fn up_and_down_walk_the_rows_within_bounds() {
    let mut view = TransfersView::new();
    let state = three_downloads();
    view.handle_key(press(KeyCode::Down), &state);
    assert_eq!(view.table_state.selected(), Some(1));
    view.handle_key(press(KeyCode::Char('j')), &state);
    assert_eq!(view.table_state.selected(), Some(2));
    // Past the bottom stays put.
    view.handle_key(press(KeyCode::Char('j')), &state);
    assert_eq!(view.table_state.selected(), Some(2));
    view.handle_key(press(KeyCode::Char('k')), &state);
    assert_eq!(view.table_state.selected(), Some(1));
}

#[test]
fn tab_cycles_focus_between_the_two_panes() {
    let mut view = TransfersView::new();
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
    let mut view = TransfersView::new();
    let state = three_downloads();
    view.handle_key(press(KeyCode::Tab), &state); // focus sources
    view.handle_key(press(KeyCode::Char('j')), &state);
    assert_eq!(
        view.sources_state.selected(),
        Some(1),
        "second of two workers"
    );
    assert_eq!(
        view.table_state.selected(),
        Some(0),
        "table selection unmoved"
    );
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
        let mut view = TransfersView::new();
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
    let mut view = TransfersView::new();
    let state = UiState::default();
    assert_golden("transfers_empty", GOLDEN_W, GOLDEN_H, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now());
    });
}

#[test]
fn golden_populated() {
    let mut view = TransfersView::new();
    let state = three_downloads();
    assert_golden("transfers_populated", GOLDEN_W, GOLDEN_H, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now());
    });
}

#[test]
fn a_click_on_a_table_row_selects_it_and_focuses_the_pane() {
    use ratatui::{Terminal, backend::TestBackend};
    let mut view = TransfersView::new();
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
            )
        })
        .expect("draw");
    view.focus = Pane::Sources; // prove the click refocuses
    // Table pane: border y=0, header y=1, first row y=2.
    assert!(matches!(
        view.handle_click(5, 3, &state),
        ViewOutcome::Redraw
    ));
    assert_eq!(view.focus, Pane::Table);
    assert_eq!(view.table_state.selected(), Some(1));
    // A click past both panes is nobody's.
    assert!(matches!(
        view.handle_click(5, 60, &state),
        ViewOutcome::Ignored
    ));
}
