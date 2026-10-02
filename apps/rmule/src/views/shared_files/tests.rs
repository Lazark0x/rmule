//! Unit tests for the Shared Files view: the files table over the upload-peers pane, focus, filters and goldens.

use ratatui::crossterm::event::{KeyModifiers, ModifierKeyCode};

use crate::golden::assert_golden;

use super::*;
use crate::fixture::*;

#[test]
fn the_peers_pane_meters_slot_holders_and_dashes_queued_peers() {
    let state = metered();
    let mut view = SharedView::default();
    view.handle_key(press(KeyCode::Char('a')), &state); // filter off: queued peers show too
    let rendered =
        crate::golden::render_to_lines(golden_area().width, golden_area().height, |frame| {
            view.draw(frame, golden_area(), &state, &theme(), Instant::now());
        });
    let row = |addr: &str| {
        rendered
            .lines()
            .find(|line| line.contains(addr))
            .unwrap_or_else(|| panic!("no row for {addr} in\n{rendered}"))
            .to_string()
    };
    let holder = row("10.0.0.1:4662");
    assert!(
        holder.contains("123.4 KB/s"),
        "the slot holder's meter: {holder}"
    );
    let queued = row("10.0.0.2:4662");
    assert!(
        !queued.contains("KB/s"),
        "a queued peer has no counter: {queued}"
    );
}

#[test]
fn the_active_only_filter_defaults_on_and_a_toggles_it() {
    let state = served_files();
    let mut view = SharedView::default();
    assert!(view.active_only, "spec §3.5: default on");
    assert_eq!(
        view.visible_peers(&state).len(),
        1,
        "only the uploading peer"
    );

    assert!(matches!(
        view.handle_key(press(KeyCode::Char('a')), &state),
        ViewOutcome::Redraw
    ));
    assert!(!view.active_only);
    assert_eq!(
        view.visible_peers(&state).len(),
        3,
        "queued peers now shown"
    );

    // Back on: the two queued peers are hidden, and counted.
    view.handle_key(press(KeyCode::Char('a')), &state);
    let hidden = state.upload_peers.len() - view.visible_peers(&state).len();
    assert_eq!(hidden, 2);
}

#[test]
fn tab_and_shift_tab_cycle_focus_between_the_two_panes() {
    let state = served_files();
    let mut view = SharedView::default();
    assert_eq!(view.focus, Pane::Files);
    view.handle_key(press(KeyCode::Tab), &state);
    assert_eq!(view.focus, Pane::Peers);
    view.handle_key(press(KeyCode::BackTab), &state);
    assert_eq!(view.focus, Pane::Files);
}

#[test]
fn selection_moves_and_clamps_to_the_focused_pane() {
    let state = served_files(); // 2 files
    let mut view = SharedView::default();
    view.handle_key(press(KeyCode::Char('G')), &state);
    assert_eq!(view.files_selected, 1);
    view.handle_key(press(KeyCode::Char('j')), &state); // already at the bottom
    assert_eq!(view.files_selected, 1);
    view.handle_key(press(KeyCode::Char('g')), &state);
    assert_eq!(view.files_selected, 0);
}

#[test]
fn q_dismisses_an_open_modal_rather_than_bubbling_to_quit() {
    let state = served_files();
    // Menu: q closes it (Redraw, not Ignored → the global quit never sees it).
    let mut view = SharedView::default();
    view.handle_key(press(KeyCode::Char('m')), &state);
    assert!(matches!(
        view.handle_key(press(KeyCode::Char('q')), &state),
        ViewOutcome::Redraw
    ));
    assert!(view.menu.is_none());
    // Confirm: q aborts it, emitting nothing.
    view.handle_key(press(KeyCode::Char('m')), &state);
    view.handle_key(press(KeyCode::Enter), &state);
    assert!(matches!(
        view.handle_key(press(KeyCode::Char('q')), &state),
        ViewOutcome::Redraw
    ));
    assert!(view.confirm.is_none());
    // With no modal, q bubbles to the globals.
    assert!(matches!(
        view.handle_key(press(KeyCode::Char('q')), &state),
        ViewOutcome::Ignored
    ));
}

#[test]
fn key_releases_are_ignored() {
    let state = served_files();
    let mut view = SharedView::default();
    let release = KeyEvent {
        code: KeyCode::Char('a'),
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Release,
        state: ratatui::crossterm::event::KeyEventState::NONE,
    };
    assert!(matches!(
        view.handle_key(release, &state),
        ViewOutcome::Ignored
    ));
    assert!(view.active_only, "a release must not toggle the filter");
    // A modifier key press is not a view key either.
    assert!(matches!(
        view.handle_key(press(KeyCode::Modifier(ModifierKeyCode::LeftShift)), &state),
        ViewOutcome::Ignored
    ));
}

#[test]
fn golden_shared_empty() {
    assert_golden(
        "shared_empty",
        golden_area().width,
        golden_area().height,
        |frame| {
            SharedView::default().draw(
                frame,
                golden_area(),
                &UiState::default(),
                &theme(),
                Instant::now(),
            );
        },
    );
}

/// Both panes too narrow for every header give columns away in
/// their stated orders and say which, rather than splitting a header.
#[test]
fn golden_shared_narrow_headers_whole() {
    let area = ratatui::layout::Rect::new(0, 0, 34, golden_area().height);
    assert_golden("shared_narrow_headers", area.width, area.height, |frame| {
        SharedView::default().draw(frame, area, &served_files(), &theme(), Instant::now());
    });
}

#[test]
fn golden_shared_populated() {
    assert_golden(
        "shared_populated",
        golden_area().width,
        golden_area().height,
        |frame| {
            // Default filter (active only): the two queued peers are hidden
            // and counted in the pane footer.
            SharedView::default().draw(
                frame,
                golden_area(),
                &served_files(),
                &theme(),
                Instant::now(),
            );
        },
    );
}

#[test]
fn golden_shared_filter_off() {
    assert_golden(
        "shared_filter_off",
        golden_area().width,
        golden_area().height,
        |frame| {
            let state = served_files();
            let mut view = SharedView::default();
            view.handle_key(press(KeyCode::Char('a')), &state); // toggle the filter off
            view.draw(frame, golden_area(), &state, &theme(), Instant::now());
        },
    );
}

/// The meter golden: a live per-peer upload rate beside the honest
/// dashes of the queued peers that hold no slot.
#[test]
fn golden_shared_upload_speeds() {
    assert_golden(
        "shared_upload_speeds",
        golden_area().width,
        golden_area().height,
        |frame| {
            let state = metered();
            let mut view = SharedView::default();
            view.handle_key(press(KeyCode::Char('a')), &state); // filter off: show the queue too
            view.draw(frame, golden_area(), &state, &theme(), Instant::now());
        },
    );
}

#[test]
fn clicks_select_rows_in_either_pane() {
    use ratatui::{Terminal, backend::TestBackend};
    let mut view = SharedView::default();
    let state = served_files();
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
    view.focus = Pane::Peers;
    // The second row starts where it was drawn: a row whose all-time
    // figures wrap is two lines tall.
    let second = view.file_rows.line_of(1).expect("the second row is drawn");
    assert!(matches!(
        view.handle_click(3, second, &state),
        ViewOutcome::Redraw
    ));
    assert_eq!(view.focus, Pane::Files);
    assert_eq!(view.files_selected, 1);
    let peers_rows = crate::views::table_rows(view.peers_area);
    assert!(matches!(
        view.handle_click(3, peers_rows.y, &state),
        ViewOutcome::Redraw
    ));
    assert_eq!(view.focus, Pane::Peers);
    assert_eq!(view.peers_selected, 0);
}
