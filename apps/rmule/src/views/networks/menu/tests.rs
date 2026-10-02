//! Unit tests for the server row-action menu and the remove confirm.

use rmule_core::ServerPriority;

use crate::golden::assert_golden;

use crate::views::networks::*;

use super::*;
use crate::fixture::*;

/// Every label in the open menu, in order. Reads `NetworksView::menu`,
/// which is private to this module tree — so the probe stays here rather
/// than in the crate's fixture home.
fn menu_labels(view: &NetworksView) -> Vec<String> {
    view.menu
        .as_ref()
        .expect("menu open")
        .items
        .iter()
        .map(|item| item.label.clone())
        .collect()
}

/// The label the open menu's selection sits on.
fn menu_sel_label(view: &NetworksView) -> String {
    let menu = view.menu.as_ref().expect("menu open");
    menu.items[menu.sel].label.clone()
}

/// Open the menu and move to the item whose label starts with `prefix`.
fn menu_to(view: &mut NetworksView, state: &UiState, prefix: &str) {
    view.handle_key(press(KeyCode::Char('m')), state);
    for _ in 0..menu_labels(view).len() {
        if menu_sel_label(view).starts_with(prefix) {
            return;
        }
        view.handle_key(press(KeyCode::Char('j')), state);
    }
    panic!(
        "no enabled menu item starting with {prefix:?}: {:?}",
        menu_labels(view)
    );
}

#[test]
fn connect_emits_the_real_command_with_the_session_credentials() {
    let state = listed_servers();
    let mut view = NetworksView::new();
    // Row 2 by name: Static Pin, not the connected server.
    view.handle_key(press(KeyCode::Char('j')), &state);
    view.handle_key(press(KeyCode::Char('j')), &state);
    menu_to(&mut view, &state, "Connect");
    match view.handle_key(press(KeyCode::Enter), &state) {
        ViewOutcome::Emit(Action::Command(CoreCommand::ConnectToServer { server, .. })) => {
            assert_eq!(server, endpoint("10.0.0.2", 4242));
        }
        other => panic!("expected ConnectToServer, got {other:?}"),
    }
    assert!(view.menu.is_none(), "menu closes after activating");
}

/// The degrade pattern: no credentials ⇒ the item is greyed with the
/// reason. The connected row offers Disconnect in Connect's place,
/// which ends the session and the intent to stay connected.
#[test]
fn connect_is_greyed_without_a_session_and_the_connected_row_offers_disconnect() {
    let mut state = listed_servers();
    state.session = None;
    let mut view = NetworksView::new();
    // Row 2: not the connected one.
    view.handle_key(press(KeyCode::Char('j')), &state);
    view.handle_key(press(KeyCode::Char('j')), &state);
    view.handle_key(press(KeyCode::Char('m')), &state);
    let menu = view.menu.as_ref().unwrap();
    assert_eq!(menu.items[0].label, "Connect (c)");
    assert_eq!(menu.items[0].disabled.as_deref(), Some(NO_CREDENTIALS));
    view.menu = None;

    // Row 0 *is* the connected server: Disconnect, where Connect was.
    let state = listed_servers();
    let mut view = NetworksView::new();
    view.handle_key(press(KeyCode::Char('m')), &state);
    let menu = view.menu.as_ref().unwrap();
    assert_eq!(menu.items[0].label, "Disconnect (c)");
    assert_eq!(menu.items[0].disabled, None);
    assert!(
        !menu_labels(&view)
            .iter()
            .any(|label| label.starts_with("Connect")),
        "no Connect on the row already connected: {:?}",
        menu_labels(&view)
    );
    assert!(matches!(
        view.handle_key(press(KeyCode::Enter), &state),
        ViewOutcome::Emit(Action::Command(CoreCommand::DisconnectFromServer))
    ));
}

/// `K` is Kad's switch, read off core's Kad state: start when off,
/// stop when running, a flash while a stop is under way.
#[test]
fn k_starts_kad_when_off_stops_it_when_running_and_waits_while_it_stops() {
    use rmule_core::diagnostics::KadState;
    let mut state = listed_servers();
    let mut view = NetworksView::new();
    for (kad, expected) in [
        (KadState::Off, "start"),
        (KadState::Running, "stop"),
        (KadState::Stopping, "flash"),
    ] {
        state.diagnostics.kad_state = kad;
        let got = match view.handle_key(press(KeyCode::Char('K')), &state) {
            ViewOutcome::Emit(Action::StartKad) => "start",
            ViewOutcome::Emit(Action::Command(CoreCommand::DisableKad)) => "stop",
            ViewOutcome::Emit(Action::Flash(_)) => "flash",
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(got, expected, "{kad:?}");
    }
}

#[test]
fn the_c_key_acts_on_the_selected_row_and_says_so_when_there_is_none() {
    let mut state = listed_servers();
    let mut view = NetworksView::new();
    // Row 0 is the connected server: `c` hangs up.
    assert!(matches!(
        view.handle_key(press(KeyCode::Char('c')), &state),
        ViewOutcome::Emit(Action::Command(CoreCommand::DisconnectFromServer))
    ));
    // Row 2 by name: Static Pin, another server: `c` connects there.
    view.handle_key(press(KeyCode::Char('j')), &state);
    view.handle_key(press(KeyCode::Char('j')), &state);
    match view.handle_key(press(KeyCode::Char('c')), &state) {
        ViewOutcome::Emit(Action::Command(CoreCommand::ConnectToServer { server, .. })) => {
            assert_eq!(server, endpoint("10.0.0.2", 4242));
        }
        other => panic!("expected ConnectToServer, got {other:?}"),
    }
    // Core re-making Static Pin's lost session: on its row `c` ends the
    // intent, on any other row it connects there.
    state.connected_server = None;
    state.diagnostics.connected_server = None;
    state.reconnect = Some(crate::state::Reconnect {
        server: endpoint("10.0.0.2", 4242),
        step: crate::words::server::ReconnectStep {
            attempt: 2,
            bound: None,
            delay: std::time::Duration::from_secs(60),
            steady: false,
        },
        at: std::time::Instant::now(),
        said: crate::words::server::NO_SERVER_LISTED,
    });
    assert!(matches!(
        view.handle_key(press(KeyCode::Char('c')), &state),
        ViewOutcome::Emit(Action::Command(CoreCommand::DisconnectFromServer))
    ));
    view.handle_key(press(KeyCode::Char('k')), &state);
    assert!(matches!(
        view.handle_key(press(KeyCode::Char('c')), &state),
        ViewOutcome::Emit(Action::Command(CoreCommand::ConnectToServer { .. }))
    ));
    // No rows: nothing to act on, and the tab says so.
    let mut view = NetworksView::new();
    assert!(matches!(
        view.handle_key(press(KeyCode::Char('c')), &UiState::default()),
        ViewOutcome::Emit(Action::Flash(_))
    ));
}

#[test]
fn static_and_priority_items_emit_the_toggle_they_promise() {
    let state = listed_servers();
    let mut view = NetworksView::new();
    // Row 2 by name: Static Pin — static, High.
    view.handle_key(press(KeyCode::Char('j')), &state);
    view.handle_key(press(KeyCode::Char('j')), &state);

    menu_to(&mut view, &state, "Unpin");
    match view.handle_key(press(KeyCode::Enter), &state) {
        ViewOutcome::Emit(Action::Command(CoreCommand::ServerList(
            ServerListCommand::SetServerStatic { server, is_static },
        ))) => {
            assert_eq!(server, endpoint("10.0.0.2", 4242));
            assert!(!is_static, "the label said Unpin");
        }
        other => panic!("expected SetServerStatic, got {other:?}"),
    }

    menu_to(&mut view, &state, "Priority");
    assert_eq!(menu_sel_label(&view), "Priority: High → Low");
    match view.handle_key(press(KeyCode::Enter), &state) {
        ViewOutcome::Emit(Action::Command(CoreCommand::ServerList(
            ServerListCommand::SetServerPriority { priority, .. },
        ))) => assert_eq!(priority, ServerPriority::Low),
        other => panic!("expected SetServerPriority, got {other:?}"),
    }
}

#[test]
fn removing_a_server_confirms_then_emits_remove_and_leaves_the_row_to_the_level() {
    let state = listed_servers();
    let mut view = NetworksView::new();
    menu_to(&mut view, &state, "Remove");
    assert!(matches!(
        view.handle_key(press(KeyCode::Enter), &state),
        ViewOutcome::Redraw
    ));
    let confirm = view.confirm.as_ref().expect("confirm modal up");
    assert_eq!(confirm.name, "eDonkey Prime");
    assert!(view.menu.is_none(), "menu closes when confirm opens");

    match view.handle_key(press(KeyCode::Char('y')), &state) {
        ViewOutcome::Emit(Action::Command(CoreCommand::ServerList(
            ServerListCommand::RemoveServer { server },
        ))) => assert_eq!(server, endpoint("10.0.0.1", 4661)),
        other => panic!("expected RemoveServer, got {other:?}"),
    }
    assert_eq!(
        servers(&state).len(),
        4,
        "the view removes nothing locally — the level does"
    );
}

#[test]
fn copy_link_builds_the_server_link_from_the_real_endpoint() {
    let state = listed_servers();
    let mut view = NetworksView::new();
    menu_to(&mut view, &state, "Copy");
    match view.handle_key(press(KeyCode::Enter), &state) {
        ViewOutcome::Emit(Action::CopyLink(link)) => {
            assert_eq!(link, "ed2k://|server|10.0.0.1|4661|/");
        }
        other => panic!("expected CopyLink, got {other:?}"),
    }
}

#[test]
fn golden_networks_server_menu() {
    let state = listed_servers();
    let mut view = NetworksView::new();
    // Row 1: not the connected server, so Connect is live.
    view.handle_key(press(KeyCode::Char('j')), &state);
    assert!(matches!(
        view.handle_key(press(KeyCode::Char('m')), &state),
        ViewOutcome::Redraw
    ));
    let now = Instant::now();
    assert_golden("networks_server_menu", 78, 21, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now);
    });
}

#[test]
fn golden_networks_remove_confirm() {
    let state = listed_servers();
    let mut view = NetworksView::new();
    menu_to(&mut view, &state, "Remove");
    view.handle_key(press(KeyCode::Enter), &state);
    let now = Instant::now();
    assert_golden("networks_remove_confirm", 78, 21, |frame| {
        let area = frame.area();
        view.draw(frame, area, &state, &Theme::default_dark(), now);
    });
}
