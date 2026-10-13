//! The two Networks modals that take typed input: add-a-server and
//! update-the-list-from-a-URL.
//!
//! Both validate before they emit, so a malformed host or a non-HTTP URL is
//! refused in the form with a reason rather than sent to core to be rejected.
//! A focused form swallows the global binding letters — typing `q` into a
//! hostname must not quit.

use std::cell::Cell;
use std::net::Ipv4Addr;

use ratatui::Frame;
use ratatui::crossterm::event::KeyEvent;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};

use rmule_core::{CoreCommand, ManagedServer, ServerListCommand};
use rmule_primitives::{Ed2kText, ServerEndpoint};

use super::NetworksView;
use crate::action::Action;
use crate::form::{Field, Form, FormKey, validate_port, validate_url};
use crate::row_selection::viewport::Viewport;
use crate::state::UiState;
use crate::theme::Theme;
use crate::views::ViewOutcome;
use crate::views::modal::{Modal, release_form, scroll_form};
use crate::wrap::clamp_u16;

/// Floor width of a modal form; a longer entry grows it (see [`draw_form`]).
pub(super) const FORM_W: u16 = 58;

/// Greyed-menu reason: the run has no core to log in with.
pub(super) const NOT_ATTACHED: &str = "(core not attached — UI-only run)";

/// Which form is up. Both are the same machine — labelled text fields, one
/// focused, `Enter` commits — so the add form and the update-URL prompt cannot
/// drift apart in behaviour.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FormKind {
    AddServer,
    UpdateFromUrl,
}

impl FormKind {
    fn title(self) -> &'static str {
        match self {
            FormKind::AddServer => " Add server ",
            FormKind::UpdateFromUrl => " Update server list from URL ",
        }
    }

    /// What `Enter` does here, for the modal's key legend.
    fn commit_verb(self) -> &'static str {
        match self {
            FormKind::AddServer => "add",
            FormKind::UpdateFromUrl => "fetch",
        }
    }
}

/// A modal form: the shared [`Form`] machine plus which command its fields
/// name (the machine was three copies of the same thing before).
pub(super) struct ServerForm {
    kind: FormKind,
    form: Form,
    /// What part of the form is on screen, in a frame too short for it.
    viewport: Cell<Viewport>,
}

impl ServerForm {
    pub(super) fn add_server() -> Self {
        Self {
            kind: FormKind::AddServer,
            form: Form::new(vec![
                Field::text("Name", ""),
                Field::text("Address", "").with_placeholder("IPv4 or hostname"),
                Field::text("Port", "").with_placeholder("1–65535"),
            ])
            // Address: the only field with no sane default.
            .focused_on(1),
            viewport: Cell::default(),
        }
    }

    /// Pre-filled with the mirror a list update fetches from — the stored
    /// preference (the Settings tab owns it now), falling back to the
    /// Join Sequence's default — so `U` + `Enter` is the whole gesture.
    fn update_url(url: &str) -> Self {
        Self {
            kind: FormKind::UpdateFromUrl,
            form: Form::new(vec![Field::text("URL", url)]),
            viewport: Cell::default(),
        }
    }

    /// Validate the typed fields into the command they name, or the reason
    /// they do not (rendered in the form, never as a vanished modal).
    fn commit(&self) -> Result<CoreCommand, String> {
        match self.kind {
            FormKind::AddServer => {
                let host = validate_host(self.form.text(1))?;
                let port = validate_port(self.form.text(2))?;
                let endpoint = ServerEndpoint::new(host, port)
                    .map_err(|_| crate::words::server::INVALID_ADDRESS.to_string())?;
                let mut server = ManagedServer::listed(endpoint);
                server.name = Ed2kText::from_utf8(self.form.text(0));
                Ok(CoreCommand::ServerList(ServerListCommand::AddServer {
                    server,
                }))
            }
            FormKind::UpdateFromUrl => Ok(CoreCommand::ServerList(
                ServerListCommand::UpdateServerList {
                    url: validate_url(self.form.text(0))?.to_string(),
                },
            )),
        }
    }
}

/// A server address: an IPv4 literal, or a DNS name core will canonicalise.
///
/// A dotted-quad shape must actually *be* one — `999.1.2.3` is a typo, not a
/// hostname — while anything else is left to the endpoint primitive, because
/// the managed list keys DNS-named rows in their own right (ADR-0080).
fn validate_host(host: &str) -> Result<&str, String> {
    if host.is_empty() {
        return Err("address is required (IPv4 or hostname)".to_string());
    }
    let labels: Vec<&str> = host.split('.').collect();
    let dotted_quad = labels.len() == 4
        && labels
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()));
    if dotted_quad {
        host.parse::<Ipv4Addr>()
            .map_err(|_| format!("'{host}' is not a valid IPv4 address"))?;
        return Ok(host);
    }
    let hostname = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && labels.iter().all(|part| !part.is_empty());
    if hostname {
        Ok(host)
    } else {
        Err(format!("'{host}' is not an IPv4 address or a hostname"))
    }
}

/// The add-server / update-URL modal: labelled fields with a trailing caret on
/// the focused one, the last rejection under them, and the key legend.
pub(super) fn draw_form(frame: &mut Frame, area: Rect, entry: &ServerForm, theme: &Theme) {
    // Greedy width: at least the house 58, and as much more as the
    // longest entry needs to read on one line — a pre-filled `server.met` URL
    // is longer than the add-server fields ever are.
    let width = clamp_u16(entry.form.natural_width() + 2)
        .max(FORM_W)
        .min(area.width);
    Modal::new(entry.kind.title(), theme).draw_form(
        frame,
        area,
        width,
        theme,
        &entry.viewport,
        |width| {
            let inner_w = usize::from(width).saturating_sub(2).max(1);
            let legend = Line::from(vec![
                Span::styled(" Tab", Style::new().fg(theme.accent)),
                Span::styled(" field    ", Style::new().fg(theme.fg)),
                Span::styled("Enter", Style::new().fg(theme.accent)),
                Span::styled(
                    format!(" {}    ", entry.kind.commit_verb()),
                    Style::new().fg(theme.fg),
                ),
                Span::styled("Esc", Style::new().fg(theme.accent)),
                Span::styled(" cancel", Style::new().fg(theme.fg)),
            ]);
            entry.form.render_modal(inner_w, theme, vec![legend])
        },
    );
}

impl NetworksView {
    /// Open the update-from-URL form, unless one fetch is already running —
    /// core would refuse a second, so the honest answer comes before the
    /// keystroke, not as a rejection after it.
    pub(super) fn open_update_form(&mut self, state: &UiState) -> ViewOutcome {
        if state.server_list_updating {
            return ViewOutcome::Emit(Action::Flash(crate::words::server::LIST_UPDATE_RUNNING));
        }
        self.form = Some(ServerForm::update_url(&state.preferences.server_met_url));
        ViewOutcome::Redraw
    }

    pub(super) fn handle_form_key(&mut self, key: KeyEvent) -> ViewOutcome {
        let Some(entry) = self.form.as_mut() else {
            return ViewOutcome::Ignored;
        };
        if scroll_form(&mut entry.viewport, key.code) {
            return ViewOutcome::Redraw;
        }
        release_form(&mut entry.viewport);
        match entry.form.handle_key(key) {
            FormKey::Cancel => {
                self.form = None;
                ViewOutcome::Redraw
            }
            FormKey::Commit => match entry.commit() {
                Ok(command) => {
                    self.form = None;
                    ViewOutcome::Emit(Action::Command(command))
                }
                Err(reason) => {
                    // The form stays up with everything typed still in it.
                    entry.form.error = Some(reason);
                    ViewOutcome::Redraw
                }
            },
            // A modal swallows the rest, so nothing leaks to the globals.
            FormKey::Consumed | FormKey::Ignored => ViewOutcome::Redraw,
        }
    }
}

#[cfg(test)]
mod tests {
    use rmule_core::ServerPriority;
    use std::time::Duration;

    use rmule_core::CoreEvent;

    use crate::golden::assert_golden;

    use crate::views::networks::*;

    use super::*;
    use crate::fixture::*;
    #[test]
    fn the_add_form_validates_before_it_emits() {
        let state = listed_servers();
        let mut view = NetworksView::new();
        view.handle_key(press(KeyCode::Char('a')), &state);
        assert!(view.form.is_some(), "`a` opens the add form");

        // Address is focused first; a bad dotted quad is a typo, not a host.
        typed(&mut view, &state, "10.0.0.300");
        view.handle_key(press(KeyCode::Enter), &state);
        let form = view.form.as_ref().expect("form stays up on a rejection");
        assert_eq!(
            form.form.error.as_deref(),
            Some("'10.0.0.300' is not a valid IPv4 address")
        );
        assert_eq!(form.form.text(1), "10.0.0.300", "the typing survives");

        // Fix the address, leave the port empty.
        for _ in 0..10 {
            view.handle_key(press(KeyCode::Backspace), &state);
        }
        typed(&mut view, &state, "10.9.9.9");
        view.handle_key(press(KeyCode::Enter), &state);
        assert_eq!(
            view.form.as_ref().unwrap().form.error.as_deref(),
            Some("port is required (1–65535)")
        );

        // Name and port; Tab walks the fields.
        view.handle_key(press(KeyCode::Tab), &state);
        typed(&mut view, &state, "70000");
        view.handle_key(press(KeyCode::Enter), &state);
        assert_eq!(
            view.form.as_ref().unwrap().form.error.as_deref(),
            Some("'70000' is not a port number (1–65535)")
        );
        for _ in 0..5 {
            view.handle_key(press(KeyCode::Backspace), &state);
        }
        typed(&mut view, &state, "4661");
        view.handle_key(press(KeyCode::BackTab), &state); // back to Address
        view.handle_key(press(KeyCode::BackTab), &state); // to Name
        typed(&mut view, &state, "New Hub");

        match view.handle_key(press(KeyCode::Enter), &state) {
            ViewOutcome::Emit(Action::Command(CoreCommand::ServerList(
                ServerListCommand::AddServer { server },
            ))) => {
                assert_eq!(server.endpoint, endpoint("10.9.9.9", 4661));
                assert_eq!(server.name.to_display_string(), "New Hub");
                assert_eq!(
                    server.priority,
                    ServerPriority::Normal,
                    "core's fold owns the rest"
                );
            }
            other => panic!("expected AddServer, got {other:?}"),
        }
        assert!(view.form.is_none(), "a committed form closes");
    }

    #[test]
    fn the_add_form_takes_a_hostname_and_esc_abandons_it() {
        let state = UiState::default();
        let mut view = NetworksView::new();
        view.handle_key(press(KeyCode::Char('a')), &state);
        typed(&mut view, &state, "srv.example.org");
        view.handle_key(press(KeyCode::Tab), &state);
        typed(&mut view, &state, "4232");
        match view.handle_key(press(KeyCode::Enter), &state) {
            ViewOutcome::Emit(Action::Command(CoreCommand::ServerList(
                ServerListCommand::AddServer { server },
            ))) => assert_eq!(server.endpoint.host(), "srv.example.org"),
            other => panic!("expected AddServer, got {other:?}"),
        }

        view.handle_key(press(KeyCode::Char('a')), &state);
        typed(&mut view, &state, "junk");
        assert!(matches!(
            view.handle_key(press(KeyCode::Esc), &state),
            ViewOutcome::Redraw
        ));
        assert!(view.form.is_none(), "Esc abandons the form");
    }

    /// A focused form is modal: printables are text, so the global bindings
    /// (`q` quits, the tab's `c` connects) must not fire underneath it.
    #[test]
    fn a_focused_form_swallows_the_global_binding_letters() {
        let state = listed_servers();
        let mut view = NetworksView::new();
        view.handle_key(press(KeyCode::Char('a')), &state);
        typed(&mut view, &state, "qc3");
        assert_eq!(view.form.as_ref().unwrap().form.text(1), "qc3");
    }

    #[test]
    fn update_from_url_prefills_the_mirror_and_emits_the_fetch() {
        let state = listed_servers();
        let mut view = NetworksView::new();
        view.handle_key(press(KeyCode::Char('U')), &state);
        assert_eq!(
            view.form.as_ref().unwrap().form.text(0),
            rmule_bootstrap::DEFAULT_SERVER_MET_URL
        );
        match view.handle_key(press(KeyCode::Enter), &state) {
            ViewOutcome::Emit(Action::Command(CoreCommand::ServerList(
                ServerListCommand::UpdateServerList { url },
            ))) => assert_eq!(url, rmule_bootstrap::DEFAULT_SERVER_MET_URL),
            other => panic!("expected UpdateServerList, got {other:?}"),
        }
    }

    #[test]
    fn a_non_http_url_is_refused_in_the_form() {
        let state = UiState::default();
        let mut view = NetworksView::new();
        view.handle_key(press(KeyCode::Char('U')), &state);
        for _ in 0..rmule_bootstrap::DEFAULT_SERVER_MET_URL.len() {
            view.handle_key(press(KeyCode::Backspace), &state);
        }
        typed(&mut view, &state, "ftp://mirror/server.met");
        view.handle_key(press(KeyCode::Enter), &state);
        assert_eq!(
            view.form.as_ref().unwrap().form.error.as_deref(),
            Some("URL must start with http:// or https://")
        );
    }

    /// Core refuses a second fetch; the UI says so before the keystroke costs
    /// a rejection, and greys the menu item with the same reason.
    #[test]
    fn an_in_flight_update_greys_the_action_instead_of_racing_it() {
        let mut state = listed_servers();
        state.server_list_updating = true;
        let mut view = NetworksView::new();
        match view.handle_key(press(KeyCode::Char('U')), &state) {
            ViewOutcome::Emit(Action::Flash(text)) => assert!(text.contains("already running")),
            other => panic!("expected a flash, got {other:?}"),
        }
        assert!(view.form.is_none(), "no form opens while a fetch runs");

        view.handle_key(press(KeyCode::Char('m')), &state);
        let update = view
            .menu
            .as_ref()
            .unwrap()
            .items
            .iter()
            .find(|item| item.label.starts_with("Update"))
            .expect("update item");
        assert_eq!(update.disabled.as_deref(), Some("(update in flight)"));
    }

    #[test]
    fn golden_networks_add_form() {
        let state = listed_servers();
        let mut view = NetworksView::new();
        view.handle_key(press(KeyCode::Char('a')), &state);
        typed(&mut view, &state, "10.0.0.300");
        view.handle_key(press(KeyCode::Enter), &state); // surfaces the validation error
        let now = Instant::now();
        assert_golden("networks_add_form", 78, 21, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now);
        });
    }

    #[test]
    fn golden_networks_update_form() {
        let state = listed_servers();
        let mut view = NetworksView::new();
        view.handle_key(press(KeyCode::Char('U')), &state);
        let now = Instant::now();
        assert_golden("networks_update_form", 78, 21, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now);
        });
    }

    /// The update outcome as the operator sees it: the flash text is the fold's
    /// note, and the pane title says a fetch is running.
    #[test]
    fn golden_networks_update_in_flight() {
        let base = Instant::now();
        let mut state = listed_servers();
        state.apply(
            Action::Core(CoreEvent::ServerList(
                rmule_core::ServerListEvent::ServerListUpdateStarted {
                    url: rmule_bootstrap::DEFAULT_SERVER_MET_URL.to_string(),
                },
            )),
            base,
        );
        assert!(state.server_list_updating);
        let mut view = NetworksView::new();
        assert_golden("networks_update_in_flight", 78, 21, |frame| {
            let area = frame.area();
            view.draw(
                frame,
                area,
                &state,
                &Theme::default_dark(),
                base + Duration::from_secs(2),
            );
        });
    }

    /// Tab to the last field of a form taller than the frame keeps that
    /// field, and the legend under it, on screen; `Home` reaches the top.
    #[test]
    fn golden_networks_add_form_scrolls_in_a_short_frame() {
        let state = listed_servers();
        let mut view = NetworksView::new();
        view.handle_key(press(KeyCode::Char('a')), &state);
        let now = Instant::now();
        let shown = |view: &mut NetworksView| {
            crate::golden::render_to_lines(70, 6, |frame| {
                let area = frame.area();
                view.draw(frame, area, &state, &Theme::default_dark(), now);
            })
        };
        assert_golden("networks_add_form_short", 70, 6, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now);
        });
        view.handle_key(press(KeyCode::Tab), &state);
        let last = shown(&mut view);
        assert!(
            last.contains("Port") && last.contains("Esc cancel"),
            "{last}"
        );
        view.handle_key(press(KeyCode::Home), &state);
        assert!(shown(&mut view).contains("Name"));
    }
}
