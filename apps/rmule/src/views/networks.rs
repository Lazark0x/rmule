//! The Networks view (spec §3.4): aMule's Servers tab — the managed server
//! table with its row actions, the add-server and update-from-URL forms — plus
//! the Kad panel and the core-event log pane. The first tab, as in aMule, and
//! the one the app opens on.
//!
//! **The table is a projection of a level.** Every row comes from
//! [`DiagnosticsSnapshot::servers`](rmule_core::diagnostics::DiagnosticsSnapshot::servers),
//! republished whole on each data tick (ADR-0080), joined with
//! `connected_server` for the one session fact. This component therefore owns
//! *no* server data at all — only which row is selected, which modal is up, and
//! what has been typed into it. An action emits a `CoreCommand` and waits for
//! the level to move; nothing is edited locally and reconciled later, so the
//! table can never show a row core does not have.
//!
//! **Degrade that is still real (spec §1, §6).** The dynamic three — ping,
//! users, files — are `Option`: a server that has never answered renders `—`,
//! never a zero nobody measured. The Kad panel shows the runtime facts core
//! reports (`contact_responded`, live contact count, node id, ADR-0058
//! firewall verdict); the keyword row is the one §3.4 fact still
//! without a core surface and keeps its reasoned dash.
//!
//! Rendering is pure (`UiState` + view state + injected `now` → widgets), so
//! every state goldens under `TestBackend`.

use std::time::Instant;

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Layout, Position, Rect};

use rmule_core::diagnostics::ServerDiagnostics;
use rmule_primitives::ServerEndpoint;

use crate::action::Action;
use crate::row_filter::RowFilter;
use crate::row_selection::tags::Tags;
use crate::row_selection::viewport::Viewport;
use crate::state::UiState;
use crate::table::Drawn;
use crate::table_sort::{RowCursor, RowMove, TableSort};
use crate::theme::Theme;
use crate::views::{ViewOutcome, connect_toggle, say_gave_way};
use crate::words::severity::Severity;
use form::{ServerForm, draw_form};
use kad::draw_kad;
use menu::{Confirm, Menu, draw_confirm, draw_menu};
use sort::ServersTable;

mod form;
mod kad;
mod log;
mod menu;
mod servers;
mod sort;

/// Height of the bottom strip that the log and Kad panes share.
///
/// The server table is the view's main act now, so it takes the full frame
/// width for its ten columns and everything else moves below it: the Kad panel
/// is a fixed-width key-value block ([`KAD_PANE_W`]) and the log takes the rest.
/// Nine inner rows is exactly what the Kad panel's body needs — status, six
/// facts, and the Received and Sent traffic rows.
const BOTTOM_H: u16 = 11;
/// The narrowest tab that keeps the Kad panel beside the log; narrower, the
/// log needs the width and the panel gives way, saying so.
const KAD_PANE_MIN_TAB_W: u16 = 78;
/// Width of the Kad panel — its longest value row ("firewalled · not checked
/// yet", the verdict and why on one line) under a ten-column label, plus
/// borders.
const KAD_PANE_W: u16 = 40;

/// How the bottom border names the panel when it gave way.
const KAD: &str = crate::words::networks::KAD;

/// The two focusable panes (spec §3.4: the Kad panel is display-only).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Pane {
    #[default]
    Servers,
    Log,
}

impl Pane {
    fn toggled(self) -> Self {
        match self {
            Pane::Servers => Pane::Log,
            Pane::Log => Pane::Servers,
        }
    }
}

/// The Networks view. Holds view state only (ADR-0069): focus, selection,
/// scroll, and the transient menu/confirm/form machines. Every server fact
/// lives in [`UiState::diagnostics`].
pub struct NetworksView {
    focus: Pane,
    /// The server table's order.
    sort: TableSort<ServersTable>,
    /// `/`: the servers it keeps.
    filter: RowFilter,
    /// `/` over the log.
    log_filter: RowFilter,
    /// The rows `Space` tagged.
    tags: Tags<ServerEndpoint>,
    /// The selected server, by endpoint.
    cursor: RowCursor<ServerEndpoint>,
    /// The selected server's position in the current order — `cursor`
    /// re-placed before every key and draw.
    server_sel: usize,
    /// What part of the server table is on screen.
    viewport: Viewport,
    /// The table as last drawn, for clicks.
    drawn: Drawn,
    /// What part of the log is on screen, in *wrapped* lines, not entries:
    /// it opens on the newest line and keeps it in view until scrolled back.
    log_viewport: Viewport,
    /// The least severe line the log shows: `f` walks it.
    log_floor: Severity,
    /// Where the log's filter wants the terminal's cursor.
    log_caret: Option<Position>,
    menu: Option<Menu>,
    confirm: Option<Confirm>,
    form: Option<ServerForm>,
    /// `z`: the focused pane has the whole tab.
    zoomed: bool,
    /// The selected server's details modal (`d`), while it is up; what part
    /// of it is on screen in a frame too short for it.
    details: Option<std::cell::Cell<Viewport>>,
    /// Pane areas cached at draw time for click hit-testing.
    servers_area: Rect,
    log_area: Rect,
}

impl Default for NetworksView {
    fn default() -> Self {
        Self {
            focus: Pane::Servers,
            sort: TableSort::default(),
            filter: RowFilter::default(),
            log_filter: RowFilter::default(),
            tags: Tags::default(),
            cursor: RowCursor::default(),
            server_sel: 0,
            viewport: Viewport::default(),
            drawn: Drawn::default(),
            log_viewport: Viewport::at_end(),
            log_floor: Severity::Info,
            log_caret: None,
            menu: None,
            confirm: None,
            form: None,
            zoomed: false,
            details: None,
            servers_area: Rect::default(),
            log_area: Rect::default(),
        }
    }
}

/// The listed servers, as the latest data tick published them.
/// What `K` does with Kad as core reports it: start it when off, stop
/// it when running, and say so while a stop is under way.
fn kad_switch(state: &UiState) -> Action {
    use rmule_core::diagnostics::KadState;
    match state.diagnostics.kad_state {
        KadState::Off => Action::StartKad,
        KadState::Running => Action::Command(rmule_core::CoreCommand::DisableKad),
        KadState::Stopping => Action::Flash(crate::words::kad::STOPPING),
    }
}

fn servers(state: &UiState) -> &[ServerDiagnostics] {
    &state.diagnostics.servers
}

impl NetworksView {
    /// A view with the first server row selected and no modal open.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The selected row, or `None` when the list is empty.
    fn selected<'a>(&self, state: &'a UiState) -> Option<&'a ServerDiagnostics> {
        self.ordered(state).get(self.server_sel).copied()
    }

    /// Put the selection back on its server wherever the order now has it,
    /// in a list that may have grown, shrunk or re-ordered since the last
    /// tick.
    fn clamp_selection(&mut self, state: &UiState) {
        let ids = self.server_ids(state);
        self.server_sel = self.cursor.place(&ids).unwrap_or(0);
    }

    /// The operator put the cursor on display row `index` (clamped).
    /// `Ignored` when it was already there.
    fn select_server(&mut self, state: &UiState, index: usize) -> ViewOutcome {
        let ids = self.server_ids(state);
        if ids.is_empty() {
            return ViewOutcome::Ignored;
        }
        let before = self.server_sel;
        self.cursor.select(&ids, index);
        self.server_sel = self.cursor.place(&ids).unwrap_or(0);
        if self.server_sel == before {
            ViewOutcome::Ignored
        } else {
            ViewOutcome::Redraw
        }
    }

    /// Offer one key the globals did not claim. A modal captures
    /// first; otherwise the focused pane navigates, and anything unclaimed
    /// bubbles back out as [`ViewOutcome::Ignored`].
    pub fn handle_key(&mut self, key: KeyEvent, state: &UiState) -> ViewOutcome {
        self.clamp_selection(state);

        // Modals capture input (globals must not fire underneath them), in
        // the order they stack: a confirm is opened from a menu, a form is not.
        if self.confirm.is_some() {
            return self.handle_confirm_key(key);
        }
        if self.form.is_some() {
            return self.handle_form_key(key);
        }
        if self.menu.is_some() {
            return self.handle_menu_key(key, state);
        }
        if self.details.is_some() {
            return self.handle_details_key(key);
        }

        let filtered = match self.focus {
            Pane::Servers => self.filter.key(&key, !servers(state).is_empty()),
            Pane::Log => self.log_filter.key(&key, !state.log.is_empty()),
        };
        if let Some(outcome) = filtered {
            return outcome;
        }
        if let Some(movement) = RowMove::of(key.code) {
            return self.move_selection(movement, state);
        }
        if self.focus == Pane::Servers {
            let ids = self.server_ids(state);
            if let Some(outcome) = self.tags.key(key.code, &ids, &mut self.cursor) {
                self.clamp_selection(state);
                return outcome;
            }
        }
        match key.code {
            KeyCode::Tab | KeyCode::BackTab => {
                self.focus = self.focus.toggled();
                ViewOutcome::Redraw
            }
            KeyCode::Char('m') | KeyCode::Enter if self.focus == Pane::Servers => {
                // Pinned: a tick that re-orders the table under the open menu
                // does not move its target.
                self.cursor.pin(&self.server_ids(state));
                self.open_menu(state)
            }
            KeyCode::Char('z') => {
                self.zoomed = !self.zoomed;
                ViewOutcome::Redraw
            }
            KeyCode::Char('f') if self.focus == Pane::Log => self.narrow_log(),
            KeyCode::Char('d') if self.focus == Pane::Servers => self.open_details(state),
            // `x` is the row's way out everywhere; it asks first.
            KeyCode::Char('x') if self.focus == Pane::Servers => self.ask_remove(state),
            KeyCode::Char('s') if self.focus == Pane::Servers && !servers(state).is_empty() => {
                self.sort.key(true)
            }
            KeyCode::Char('S') if self.focus == Pane::Servers && !servers(state).is_empty() => {
                self.sort.key(false)
            }
            KeyCode::Char('a') => {
                self.form = Some(ServerForm::add_server());
                ViewOutcome::Redraw
            }
            KeyCode::Char('U') => self.open_update_form(state),
            // `c` exists only here, and acts on the selected row; with no row
            // it says so.
            KeyCode::Char('c') => ViewOutcome::Emit(match self.selected(state) {
                Some(row) => connect_toggle(state, row.server.endpoint.clone()),
                None => Action::Flash(crate::words::server::NO_SERVER_LISTED),
            }),
            // Kad's own switch, wherever the focus is: `K` is bound
            // nowhere else in the TUI (`k` moves up).
            KeyCode::Char('K') => ViewOutcome::Emit(kad_switch(state)),
            // Everything else — 1–6, h/l, ?, q — bubbles to the app loop.
            _ => ViewOutcome::Ignored,
        }
    }

    fn move_selection(&mut self, movement: RowMove, state: &UiState) -> ViewOutcome {
        match self.focus {
            Pane::Servers => {
                let before = self.server_sel;
                let page = self.viewport.page();
                self.cursor.apply(&self.server_ids(state), movement, page);
                self.clamp_selection(state);
                if self.server_sel == before {
                    ViewOutcome::Ignored
                } else {
                    ViewOutcome::Redraw
                }
            }
            // The log scrolls rather than selects: down is toward newer, and
            // the ends are the oldest and the newest line.
            Pane::Log => {
                if self.log_viewport.scroll(movement) {
                    ViewOutcome::Redraw
                } else {
                    ViewOutcome::Ignored
                }
            }
        }
    }

    /// A wheel notch at (`column`, `row`), read as `key` on the pane under the
    /// pointer; the focus stays where it is. A modal takes it as a key.
    pub fn handle_wheel(
        &mut self,
        (column, row): (u16, u16),
        key: KeyEvent,
        state: &UiState,
    ) -> ViewOutcome {
        let modal = self.menu.is_some()
            || self.confirm.is_some()
            || self.form.is_some()
            || self.details.is_some();
        let under = if modal {
            None
        } else if crate::views::pane_hit(self.servers_area, column, row) {
            Some(Pane::Servers)
        } else if crate::views::pane_hit(self.log_area, column, row) {
            Some(Pane::Log)
        } else {
            None
        };
        let Some(under) = under else {
            return self.handle_key(key, state);
        };
        let focus = std::mem::replace(&mut self.focus, under);
        let outcome = self.handle_key(key, state);
        self.focus = focus;
        outcome
    }

    /// Click routing (ADR-0072, Row Selection): server rows select + focus, the
    /// log pane focuses (its rows scroll, they don't select). The Kad panel
    /// is display-only. The row menu takes its clicks; other modals keep to
    /// the keyboard.
    pub fn handle_click(&mut self, column: u16, row: u16, state: &UiState) -> ViewOutcome {
        if self.confirm.is_none() && self.form.is_none() && self.menu.is_some() {
            return self.click_menu(column, row, state);
        }
        if self.confirm.is_some() || self.form.is_some() || self.details.is_some() {
            return ViewOutcome::Ignored;
        }
        if let Some(outcome) = self.header_click(column, row) {
            self.focus = Pane::Servers;
            return outcome;
        }
        if let Some(index) = self.drawn.hit(column, row) {
            self.focus = Pane::Servers;
            self.select_server(state, index);
            return ViewOutcome::Redraw;
        }
        if crate::views::pane_hit(self.servers_area, column, row) {
            self.focus = Pane::Servers;
            return ViewOutcome::Redraw;
        }
        if crate::views::pane_hit(self.log_area, column, row) {
            self.focus = Pane::Log;
            return ViewOutcome::Redraw;
        }
        ViewOutcome::Ignored
    }

    /// Render one frame into `area` (spec §3.4): the server table over the
    /// log and Kad panes. Caches each pane's rect for click hit-testing, so a
    /// click can only ever land on the layout actually drawn.
    pub fn draw(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
        _now: Instant,
    ) -> Option<Position> {
        self.clamp_selection(state);

        let [servers_area, bottom] =
            Layout::vertical([Constraint::Min(0), Constraint::Length(BOTTOM_H)]).areas(area);
        let kad_w = if area.width < KAD_PANE_MIN_TAB_W {
            0
        } else {
            KAD_PANE_W
        };
        let [log_area, kad_area] =
            Layout::horizontal([Constraint::Min(0), Constraint::Length(kad_w)]).areas(bottom);
        let (servers_area, log_area, kad_area) = match (self.zoomed, self.focus) {
            (false, _) => (servers_area, log_area, kad_area),
            (true, Pane::Servers) => (area, Rect::default(), Rect::default()),
            (true, Pane::Log) => (Rect::default(), area, Rect::default()),
        };
        self.servers_area = servers_area;
        self.log_area = log_area;
        self.drawn = Drawn::default();

        if !servers_area.is_empty() {
            self.draw_servers(frame, servers_area, state, theme);
        }
        if !kad_area.is_empty() {
            draw_kad(frame, kad_area, state, theme);
        }
        if !log_area.is_empty() {
            self.draw_log(frame, log_area, state, theme);
        }
        if kad_w == 0 && !self.zoomed {
            say_gave_way(frame, crate::views::bottom_border(log_area), &[KAD], theme);
        }

        if let (Some(viewport), Some(row)) = (self.details.as_ref(), self.selected(state)) {
            menu::draw_details(frame, area, row, state, viewport, theme);
        }
        if let Some(menu) = self.menu.as_ref() {
            draw_menu(frame, area, menu, theme);
        }
        let caret = self
            .form
            .as_ref()
            .and_then(|form| draw_form(frame, area, form, theme));
        let caret = caret.or(match self.focus {
            Pane::Servers => self.drawn.caret,
            Pane::Log => self.log_caret,
        });
        if let Some(confirm) = self.confirm.as_ref() {
            draw_confirm(frame, area, confirm, theme);
        }
        caret
    }

    /// Whether a form or a Row Filter holds the keyboard.
    pub(crate) fn text_open(&self) -> bool {
        let filter = match self.focus {
            Pane::Servers => &self.filter,
            Pane::Log => &self.log_filter,
        };
        let open = self.menu.is_none() && self.confirm.is_none() && self.details.is_none();
        if open && self.form.is_none() && filter.typing() {
            return true;
        }
        self.form.is_some()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::fixture::*;

    #[test]
    fn tab_cycles_focus_between_servers_and_log() {
        let state = UiState::default();
        let mut view = NetworksView::new();
        assert_eq!(view.focus, Pane::Servers);
        view.handle_key(press(KeyCode::Tab), &state);
        assert_eq!(view.focus, Pane::Log);
        view.handle_key(press(KeyCode::BackTab), &state);
        assert_eq!(view.focus, Pane::Servers);
    }

    /// Every list reads its page keys in one place, so one table proves them.
    #[test]
    fn the_page_and_end_keys_move_the_cursor() {
        let state = listed_servers();
        let mut view = NetworksView::new();
        view.handle_key(press(KeyCode::End), &state);
        assert_eq!(view.server_sel, 3);
        view.handle_key(press(KeyCode::Home), &state);
        assert_eq!(view.server_sel, 0);
        view.handle_key(press(KeyCode::PageDown), &state);
        assert_eq!(
            view.server_sel, 1,
            "a page of the one row a fresh view knows"
        );
        view.handle_key(press(KeyCode::PageUp), &state);
        assert_eq!(view.server_sel, 0);
    }

    /// The wheel scrolls what the pointer is over, and the focus stays put.
    #[test]
    fn the_wheel_moves_the_pane_under_the_pointer_not_the_focused_one() {
        let state = listed_servers();
        let mut view = NetworksView::new();
        view.servers_area = Rect::new(0, 0, 80, 10);
        view.log_area = Rect::new(0, 10, 40, 10);
        let log = view.log_viewport;
        view.handle_wheel((5, 14), press(KeyCode::Down), &state);
        assert_eq!(view.server_sel, 0, "the focused table stayed");
        assert_eq!(view.focus, Pane::Servers);
        assert_eq!(view.log_viewport.first(), log.first());
        view.handle_wheel((5, 4), press(KeyCode::Down), &state);
        assert_eq!(view.server_sel, 1);
    }

    #[test]
    fn selection_walks_the_listed_rows_and_stops_at_the_ends() {
        let state = listed_servers();
        let mut view = NetworksView::new();
        assert_eq!(view.server_sel, 0);
        view.handle_key(press(KeyCode::Char('j')), &state);
        view.handle_key(press(KeyCode::Char('j')), &state);
        assert_eq!(view.server_sel, 2);
        view.handle_key(press(KeyCode::Char('G')), &state);
        assert_eq!(view.server_sel, 3, "G lands on the last listed row");
        assert!(
            matches!(
                view.handle_key(press(KeyCode::Char('j')), &state),
                ViewOutcome::Ignored
            ),
            "past the end is nobody's key"
        );
        view.handle_key(press(KeyCode::Char('g')), &state);
        assert_eq!(view.server_sel, 0);
    }

    /// The list is a level: a shrinking republish must not strand the cursor
    /// past the end (a removal is exactly this).
    #[test]
    fn a_shrinking_list_pulls_the_selection_back_in() {
        let full = listed_servers();
        let mut view = NetworksView::new();
        view.handle_key(press(KeyCode::Char('G')), &full);
        assert_eq!(view.server_sel, 3);

        let mut shrunk = listed_servers();
        shrunk.diagnostics.servers.truncate(2);
        view.handle_key(press(KeyCode::Tab), &shrunk); // any key re-clamps
        assert_eq!(view.server_sel, 1);
    }

    #[test]
    fn the_focused_pane_border_is_accent_the_others_dim() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let theme = Theme::default_dark();
        let state = UiState::default();
        let mut view = NetworksView::new();
        view.handle_key(press(KeyCode::Tab), &state); // focus → Log
        let mut terminal = Terminal::new(TestBackend::new(78, 21)).expect("terminal");
        terminal
            .draw(|frame| {
                let area = frame.area();
                view.draw(frame, area, &state, &theme, Instant::now());
            })
            .expect("draw");
        let buffer = terminal.backend().buffer();
        let servers = buffer.cell((0u16, 0u16)).expect("servers corner");
        let log = buffer
            .cell((view.log_area.x, view.log_area.y))
            .expect("log corner");
        assert_eq!(
            log.style().fg,
            Some(theme.accent),
            "focused log pane border is accent"
        );
        assert_eq!(
            servers.style().fg,
            Some(theme.dim),
            "unfocused servers pane border is dim"
        );
    }

    #[test]
    fn clicks_route_to_the_servers_and_log_panes_and_miss_the_kad_panel() {
        use ratatui::{Terminal, backend::TestBackend};
        let mut view = NetworksView::new();
        let state = listed_servers();
        // 30 rows: at 21 the selected server's detail line leaves the table
        // one row, and this test clicks the second.
        let mut terminal = Terminal::new(TestBackend::new(78, 30)).expect("terminal");
        terminal
            .draw(|f| {
                view.draw(
                    f,
                    Rect::new(0, 0, 78, 30),
                    &state,
                    &Theme::default_dark(),
                    Instant::now(),
                );
            })
            .expect("draw");
        view.focus = Pane::Log;
        let row1 = view.drawn.line_of(1).expect("row 1 on screen");
        assert!(
            matches!(view.handle_click(3, row1, &state), ViewOutcome::Redraw),
            "servers pane"
        );
        assert_eq!(view.focus, Pane::Servers);
        assert_eq!(
            view.server_sel, 1,
            "the click selected the row it landed on"
        );
        let log_y = view.log_area.y + 1;
        assert!(
            matches!(view.handle_click(3, log_y, &state), ViewOutcome::Redraw),
            "log pane"
        );
        assert_eq!(view.focus, Pane::Log);
        // The Kad panel is display-only: clicks there are nobody's.
        let kad_x = view.log_area.right() + 2;
        assert!(matches!(
            view.handle_click(kad_x, log_y, &state),
            ViewOutcome::Ignored
        ));
    }
}
