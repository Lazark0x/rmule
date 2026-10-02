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
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::layout::{Constraint, Layout, Rect};

use rmule_core::diagnostics::ServerDiagnostics;
use rmule_primitives::ServerEndpoint;

use crate::action::Action;
use crate::state::UiState;
use crate::table_sort::{RowCursor, RowMove, TableSort};
use crate::theme::Theme;
use crate::views::{DrawnRows, ViewOutcome, connect_toggle};
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
/// Width of the Kad panel — its longest value row ("firewalled · not checked
/// yet", the verdict and why on one line) under a ten-column label, plus
/// borders.
const KAD_PANE_W: u16 = 40;

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
    /// The selected server, by endpoint.
    cursor: RowCursor<ServerEndpoint>,
    /// The selected server's position in the current order — `cursor`
    /// re-placed before every key and draw.
    server_sel: usize,
    /// First listed row rendered — the table scrolls by *entry*, because a
    /// wrapped row must not be split across the pane edge.
    server_offset: usize,
    /// The server rows as last drawn: the map a row click needs once rows
    /// can be more than one line tall.
    server_rows: DrawnRows,
    /// The header as last drawn, and its column widths: a click there sorts.
    header_area: Rect,
    header_cols: Vec<usize>,
    /// Display lines scrolled up from the newest; `0` pins the log to the
    /// bottom. Counted in *wrapped* lines, not entries.
    log_offset: usize,
    /// Inner log height from the last draw, for input-time scroll clamping.
    log_rows: usize,
    /// Wall clock stamped by the app each frame (`None` in goldens/tests → a
    /// fixed fallback, keeping renders deterministic). Log lines carry only
    /// injected `Instant`s; the wall stamp is derived at draw time as
    /// `wall_now − age`, so state stays clock-free.
    pub(crate) wall_now: Option<chrono::DateTime<chrono::FixedOffset>>,
    /// Wrapped display-line count from the last draw; `0` before the first
    /// one, where the entry count is the honest estimate.
    log_lines: usize,
    menu: Option<Menu>,
    confirm: Option<Confirm>,
    form: Option<ServerForm>,
    /// Pane areas cached at draw time for click hit-testing.
    servers_area: Rect,
    log_area: Rect,
}

impl Default for NetworksView {
    fn default() -> Self {
        Self {
            focus: Pane::Servers,
            sort: TableSort::default(),
            cursor: RowCursor::default(),
            server_sel: 0,
            server_offset: 0,
            server_rows: DrawnRows::default(),
            header_area: Rect::default(),
            header_cols: Vec::new(),
            log_offset: 0,
            log_rows: 4,
            log_lines: 0,
            wall_now: None,
            menu: None,
            confirm: None,
            form: None,
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
        if self.server_offset > self.server_sel {
            self.server_offset = self.server_sel;
        }
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
        if key.kind == KeyEventKind::Release {
            return ViewOutcome::Ignored;
        }
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

        if let Some(movement) = RowMove::of(key.code) {
            return self.move_selection(movement, state);
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
                self.cursor.apply(&self.server_ids(state), movement);
                self.clamp_selection(state);
                if self.server_sel == before {
                    ViewOutcome::Ignored
                } else {
                    ViewOutcome::Redraw
                }
            }
            // The log scrolls rather than selects: down is toward newer, which
            // is a smaller offset, and the ends are the newest and oldest line.
            Pane::Log => {
                let max = self.max_log_offset(state);
                let next = match movement {
                    RowMove::Step(delta) => self
                        .log_offset
                        .saturating_add_signed(delta.saturating_neg())
                        .min(max),
                    RowMove::First => max,
                    RowMove::Last => 0,
                };
                if next == self.log_offset {
                    ViewOutcome::Ignored
                } else {
                    self.log_offset = next;
                    ViewOutcome::Redraw
                }
            }
        }
    }

    /// Click routing (ADR-0072, Row Selection): server rows select + focus, the
    /// log pane focuses (its rows scroll, they don't select). The Kad panel
    /// is display-only. Modals stay keyboard-only in v1.
    pub fn handle_click(&mut self, column: u16, row: u16, state: &UiState) -> ViewOutcome {
        if self.menu.is_some() || self.confirm.is_some() || self.form.is_some() {
            return ViewOutcome::Ignored;
        }
        if let Some(outcome) = self.header_click(column, row) {
            self.focus = Pane::Servers;
            return outcome;
        }
        if let Some(index) = self.server_rows.hit(column, row) {
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
        now: Instant,
    ) {
        self.clamp_selection(state);

        let [servers_area, bottom] =
            Layout::vertical([Constraint::Min(0), Constraint::Length(BOTTOM_H)]).areas(area);
        let [log_area, kad_area] =
            Layout::horizontal([Constraint::Min(0), Constraint::Length(KAD_PANE_W)]).areas(bottom);
        self.servers_area = servers_area;
        self.log_area = log_area;

        self.draw_servers(frame, servers_area, state, theme);
        draw_kad(frame, kad_area, state, theme);
        self.draw_log(frame, log_area, state, theme, now);

        if let Some(menu) = self.menu.as_ref() {
            draw_menu(frame, area, menu, theme);
        }
        if let Some(form) = self.form.as_ref() {
            draw_form(frame, area, form, theme);
        }
        if let Some(confirm) = self.confirm.as_ref() {
            draw_confirm(frame, area, confirm, theme);
        }
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
                )
            })
            .expect("draw");
        view.focus = Pane::Log;
        // The second listed row's first display line, whatever height the
        // rows above it wrapped to.
        let row1 = view.server_rows.line_of(1).expect("row 1 on screen");
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
