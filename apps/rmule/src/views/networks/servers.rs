//! The managed-server table (spec §3.4): its column budget and the row
//! projection itself, with the selected server's health on one line under it.
//!
//! Every row is a projection of a level — [`ServerDiagnostics`] joined with
//! the one session fact — so nothing here is edited locally and reconciled
//! later. The dynamic three (ping, users, files) are `Option`: a server that
//! has never answered renders a dash, never a zero nobody measured.

use std::time::Duration;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use rmule_core::diagnostics::{PingState, ServerDiagnostics};
use rmule_core::{ServerHealth, ServerPriority};

use super::{NetworksView, Pane};
use crate::row_selection::selection_style;
use crate::state::{Ed2kConnection, UiState, server_label};
use crate::table::{self, Cell, Rows, Table, cut_middle, widest};
use crate::theme::Theme;
use crate::words::server::{DetailContext, UNMEASURED_PING_WORDS};
use crate::words::units::short_count;
use crate::words::{absent, hints, networks as words};
use crate::wrap::display_width;

/// Floors of the eleven server columns — Name · Address · Port · Description
/// · Ping · Users · Files · Age · Prio · Fail · Static.
///
/// Name and Description are **greedy** and share what the fixed columns leave
/// over. Name's floor is the room it keeps before other columns give way to
/// it, Description's the narrowest worth showing. Address's floor fits the
/// widest IPv4 (`255.255.255.255`) whole; the rest are measured from what they
/// draw.
fn server_floors() -> [usize; 11] {
    let priority = widest(&[words::PRIO_LOW, words::PRIO_NORMAL, words::PRIO_HIGH]);
    let flag = widest(&[words::YES, words::NO]);
    let unmeasured = widest(&UNMEASURED_PING_WORDS);
    let age = display_width(&words::age(WIDEST_AGE_SECS)).max(unmeasured);
    let ping = display_width(&words::ping_ms(999)).max(unmeasured);
    let count = unmeasured.max(5);
    [20, 15, 5, 16, ping, count, count, age, priority, 4, flag]
}
/// A hundred days less a second: the age with the most digits a cell shows.
const WIDEST_AGE_SECS: u64 = 8_639_999;
/// The greedy pair's indices in the floors.
const SERVER_NAME_COL: usize = 0;
const SERVER_DESC_COL: usize = 3;

/// The order the server table's columns give way in: Description, which reads
/// whole on the Off-screen line, then Static, Fail, Prio, Files, Users, Port,
/// Ping, Age — the last of the figures, so none shows without its age — then
/// Address. Name never gives way.
const SERVER_GIVE_WAY: [usize; 10] = [3, 10, 9, 8, 6, 5, 2, 4, 7, 1];
/// Row gutter: selection arrow, connected dot, separator. Both marks are
/// glyphs, so neither fact is carried by colour alone (spec §5).
const SERVER_GUTTER_W: usize = 3;

/// A row's display name: the server's own banner, or an honest dash. Core
/// never invents one, and the address is its own column — repeating it here
/// would make an unnamed row look named.
pub(super) fn row_name(row: &ServerDiagnostics) -> String {
    let name = row.server.name.to_display_string();
    if name.trim().is_empty() {
        absent::NO_NAME.to_string()
    } else {
        name
    }
}

/// aMule's `ST_PREFERENCE` in four columns.
pub(super) fn priority_word(priority: ServerPriority) -> &'static str {
    match priority {
        ServerPriority::Low => words::PRIO_LOW,
        ServerPriority::Normal => words::PRIO_NORMAL,
        ServerPriority::High => words::PRIO_HIGH,
    }
}

/// The cycling row-menu order: Low → Normal → High → Low.
pub(super) fn next_priority(priority: ServerPriority) -> ServerPriority {
    match priority {
        ServerPriority::Low => ServerPriority::Normal,
        ServerPriority::Normal => ServerPriority::High,
        ServerPriority::High => ServerPriority::Low,
    }
}

/// How long ago a server's figures were dated, in a row's Age cell: the
/// age, or for a row nothing has dated the word its ping gives for why.
fn age_cell(age: Option<Duration>, ping: &PingState) -> String {
    age.map_or_else(
        || crate::words::server::undated_word(ping).to_string(),
        format_age,
    )
}

/// How long ago a server last answered, three cells: seconds under a minute,
/// then minutes, hours under two days, days under a hundred, then weeks.
fn format_age(age: Duration) -> String {
    words::age(age.as_secs())
}

/// What the detail words need beyond the row.
fn detail_context(row: &ServerDiagnostics, state: &UiState) -> DetailContext {
    DetailContext {
        connected: state.diagnostics.connected_server.as_ref() == Some(&row.server.endpoint),
        told: state
            .diagnostics
            .share_announcement
            .as_ref()
            .filter(|told| told.server == row.server.endpoint)
            .map(|told| told.shares),
        policy: state.preferences.server_policy(),
    }
}

/// The selected server's four detail sentences (ADR-0080): grants, UDP flags,
/// health, shares. What the `d` modal says.
pub(super) fn detail_sentences(row: &ServerDiagnostics, state: &UiState) -> [String; 4] {
    crate::words::server::detail_pane(row, detail_context(row, state), format_age)
}

/// A row's **Ping State** in its five-column cell: the measured UDP round
/// trip, or the word for why there is none.
fn format_ping(ping: &PingState) -> String {
    match ping.measured() {
        Some(rtt) if rtt.as_millis() < 1000 => words::ping_ms(rtt.as_millis()),
        Some(rtt) => words::ping_s(rtt.as_secs_f64()),
        None => crate::words::server::unmeasured_ping_word(ping)
            .unwrap_or_default()
            .to_string(),
    }
}

/// A user or file count, or why the server has not reported one — the
/// row's ping says whether a status answer is still to come.
fn count_cell(count: Option<u32>, ping: &PingState) -> String {
    count.map_or_else(
        || crate::words::server::unreported_count_word(ping).to_string(),
        |count| short_count(u64::from(count)),
    )
}

impl NetworksView {
    pub(super) fn draw_servers(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
    ) {
        let focused = self.focus == Pane::Servers;
        let rows = self.ordered(state);
        // The edge, as the status bar reads it, so the two say one thing in
        // every frame.
        let connected = state.connected_server.as_ref();
        let title = match (&state.ed2k, connected) {
            (Ed2kConnection::Connected { client_id }, server) => {
                let server = server.map_or_else(String::new, server_label);
                words::servers_connected(rows.len(), &server, client_id.is_high_id())
            }
            (Ed2kConnection::Connecting { server }, _) => {
                words::servers_title(rows.len(), &crate::words::server::dialling(server))
            }
            _ => words::servers_off(rows.len()),
        };
        let title = if self.tags.is_empty() {
            title
        } else {
            let tagged = crate::words::rows::tagged(self.tags.len());
            format!(
                "{}· {tagged} ",
                title.trim_end_matches(' ').to_string() + " "
            )
        };
        // `c` is hinted only where it can act (No dead UI): a selected row.
        let toggle = match self.selected(state) {
            Some(row) if crate::views::is_remaking(state, &row.server.endpoint) => {
                Some(hints::STOP_RECONNECTING)
            }
            Some(row) if crate::views::is_dialling(state, &row.server.endpoint) => {
                Some(hints::STOP_CONNECTING)
            }
            Some(row) if crate::views::is_ours(state, &row.server.endpoint) => {
                Some(hints::DISCONNECT)
            }
            Some(_) => Some(hints::CONNECT),
            None => None,
        };
        let hint = if state.server_list_updating {
            words::UPDATING.to_string()
        } else if rows.is_empty() {
            hints::line(&[hints::ADD_SERVER, hints::UPDATE_LIST, hints::MENU])
        } else {
            let mut keys: Vec<_> = toggle.into_iter().collect();
            keys.extend([
                hints::MENU,
                hints::FILTER,
                hints::ADD_SERVER,
                hints::TO_LOG,
                hints::DETAILS,
                hints::UPDATE_LIST,
                hints::TAG,
                hints::SORT,
                hints::REVERSE,
                hints::ZOOM,
            ]);
            hints::line(&keys)
        };
        let block = crate::views::title::titled(
            theme.pane(focused),
            area.width,
            (&title, Style::new().fg(theme.fg)),
            (&hint, theme.dim_text()),
        );
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if inner.height == 0 || inner.width == 0 {
            return;
        }

        let selected = rows.get(self.server_sel).copied();
        let body = draw_health(frame, inner, selected, state, theme);
        let cells =
            |index: usize, _: &[usize]| server_cells(rows[index], Style::new().fg(theme.fg), theme);
        let server_sel = self.server_sel;
        let marker = |index: usize| {
            let endpoint = &rows[index].server.endpoint;
            server_marker(
                (index == server_sel, self.tags.contains(endpoint)),
                connected == Some(endpoint),
                focused,
                theme,
            )
        };
        let table = Table::of(
            &self.sort,
            &server_floors(),
            SERVER_NAME_COL,
            &SERVER_GIVE_WAY,
            theme.header(),
        )
        .flex_pair(SERVER_DESC_COL)
        .gutter(SERVER_GUTTER_W)
        .empty(if self.filter.shown() {
            crate::words::rows::NO_MATCH
        } else {
            words::NO_SERVERS
        });
        let rows = Rows {
            count: rows.len(),
            selected: Some(server_sel),
            focused,
            cells: &cells,
            marker: Some(&marker),
            tagged: None,
            filter: Some((&self.filter, state.diagnostics.servers.len())),
        };
        self.drawn = table::draw(
            frame,
            (area, body),
            &table,
            &rows,
            &mut self.viewport,
            theme,
        );
    }
}

/// The selected server's health on the last line of `body`, its full detail a
/// key away, and what is left of `body` above it.
fn draw_health(
    frame: &mut Frame,
    body: Rect,
    row: Option<&ServerDiagnostics>,
    state: &UiState,
    theme: &Theme,
) -> Rect {
    let Some(row) = row.filter(|_| body.height >= 3) else {
        return body;
    };
    let health = crate::words::server::health_line(row, detail_context(row, state), format_age);
    let line = Rect::new(body.x, body.bottom() - 1, body.width, 1);
    let text = cut_middle(&health, usize::from(body.width));
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(text, theme.dim_text()))),
        line,
    );
    Rect {
        height: body.height - 1,
        ..body
    }
}

/// A server row's gutter: the selection arrow and the connected dot.
fn server_marker(
    (selected, tagged): (bool, bool),
    is_connected: bool,
    focused: bool,
    theme: &Theme,
) -> Span<'static> {
    Span::styled(
        format!(
            "{}{}{}",
            if selected { "▸" } else { " " },
            if is_connected { "●" } else { " " },
            if tagged { "•" } else { " " }
        ),
        if selected {
            selection_style(theme, focused)
        } else if tagged {
            Style::new().fg(theme.accent)
        } else if is_connected {
            Style::new().fg(theme.good)
        } else {
            theme.dim_text()
        },
    )
}

/// One listed server's eleven cells, in `ServersTable::COLUMNS`' order.
///
/// A **Dead Server** (ADR-0052) is dimmed whole and its Fail cell says
/// `dead` instead of the tally, in the colour of bad news — the word, not the
/// colour, carries the state, and the column still sorts by the tally.
fn server_cells(row: &ServerDiagnostics, base: Style, theme: &Theme) -> Vec<Cell> {
    let dead = row.health == ServerHealth::Dead;
    let base = if dead { base.fg(theme.dim) } else { base };
    // Unknown dynamics stay dim on whatever background the row has, so a
    // dash never loses the selection bar it sits in.
    let unknown = base.fg(theme.dim);
    let known = |present: bool| if present { base } else { unknown };
    let name = row_name(row);
    let description = row.server.description.to_display_string();
    let has_description = !description.trim().is_empty();
    let fails = row.server.fail_count;
    vec![
        Cell::new(name, known(!row.server.name.as_bytes().is_empty())),
        Cell::new(row.server.endpoint.host().to_string(), base),
        Cell::new(row.server.endpoint.port().to_string(), base),
        Cell::new(
            if has_description {
                description
            } else {
                absent::NONE.to_string()
            },
            known(has_description),
        ),
        Cell::new(format_ping(&row.ping), known(row.ping.measured().is_some())),
        Cell::new(count_cell(row.users, &row.ping), known(row.users.is_some())),
        Cell::new(count_cell(row.files, &row.ping), known(row.files.is_some())),
        Cell::new(age_cell(row.age, &row.ping), known(row.age.is_some())),
        Cell::new(priority_word(row.server.priority), base),
        // A climbing tally is the row's own bad news; the number says
        // it and the colour only underlines it.
        Cell::new(
            if dead {
                crate::words::server::DEAD_CELL.to_string()
            } else {
                fails.to_string()
            },
            if fails > 0 {
                base.fg(theme.bad)
            } else {
                unknown
            },
        ),
        // A known no, not an unknown: aMule's Yes/No
        // (`ServerListCtrl.cpp:334`), never a dash.
        Cell::new(
            if row.server.is_static {
                words::YES
            } else {
                words::NO
            },
            known(row.server.is_static),
        ),
    ]
}

#[cfg(test)]
mod tests;
