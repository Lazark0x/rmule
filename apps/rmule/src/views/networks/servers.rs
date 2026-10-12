//! The managed-server table (spec §3.4): its column budget, the greedy widths
//! that keep a row fitting any terminal, and the row projection itself.
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
use ratatui::widgets::{Block, Paragraph};

use rmule_core::diagnostics::ServerDiagnostics;
use rmule_core::{ServerHealth, ServerPriority};
use rmule_primitives::ServerEndpoint;

use super::sort::ServersTable;
use super::{NetworksView, Pane};
use crate::row_selection::{mark_row, selection_style};
use crate::state::{Ed2kConnection, UiState, server_label};
use crate::table_sort::{SortedTable, arrow_floors, header_label, header_widths};
use crate::theme::Theme;
use crate::views::{DrawnRows, say_gave_way, short_count};
use crate::wrap::{
    Column, TableColumns, clamp_u16, column_lines, gave_way, greedy_widths, wrapped_lines,
};

/// Declared widths of the eleven server columns — Name · Address · Port ·
/// Description · Ping · Users · Files · Age · Prio · Fail · Static.
///
/// Name and Description are **greedy**: their entries are floors, and
/// the two of them share whatever the eight fixed columns leave over. Every
/// floor is at least its *header*'s width, and the whole set plus its gaps and
/// gutter fits an 80-column terminal exactly — a wrapped header row reads as a
/// layout fault rather than as content, so the narrowest supported frame is
/// where the budget is set.
/// Address's floor fits the widest IPv4 (`255.255.255.255`, 15 cells) whole —
/// an address split across lines reads as two rows, not one host (a hands-on
/// run's finding). The slack came out of the description column,
/// whose header shortened to `Desc` to keep the header-fits-floor invariant,
/// and Age took the rest of the description's floor above its header.
const SERVER_COLS: [usize; 11] = [8, 15, 5, 4, 5, 5, 5, 3, 4, 4, 6];
/// The greedy pair's indices in [`SERVER_COLS`].
const SERVER_NAME_COL: usize = 0;
const SERVER_DESC_COL: usize = 3;

/// The order the server table's columns give way in when the pane cannot hold
/// every header: Static, Fail, Prio, Files, Users, Desc, Port, Ping,
/// Age — the last of the figures, so none shows without its age — then
/// Address. Name never gives way.
const SERVER_GIVE_WAY: [usize; 10] = [10, 9, 8, 6, 5, 3, 2, 4, 7, 1];
/// Row gutter: selection arrow, connected dot, separator. Both marks are
/// glyphs, so neither fact is carried by colour alone (spec §5).
const SERVER_GUTTER_W: usize = 3;

/// Column widths for the server table: [`greedy_widths`] with the slack shared
/// between the two identity columns.
///
/// `greedy_widths` grows exactly one column, which is the right primitive for a
/// table with one name; this table has two things worth reading in full, so the
/// surplus is handed to Name and then levelled: the pair end up as equal as
/// their floors allow, Name keeping the odd column. Description's floor is the
/// wider of the two only because its header is, so at the tightest frame it
/// stays wider and everywhere else they match. When there is no surplus at all
/// the primitive's proportional shrink stands untouched — every column keeps a
/// usable share and the cells wrap.
fn server_widths(pane_width: usize, floors: &[usize], headers: &[usize]) -> Vec<usize> {
    let total = pane_width.saturating_sub(SERVER_GUTTER_W);
    let table = TableColumns {
        floors,
        headers,
        flex: SERVER_NAME_COL,
        wants: &[],
        give_way: &SERVER_GIVE_WAY,
    };
    let mut widths = greedy_widths(total, &table, 1);
    let slack = widths[SERVER_NAME_COL].saturating_sub(floors[SERVER_NAME_COL]);
    let pair = floors[SERVER_NAME_COL] + floors[SERVER_DESC_COL] + slack;
    let to_description = (pair / 2)
        .saturating_sub(floors[SERVER_DESC_COL])
        .min(slack);
    widths[SERVER_NAME_COL] -= to_description;
    widths[SERVER_DESC_COL] += to_description;
    widths
}

/// A row's display name: the server's own banner, or an honest dash. Core
/// never invents one, and the address is its own column — repeating it here
/// would make an unnamed row look named.
pub(super) fn row_name(row: &ServerDiagnostics) -> String {
    let name = row.server.name.to_display_string();
    if name.trim().is_empty() {
        "—".to_string()
    } else {
        name
    }
}

/// aMule's `ST_PREFERENCE` in four columns.
pub(super) fn priority_word(priority: ServerPriority) -> &'static str {
    match priority {
        ServerPriority::Low => "Low",
        ServerPriority::Normal => "Norm",
        ServerPriority::High => "High",
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

/// How long ago a server last answered, three cells: seconds under a minute,
/// then minutes, hours under two days, days under a hundred, then weeks — a
/// dash for one that never answered.
fn format_age(age: Option<Duration>) -> String {
    let Some(age) = age else {
        return "—".to_string();
    };
    let secs = age.as_secs();
    match secs {
        0..60 => format!("{secs}s"),
        60..3_600 => format!("{}m", secs / 60),
        3_600..172_800 => format!("{}h", secs / 3_600),
        172_800..8_640_000 => format!("{}d", secs / 86_400),
        _ => format!("{}w", secs / 604_800),
    }
}

/// The fewest lines the detail pane takes: one per sentence.
const DETAIL_PANE_MIN_H: u16 = 4;

/// Draw the selected server's detail at the bottom of `body` and return what
/// is left of `body` above it (ADR-0080, "The detail pane"). The table has no
/// room for these as columns at 80 cells, so they are said whole, wrapped,
/// for whichever row the cursor is on.
///
/// The pane — grants, UDP flags, health and shares, one sentence each —
/// takes the height its sentences wrap to, at least [`DETAIL_PANE_MIN_H`].
/// Where that would take more than half of `body` from the table, it
/// collapses to one wrapped line of grants, UDP flags and the connected
/// server's share news (ADR-0099).
fn draw_detail(
    frame: &mut Frame,
    body: Rect,
    row: Option<&ServerDiagnostics>,
    state: &UiState,
    theme: &Theme,
) -> Rect {
    let Some(row) = row else {
        return body;
    };
    if body.height < 3 || body.width == 0 {
        return body;
    }
    let width = usize::from(body.width);
    let age = |ago| format_age(Some(ago));
    let told = state
        .diagnostics
        .share_announcement
        .as_ref()
        .filter(|told| told.server == row.server.endpoint)
        .map(|told| told.shares);
    let context = crate::words::server::DetailContext {
        connected: state.diagnostics.connected_server.as_ref() == Some(&row.server.endpoint),
        told,
        policy: state.preferences.server_policy(),
    };
    let pane: Vec<Line<'static>> = crate::words::server::detail_pane(row, context, age)
        .iter()
        .flat_map(|sentence| wrapped_lines(sentence, width, theme.dim_text()))
        .collect();
    let pane_h = clamp_u16(pane.len()).max(DETAIL_PANE_MIN_H);
    let (lines, height) = if pane_h <= body.height / 2 {
        (pane, pane_h)
    } else {
        let mut text = crate::words::server::grants_line(row, age);
        if let Some(news) = told.and_then(crate::words::server::shares_line) {
            text = format!("{text} · {news}");
        }
        let lines = wrapped_lines(&text, width, theme.dim_text());
        let height = clamp_u16(lines.len()).min(body.height / 2);
        (lines, height)
    };
    let line_area = Rect::new(body.x, body.bottom() - height, body.width, height);
    frame.render_widget(Paragraph::new(lines), line_area);
    Rect::new(body.x, body.y, body.width, body.height - height)
}

/// A measured UDP round trip, five columns wide at most.
fn format_ping(ping: Option<Duration>) -> String {
    match ping {
        None => "—".to_string(),
        Some(rtt) if rtt.as_millis() < 1000 => format!("{}ms", rtt.as_millis()),
        Some(rtt) => format!("{:.1}s", rtt.as_secs_f64()),
    }
}

impl NetworksView {
    pub(super) fn draw_servers(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
    ) {
        // No rows or header until this draw says so.
        self.server_rows = DrawnRows::default();
        self.header_area = Rect::default();
        let focused = self.focus == Pane::Servers;
        let border = if focused { theme.accent } else { theme.dim };
        let rows = self.ordered(state);
        let connected = state.diagnostics.connected_server.as_ref();
        let title = match (connected, state.ed2k) {
            (Some(server), Ed2kConnection::Connected { client_id }) => {
                let class = if client_id.is_high_id() {
                    "HighID"
                } else {
                    "LowID"
                };
                format!(
                    " Servers ({}) · {} {class} ",
                    rows.len(),
                    server_label(server)
                )
            }
            // The level and the edge disagree only for the instant between the
            // login and the tick that publishes it; say what is proven.
            (Some(server), Ed2kConnection::Disconnected) => {
                format!(" Servers ({}) · {} ", rows.len(), server_label(server))
            }
            (None, _) => format!(" Servers ({}) · not connected ", rows.len()),
        };
        // `c` is hinted only where it can act (No dead UI): a selected row
        // and a core to log in with, or the row to disconnect from.
        let toggle = match self.selected(state) {
            Some(row) if crate::views::is_remaking(state, &row.server.endpoint) => {
                "c stop reconnecting · "
            }
            Some(row) if crate::views::is_ours(state, &row.server.endpoint) => "c disconnect · ",
            Some(_) if state.session.is_some() => "c connect · ",
            _ => "",
        };
        let hint = if state.server_list_updating {
            " updating… ".to_string()
        } else if rows.is_empty() {
            " a add · U update · m menu ".to_string()
        } else {
            format!(" {toggle}a add · U update · m menu · s/S sort ")
        };
        let block = crate::views::title::titled(
            Block::bordered().border_style(Style::new().fg(border)),
            area.width,
            (&title, Style::new().fg(theme.fg)),
            (&hint, theme.dim_text()),
        );
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if inner.height == 0 || inner.width == 0 {
            return;
        }

        // Greedy Name + Description; every cell wraps rather than clipping.
        // The sorted column's floor holds its label and the arrow, so the
        // header stays one line; Name pays for the arrow.
        let floors = arrow_floors(&self.sort, &SERVER_COLS, SERVER_NAME_COL);
        let headers = header_widths(&self.sort);
        let widths = server_widths(usize::from(inner.width), &floors, &headers);
        say_gave_way(
            frame,
            area,
            &gave_way(ServersTable::COLUMNS.iter().map(|c| c.label), &widths),
            theme,
        );
        let dim = theme.dim_text();
        let labels: Vec<Column> = ServersTable::COLUMNS
            .iter()
            .map(|column| {
                let label = header_label(column.label, self.sort.arrow(column.column));
                if column.kind.right_aligned() {
                    Column::right(label, dim)
                } else {
                    Column::left(label, dim)
                }
            })
            .collect();
        let header = column_lines(&labels, &widths, 1, &Span::raw(" ".repeat(SERVER_GUTTER_W)));
        let header_h = clamp_u16(header.len()).min(inner.height);
        frame.render_widget(
            Paragraph::new(header),
            Rect::new(inner.x, inner.y, inner.width, header_h),
        );
        self.header_area = Rect::new(
            inner.x.saturating_add(clamp_u16(SERVER_GUTTER_W)),
            inner.y,
            inner.width.saturating_sub(clamp_u16(SERVER_GUTTER_W)),
            header_h,
        );
        self.header_cols.clone_from(&widths);
        if inner.height <= header_h {
            return;
        }
        let body = Rect::new(
            inner.x,
            inner.y + header_h,
            inner.width,
            inner.height - header_h,
        );

        if rows.is_empty() {
            self.server_offset = 0;
            frame.render_widget(
                Paragraph::new(wrapped_lines(
                    "no servers — press a to add one, or U to update the list from a URL",
                    usize::from(body.width),
                    dim,
                )),
                body,
            );
            return;
        }

        // The selected server's values in the columns that gave way.
        let off_screen = rows.get(self.server_sel).map_or_else(Vec::new, |row| {
            let values: Vec<String> = server_columns(row, Style::new(), theme)
                .into_iter()
                .map(|column| column.text)
                .collect();
            crate::views::off_screen::hidden(
                ServersTable::COLUMNS.iter().map(|column| column.label),
                &values,
                &widths,
            )
        });
        let body = draw_detail(
            frame,
            body,
            rows.get(self.server_sel).copied(),
            state,
            theme,
        );
        let body = crate::views::off_screen::draw(frame, body, &off_screen, theme);
        let budget = usize::from(body.height);
        self.scroll_to_selection(&rows, &widths, connected, budget, theme);

        let mut lines: Vec<Line> = Vec::new();
        let mut heights: Vec<u16> = Vec::new();
        for (index, row) in rows.iter().enumerate().skip(self.server_offset) {
            let rendered = self.row_lines(row, index, &widths, connected, theme);
            // A row that cannot fit whole is not started: half a wrapped row
            // at the pane edge reads as truncation, which is the one thing
            // the never-truncate rule forbids. A row taller than the whole pane still renders.
            if !lines.is_empty() && lines.len() + rendered.len() > budget {
                break;
            }
            heights.push(clamp_u16(rendered.len()));
            lines.extend(rendered);
            if lines.len() >= budget {
                break;
            }
        }
        self.server_rows = DrawnRows::new(body, self.server_offset, heights);
        frame.render_widget(Paragraph::new(lines), body);
    }

    /// Put the selected row on screen, scrolling as little as it takes.
    ///
    /// The walk goes *up* from the selection, taking rows while they still fit
    /// — so it touches only rows that will be drawn, whatever the list's
    /// length. A downloaded server.met is thousands of rows and this runs
    /// every frame; summing from the current offset instead would make the
    /// cost of pressing `G` quadratic in the list.
    fn scroll_to_selection(
        &mut self,
        rows: &[&ServerDiagnostics],
        widths: &[usize],
        connected: Option<&ServerEndpoint>,
        budget: usize,
        theme: &Theme,
    ) {
        let height = |view: &Self, index: usize| {
            view.row_lines(rows[index], index, widths, connected, theme)
                .len()
        };
        let mut used = height(self, self.server_sel);
        // The highest row that can be on screen with the selection still on it.
        let mut top = self.server_sel;
        while top > 0 {
            let above = height(self, top - 1);
            if used + above > budget {
                break;
            }
            used += above;
            top -= 1;
        }
        self.server_offset = self.server_offset.clamp(top, self.server_sel);
    }

    /// One listed server as display lines: the ten cells, wrapped, under a
    /// gutter that carries the selection arrow and the connected dot.
    fn row_lines(
        &self,
        row: &ServerDiagnostics,
        index: usize,
        widths: &[usize],
        connected: Option<&ServerEndpoint>,
        theme: &Theme,
    ) -> Vec<Line<'static>> {
        let selected = index == self.server_sel;
        let focused = self.focus == Pane::Servers;
        let is_connected = connected == Some(&row.server.endpoint);
        let marker = Span::styled(
            format!(
                "{}{} ",
                if selected { "▸" } else { " " },
                if is_connected { "●" } else { " " }
            ),
            if selected {
                selection_style(theme, focused)
            } else if is_connected {
                Style::new().fg(theme.good)
            } else {
                theme.dim_text()
            },
        );
        let mut lines = column_lines(
            &server_columns(row, Style::new().fg(theme.fg), theme),
            widths,
            1,
            &marker,
        );
        if selected {
            mark_row(&mut lines, focused, theme);
        }
        lines
    }
}

/// One listed server's eleven cells, in [`ServersTable::COLUMNS`]' order: what
/// its row draws, and what the `Off-screen:` line says of a column that gave
/// way.
///
/// A **Dead Server** (ADR-0052) is dimmed whole and its Fail cell says
/// `dead` instead of the tally, in the colour of bad news — the word, not the
/// colour, carries the state, and the column still sorts by the tally.
fn server_columns(row: &ServerDiagnostics, base: Style, theme: &Theme) -> Vec<Column> {
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
        Column::left(name, known(!row.server.name.as_bytes().is_empty())),
        Column::left(row.server.endpoint.host().to_string(), base),
        Column::right(row.server.endpoint.port().to_string(), base),
        Column::left(
            if has_description {
                description
            } else {
                "—".to_string()
            },
            known(has_description),
        ),
        Column::right(format_ping(row.ping), known(row.ping.is_some())),
        Column::right(short_count(row.users), known(row.users.is_some())),
        Column::right(short_count(row.files), known(row.files.is_some())),
        Column::right(format_age(row.age), known(row.age.is_some())),
        Column::left(priority_word(row.server.priority), base),
        // A climbing tally is the row's own bad news; the number says
        // it and the colour only underlines it.
        Column::right(
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
        Column::left(
            if row.server.is_static { "yes" } else { "no" },
            known(row.server.is_static),
        ),
    ]
}

#[cfg(test)]
mod tests;
