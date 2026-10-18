//! The server table's **Table Sort** (ADR-0070): its columns
//! and how a listed server answers for each, the `s` / `S` keys and the
//! header click. The cursor is bound to the server's endpoint, so a row that
//! a data tick re-orders — a ping landing, a user count moving — keeps the
//! selection.

use std::borrow::Cow;

use rmule_core::ServerPriority;
use rmule_core::diagnostics::{PingState, ServerDiagnostics};
use rmule_primitives::ServerEndpoint;

use super::{NetworksView, servers};
use crate::state::UiState;
use crate::table_sort::{ColumnKind, ColumnSpec, SortValue, SortedTable, TableSort, TableSorts};
use crate::views::ViewOutcome;

/// The server table, as the sort sees it.
pub(super) struct ServersTable;

/// The server table's visible columns, left to right.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ServerColumn {
    Name,
    Address,
    Port,
    Description,
    Ping,
    Users,
    Files,
    /// How long ago the server last answered: its figures' age.
    Age,
    Priority,
    Fails,
    Static,
}

/// Text that renders as a dash when blank is no value at all.
fn text(value: String) -> Option<SortValue<'static>> {
    (!value.trim().is_empty()).then_some(SortValue::Text(Cow::Owned(value)))
}

impl SortedTable for ServersTable {
    type Row = ServerDiagnostics;
    type Column = ServerColumn;
    type Identity = ServerEndpoint;
    const TABLE: &'static str = "servers";
    // Priority and Static render as words but are a rank and a flag: they
    // order by that, where their spelling would put `High` before `Low`
    // before `Norm`.
    const COLUMNS: &'static [ColumnSpec<ServerColumn>] = &[
        ColumnSpec::new(ServerColumn::Name, "name", "Name", ColumnKind::Text),
        ColumnSpec::new(
            ServerColumn::Address,
            "address",
            "Address",
            ColumnKind::Text,
        ),
        ColumnSpec::new(ServerColumn::Port, "port", "Port", ColumnKind::Quantity),
        ColumnSpec::new(
            ServerColumn::Description,
            "description",
            "Desc",
            ColumnKind::Text,
        ),
        ColumnSpec::new(ServerColumn::Ping, "ping", "Ping", ColumnKind::Quantity),
        ColumnSpec::new(ServerColumn::Users, "users", "Users", ColumnKind::Quantity),
        ColumnSpec::new(ServerColumn::Files, "files", "Files", ColumnKind::Quantity),
        ColumnSpec::new(ServerColumn::Age, "age", "Age", ColumnKind::Quantity),
        ColumnSpec::new(ServerColumn::Priority, "priority", "Prio", ColumnKind::Rank),
        ColumnSpec::new(ServerColumn::Fails, "fails", "Fail", ColumnKind::Quantity),
        ColumnSpec::new(ServerColumn::Static, "static", "Static", ColumnKind::Rank),
    ];
    const NAME: ServerColumn = ServerColumn::Name;

    fn value(column: ServerColumn, row: &ServerDiagnostics) -> Option<SortValue<'_>> {
        let server = &row.server;
        match column {
            ServerColumn::Name => text(server.name.to_display_string()),
            ServerColumn::Address => Some(SortValue::Text(Cow::Borrowed(server.endpoint.host()))),
            ServerColumn::Port => Some(SortValue::Quantity(u64::from(server.endpoint.port()))),
            ServerColumn::Description => text(server.description.to_display_string()),
            // Within its rank ([`Self::rank`]): the round trip, or how
            // long the pings have gone unanswered.
            ServerColumn::Ping => match row.ping {
                PingState::Measured(rtt) => Some(SortValue::Quantity(
                    u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX),
                )),
                PingState::Unanswered { since } => Some(SortValue::Quantity(since.as_secs())),
                PingState::NotAskedYet | PingState::Awaiting => None,
            },
            ServerColumn::Users => row.users.map(|n| SortValue::Quantity(u64::from(n))),
            ServerColumn::Files => row.files.map(|n| SortValue::Quantity(u64::from(n))),
            // A quantity, in seconds; a server that never answered has none
            // and sorts last either way.
            ServerColumn::Age => row.age.map(|age| SortValue::Quantity(age.as_secs())),
            ServerColumn::Priority => Some(SortValue::Quantity(match server.priority {
                ServerPriority::High => 0,
                ServerPriority::Normal => 1,
                ServerPriority::Low => 2,
            })),
            ServerColumn::Fails => Some(SortValue::Quantity(u64::from(server.fail_count))),
            ServerColumn::Static => Some(SortValue::Quantity(u64::from(!server.is_static))),
        }
    }

    /// A Ping State groups by its rank in both directions — measured,
    /// awaiting, not asked, unanswered — never by the word its cell reads.
    fn rank(column: ServerColumn, row: &ServerDiagnostics) -> u8 {
        match column {
            ServerColumn::Ping => row.ping.rank(),
            _ => 0,
        }
    }

    fn identity(row: &ServerDiagnostics) -> ServerEndpoint {
        row.server.endpoint.clone()
    }
}

impl NetworksView {
    /// The listed servers in display order.
    pub(super) fn ordered<'a>(&self, state: &'a UiState) -> Vec<&'a ServerDiagnostics> {
        let rows = servers(state);
        self.sort
            .order(rows)
            .into_iter()
            .map(|at| &rows[at])
            .collect()
    }

    /// The listed servers' endpoints in display order — what the cursor is
    /// placed against.
    pub(super) fn server_ids(&self, state: &UiState) -> Vec<ServerEndpoint> {
        self.ordered(state)
            .into_iter()
            .map(ServersTable::identity)
            .collect()
    }

    /// Take up the servers' sort as the durable preferences kept it.
    pub fn restore_sort(&mut self, sorts: &TableSorts) {
        self.sort = TableSort::restore(sorts);
    }

    /// A click on the header row: sort by the column under it. `None` when
    /// the click was not on a header cell.
    pub(super) fn header_click(&mut self, column: u16, row: u16) -> Option<ViewOutcome> {
        self.sort
            .header_click(self.header_area, &self.header_cols, 1, column, row)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use ratatui::crossterm::event::KeyCode;

    use super::*;
    use crate::action::Action;
    use crate::config::PrefEdit;
    use crate::fixture::*;
    use crate::golden::{assert_golden, render_to_lines};
    use crate::table_sort::Direction;
    use crate::theme::Theme;

    fn draw(view: &mut NetworksView, state: &UiState, width: u16) -> Vec<String> {
        render_to_lines(width, 21, |frame| {
            view.draw(
                frame,
                frame.area(),
                state,
                &Theme::default_dark(),
                Instant::now(),
            );
        })
        .lines()
        .map(str::to_string)
        .collect()
    }

    fn cell_of(lines: &[String], needle: &str) -> (u16, u16) {
        lines
            .iter()
            .enumerate()
            .find_map(|(y, line)| {
                let at = line.find(needle)?;
                let x = line[..at].chars().count();
                Some((u16::try_from(x).ok()?, u16::try_from(y).ok()?))
            })
            .unwrap_or_else(|| panic!("{needle} not on screen:\n{}", lines.join("\n")))
    }

    /// Hosts in display order.
    fn hosts(view: &NetworksView, state: &UiState) -> Vec<String> {
        view.ordered(state)
            .into_iter()
            .map(|row| row.server.endpoint.host().to_string())
            .collect()
    }

    fn sort_to(view: &mut NetworksView, state: &UiState, column: ServerColumn) {
        while view.sort.column() != column {
            view.handle_key(press(KeyCode::Char('s')), state);
        }
    }

    /// At the narrowest supported frame the header is one line whichever
    /// column holds the sort, either way: the arrow never wraps a label.
    #[test]
    fn the_header_is_one_line_whichever_column_holds_the_sort() {
        let state = listed_servers();
        let mut view = NetworksView::new();
        for column in ServersTable::COLUMNS {
            sort_to(&mut view, &state, column.column);
            for _ in 0..2 {
                draw(&mut view, &state, 80);
                assert_eq!(view.header_area.height, 1, "{column:?}");
                view.handle_key(press(KeyCode::Char('S')), &state);
            }
        }
    }

    const PRIME: &str = "10.0.0.1";
    const PIN: &str = "10.0.0.2";
    const FLAKY: &str = "172.16.9.9";
    const UNNAMED: &str = "192.168.4.4";

    /// Prime: 42 ms, 1.2 M users, answered 12 s ago, Normal. Pin: 1.2 s,
    /// 9812 users, answered 2 h ago, High, static. Flaky: never answered, Low, 7 fails. The unnamed row has
    /// said nothing at all.
    #[test]
    fn every_column_orders_by_its_value_and_a_dash_sorts_last_both_ways() {
        let state = listed_servers();
        let mut view = NetworksView::new();
        assert_eq!(hosts(&view, &state), [PRIME, FLAKY, PIN, UNNAMED]);
        view.handle_key(press(KeyCode::Char('S')), &state);
        assert_eq!(
            hosts(&view, &state),
            [PIN, FLAKY, PRIME, UNNAMED],
            "nameless last"
        );

        let expect = [
            (
                ServerColumn::Address,
                [PRIME, PIN, FLAKY, UNNAMED],
                [UNNAMED, FLAKY, PIN, PRIME],
            ),
            // Ties (4661) fall to the name: Prime before the nameless.
            (
                ServerColumn::Port,
                [FLAKY, PRIME, UNNAMED, PIN],
                [PIN, PRIME, UNNAMED, FLAKY],
            ),
            (
                ServerColumn::Description,
                [PRIME, PIN, FLAKY, UNNAMED],
                [PIN, PRIME, FLAKY, UNNAMED],
            ),
            // 1.2 s is slower than 42 ms, not "1.2" against "42"; a ping
            // with no round trip follows every measured one both ways, by
            // its state's rank: not asked yet, then unanswered.
            (
                ServerColumn::Ping,
                [PIN, PRIME, UNNAMED, FLAKY],
                [PRIME, PIN, UNNAMED, FLAKY],
            ),
            (
                ServerColumn::Users,
                [PRIME, PIN, FLAKY, UNNAMED],
                [PIN, PRIME, FLAKY, UNNAMED],
            ),
            (
                ServerColumn::Files,
                [PRIME, PIN, FLAKY, UNNAMED],
                [PIN, PRIME, FLAKY, UNNAMED],
            ),
            // How long ago it answered, a quantity: two hours before
            // twelve seconds, and a server that never answered last.
            (
                ServerColumn::Age,
                [PIN, PRIME, FLAKY, UNNAMED],
                [PRIME, PIN, FLAKY, UNNAMED],
            ),
            // A rank: High, Normal, Low — not the words' spelling.
            (
                ServerColumn::Priority,
                [PIN, PRIME, UNNAMED, FLAKY],
                [FLAKY, PRIME, UNNAMED, PIN],
            ),
            (
                ServerColumn::Fails,
                [FLAKY, PRIME, PIN, UNNAMED],
                [PRIME, PIN, UNNAMED, FLAKY],
            ),
            (
                ServerColumn::Static,
                [PIN, PRIME, FLAKY, UNNAMED],
                [PRIME, FLAKY, UNNAMED, PIN],
            ),
        ];
        for (column, natural, reversed) in expect {
            sort_to(&mut view, &state, column);
            assert_eq!(
                view.sort.direction(),
                ServersTable::kind(column).natural_direction(),
                "{column:?}"
            );
            assert_eq!(hosts(&view, &state), natural, "{column:?} natural");
            view.handle_key(press(KeyCode::Char('S')), &state);
            assert_eq!(hosts(&view, &state), reversed, "{column:?} reversed");
        }
    }

    #[test]
    fn the_cursor_follows_its_server_as_rows_arrive_leave_and_reorder() {
        let mut state = listed_servers();
        let mut view = NetworksView::new();
        view.handle_key(press(KeyCode::Char('j')), &state); // onto Flaky
        let selected = |view: &NetworksView, state: &UiState| {
            view.selected(state)
                .map(|row| row.server.endpoint.host().to_string())
        };

        // A server that sorts first arrives with the next tick.
        let early = listed("10.9.9.9", 4661, "Aardvark");
        state.diagnostics.servers.push(early);
        draw(&mut view, &state, 78);
        assert_eq!(view.server_sel, 2);
        assert_eq!(selected(&view, &state).as_deref(), Some(FLAKY));

        // The row above it leaves.
        state
            .diagnostics
            .servers
            .retain(|row| row.server.endpoint.host() != PRIME);
        draw(&mut view, &state, 78);
        assert_eq!(selected(&view, &state).as_deref(), Some(FLAKY));

        // Its ping lands and a ping sort carries it to the top.
        sort_to(&mut view, &state, ServerColumn::Ping);
        state
            .diagnostics
            .servers
            .iter_mut()
            .find(|row| row.server.endpoint.host() == FLAKY)
            .expect("flaky listed")
            .ping = PingState::Measured(Duration::from_secs(9));
        draw(&mut view, &state, 78);
        assert_eq!(view.server_sel, 0);
        assert_eq!(selected(&view, &state).as_deref(), Some(FLAKY));
    }

    #[test]
    fn a_header_click_sorts_by_its_column_and_again_reverses_at_two_widths() {
        let state = listed_servers();
        for width in [78, 110] {
            let mut view = NetworksView::new();
            let lines = draw(&mut view, &state, width);
            let (x, y) = cell_of(&lines, "Ping");
            assert!(matches!(
                view.handle_click(x, y, &state),
                ViewOutcome::Emit(Action::Preference(PrefEdit::TableSort {
                    table: "servers",
                    column: "ping",
                    direction: Direction::Descending,
                }))
            ));
            // The sorted column is floored for its arrow: "Ping ▼" stays on
            // the header's one line, and a click on the arrow reverses.
            let lines = draw(&mut view, &state, width);
            let (ax, ay) = cell_of(&lines, "▼");
            assert_eq!(ay, y, "width {width}: the arrow beside Ping");
            view.handle_click(ax, ay, &state);
            assert_eq!(view.sort.direction(), Direction::Ascending, "width {width}");
            let lines = draw(&mut view, &state, width);
            let (x, y) = cell_of(&lines, "Static");
            let first_row = view.server_rows.line_of(0).expect("rows drawn");
            view.handle_click(x, first_row, &state);
            assert_eq!(
                view.sort.column(),
                ServerColumn::Ping,
                "a row, not the header"
            );
            view.handle_click(x, y, &state);
            assert_eq!(view.sort.column(), ServerColumn::Static, "width {width}");
        }
    }

    #[test]
    fn golden_networks_sorted_by_users() {
        let state = listed_servers();
        let mut view = NetworksView::new();
        sort_to(&mut view, &state, ServerColumn::Users);
        let now = Instant::now();
        assert_golden("networks_sorted_users", 78, 21, |frame| {
            view.draw(frame, frame.area(), &state, &Theme::default_dark(), now);
        });
    }
}
