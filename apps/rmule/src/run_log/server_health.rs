//! The server list's health is a level on the diagnostics snapshot, not an
//! event, so the [`ServerHealthTrail`] turns each edge of it into a record —
//! the same edges the Networks log words (ADR-0052, ADR-0099): a server marked
//! dead, a dead one answering again, a Status Ping Sweep that hears nobody, and
//! the connected server's shares withheld or told before withholding. It also
//! writes each server's grant words — the TCP word its login granted and the
//! UDP word its status answers named — whenever they change, so the Networks
//! pane's sentences about them can be checked against the bits. A server's
//! address is the operator's own list, so it is lean.

use rmule_core::diagnostics::{DiagnosticsSnapshot, SharesToServer};
use rmule_primitives::{ServerEndpoint, ServerUdpFlags};

use super::record::Record;
use crate::state::server_health::{HealthEdge, HealthLevel};

/// The health level as last observed, so a data tick that moved nothing
/// writes nothing. It starts empty, as the Networks log does: a row first seen
/// dead says nothing, an unheard sweep already under way is said.
#[derive(Default)]
pub struct ServerHealthTrail {
    last: HealthLevel,
    /// Each server's grant words as last written.
    words: Vec<(ServerEndpoint, GrantWords)>,
}

/// A server's TCP grant word and UDP flags word; `None` where it has not
/// said one.
type GrantWords = (Option<u32>, Option<u32>);

impl ServerHealthTrail {
    /// The records of every edge between the level last observed and
    /// `snapshot`, then of every server whose grant words moved.
    pub fn observe(&mut self, snapshot: &DiagnosticsSnapshot) -> Vec<Record> {
        let mut records: Vec<Record> = self.last.edges(snapshot).iter().map(record).collect();
        self.last = HealthLevel::of(snapshot);
        let words: Vec<(ServerEndpoint, GrantWords)> = snapshot
            .servers
            .iter()
            .map(|row| {
                let tcp = row.server.grants.map(|report| report.tcp_flags.bits());
                let udp = row
                    .server
                    .figures
                    .as_ref()
                    .and_then(|figures| figures.udp_flags)
                    .map(ServerUdpFlags::bits);
                (row.server.endpoint.clone(), (tcp, udp))
            })
            .filter(|(_, (tcp, udp))| tcp.is_some() || udp.is_some())
            .collect();
        for (server, now) in &words {
            let before = self.words.iter().find(|(seen, _)| seen == server);
            if before.is_none_or(|(_, before)| before != now) {
                records.push(grant_words(server, *now));
            }
        }
        self.words = words;
        records
    }
}

fn grant_words(server: &ServerEndpoint, (tcp, udp): GrantWords) -> Record {
    let record = Record::new("server.grants").server_endpoint("server", server);
    let record = match tcp {
        Some(word) => record.flag_word("tcp_flags", word),
        None => record.code("tcp_flags", "none"),
    };
    match udp {
        Some(word) => record.flag_word("udp_flags", word),
        None => record.code("udp_flags", "none"),
    }
}

fn record(edge: &HealthEdge) -> Record {
    match edge {
        HealthEdge::MarkedDead { server, failures } => Record::new("server_health.marked_dead")
            .server_endpoint("server", server)
            .count("failures", *failures),
        HealthEdge::AnsweredAgain { server } => {
            Record::new("server_health.answered_again").server_endpoint("server", server)
        }
        HealthEdge::SweepUnheard => Record::new("server_health.sweep_unheard"),
        HealthEdge::Shares(told) => Record::new("server_health.shares")
            .server_endpoint("server", &told.server)
            .code(
                "shares",
                match told.shares {
                    SharesToServer::Announced => "announced",
                    SharesToServer::Withheld => "withheld",
                    SharesToServer::AnnouncedBeforeWithholding => "announced_before_withholding",
                },
            ),
    }
}

#[cfg(test)]
mod tests {
    use rmule_core::diagnostics::{ServerDiagnostics, ShareAnnouncement};
    use rmule_core::{ManagedServer, ServerHealth};
    use rmule_primitives::ServerEndpoint;

    use super::*;
    use crate::run_log::Level;

    fn row(host: &str, health: ServerHealth, fail_count: u32) -> ServerDiagnostics {
        let mut row = ServerDiagnostics::listed(ManagedServer {
            fail_count,
            ..ManagedServer::listed(ServerEndpoint::new(host, 4661).unwrap())
        });
        row.health = health;
        row
    }

    /// Each edge is one lean line naming the server from the operator's own
    /// list; a tick that moved nothing writes nothing.
    #[test]
    fn each_health_edge_is_one_lean_record() {
        let mut trail = ServerHealthTrail::default();
        let level = |rows, unheard, shares| DiagnosticsSnapshot {
            servers: rows,
            status_sweep_unheard: unheard,
            share_announcement: shares,
            ..DiagnosticsSnapshot::default()
        };
        let withheld = Some(ShareAnnouncement {
            server: ServerEndpoint::new("203.0.113.40", 4242).unwrap(),
            shares: SharesToServer::Withheld,
        });
        let steps = [
            level(
                vec![row("192.0.2.33", ServerHealth::Failing, 2)],
                false,
                None,
            ),
            level(vec![row("192.0.2.33", ServerHealth::Dead, 3)], true, None),
            level(vec![row("192.0.2.33", ServerHealth::Dead, 4)], true, None),
            level(
                vec![row("192.0.2.33", ServerHealth::Answered, 0)],
                false,
                withheld.clone(),
            ),
            level(
                vec![row("192.0.2.33", ServerHealth::Answered, 0)],
                false,
                withheld,
            ),
        ];
        let lines: Vec<String> = steps
            .iter()
            .flat_map(|step| trail.observe(step))
            .map(|record| record.render(Level::Lean))
            .collect();
        assert_eq!(
            lines,
            vec![
                "server_health.marked_dead server=192.0.2.33:4661 failures=3",
                "server_health.sweep_unheard",
                "server_health.answered_again server=192.0.2.33:4661",
                "server_health.shares server=203.0.113.40:4242 shares=withheld",
            ]
        );
    }

    /// A server's grant words are written as sent, unknown bits included,
    /// when first said and again only when one moves.
    #[test]
    fn grant_words_are_written_raw_when_they_move() {
        let mut trail = ServerHealthTrail::default();
        let with = |tcp: Option<u32>, udp: Option<u32>| {
            let mut row = row("192.0.2.33", ServerHealth::Answered, 0);
            row.server.grants = tcp.map(|tcp_flags| rmule_core::ServerGrantsReport {
                tcp_flags: rmule_primitives::ServerTcpFlags::from_bits(tcp_flags),
                reported_at: 1_790_000_000,
            });
            row.server.figures = udp.map(|flags| rmule_core::ServerFigures {
                udp_flags: Some(ServerUdpFlags::from_bits(flags)),
                ..rmule_core::ServerFigures::answered(1_790_000_000)
            });
            DiagnosticsSnapshot {
                servers: vec![row],
                ..DiagnosticsSnapshot::default()
            }
        };
        let steps = [
            with(None, None),
            with(Some(0x0000_10D9), None),
            with(Some(0x0000_10D9), None),
            with(Some(0x0000_10D9), Some(0x0000_073B)),
        ];
        let lines: Vec<String> = steps
            .iter()
            .flat_map(|step| trail.observe(step))
            .map(|record| record.render(Level::Lean))
            .collect();
        assert_eq!(
            lines,
            vec![
                "server.grants server=192.0.2.33:4661 tcp_flags=0x000010D9 udp_flags=none",
                "server.grants server=192.0.2.33:4661 tcp_flags=0x000010D9 udp_flags=0x0000073B",
            ]
        );
    }
}
