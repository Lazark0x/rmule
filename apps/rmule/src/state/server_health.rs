//! The server list's edges in the Networks log: a server marked dead, a dead
//! one answering again, a sweep that hears nobody (ADR-0052), and the
//! connected server's shares withheld or told before withholding (ADR-0099).
//!
//! Health is a level core republishes every tick, so the edges are read off
//! two snapshots rather than sent — here once, for the Networks log and the
//! Run Log alike: a row whose health moved says so once, and
//! a row that was not in the previous snapshot — the first one after attach,
//! a fresh import — says nothing, because nothing happened to it here.

use std::time::Instant;

use rmule_core::ServerHealth;
use rmule_core::diagnostics::{DiagnosticsSnapshot, ShareAnnouncement, SharesToServer};
use rmule_primitives::ServerEndpoint;

use super::UiState;
use crate::words::server as words;

/// What moved on the server list between two levels, as a code: the Networks
/// log words it, the Run Log records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HealthEdge {
    /// A server's failure tally reached the dead-server limit.
    MarkedDead {
        server: ServerEndpoint,
        failures: u32,
    },
    /// A dead server answered again.
    AnsweredAgain { server: ServerEndpoint },
    /// Every status ping near a silence went unanswered too.
    SweepUnheard,
    /// The connected server was told of the shares in a way that is news:
    /// withheld, or told before withholding was switched on.
    Shares(ShareAnnouncement),
}

/// The part of a level the edges are read off.
#[derive(Clone, Debug, Default)]
pub(crate) struct HealthLevel {
    rows: Vec<(ServerEndpoint, ServerHealth)>,
    unheard: bool,
    shares: Option<ShareAnnouncement>,
}

impl HealthLevel {
    pub(crate) fn of(snapshot: &DiagnosticsSnapshot) -> Self {
        Self {
            rows: snapshot
                .servers
                .iter()
                .map(|row| (row.server.endpoint.clone(), row.health))
                .collect(),
            unheard: snapshot.status_sweep_unheard,
            shares: snapshot.share_announcement.clone(),
        }
    }

    /// What moved between this level and `next`. A row this level did not
    /// hold says nothing: nothing happened to it here.
    pub(crate) fn edges(&self, next: &DiagnosticsSnapshot) -> Vec<HealthEdge> {
        let mut edges = Vec::new();
        for row in &next.servers {
            let Some(before) = self
                .rows
                .iter()
                .find(|(endpoint, _)| *endpoint == row.server.endpoint)
                .map(|(_, health)| *health)
            else {
                continue;
            };
            match (before, row.health) {
                (ServerHealth::Dead, ServerHealth::Dead) => {}
                (_, ServerHealth::Dead) => edges.push(HealthEdge::MarkedDead {
                    server: row.server.endpoint.clone(),
                    failures: row.server.fail_count,
                }),
                (ServerHealth::Dead, _) => edges.push(HealthEdge::AnsweredAgain {
                    server: row.server.endpoint.clone(),
                }),
                _ => {}
            }
        }
        if next.status_sweep_unheard && !self.unheard {
            edges.push(HealthEdge::SweepUnheard);
        }
        if let Some(told) = &next.share_announcement
            && self.shares.as_ref() != Some(told)
        {
            match told.shares {
                SharesToServer::Announced => {}
                SharesToServer::Withheld | SharesToServer::AnnouncedBeforeWithholding => {
                    edges.push(HealthEdge::Shares(told.clone()));
                }
            }
        }
        edges
    }
}

/// Log what moved between the level on show and `next`.
pub(super) fn log_edges(state: &mut UiState, next: &DiagnosticsSnapshot, now: Instant) {
    for edge in HealthLevel::of(&state.diagnostics).edges(next) {
        state.push_log(words::health_edge(&edge), now);
    }
}

#[cfg(test)]
mod tests {
    use rmule_core::ManagedServer;
    use rmule_core::diagnostics::ServerDiagnostics;
    use rmule_primitives::ServerEndpoint;

    use super::*;

    fn row(host: &str, health: ServerHealth, fail_count: u32) -> ServerDiagnostics {
        let mut row = ServerDiagnostics::listed(ManagedServer {
            fail_count,
            ..ManagedServer::listed(ServerEndpoint::new(host, 4661).unwrap())
        });
        row.health = health;
        row
    }

    fn logged(state: &UiState) -> Vec<String> {
        state.log.iter().map(|line| line.text.to_string()).collect()
    }

    /// One line when a server dies, one when it comes back, none while it
    /// stays either way, and none for a row the last level did not hold.
    #[test]
    fn a_server_dying_and_coming_back_is_said_once_each() {
        let now = Instant::now();
        let mut state = UiState::default();
        let snapshot = |rows| DiagnosticsSnapshot {
            servers: rows,
            ..DiagnosticsSnapshot::default()
        };
        let first = snapshot(vec![row("192.0.2.33", ServerHealth::Dead, 4)]);
        log_edges(&mut state, &first, now);
        state.diagnostics = first;
        assert!(logged(&state).is_empty(), "dead before we looked");

        let steps = [
            snapshot(vec![
                row("192.0.2.33", ServerHealth::Dead, 5),
                row("198.51.100.12", ServerHealth::Failing, 2),
            ]),
            snapshot(vec![
                row("192.0.2.33", ServerHealth::Answered, 0),
                row("198.51.100.12", ServerHealth::Dead, 3),
            ]),
            snapshot(vec![
                row("192.0.2.33", ServerHealth::Answered, 0),
                row("198.51.100.12", ServerHealth::Dead, 4),
            ]),
        ];
        for next in steps {
            log_edges(&mut state, &next, now);
            state.diagnostics = next;
        }
        assert_eq!(
            logged(&state),
            vec![
                "192.0.2.33:4661 answered again — no longer dead",
                "198.51.100.12:4661 marked dead: 3 tries in a row went unanswered — it stays \
                 listed, is still pinged every 20 minutes and can be connected to by hand",
            ]
        );
    }

    /// A sweep that hears nobody is said once, not on every tick it lasts.
    #[test]
    fn an_unheard_sweep_is_said_once() {
        let now = Instant::now();
        let mut state = UiState::default();
        let unheard = DiagnosticsSnapshot {
            status_sweep_unheard: true,
            ..DiagnosticsSnapshot::default()
        };
        for _ in 0..3 {
            log_edges(&mut state, &unheard, now);
            state.diagnostics = unheard.clone();
        }
        assert_eq!(logged(&state).len(), 1);
    }

    /// Withheld shares are said once, when they first are; an announce is
    /// not news and says nothing.
    #[test]
    fn withheld_shares_are_said_once() {
        use rmule_core::diagnostics::{ShareAnnouncement, SharesToServer};
        let now = Instant::now();
        let mut state = UiState::default();
        let server = ServerEndpoint::new("203.0.113.40", 4242).unwrap();
        let told = |shares| DiagnosticsSnapshot {
            share_announcement: Some(ShareAnnouncement {
                server: server.clone(),
                shares,
            }),
            ..DiagnosticsSnapshot::default()
        };
        for next in [
            told(SharesToServer::Announced),
            told(SharesToServer::Withheld),
            told(SharesToServer::Withheld),
        ] {
            log_edges(&mut state, &next, now);
            state.diagnostics = next;
        }
        assert_eq!(
            logged(&state),
            vec![
                "203.0.113.40:4242: Shares withheld from this server: it answers related \
                 searches, which would tell anyone which files you share together. Kad and \
                 other servers still have them"
            ]
        );
    }
}
