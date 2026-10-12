//! The server half of the trail: the connected server, and each edge of the
//! server list's health — a server marked dead, a dead one answering again, a
//! Status Ping Sweep that hears nobody (ADR-0052), and the connected server's
//! shares withheld or told before withholding (ADR-0099) — with each server's
//! grant words, the TCP word its login granted and the UDP word its status
//! answers named, whenever they change. A server's address is the operator's
//! own list, so it is lean.

use rmule_primitives::ServerEndpoint;

use crate::ServerHealth;
use crate::diagnostics::{ServerHalf, ShareAnnouncement, SharesToServer};
use crate::run_log::Record;
use crate::server_list::ManagedServer;

/// A server's TCP grant word and UDP flags word; `None` where it has not
/// said one.
type GrantWords = (Option<u32>, Option<u32>);

/// The server half of the level as the trail reads it.
#[derive(Clone, Debug, Default)]
pub(crate) struct ServerLevel {
    /// The server a session holds.
    pub(crate) connected: Option<ServerEndpoint>,
    rows: Vec<ServerRow>,
    unheard: bool,
    shares: Option<ShareAnnouncement>,
}

#[derive(Clone, Debug)]
struct ServerRow {
    endpoint: ServerEndpoint,
    health: ServerHealth,
    failures: u32,
    words: GrantWords,
}

impl ServerRow {
    fn of(server: &ManagedServer, health: ServerHealth) -> Self {
        Self {
            endpoint: server.endpoint.clone(),
            health,
            failures: server.fail_count,
            words: (
                server.grants.map(|report| report.tcp_flags.bits()),
                server
                    .figures
                    .as_ref()
                    .and_then(|figures| figures.udp_flags)
                    .map(|flags| flags.bits()),
            ),
        }
    }
}

impl ServerLevel {
    /// The level as `half` holds it, each row's health judged under its
    /// policy.
    pub(crate) fn of(half: &ServerHalf<'_>) -> Self {
        Self {
            connected: half.connected.cloned(),
            rows: half
                .servers
                .iter()
                .map(|server| ServerRow::of(server, half.policy.health(server)))
                .collect(),
            unheard: half.unheard,
            shares: half.shares.cloned(),
        }
    }

    /// The level a diagnostics snapshot shows.
    #[cfg(test)]
    pub(crate) fn of_snapshot(snapshot: &crate::diagnostics::DiagnosticsSnapshot) -> Self {
        Self {
            connected: snapshot.connected_server.clone(),
            rows: snapshot
                .servers
                .iter()
                .map(|row| ServerRow::of(&row.server, row.health))
                .collect(),
            unheard: snapshot.status_sweep_unheard,
            shares: snapshot.share_announcement.clone(),
        }
    }
}

/// The health level as last observed and each server's grant words as last
/// written, so a wake that moved nothing writes nothing. It starts empty: a
/// row first seen dead says nothing, an unheard sweep already under way is
/// said.
#[derive(Default)]
pub(super) struct HealthTrail {
    last: ServerLevel,
    words: Vec<(ServerEndpoint, GrantWords)>,
}

impl HealthTrail {
    /// The records of every edge between the level last observed and
    /// `level`, then of every server whose grant words moved.
    pub(super) fn observe(&mut self, level: &ServerLevel) -> Vec<Record> {
        let mut records = edges(&self.last, level);
        self.last = level.clone();
        let words: Vec<(ServerEndpoint, GrantWords)> = level
            .rows
            .iter()
            .filter(|row| row.words.0.is_some() || row.words.1.is_some())
            .map(|row| (row.endpoint.clone(), row.words))
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

/// What moved between `last` and `next`. A row `last` did not hold says
/// nothing: nothing happened to it here.
fn edges(last: &ServerLevel, next: &ServerLevel) -> Vec<Record> {
    let mut edges = Vec::new();
    for row in &next.rows {
        let Some(before) = last
            .rows
            .iter()
            .find(|seen| seen.endpoint == row.endpoint)
            .map(|seen| seen.health)
        else {
            continue;
        };
        match (before, row.health) {
            (ServerHealth::Dead, ServerHealth::Dead) => {}
            (_, ServerHealth::Dead) => edges.push(
                Record::new("server_health.marked_dead")
                    .server_endpoint("server", &row.endpoint)
                    .count("failures", row.failures),
            ),
            (ServerHealth::Dead, _) => edges.push(
                Record::new("server_health.answered_again")
                    .server_endpoint("server", &row.endpoint),
            ),
            _ => {}
        }
    }
    if next.unheard && !last.unheard {
        edges.push(Record::new("server_health.sweep_unheard"));
    }
    if let Some(told) = &next.shares
        && last.shares.as_ref() != Some(told)
    {
        let shares = match told.shares {
            SharesToServer::Announced => None,
            SharesToServer::Withheld => Some("withheld"),
            SharesToServer::AnnouncedBeforeWithholding => Some("announced_before_withholding"),
        };
        if let Some(shares) = shares {
            edges.push(
                Record::new("server_health.shares")
                    .server_endpoint("server", &told.server)
                    .code("shares", shares),
            );
        }
    }
    edges
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
