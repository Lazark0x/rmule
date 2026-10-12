//! The server surface's words: the managed list and its update, the session
//! and its reconnects, why a login landed Low ID, and every server event's
//! line in the Networks log.

use rmule_core::port_mapping::{MappingDiagnostics, MappingStatus};
use rmule_core::{
    ReconnectEnd, ServerConnectFailure, ServerConnectionEvent, ServerListEvent,
    ServerListUpdateFailure, ServerPriority, SocketRole,
};
use rmule_primitives::{AddressFamily, ClientId, ServerEndpoint};

use super::Sentence;
use super::portmap::mapping_error_words;
use super::units::{address, human_size, seconds, server_label};

/// A server's priority, as its cell reads it.
#[must_use]
pub const fn priority_word(priority: ServerPriority) -> &'static str {
    match priority {
        ServerPriority::Low => "Low",
        ServerPriority::Normal => "Norm",
        ServerPriority::High => "High",
    }
}

/// A server's priority, spelled out.
const fn priority_name(priority: ServerPriority) -> &'static str {
    match priority {
        ServerPriority::Low => "low",
        ServerPriority::Normal => "normal",
        ServerPriority::High => "high",
    }
}

/// HighID or LowID, by the id a server assigned.
pub(super) const fn id_class(client_id: ClientId) -> &'static str {
    if client_id.is_high_id() {
        "HighID"
    } else {
        "LowID"
    }
}

/// A server joined the list.
pub const ADDED: Sentence = Sentence::fixed("server added");
/// A listed server folded a fresh record.
pub const UPDATED: Sentence = Sentence::fixed("server updated");
/// A server left the list.
pub const REMOVED: Sentence = Sentence::fixed("server removed");
/// A server.met update began.
pub const LIST_UPDATE_STARTED: Sentence = Sentence::fixed("server list update started");
/// Update from URL while one runs.
pub const LIST_UPDATE_RUNNING: Sentence =
    Sentence::fixed("a server list update is already running");

/// A server's priority was set.
#[must_use]
pub fn priority_set(priority: ServerPriority) -> Sentence {
    Sentence::owned(format!(
        "server priority set to {}",
        priority_name(priority)
    ))
}

/// A server was pinned or unpinned.
#[must_use]
pub const fn static_set(is_static: bool) -> Sentence {
    Sentence::fixed(if is_static {
        "server pinned static"
    } else {
        "server unpinned"
    })
}

/// A server.met update installed its list.
#[must_use]
pub fn list_updated(added: usize, updated: usize, total: usize) -> Sentence {
    Sentence::owned(format!(
        "server list updated: {added} new, {updated} refreshed, {total} listed"
    ))
}

/// Why a server-list update produced no list.
#[must_use]
pub fn list_update_failure_words(reason: ServerListUpdateFailure) -> String {
    match reason {
        ServerListUpdateFailure::Unreachable => "the address could not be reached".to_string(),
        ServerListUpdateFailure::TimedOut => "the address did not answer in time".to_string(),
        ServerListUpdateFailure::HttpStatus(status) => {
            format!("the web server answered HTTP {status}, not the file")
        }
        ServerListUpdateFailure::TooLarge { cap } => format!(
            "the file is larger than {}, more than any server.met",
            human_size(cap as u64)
        ),
        ServerListUpdateFailure::NotServerMet => "what came back is not a server.met".to_string(),
        ServerListUpdateFailure::StoreFailed => {
            "the list could not be saved (see the run log)".to_string()
        }
    }
}

/// A server-list update produced no list.
#[must_use]
pub fn list_update_failed(reason: ServerListUpdateFailure) -> Sentence {
    Sentence::owned(format!(
        "server list update failed: {}",
        list_update_failure_words(reason)
    ))
}

/// The dial to a server started.
#[must_use]
pub fn connecting(server: &ServerEndpoint, leaving: Option<&ServerEndpoint>) -> Sentence {
    Sentence::owned(match leaving {
        // The connect ended another session to make room: said, so
        // the operator knows the server they were on is no longer theirs.
        Some(left) => format!(
            "disconnected from {}; connecting to {}",
            server_label(left),
            server_label(server)
        ),
        None => format!("connecting to {}", server_label(server)),
    })
}

/// A login was accepted; a Low ID says why, as far as the listener's mapping
/// can.
#[must_use]
pub fn connected(
    server: &ServerEndpoint,
    client_id: ClientId,
    mappings: &[MappingDiagnostics],
) -> Sentence {
    let why = if client_id.is_high_id() {
        String::new()
    } else {
        format!(" — {}", low_id_reason(mappings))
    };
    Sentence::owned(format!(
        "connected to {} ({}){why}",
        server_label(server),
        id_class(client_id)
    ))
}

/// Why a connect produced no session.
#[must_use]
pub const fn connect_failure_words(reason: ServerConnectFailure) -> &'static str {
    match reason {
        ServerConnectFailure::Filtered => "its address is in your IP filter; rmule did not dial",
        ServerConnectFailure::Unreachable => {
            "it could not be reached — the connection was refused, unreachable or timed out"
        }
        ServerConnectFailure::LoginRefused => "it refused the login",
        ServerConnectFailure::ClosedBeforeAnswer => {
            "it closed the connection before answering the login"
        }
        ServerConnectFailure::LoginTimedOut => {
            "it accepted the connection but never answered the login"
        }
    }
}

/// A connect produced no session.
#[must_use]
pub fn connect_failed(server: &ServerEndpoint, reason: ServerConnectFailure) -> Sentence {
    Sentence::owned(format!(
        "connect to {} failed: {}",
        server_label(server),
        connect_failure_words(reason)
    ))
}

/// A session ended.
#[must_use]
pub fn disconnected(server: &ServerEndpoint) -> Sentence {
    Sentence::owned(format!("disconnected from {}", server_label(server)))
}

/// A scheduled re-make, as core scheduled it: which attempt, of
/// how many when a bound is set, and the delay, which stops growing at its
/// ceiling (`steady`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconnectStep {
    /// Which attempt the next dial is.
    pub attempt: u32,
    /// The most attempts core makes; `None`, it keeps trying.
    pub bound: Option<u32>,
    /// The delay core set for the attempt.
    pub delay: std::time::Duration,
    /// The delay has reached its ceiling and repeats.
    pub steady: bool,
}

/// "reconnecting to `server` · attempt N · next in S s" — the status note's,
/// the Sources pane's and the log's one spelling. `remaining` is what is left
/// of the wait: the log line says the delay as scheduled, the note counts it
/// down on the data tick. With no bound and the delay at its ceiling
/// the line says the tries go on until the operator disconnects.
#[must_use]
pub fn reconnecting(
    server: &ServerEndpoint,
    step: ReconnectStep,
    remaining: std::time::Duration,
) -> Sentence {
    let attempt = match step.bound {
        Some(bound) => format!("attempt {} of {bound}", step.attempt),
        None => format!("attempt {}", step.attempt),
    };
    let next = if remaining.is_zero() {
        "dialing now".to_string()
    } else {
        format!("next in {} s", seconds(remaining))
    };
    let pace = if step.bound.is_none() && step.steady {
        format!(" · every {} until you disconnect (c)", every(step.delay))
    } else {
        String::new()
    };
    Sentence::owned(format!(
        "reconnecting to {} · {attempt} · {next}{pace}",
        server_label(server)
    ))
}

/// A repeating delay: whole minutes from a minute on, else seconds.
fn every(delay: std::time::Duration) -> String {
    let secs = seconds(delay);
    if secs >= 60 && secs.is_multiple_of(60) {
        format!("{} min", secs / 60)
    } else {
        format!("{secs} s")
    }
}

/// Why core stopped re-making a lost session.
#[must_use]
pub fn reconnect_ended(server: &ServerEndpoint, reason: ReconnectEnd) -> Sentence {
    let label = server_label(server);
    Sentence::owned(match reason {
        ReconnectEnd::OperatorDisconnected => {
            format!("stopped reconnecting to {label}: you disconnected")
        }
        ReconnectEnd::Replaced => {
            format!("stopped reconnecting to {label}: you connected to another server")
        }
        ReconnectEnd::AttemptsSpent { attempts } => format!(
            "gave up reconnecting to {label} after {attempts} attempts; press c on a server in Networks (1) to connect again"
        ),
        ReconnectEnd::Unlisted => {
            format!("stopped reconnecting: {label} is no longer in the server list")
        }
    })
}

/// Why a login landed Low ID, as far as the eD2k listener's IPv4 mapping row
/// can say: the server's port check could not reach the port, and the
/// row says whether the router forwarded it.
fn low_id_reason(mappings: &[MappingDiagnostics]) -> String {
    let listener = mappings
        .iter()
        .find(|row| row.mapping.role == SocketRole::Tcp && row.mapping.family == AddressFamily::V4);
    let Some(row) = listener else {
        return "the eD2k listener has no port mapping; forward its TCP port to this machine for HighID"
            .to_owned();
    };
    let port = row.mapping.internal_port;
    match row.status {
        MappingStatus::Mapped => {
            format!("TCP {port} is forwarded, yet the server's port check did not reach it")
        }
        MappingStatus::Degraded => format!(
            "the router forwarded TCP {port} as {}, which peers cannot use; forward TCP {port} to this machine",
            row.external
                .map_or_else(|| "another endpoint".to_owned(), address)
        ),
        MappingStatus::NotMapped | MappingStatus::Probing | MappingStatus::Failed => {
            let error = row.last_error.as_ref().map_or_else(String::new, |error| {
                format!(" ({})", mapping_error_words(error))
            });
            format!(
                "the router did not forward TCP {port}{error}; forward it to this machine for HighID"
            )
        }
    }
}

/// A list event's line in the Networks log. Not core's `Display`: that is a
/// diagnostic key=value record, three wrapped lines of a pane meant to read
/// like aMule's log.
#[must_use]
pub fn list_log_line(event: &ServerListEvent) -> Sentence {
    use ServerListEvent as L;
    match event {
        L::ServerAdded { server } => {
            Sentence::owned(format!("server added: {}", server_label(server)))
        }
        L::ServerUpdated { server } => {
            Sentence::owned(format!("server updated: {}", server_label(server)))
        }
        L::ServerRemoved { server } => {
            Sentence::owned(format!("server removed: {}", server_label(server)))
        }
        L::ServerPriorityChanged { server, priority } => Sentence::owned(format!(
            "{}: priority {}",
            server_label(server),
            priority_name(*priority)
        )),
        L::ServerStaticChanged { server, is_static } => Sentence::owned(format!(
            "{} {}",
            server_label(server),
            if *is_static {
                "pinned static"
            } else {
                "unpinned"
            }
        )),
        L::ServerListUpdateStarted { url } => {
            Sentence::owned(format!("updating server list from {url}"))
        }
        L::ServerListUpdated {
            added,
            updated,
            total,
        } => list_updated(*added, *updated, *total),
        L::ServerListUpdateFailed { reason } => list_update_failed(*reason),
    }
}

/// A session event's line in the Networks log.
#[must_use]
pub fn connection_log_line(event: &ServerConnectionEvent) -> Sentence {
    use ServerConnectionEvent as C;
    match event {
        C::Connecting { server, leaving } => connecting(server, leaving.as_ref()),
        C::Connected { server, client_id } => Sentence::owned(format!(
            "connected to {} ({})",
            server_label(server),
            id_class(*client_id)
        )),
        C::ConnectFailed { server, reason } => connect_failed(server, *reason),
        C::Disconnected { server } => disconnected(server),
        C::Reconnecting {
            server,
            attempt,
            bound,
            next_in,
            steady,
            ..
        } => reconnecting(
            server,
            ReconnectStep {
                attempt: *attempt,
                bound: *bound,
                delay: *next_in,
                steady: *steady,
            },
            *next_in,
        ),
        C::ReconnectEnded { server, reason } => reconnect_ended(server, *reason),
    }
}

/// `c` in Networks with no server listed.
pub const NO_SERVER_LISTED: Sentence = Sentence::fixed("no server listed — press a to add one");

/// The add-server form's address does not make a server endpoint.
pub const INVALID_ADDRESS: &str = "not a server address: a host name or IP and a port 1–65535";

/// Connect at start with no server ever connected to.
pub const NO_LAST_SERVER: Sentence =
    Sentence::fixed("connect at start: no server connected to yet — connect once with c");
/// Connect at start with the last server gone from the list.
pub const LAST_SERVER_UNLISTED: Sentence =
    Sentence::fixed("connect at start: the server last connected to is no longer listed");

// ----- server health and the server policy (ADR-0052) -----

/// A **Dead Server**'s Fail cell, in place of its tally.
pub const DEAD_CELL: &str = "dead";

/// A server's failure tally reached the dead-server limit.
#[must_use]
pub fn marked_dead(server: &ServerEndpoint, failures: u32) -> Sentence {
    Sentence::owned(format!(
        "{} marked dead: {failures} tries in a row went unanswered — it stays listed, \
         is still pinged every 20 minutes and can be connected to by hand",
        server_label(server)
    ))
}

/// A dead server answered again.
#[must_use]
pub fn came_back(server: &ServerEndpoint) -> Sentence {
    Sentence::owned(format!(
        "{} answered again — no longer dead",
        server_label(server)
    ))
}

/// What a row listed by host name resolved to (ADR-0052's amendment), as
/// the detail pane's health sentence ends; `None` for a row listed by
/// address, whose address is the row.
#[must_use]
pub fn resolved_address_words(
    server: &ServerEndpoint,
    resolved: Option<rmule_core::ResolvedAddress>,
) -> Option<String> {
    if server.host().parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    Some(match resolved {
        Some(rmule_core::ResolvedAddress::Resolved(ip)) => format!("its name resolves to {ip}"),
        Some(rmule_core::ResolvedAddress::DoesNotResolve) => {
            "its name does not resolve, so it cannot be pinged — each pass that finds no \
             address counts as an unanswered try"
                .to_string()
        }
        None => "its name has not been looked up yet".to_string(),
    })
}

/// Every status ping near a silence went unanswered too.
pub const SWEEP_UNHEARD: Sentence = Sentence::fixed(
    "no server answers status pings — the network looks down, so no server is counted as failing for it",
);

/// The connected server was told the shares, as every server is by default.
pub const SHARES_ANNOUNCED: &str = "Shares announced to this server";

mod detail;
pub use detail::{DetailContext, detail_pane, grants_line, shares_line, shares_log_line};
