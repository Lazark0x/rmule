//! The Managed Server List's rows as the snapshot carries them (ADR-0080):
//! the durable row joined with what the server has said about itself.

use std::time::{Duration, SystemTime};

use crate::server_list::{DeadSince, ManagedServer, ResolvedAddress, ServerHealth, ServerPolicy};

/// One row of the managed server list as a consumer reads it (ADR-0080): the
/// durable row, its figures projected, and how old they are.
///
/// The figures are `Option` because a server that has never answered has no
/// ping, no user count and no file count — a consumer renders that as
/// "unknown", not as zero. They are the durable row's: the UDP status
/// sweep's `0x96`/`0x97` round trip writes all three and dates them, the
/// login welcome burst's `OP_SERVERSTATUS` writes the counts, and a server.met
/// import that carried them brings its own date. `age` says how long ago the
/// server last answered, as of the snapshot, so a figure an hour old never
/// reads as fresh.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerDiagnostics {
    /// The persisted row: endpoint, name, description, priority, static pin,
    /// failure tally and figures.
    pub server: ManagedServer,
    /// Last measured round trip to the server's UDP port.
    pub ping: Option<Duration>,
    /// Users the server last reported online.
    pub users: Option<u32>,
    /// Files the server last reported indexed.
    pub files: Option<u32>,
    /// How long ago the server last answered, as of the snapshot; `None` for
    /// one that never has.
    pub age: Option<Duration>,
    /// How reaching the server has gone under the policy of the snapshot
    /// (ADR-0052): a **Dead Server** is one whose failure tally reached
    /// the **Dead Server Limit**.
    pub health: ServerHealth,
    /// How long ago the server reported what it grants (its row's
    /// [`grants`](ManagedServer::grants)), as of the snapshot; `None` for a
    /// server never logged into.
    pub grants_age: Option<Duration>,
    /// What the row's host name last resolved to (ADR-0052's amendment):
    /// a run-time fact beside the name the operator listed, which stays the
    /// row's key. `None` for a row listed by address, and for a name the
    /// Status Ping Sweep has not reached yet.
    pub resolved_address: Option<ResolvedAddress>,
    /// When a dead row died (ADR-0052, "Dead since when"); `None` while it
    /// is not dead.
    pub dead_since: Option<DeadSince>,
}

/// What the connected session was told of the share set (ADR-0093, "What is
/// announced to a server that answers related searches").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SharesToServer {
    /// The share set was announced (`OP_OFFERFILES`).
    Announced,
    /// Nothing was announced on purpose: the **Announce Policy** withholds
    /// the set from a server that grants related search.
    Withheld,
    /// The set was announced before the policy was switched on; an offer
    /// cannot be taken back in the session, so nothing more is sent.
    AnnouncedBeforeWithholding,
}

/// [`SharesToServer`] for the one connected server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareAnnouncement {
    /// The connected server.
    pub server: rmule_primitives::ServerEndpoint,
    /// What it was told.
    pub shares: SharesToServer,
}

impl ServerDiagnostics {
    /// The row of a server that has told us nothing about itself yet.
    #[must_use]
    pub fn listed(server: ManagedServer) -> Self {
        Self {
            health: ServerPolicy::default().health(&server),
            grants_age: None,
            server,
            ping: None,
            users: None,
            files: None,
            age: None,
            resolved_address: None,
            dead_since: None,
        }
    }

    /// The row as a consumer reads it at `now` under `policy`: the figures
    /// projected, dated, and its health derived.
    #[must_use]
    pub fn at(server: ManagedServer, now: SystemTime, policy: ServerPolicy) -> Self {
        let figures = server.figures.as_ref();
        Self {
            health: policy.health(&server),
            grants_age: server.grants.map(|report| report.age(now)),
            ping: figures.and_then(|figures| figures.ping),
            users: figures.and_then(|figures| figures.users),
            files: figures.and_then(|figures| figures.files),
            age: figures.map(|figures| figures.age(now)),
            server,
            resolved_address: None,
            dead_since: None,
        }
    }

    /// The same row with what its name last resolved to.
    #[must_use]
    pub const fn resolved_at(mut self, resolved_address: Option<ResolvedAddress>) -> Self {
        self.resolved_address = resolved_address;
        self
    }

    /// The same row with when it died.
    #[must_use]
    pub const fn died(mut self, dead_since: Option<DeadSince>) -> Self {
        self.dead_since = dead_since;
        self
    }
}
