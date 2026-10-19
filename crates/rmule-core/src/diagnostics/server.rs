//! The Managed Server List's rows as the snapshot carries them (ADR-0080):
//! the durable row joined with what the server has said about itself.

use std::time::{Duration, Instant, SystemTime};

use crate::server_list::{DeadSince, ManagedServer, ResolvedAddress, ServerHealth, ServerPolicy};

/// One row of the managed server list as a consumer reads it (ADR-0080): the
/// durable row, its figures projected, and how old they are.
///
/// The counts are `Option` because a server that has never reported has no
/// user count and no file count — a consumer renders that as "unknown", not
/// as zero — and the ping is a [`PingState`], which says why there is no
/// round trip when there is none. They are the durable row's: the UDP status
/// sweep's `0x96`/`0x97` round trip writes all three and dates them, the
/// login welcome burst's `OP_SERVERSTATUS` writes and dates the counts only,
/// and a server.met import that carried them brings its own date. `age` says
/// how long ago the figures were last dated, as of the snapshot, so a figure
/// an hour old never reads as fresh; `status_age` dates the last status
/// answer alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerDiagnostics {
    /// The persisted row: endpoint, name, description, priority, static pin,
    /// failure tally and figures.
    pub server: ManagedServer,
    /// What core knows of the server's status ping: its last measured round
    /// trip, or why there is none.
    pub ping: PingState,
    /// Users the server last reported online.
    pub users: Option<u32>,
    /// Files the server last reported indexed.
    pub files: Option<u32>,
    /// How long ago the figures were last dated — by a status answer or a
    /// count report, whichever is later — as of the snapshot; `None` for a
    /// server that never reported.
    pub age: Option<Duration>,
    /// How long ago the server last gave a status answer (a
    /// challenge-matched `0x97`, or an import's last-ping time), as of the
    /// snapshot; `None` for one that never has.
    pub status_age: Option<Duration>,
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

/// What core knows of a server's status ping (ADR-0080, "The Ping State"),
/// so a consumer never shows a bare blank where a round trip would be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PingState {
    /// The round trip of the last challenge-matched `0x97`.
    Measured(Duration),
    /// No round trip measured, and the Status Ping Sweep has sent the server
    /// nothing this run.
    NotAskedYet,
    /// No round trip measured, and a probe is out awaiting its answer.
    Awaiting,
    /// The server's last plain probe was judged silent and nothing was
    /// answered since; `since` is how long ago the first silence of that run
    /// of silences left. It outranks an older measured round trip.
    Unanswered {
        /// How long ago the first unanswered probe of the run left.
        since: Duration,
    },
}

impl PingState {
    /// The state as the measured round trip and the sweep's probe fact make
    /// it: a silence outranks any round trip, a round trip outranks a probe
    /// in flight.
    #[must_use]
    pub(crate) fn of(measured: Option<Duration>, probe: Option<PingProbe>) -> Self {
        match (probe, measured) {
            (Some(PingProbe::Silent(first)), _) => Self::Unanswered {
                since: first.elapsed(),
            },
            (_, Some(rtt)) => Self::Measured(rtt),
            (Some(PingProbe::Out), None) => Self::Awaiting,
            (None, None) => Self::NotAskedYet,
        }
    }

    /// The state's rank for ordering: a measured round trip first, then a
    /// probe in flight, then one not sent yet, then a silence.
    #[must_use]
    pub const fn rank(&self) -> u8 {
        match self {
            Self::Measured(_) => 0,
            Self::Awaiting => 1,
            Self::NotAskedYet => 2,
            Self::Unanswered { .. } => 3,
        }
    }

    /// The measured round trip, when there is one.
    #[must_use]
    pub const fn measured(&self) -> Option<Duration> {
        match self {
            Self::Measured(rtt) => Some(*rtt),
            _ => None,
        }
    }
}

/// The Status Ping Sweep's word on a row this run (ADR-0080, "The Ping
/// State"): a run-time fact on the level, never stored, that a
/// challenge-matched `0x97` clears.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PingProbe {
    /// A probe is out.
    Out,
    /// A plain probe was judged silent; the first silence of this run of
    /// them left at this instant.
    Silent(Instant),
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
            ping: PingState::NotAskedYet,
            users: None,
            files: None,
            age: None,
            status_age: None,
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
            ping: PingState::of(figures.and_then(|figures| figures.ping), None),
            users: figures.and_then(|figures| figures.users),
            files: figures.and_then(|figures| figures.files),
            age: figures.and_then(|figures| figures.age(now)),
            status_age: figures.and_then(|figures| figures.status_age(now)),
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

    /// The same row with the Status Ping Sweep's probe fact for it.
    #[must_use]
    pub(crate) fn probed(mut self, probe: Option<PingProbe>) -> Self {
        let measured = self
            .server
            .figures
            .as_ref()
            .and_then(|figures| figures.ping);
        self.ping = PingState::of(measured, probe);
        self
    }

    /// The same row with when it died.
    #[must_use]
    pub const fn died(mut self, dead_since: Option<DeadSince>) -> Self {
        self.dead_since = dead_since;
        self
    }
}
