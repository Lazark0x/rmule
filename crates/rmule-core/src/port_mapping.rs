//! **Port Mapping** (ADR-0086): the core-owned, sans-I/O brain that converts a
//! firewalled home node into a High-ID, Kad-open one by itself.
//!
//! A firewalled node is the common rmule deployment. It is a LowID on every
//! server and Kad-firewalled, so every transfer it makes is brokered —
//! the **Reachability** store can *observe* that verdict and nothing
//! in rmule could act on it. This module acts on it.
//!
//! eD2k adds the one hard constraint that shapes everything here: **the hello
//! advertises one TCP port and has no external-port tag**, so a mapping granted
//! on a different external port is a silent LowID, not a success. That is why
//! the mapper grades every trial on the *exact* external port rather than on
//! "did the router say yes", and why protocol preference is only a tie-break —
//! a UPnP grant on the right port genuinely beats a PCP grant on the wrong one.
//!
//! `PortMapper` is explicit-time and socket-free, the **Download State** /
//! **Serve State** doctrine: `now` is a parameter, it emits `MappingCommand`s
//! and consumes `MappingResult`s, and a runtime turns those into
//! [`MappingBackend`](rmule_net::portmap::MappingBackend) calls. So
//! the whole race, the grade matrix, the RFC renewal ladder, the epoch re-add
//! and the backoff ladder are driven in a microsecond against a fake backend.
//!
//! Its one non-command output is a [`MappingGrant`
//! observation](crate::AddressObservation::mapping_grant): the mapper holds the
//! **Address Learning** store the way every other feeder does and hands each
//! usable grant straight to it, which is what puts the granted endpoint on the
//! `CT_EMULE_UDPPORTS` advert and the `0x95` without any advert site knowing a
//! port mapper exists.
//!
//! This file is the **vocabulary**. The `desired` submodule derives the
//! **Desired Mapping Set** from what actually bound, `grade` holds the grading
//! rule one trial is judged by, `renewal` the lease clamps and the RFC ladders,
//! and `mapper` the state machine that ties them together.

use std::fmt;
use std::time::{Duration, Instant};

use rmule_net::portmap::MappedTransport;
/// What a diagnostics row's failure, and a release that sent no delete, are
/// made of, re-exported so a front end words them without linking the net
/// crate.
pub use rmule_net::portmap::{
    MappingError, MappingProtocol, MappingRefusal, MappingTransportFault, ReleaseKept,
};
use rmule_primitives::{AddressFamily, PeerEndpoint};

use crate::address_learning::SocketRole;

mod desired;
mod grade;
mod mapper;
mod renewal;
#[cfg(test)]
mod tests;

pub(crate) use desired::DesiredMappingSet;
pub(crate) use mapper::PortMapper;

/// The deadline every backend probe and map runs under (ADR-0086, "Every
/// grant has one owner and one end"), answered as
/// [`Timeout`](MappingError::Timeout) when it passes.
///
/// A trial is judged only once every row has answered, so one silent call
/// would hold the whole race open for the rest of the session. The two UDP
/// backends bound themselves with their own retransmit ladder, but the UPnP
/// one makes a blocking HTTP request to a device that can simply stop
/// replying — and a cancelled `spawn_blocking` keeps running, so this bounds
/// the *answer*, not the thread. Comfortably past the race's own 15-second
/// cap, so it never pre-empts a slow-but-live gateway.
pub(crate) const BACKEND_DEADLINE: Duration = Duration::from_secs(20);

/// Whether rmule maps its own ports at all (ADR-0086).
///
/// **Auto is the default**, against aMule's off-by-default: the headless
/// majority never opens a settings screen, and forfeiting High-ID for every
/// operator who does not know the option exists is the larger harm. `Off` is
/// for the deployment that already has a static forward and wants nothing
/// talking to its router.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PortMappingMode {
    /// Never talk to a gateway.
    Off,
    /// Race every enabled protocol and keep the best result mapped.
    #[default]
    Auto,
}

/// The port-mapping engineering knobs (ADR-0086). Whether to map at all is
/// the operator's [`CoreSettings::port_mapping`](crate::CoreSettings::port_mapping).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortMappingConfig {
    /// Which protocols may be raced — emule-qt's `portMapProtocols` bitmask
    /// (1 = PCP, 2 = NAT-PMP, 4 = UPnP), so a mask means the same thing in
    /// both clients. All three by default.
    pub protocols: u8,
    /// The lifetime to ask a gateway for, clamped to 2 min – 24 h (a zero
    /// lifetime is a delete on the wire). Granted lifetimes are clamped
    /// regardless (24 h for a success, 30 min for an error hold-off), so this
    /// is a request, never a promise.
    pub lease: Duration,
    /// Withdraw every mapping on a clean exit. On by default: a mapping left
    /// behind keeps a port open on the router for a process that is gone, and
    /// on a shared LAN it is another host's port.
    pub release_on_exit: bool,
}

impl Default for PortMappingConfig {
    fn default() -> Self {
        Self {
            protocols: MappingProtocol::Pcp.mask_bit()
                | MappingProtocol::NatPmp.mask_bit()
                | MappingProtocol::Upnp.mask_bit(),
            lease: Duration::from_secs(3600),
            release_on_exit: true,
        }
    }
}

impl PortMappingConfig {
    /// Whether `protocol` is in the configured mask.
    #[must_use]
    pub const fn enables(&self, protocol: MappingProtocol) -> bool {
        self.protocols & protocol.mask_bit() != 0
    }

    /// The protocols to race, in tie-break preference order.
    pub(crate) fn enabled_protocols(&self) -> Vec<MappingProtocol> {
        MappingProtocol::ALL
            .into_iter()
            .filter(|protocol| self.enables(*protocol))
            .collect()
    }
}

/// One mapping rmule wants on the router: which of its sockets, in which
/// **Address Family**.
///
/// Derived from the **Family Pairs** that actually bound, never from config —
/// the configured selection says only what was *attempted*, and a mapping for a
/// socket that never came up would be a port forwarded to nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DesiredMapping {
    /// Which of our sockets.
    pub role: SocketRole,
    /// Which family.
    pub family: AddressFamily,
    /// The port that role's pair bound — the number the hello advertises.
    pub internal_port: u16,
    /// The address an IPv6 pinhole opens to: the Known IPv6 the set was
    /// derived under (ADR-0084), `None` on IPv4. It is part of the row's
    /// identity because a PCP pinhole is keyed by its internal address — so
    /// a Known IPv6 that moves (a new privacy address, a renumber) takes the
    /// old row out of the set, releasing the old pinhole from the address it
    /// was made for, and maps a new one, as RFC 6887 §8.4 asks.
    pub pinhole: Option<std::net::Ipv6Addr>,
}

impl DesiredMapping {
    /// The transport a gateway maps this role on.
    #[must_use]
    pub const fn transport(&self) -> MappedTransport {
        match self.role {
            SocketRole::Tcp => MappedTransport::Tcp,
            SocketRole::Udp => MappedTransport::Udp,
        }
    }
}

impl fmt::Display for DesiredMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} :{}",
            self.family,
            self.role,
            self.transport(),
            self.internal_port
        )?;
        match self.pinhole {
            Some(address) => write!(f, " @{address}"),
            None => Ok(()),
        }
    }
}

/// How well one backend's trial served the whole **Desired Mapping Set**
/// (ADR-0086). Ordered worst-first, so the best trial is the maximum.
///
/// The grade is about **ports**, not about usability: an external address that
/// is not publicly routable is a
/// [`Degraded`](MappingStatus::Degraded) *status* on an otherwise
/// [`Exact`](Self::Exact) trial, because the router did exactly what it was
/// asked and the problem is upstream of it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum MappingGrade {
    /// Nothing was granted.
    #[default]
    None,
    /// Some of the set was granted.
    Partial,
    /// The whole set was granted, but at least one external port differs from
    /// its internal port.
    Mismatched,
    /// The whole set was granted, every mapping on its own port. **Ends the
    /// race** — nothing can beat it.
    Exact,
}

/// What rmule currently believes about one mapping — the level a TUI or CLI
/// reads (ADR-0086).
///
/// [`Degraded`](Self::Degraded) is a first-class outcome rather than a flavour
/// of success: reporting "forwarded" beside a permanently firewalled client is
/// a lie, and the two cases that produce it — a TCP grant on the wrong port,
/// and a grant whose external address is not publicly routable — are both
/// invisible to a boolean.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingStatus {
    /// No mapping, and none being sought — off, or nothing bound.
    NotMapped,
    /// A race is in flight.
    Probing,
    /// Granted, on its own port, at a publicly routable address.
    Mapped,
    /// Granted and unusable. A mismatched **TCP** grant (the hello cannot
    /// carry another port) or a grant whose external address is private or
    /// carrier-grade — the gateway is behind a second NAT and no mapping on it
    /// reaches past.
    Degraded,
    /// Every protocol refused, or every trial granted nothing.
    Failed,
}

impl fmt::Display for MappingStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotMapped => "not mapped",
            Self::Probing => "probing",
            Self::Mapped => "mapped",
            Self::Degraded => "degraded",
            Self::Failed => "failed",
        })
    }
}

/// What the sans-I/O [`PortMapper`] asks its runtime to do. The runtime turns
/// each into one [`MappingBackend`](rmule_net::portmap::MappingBackend) call —
/// except the last, which reaches the Kad node instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MappingCommand {
    /// Ask one protocol, statelessly, whether it is there.
    Probe {
        /// The protocol to ask.
        protocol: MappingProtocol,
    },
    /// Request one mapping, or renew one by suggesting the granted port.
    Map {
        /// Which protocol to ask.
        protocol: MappingProtocol,
        /// The mapping wanted.
        mapping: DesiredMapping,
        /// The external port to suggest — the internal port on a first map,
        /// the granted port on a renewal.
        suggested_external_port: u16,
        /// The lifetime to ask for.
        lease: Duration,
    },
    /// Withdraw a mapping — a losing trial's, or every one of ours on exit.
    Release {
        /// Which protocol granted it.
        protocol: MappingProtocol,
        /// The mapping to withdraw.
        mapping: DesiredMapping,
        /// The external port it holds.
        external_port: u16,
    },
    /// Start a Kad firewall self-check now, outside its hourly clock
    /// (ADR-0086's amendment to ADR-0058) — **the thing neither reference
    /// implementation does**. A fresh Exact grant and a gateway epoch reset
    /// each fire one; renewals never do, because a helper lookup every
    /// ~30 minutes per mapping would pollute the flood limiter's view of us.
    /// Without it a headless node sits Kad-firewalled for up to an hour after
    /// a mapping that already works.
    RecheckReachability,
}

/// What a runtime reports back to the [`PortMapper`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MappingResult {
    /// A probe answered.
    Probed {
        /// Which protocol answered.
        protocol: MappingProtocol,
        /// The families it can map through this gateway, and its epoch
        /// verdict — or why it cannot.
        outcome: Result<ProbeAnswer, MappingError>,
    },
    /// A map or renew answered.
    Mapped {
        /// Which protocol answered.
        protocol: MappingProtocol,
        /// Which mapping it was for.
        mapping: DesiredMapping,
        /// What it granted, or why it refused.
        outcome: Result<GrantAnswer, MappingError>,
    },
}

/// A probe's answer, reduced to what the sans-I/O mapper decides on.
///
/// The gateway's own external address is deliberately absent: the mapper never
/// adopts an address from a probe — only a *grant* carries an endpoint into
/// **Address Learning**, because only a grant proves the gateway will actually
/// forward to us.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProbeAnswer {
    /// The families this protocol can map through this gateway.
    pub(crate) families: Vec<AddressFamily>,
    /// Whether the gateway's epoch says it lost its state since we last spoke.
    pub(crate) epoch_reset: bool,
}

/// A grant's answer, reduced to what the sans-I/O mapper decides on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GrantAnswer {
    /// Where the outside world now reaches the mapped socket.
    pub(crate) external: PeerEndpoint,
    /// The lifetime the gateway returned, raw. `None` is a permanent mapping
    /// (IGD1's lease of 0), which has no expiry and is re-verified by a slow
    /// poll instead.
    pub(crate) lease: Option<Duration>,
    /// Whether the gateway's epoch says it lost its state.
    pub(crate) epoch_reset: bool,
}

/// One granted mapping as the mapper tracks it: what the gateway gave, when it
/// must be renewed, and how many renewals in a row have failed (ADR-0086).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MappingLease {
    /// Which protocol holds it.
    pub(crate) protocol: MappingProtocol,
    /// Where the outside world reaches the mapped socket.
    pub(crate) external: PeerEndpoint,
    /// The lifetime, clamped. `None` is permanent.
    pub(crate) lease: Option<Duration>,
    /// When it was granted — the anchor every RFC renewal fraction is measured
    /// from.
    pub(crate) granted_at: Instant,
    /// When the next renewal is due.
    pub(crate) renew_at: Instant,
    /// Which rung of the renewal ladder the next attempt is on.
    pub(crate) attempt: u32,
    /// Consecutive failed renewals; three forces a full reprobe.
    pub(crate) failures: u32,
    /// How this mapping reads to an operator.
    pub(crate) status: MappingStatus,
}

/// One **Port Mapping** row as a diagnostics consumer reads it (ADR-0086).
///
/// A row exists for every *desired* mapping, not only every granted one: "the
/// TCP listener is not mapped" is the fact an operator most needs, and a table
/// that only lists successes cannot state it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappingDiagnostics {
    /// Which socket, in which family, on which internal port.
    pub mapping: DesiredMapping,
    /// How it reads now.
    pub status: MappingStatus,
    /// Which protocol granted it, or `None` while unmapped.
    pub method: Option<MappingProtocol>,
    /// Where the outside world reaches it, or `None` while unmapped.
    pub external: Option<PeerEndpoint>,
    /// The clamped lifetime. `None` on an unmapped row *and* on a permanent
    /// one — a consumer reads the two apart by [`status`](Self::status).
    pub lease: Option<Duration>,
    /// When the next renewal or permanent-lease poll is due.
    pub next_renewal: Option<Instant>,
    /// The last failure, as a code a front end words. Kept after a
    /// later success so a flapping router is visible rather than
    /// self-erasing.
    pub last_error: Option<MappingError>,
}

/// Whether `rows` hold the eD2k listener's IPv4 row for `port` with the race
/// answered for it — `Mapped`, `Degraded` or `Failed` — which is where the
/// **Login Mapping Wait** ends (ADR-0086). A missing
/// row (the runtime has not re-derived since the bind) and a `Probing` or
/// `NotMapped` one both keep the login waiting, inside its bound.
pub(crate) fn listener_mapping_settled(rows: &[MappingDiagnostics], port: u16) -> bool {
    rows.iter().any(|row| {
        row.mapping.role == SocketRole::Tcp
            && row.mapping.family == AddressFamily::V4
            && row.mapping.internal_port == port
            && matches!(
                row.status,
                MappingStatus::Mapped | MappingStatus::Degraded | MappingStatus::Failed
            )
    })
}
