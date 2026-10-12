//! The core-owned **Reachability** verdict store and the firewall-check
//! **dial-back broker** (ADR-0058).
//!
//! `Reachability` is the sibling of [`ServerCapabilities`](crate::server_capabilities):
//! a typed record of our own network position, read by every consumer that
//! gates on whether we are reachable (the ADR-0057 reask gate, the
//! buddy/direct-callback triggers, the ADR-0047 adverts, and Kad
//! publish/routing).
//!
//! Two self-checks **compose in one store**, exactly as aMule keeps
//! `CKademlia`'s TCP state and `CUDPFirewallTester`'s separate but co-read:
//!
//! - **TCP** ([`TcpReachability`]) reads open only on ≥2 independent connect-back
//!   acks, and a recheck serves the pre-recheck snapshot so a proven-open node
//!   never flaps mid-check. [`TcpReachability::is_reachable`] is the "Kad-open"
//!   half of the ADR-0057 reask gate, which the download brain reads off its
//!   Callback Capability sample.
//! - **UDP** ([`UdpReachability`]) reads `Open{port}` / `Firewalled` /
//!   `Unverified`; its test only runs once the TCP verdict here allows it.
//!
//! The store is the Kad pump's **accumulator**: the pump publishes its settled
//! verdicts into [`SharedKadVerdicts`], and every reader — the pump's own
//! included — reads them, with the Server High ID and the NAT-T front, through
//! the one owner, [`SharedSelfReach`] (ADR-0060 "Self Reach"),
//! where aMule's `IsFirewalled()` / `CanDoCallback` unions live.
//!
//! A third verdict lives in this module but outside the store
//! ([`SharedIpv6Probe`], ADR-0084): whether the connected server says it could
//! reach us over IPv6. It is *told* to us rather than self-checked, by a task
//! that never touches the store, and it dies with the session that said it —
//! so it is a published cell, not a field. Where we are, as against whether we
//! can be reached, is [`AddressLearning`](crate::address_learning)'s.
//!
//! The store runs no check itself: the sans-I/O KadNode owns every recheck
//! cadence, emission budget and timeout, and [`Reachability::observe`] projects
//! its lifecycle events onto the two verdicts — so a verdict can only change
//! through an observed event. The ADR-0061 buddy recruit gate
//! ([`buddy`](crate::buddy)'s `BuddyUdpPosture`) is the consumer that reads both,
//! recruiting only when *both* read firewalled.
//!
//! Beside the store, and reading none of it, sits the firewall-check
//! [`dial_back`] broker: the core half of the *responder*, deciding what to do
//! with someone else's `0x50`/`0x53` check.

use std::time::Instant;

mod client_udp_bound;
mod dial_back;
mod kad_level;
mod self_reach;

pub(crate) use client_udp_bound::ClientUdpBound;
pub use kad_level::KadReachLevel;
pub(crate) use kad_level::{KadVerdicts, KadVerdictsLease, KadVerdictsWriter, SharedKadVerdicts};
pub(crate) use self_reach::{KadRunLease, ReachGeneration, SharedSelfReach};

pub(crate) use dial_back::{
    DialBackGuards, DialBackRefusal, DialBackRegistry, DialBackRequest, DialBackVerdict,
    FwCheckAck, OwnListenEndpoint, broker_dial_back,
};

/// Our own **TCP** reachability verdict (ADR-0058). Kad-checked by the ≥2-ack
/// rule ([`Reachability::TCP_ACKS_FOR_OPEN`]): fewer than two connect-back acks
/// reads firewalled; a recheck in flight reports the pre-recheck snapshot so a
/// proven-open node never flaps to firewalled mid-check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TcpReachability {
    /// At least two connect-back acks landed since the last recheck started.
    Open,
    /// Fewer than two acks and no recheck in flight — the default posture a
    /// fresh node holds until it proves otherwise.
    Firewalled,
    /// A recheck is in flight and has not yet reconfirmed; consumers read the
    /// stable pre-recheck `last` verdict, not a premature firewalled.
    Checking { last: StableTcp },
}

/// A settled TCP verdict (never `Checking`) — the snapshot a recheck preserves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StableTcp {
    Open,
    Firewalled,
}

/// Our own **IPv6** reachability verdict (ADR-0084's amendment to ADR-0058):
/// what the connected server's `ST_IPV6_STATUS` tag says about dialling us
/// over IPv6.
///
/// Unlike the two Kad-fed verdicts beside it this one is *told* to us, not
/// self-checked: an IPv6-capable server may probe the address a client claims
/// and report the result. It is session-bound and clears on disconnect — a
/// probe verdict from a server we are no longer talking to says nothing about
/// the path we have now.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Ipv6Probe {
    /// No server has reported a probe. The fresh-node default, and what a
    /// server that trusts rather than dials back always leaves us at — such a
    /// server can never suppress an advertisement, by its own design.
    #[default]
    Unknown,
    /// The server probed the address and reached it (`PROBED | REACHABLE`).
    ProbedReachable,
    /// The server probed the address and could **not** reach it (`PROBED`
    /// without `REACHABLE`) — the one verdict that suppresses the IPv6 half of
    /// an advert.
    ProbedUnreachable,
}

impl From<rmule_primitives::ServerIpv6Status> for Ipv6Probe {
    /// Project one `ST_IPV6_STATUS` word onto the verdict (ADR-0087 §4.3).
    ///
    /// Only `PROBED` decides anything: without it the server either holds no
    /// address for us or took ours on trust, and neither is a statement about
    /// the path. A server that reports `HAVE | REACHABLE` and never `PROBED`
    /// therefore leaves us at `Unknown` forever, by its own design — which must
    /// read as "nothing was probed", never as "probed and failed".
    fn from(status: rmule_primitives::ServerIpv6Status) -> Self {
        match (status.was_probed(), status.is_reachable()) {
            (false, _) => Self::Unknown,
            (true, true) => Self::ProbedReachable,
            (true, false) => Self::ProbedUnreachable,
        }
    }
}

/// Our own **UDP** reachability verdict (ADR-0058), projected from
/// the sans-I/O KadNode's UDP firewall tester. Read (with the TCP verdict) by the
/// ADR-0061 buddy recruit gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UdpReachability {
    /// Verified open on `port` — a helper's positive `0x62` reached our
    /// intern-preferred UDP port. A direct callback works, so no buddy is needed.
    Open { port: u16 },
    /// Verified firewalled — both fresh helpers failed, or the 6-minute timeout
    /// fired with the TCP verdict also firewalled. A buddy relay is needed.
    Firewalled,
    /// Not yet known: the fresh-node default and mid-test. aMule assumes open when
    /// unknown, but the buddy gate treats this as "not yet known to need a buddy"
    /// (neither recruit nor direct-callback).
    Unverified,
}

impl TcpReachability {
    /// Whether this verdict reads **reachable** for a consumer gating on TCP
    /// openness — `Open`, or a `Checking` whose preserved snapshot was open. This
    /// is the "Kad-open" half of the ADR-0057 reask gate's `server-High-ID or
    /// Kad-open` rewire (ADR-0058): mirrors aMule's `!GetFirewalled`, which reads
    /// the pre-recheck snapshot mid-recheck rather than a premature firewalled.
    pub(crate) fn is_reachable(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::Checking {
                    last: StableTcp::Open
                }
        )
    }
}

/// The core-owned Reachability store: our own network position, fed by the Kad
/// self-check and read by every reachability consumer.
pub(crate) struct Reachability {
    /// Connect-back acks counted since the current recheck started.
    tcp_confirmations: u32,
    /// `Some(last)` while a recheck is in flight (the pre-recheck snapshot);
    /// `None` when the TCP verdict is settled.
    tcp_snapshot: Option<StableTcp>,
    /// The UDP verdict (ADR-0058), projected from the node's UDP
    /// tester events. `Unverified` until the tester concludes — a fresh node has
    /// not tested its UDP surface.
    udp: UdpReachability,
    /// When the last TCP recheck started, or `None` — never. Not a verdict:
    /// it is the clock the ADR-0061 buddy recruit gate keeps five minutes clear
    /// of (`POST_RECHECK_GUARD`), so a node does not recruit a relay it may be
    /// about to prove it does not need. ADR-0086's externally triggered
    /// recheck is what made it a real edge rather than an hourly one.
    last_recheck: Option<Instant>,
}

impl Reachability {
    /// Connect-back acks that prove TCP-open (aMule `KADEMLIAFIREWALLCHECKS`
    /// verdict boundary, `Prefs.cpp`): two acks = open, fewer = firewalled.
    /// Two acks, not two distinct senders: `KadEvent::ReachabilityConnectBack`
    /// names no source, and aMule's `IncFirewalled` counts a `0x59` from
    /// anyone, so a spoofed pair reads open here as it does there.
    pub(crate) const TCP_ACKS_FOR_OPEN: u32 = crate::diagnostics::KadFirewallCheck::ACKS_FOR_OPEN;

    /// A fresh store: TCP firewalled — the default a node holds until it proves
    /// open.
    pub(crate) fn new() -> Self {
        Self {
            tcp_confirmations: 0,
            tcp_snapshot: None,
            udp: UdpReachability::Unverified,
            last_recheck: None,
        }
    }

    /// Start a TCP recheck: snapshot the current settled verdict and zero the
    /// confirmation counter (aMule `SetRecheckIP` → `SetFirewalled`). Until two
    /// acks reconfirm or [`conclude_tcp_recheck`](Self::conclude_tcp_recheck)
    /// runs, [`tcp`](Self::tcp) reports the snapshot.
    pub(crate) fn begin_tcp_recheck(&mut self, now: Instant) {
        self.tcp_snapshot = Some(self.stable_tcp());
        self.tcp_confirmations = 0;
        self.last_recheck = Some(now);
    }

    /// Count one connect-back ack (aMule `IncFirewalled`). The
    /// [`TCP_ACKS_FOR_OPEN`](Self::TCP_ACKS_FOR_OPEN)th ack concludes the
    /// recheck open.
    pub(crate) fn record_tcp_ack(&mut self) {
        self.tcp_confirmations = self.tcp_confirmations.saturating_add(1);
        if self.tcp_confirmations >= Self::TCP_ACKS_FOR_OPEN {
            self.tcp_snapshot = None;
        }
    }

    /// Conclude an in-flight recheck that never reached the ack threshold: drop
    /// the snapshot so [`tcp`](Self::tcp) settles on the ≥2-ack verdict
    /// (firewalled, given fewer than two acks). The requester cycle (ADR-0058)
    /// calls this when the hello-piggyback budget or the 180 s window expires.
    pub(crate) fn conclude_tcp_recheck(&mut self) {
        self.tcp_snapshot = None;
    }

    /// Project one Kad reachability event onto the store (ADR-0058): the sans-I/O
    /// KadNode owns the TCP recheck cadence / emission budget / 180 s windows and
    /// the UDP tester's helper set + timeout, and emits the lifecycle; core folds
    /// those into the TCP ≥2-ack verdict and the UDP verdict. A TCP recheck start
    /// snapshots and zeroes, each connect-back ack counts one leg, a conclude
    /// settles the in-flight recheck; a UDP open/firewalled event sets the UDP
    /// verdict outright (the tester already applied its 2-helper / timeout rule).
    /// Every other Kad event is ignored — this observer is reachability only.
    pub(crate) fn observe(&mut self, event: &rmule_kad::KadEvent, now: Instant) {
        match event {
            rmule_kad::KadEvent::ReachabilityRecheckStarted => self.begin_tcp_recheck(now),
            rmule_kad::KadEvent::ReachabilityConnectBack => self.record_tcp_ack(),
            rmule_kad::KadEvent::ReachabilityRecheckConcluded => self.conclude_tcp_recheck(),
            rmule_kad::KadEvent::UdpReachabilityOpen { port } => {
                self.udp = UdpReachability::Open { port: *port };
            }
            rmule_kad::KadEvent::UdpReachabilityFirewalled => {
                self.udp = UdpReachability::Firewalled;
            }
            _ => {}
        }
    }

    /// Declare this node's surface open without running the self-checks — the
    /// **Core-Pumped Stimulus Node** posture.
    ///
    /// Both verdicts are self-check-derived and each needs *other* open peers to
    /// converge: the TCP verdict wants
    /// [`TCP_ACKS_FOR_OPEN`](Self::TCP_ACKS_FOR_OPEN) connect-back acks, which an honest
    /// helper sends only after dialing us, and the UDP verdict wants a fresh helper — one never
    /// sent a datagram — to answer `0x62` to its peer-TCP `OP_FWCHECKUDPREQ`.
    /// A two-node stimulus swarm has neither, so an rmule stimulus node would
    /// refuse every `FINDBUDDY_REQ` as `TcpFirewalled`/`UdpUnverified` and the
    /// counterparty's post-`0x5A` behaviour could never be observed.
    ///
    /// This seeds the *same* verdicts the projections would settle on, so nothing
    /// downstream learns a new state. It is stimulus configuration — rmule's own
    /// posture, never a counterparty byte (ADR-0045) — and is reachable only from
    /// a harness flag that defaults off; a production node leaves it untouched and
    /// keeps the live self-check verdicts.
    pub(crate) fn assume_open(&mut self, udp_port: u16) {
        self.tcp_snapshot = None;
        self.tcp_confirmations = Self::TCP_ACKS_FOR_OPEN;
        self.udp = UdpReachability::Open { port: udp_port };
    }

    /// When the last TCP recheck started — the ADR-0061 recruit gate's
    /// five-minute clearance input.
    pub(crate) fn last_recheck(&self) -> Option<Instant> {
        self.last_recheck
    }

    /// The current UDP verdict (ADR-0058) — the buddy gate's UDP half.
    pub(crate) fn udp(&self) -> UdpReachability {
        self.udp
    }

    /// The current TCP verdict under the ≥2-ack rule, reporting the snapshot
    /// while a recheck is in flight.
    pub(crate) fn tcp(&self) -> TcpReachability {
        if self.tcp_confirmations >= Self::TCP_ACKS_FOR_OPEN {
            TcpReachability::Open
        } else if let Some(last) = self.tcp_snapshot {
            TcpReachability::Checking { last }
        } else {
            TcpReachability::Firewalled
        }
    }

    /// What the TCP self-check has drawn, for the operator: no check yet, one
    /// collecting, or the last one's connect-back count.
    pub(crate) fn tcp_check(&self) -> crate::diagnostics::KadFirewallCheck {
        use crate::diagnostics::KadFirewallCheck as Check;
        let acks = self.tcp_confirmations;
        if self.tcp_snapshot.is_some() {
            Check::Running { acks }
        } else if self.last_recheck.is_none() && acks == 0 {
            Check::NotYetRun
        } else {
            Check::Ended { acks }
        }
    }

    /// The settled TCP verdict, ignoring any in-flight recheck — the snapshot a
    /// fresh recheck preserves.
    fn stable_tcp(&self) -> StableTcp {
        if self.tcp_confirmations >= Self::TCP_ACKS_FOR_OPEN {
            StableTcp::Open
        } else {
            StableTcp::Firewalled
        }
    }
}

/// The **IPv6 probe verdict** as the connected server states it, published for
/// the readers that live elsewhere in core (ADR-0084).
///
/// A cell rather than a field on [`Reachability`] because it has a different
/// writer and a different lifetime from the two verdicts beside it: those are
/// Kad self-checks folded inside the Kad pump, this one is *told* to us by the
/// server session — a task that never touches that store — and dies with the
/// session that said it. Folding it in would need a channel between two tasks
/// to carry a level that a cell already carries.
///
/// The default is [`Ipv6Probe::Unknown`], which never suppresses anything: a
/// server that trusts rather than dials back leaves us here forever, and that
/// must read as "nothing was probed", not as "probed and failed".
#[derive(Clone, Debug, Default)]
pub(crate) struct SharedIpv6Probe(std::sync::Arc<std::sync::Mutex<Ipv6Probe>>);

impl SharedIpv6Probe {
    /// The published verdict. A poisoned lock reads the honest default.
    pub(crate) fn get(&self) -> Ipv6Probe {
        self.0.lock().map_or(Ipv6Probe::Unknown, |probe| *probe)
    }

    /// Publish what the connected server's `ST_IPV6_STATUS` said (the
    /// `OP_SERVERIDENT` reader that feeds this lands with the IPv6 dialect,
    /// ADR-0087).
    pub(crate) fn set(&self, probe: Ipv6Probe) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = probe;
        }
    }

    /// The session ended: the verdict clears, because it was that server's
    /// statement about that session's path.
    pub(crate) fn clear(&self) {
        self.set(Ipv6Probe::Unknown);
    }
}

#[cfg(test)]
mod tests;
