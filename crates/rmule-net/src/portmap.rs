//! **Port Mapping** (ADR-0086), I/O half: the [`MappingBackend`] seam one
//! port-mapping protocol implements, the [`GatewaySource`] that names the box
//! it talks to, and the epoch validation the protocol crates leave to their
//! caller.
//!
//! The *brain* is not here. Core's sans-I/O **Port Mapper** derives the
//! **Desired Mapping Set** from the bound **Family Pairs**, races the backends,
//! grades each trial on the exact external port, and schedules renewals; this
//! crate only knows how to ask one gateway one question and report what it
//! answered. That split is what lets the whole race, grade, renewal ladder and
//! backoff run against a fake backend with no router in sight.
//!
//! Three things the RFCs demand and `crab_nat` deliberately leaves open live on
//! this side of the seam, because they are facts about the transport rather
//! than about policy:
//!
//! - **Epoch validation** ([`EpochTracker`]): every PCP and NAT-PMP response carries
//!   the gateway's uptime, and each RFC states its own arithmetic for reading a
//!   reboot out of it. `crab_nat` parses the field and validates nothing, so a
//!   router that rebooted would silently keep every mapping "alive" in rmule's
//!   books while forwarding nothing. A backend validates every response and
//!   reports the verdict on its [`MappingGrant`]; core reacts by re-adding the
//!   set.
//! - **One socket per attempt**: a request opens its own socket and closes it.
//!   Firmware exists (measured on a FRITZ!Box, emule-qt
//!   `UdpMappingBackend.h`) that answers exactly one PCP request per source
//!   port over IPv6 and ignores every later one — reusing a socket makes the
//!   first mapping work and reads as "no IPv6 support" for the rest.
//! - **IPv6 source pinning**: the v6 default route is via a link-local next
//!   hop, so a kernel left to choose picks a link-local source address and the
//!   gateway answers `ADDRESS_MISMATCH` or `NOT_AUTHORIZED` — even to a
//!   state-free probe.
//!
//! `crab_nat` gives the second for free (it builds a socket per logical
//! request) and offers no way to do the third, so PCP over IPv6 is rmule's own
//! `MAP` exchange from a socket bound to [`Gateway`]'s local address;
//! the gateway carries that address and the scope id for exactly this.

use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use rmule_primitives::{AddressFamily, PeerEndpoint};

mod epoch;
mod fault;
mod gateway;
mod pcp_map;
mod udp;
mod upnp;

pub use epoch::{EpochTracker, EpochVerdict};
pub use fault::{MappingRefusal, MappingTransportFault};
pub use gateway::{Gateway, GatewaySource, SystemGateways};
pub use udp::UdpMappingBackend;
pub use upnp::UpnpMappingBackend;

/// A boxed future, the shape every [`MappingBackend`] method returns so the
/// trait stays object-safe — the racer holds `Arc<dyn MappingBackend>` values
/// and drives them concurrently, which an `async fn` in a trait cannot do.
/// Same pattern as core's `ServerListFetcher`.
pub type MappingFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Which port-mapping protocol a backend speaks.
///
/// The ordinal is the **tie-break** preference order and nothing more
/// (ADR-0086): every enabled backend probes concurrently, and a UPnP grant on
/// the exact port beats a PCP grant on a different one, because the eD2k hello
/// advertises one port and has no external-port tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MappingProtocol {
    /// Port Control Protocol, RFC 6887. The only one of the three that covers
    /// both **Address Families** and reports a gateway epoch.
    Pcp,
    /// NAT Port Mapping Protocol, RFC 6886. IPv4-only by construction — its
    /// sole address field is the 32-bit WAN IPv4 of the opcode-0 response.
    NatPmp,
    /// UPnP Internet Gateway Device. IPv4 only in this wave: an IPv6 pinhole
    /// needs IGD2 `WANIPv6FirewallControl:1` `AddPinhole`, which `igd-next`
    /// cannot issue.
    Upnp,
}

impl MappingProtocol {
    /// Every protocol, in tie-break preference order.
    pub const ALL: [Self; 3] = [Self::Pcp, Self::NatPmp, Self::Upnp];

    /// This protocol's bit in the configured protocol mask — emule-qt's
    /// `portMapProtocols` (1 = PCP, 2 = NAT-PMP, 4 = UPnP), kept so an
    /// operator's mask means the same thing in both clients.
    #[must_use]
    pub const fn mask_bit(self) -> u8 {
        match self {
            Self::Pcp => 1,
            Self::NatPmp => 2,
            Self::Upnp => 4,
        }
    }

    /// This protocol's stable persisted name — the **learned method** a front
    /// end stores so the next run opens with one short probe instead of a full
    /// race. Stable: renaming one would orphan an installed value.
    #[must_use]
    pub const fn persisted_name(self) -> &'static str {
        match self {
            Self::Pcp => "pcp",
            Self::NatPmp => "natpmp",
            Self::Upnp => "upnp",
        }
    }

    /// The protocol a persisted name refers to, or `None` for a value this
    /// build does not know — which reads as "no learned method" and simply runs
    /// the full race.
    #[must_use]
    pub fn from_persisted_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|protocol| protocol.persisted_name() == name)
    }

    /// Whether this protocol can map in `family` at all, before any gateway is
    /// asked. NAT-PMP and UPnP-IGD1 are IPv4-only by construction, so a
    /// dual-stack desired set asks neither for a pinhole.
    #[must_use]
    pub const fn supports(self, family: AddressFamily) -> bool {
        match (self, family) {
            (Self::Pcp, _) | (Self::NatPmp | Self::Upnp, AddressFamily::V4) => true,
            (Self::NatPmp | Self::Upnp, AddressFamily::V6) => false,
        }
    }

    /// Whether the gateway keys a mapping by its **external** port (ADR-0086,
    /// "Every grant has one owner and one end"). UPnP does
    /// (`DeletePortMapping` names `NewExternalPort`), so a renewal granted on
    /// another external port is a second mapping beside the first. PCP and
    /// NAT-PMP key it by the internal port, so the same answer moved the one
    /// mapping, and a delete naming the old port would remove the new one.
    #[must_use]
    pub const fn keys_by_external_port(self) -> bool {
        matches!(self, Self::Upnp)
    }
}

impl fmt::Display for MappingProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pcp => "PCP",
            Self::NatPmp => "NAT-PMP",
            Self::Upnp => "UPnP-IGD",
        })
    }
}

/// Which transport one mapping covers. Not [`SocketRole`]: a gateway knows
/// only TCP and UDP, and two roles can share one transport.
///
/// [`SocketRole`]: https://docs.rs/rmule-core "core's socket-role vocabulary"
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MappedTransport {
    /// The eD2k peer listener.
    Tcp,
    /// A UDP surface — client UDP or Kad UDP.
    Udp,
}

impl fmt::Display for MappedTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        })
    }
}

/// One mapping asked of a gateway: which socket, in which family, for how
/// long, and which external port we would like.
///
/// Both UDP protocols suggest the internal port as the external port and
/// neither uses PCP's `PREFER_FAILURE` — grading the answer afterwards is what
/// learns what the router *would* give, which a pre-emptive refusal throws
/// away (ADR-0086).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappingRequest {
    /// Which family the mapping is in. On IPv6 a PCP MAP is a firewall
    /// pinhole, not a translation, so the external address is our own GUA.
    pub family: AddressFamily,
    /// TCP or UDP.
    pub transport: MappedTransport,
    /// The port rmule actually bound — the number the hello advertises.
    pub internal_port: u16,
    /// The external port to suggest; the internal port on a first map, the
    /// port the gateway granted on a renewal.
    pub suggested_external_port: u16,
    /// The lifetime to ask for. The gateway answers with what it granted,
    /// which the caller clamps.
    pub lease: Duration,
}

/// A request to **pin a punched path** on the router (ADR-0091): PCP `PEER`
/// (RFC 6887 §12) for the five-tuple a successful punch is using.
///
/// A punch opens an *implicit* mapping, and an implicit mapping lives exactly
/// as long as the router's UDP idle timer says — often 30 s, sometimes less.
/// `PEER` turns it into one with a lease the router agreed to, so a Tunnel
/// that goes quiet for a minute is still there when it speaks again. It is a
/// repair the router can make and rmule cannot: a keepalive only ever
/// *hopes* it beat the timer.
///
/// IPv4 and UDP by construction — NAT traversal is both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerPinRequest {
    /// The bound client-UDP port the punch left from.
    pub internal_port: u16,
    /// The external port the path is known to use, when one is — the port a
    /// mapping grant or the peer's view reported. Suggested, not demanded.
    pub suggested_external_port: Option<u16>,
    /// The punched peer, as our router sees it.
    pub remote: std::net::SocketAddrV4,
    /// The lifetime to ask for.
    pub lease: Duration,
}

/// What a state-free probe learned about one gateway, before any mapping is
/// requested.
///
/// A probe is deliberately cheap and stateless — PCP sends `ANNOUNCE`,
/// NAT-PMP the external-address request, UPnP SSDP plus
/// `GetExternalIPAddress` — so the race can run every backend at once without
/// leaving state on a router that loses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeReport {
    /// The address the gateway calls ours, when it says. A private address
    /// here means the gateway itself is behind a second NAT; core grades that
    /// rather than this seam.
    pub external_address: Option<IpAddr>,
    /// The families this backend can map through *this* gateway. A device
    /// that advertises IPv6 support and then refuses pinholes reports IPv4
    /// alone — "plenty of devices advertise it and then refuse".
    pub families: Vec<AddressFamily>,
    /// The gateway's epoch verdict, when the protocol carries one. A probe
    /// that already sees a reset saves core a mapping round.
    pub epoch: EpochVerdict,
}

/// What a gateway granted for one [`MappingRequest`].
///
/// The **granted** port is the whole point: it is what core grades against the
/// internal port, and a grant on a different external port is a silent LowID
/// on eD2k rather than a success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappingGrant {
    /// Where the outside world now reaches the mapped socket — the external
    /// address the gateway reported joined to the external port it granted.
    pub external: PeerEndpoint,
    /// The lifetime the gateway actually returned, unclamped. `None` means a
    /// permanent mapping (IGD1's `PortMappingLeaseDuration` of 0), which has
    /// no expiry to renew against and is re-verified by a slow poll instead.
    pub lease: Option<Duration>,
    /// What the gateway's epoch said about its own uptime on this response.
    pub epoch: EpochVerdict,
}

/// What one release did on the gateway (ADR-0086, "A release takes down only
/// rmule's own mapping"). It says whether a delete went out, never whether the
/// gateway obeyed it: a release is fire-and-forget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseOutcome {
    /// The delete went out. PCP and NAT-PMP always send it, since their gateway
    /// keys a mapping by the requesting host's own address and the delete can
    /// name no other host's; UPnP sends it only after the gateway's entry for
    /// the external port named this host's internal address and port.
    Sent,
    /// No delete went out, and why.
    Kept(ReleaseKept),
}

/// Why a UPnP release sent no `DeletePortMapping`: the gateway's entry for the
/// external port did not name this host's internal address and port. A UPnP
/// delete names no internal client, so it would take down whoever holds the
/// port now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseKept {
    /// The gateway holds no entry on that port (`NoSuchEntryInArray`, 714):
    /// there is nothing to take down.
    Absent,
    /// The entry forwards to this internal endpoint: another LAN host's, or
    /// another of this host's ports.
    ForwardsElsewhere(PeerEndpoint),
    /// The gateway did not say whom the entry forwards to. Unknown is not
    /// ours, and the lease is the cleanup.
    Unchecked(MappingError),
}

/// Why a gateway did not do what was asked.
///
/// The distinction that matters to core is [`Unsupported`] (this protocol is
/// not there — stop asking, the race has three) against a refusal that carries
/// its own hold-off, which the RFCs make attacker-controlled input and the
/// caller must clamp.
///
/// [`Unsupported`]: Self::Unsupported
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MappingError {
    /// Nothing answered, or what answered does not speak this protocol. The
    /// cross-protocol handshake makes this detectable rather than a timeout:
    /// byte 0 of a reply is the highest version the box supports, so a
    /// NAT-PMP-only gateway answers a PCP packet with `0`.
    #[error("{0} is not available on this gateway")]
    Unsupported(MappingProtocol),
    /// The gateway answered and refused. `hold_off` is the RFC 6887 §7.4
    /// "do not repeat this request for this long" estimate when the protocol
    /// carried one — **unclamped**, exactly as it arrived on the wire; the
    /// caller clamps it, because an unclamped `0xFFFFFFFF` would disable port
    /// mapping for 136 years.
    #[error("{protocol} refused: {refusal}")]
    Refused {
        /// Which protocol refused.
        protocol: MappingProtocol,
        /// Why, as a code.
        refusal: MappingRefusal,
        /// The hold-off the gateway asked for, raw.
        hold_off: Option<Duration>,
    },
    /// The retransmit ladder ran out without an answer.
    #[error("{0} timed out")]
    Timeout(MappingProtocol),
    /// A socket or codec fault below the protocol — the layer where an ICMP
    /// port-unreachable on a connected socket surfaces.
    #[error("{protocol} transport error: {fault}")]
    Transport {
        /// Which protocol was being spoken.
        protocol: MappingProtocol,
        /// What failed, as a code.
        fault: MappingTransportFault,
    },
}

impl MappingError {
    /// The protocol that produced this error.
    #[must_use]
    pub const fn protocol(&self) -> MappingProtocol {
        match self {
            Self::Unsupported(protocol) | Self::Timeout(protocol) => *protocol,
            Self::Refused { protocol, .. } | Self::Transport { protocol, .. } => *protocol,
        }
    }

    /// The hold-off the gateway asked for, if any.
    #[must_use]
    pub const fn hold_off(&self) -> Option<Duration> {
        match self {
            Self::Refused { hold_off, .. } => *hold_off,
            _ => None,
        }
    }
}

/// One port-mapping protocol as core's **Port Mapper** uses it: probe, map,
/// release (ADR-0086).
///
/// There is no `renew`: a renewal *is* a map that suggests the port the
/// gateway already granted, which is what both crates do internally and what
/// the RFCs describe. Modelling it separately would let the two paths drift
/// while pretending they are different questions.
///
/// Every method takes the [`Gateway`] rather than holding one, so a backend is
/// a stateless speaker of its protocol and the racer can point the same
/// instance at a second gateway on a renumber. The one exception is the epoch
/// tracker a backend keeps per gateway — state about a *counterparty*, which
/// belongs with the speaker.
pub trait MappingBackend: Send + Sync + fmt::Debug {
    /// Which protocol this backend speaks.
    fn protocol(&self) -> MappingProtocol;

    /// Ask `gateway`, statelessly, whether it speaks this protocol and what it
    /// would map. Leaves nothing behind on the router, so every enabled
    /// backend can probe at once.
    fn probe(
        self: Arc<Self>,
        gateway: Gateway,
    ) -> MappingFuture<'static, Result<ProbeReport, MappingError>>;

    /// Request one mapping, or renew one by suggesting the port already
    /// granted.
    fn map(
        self: Arc<Self>,
        gateway: Gateway,
        request: MappingRequest,
    ) -> MappingFuture<'static, Result<MappingGrant, MappingError>>;

    /// Withdraw this host's own mapping, and never another host's (ADR-0086,
    /// "A release takes down only rmule's own mapping"). Fire-and-forget by
    /// design: at least one firmware never acknowledges a PCP delete, and the
    /// finite lease is the real cleanup — so a caller that waited for
    /// confirmation would hang on exit for nothing. The outcome says whether
    /// a delete went out, and why not when none did.
    fn release(
        self: Arc<Self>,
        gateway: Gateway,
        request: MappingRequest,
        external_port: u16,
    ) -> MappingFuture<'static, ReleaseOutcome>;

    /// Pin a punched path (see [`PeerPinRequest`]). Only PCP can express it —
    /// NAT-PMP and UPnP have no notion of a remote peer — so the default says
    /// so, and a caller treats [`MappingError::Unsupported`] as the ordinary
    /// answer it is: the keepalive carries the path alone.
    fn pin_peer(
        self: Arc<Self>,
        _gateway: Gateway,
        _request: PeerPinRequest,
    ) -> MappingFuture<'static, Result<MappingGrant, MappingError>> {
        let protocol = self.protocol();
        Box::pin(async move { Err(MappingError::Unsupported(protocol)) })
    }
}

/// The three live **Mapping Backends** (ADR-0086), ready to install.
///
/// Handed out as a set rather than built inside `rmule-core` because talking to
/// the operator's router is a deployment decision, not a library one: a core
/// built for a test, a tool or a harness must be able to hold none of these and
/// map nothing, exactly as it holds no HTTP client without one being injected.
/// A front end that owns the deployment installs them, and the
/// `port_mapping = auto` default then does the rest.
///
/// `secret` is the per-install value mixed into the PCP Mapping Nonce (RFC 6887
/// §11.3): the same secret across restarts is what lets rmule renew or delete
/// its own mapping, and a secret a LAN neighbour does not hold is what stops
/// them deleting it. `0` is a legitimate value — the nonce is still stable, just
/// guessable.
#[must_use]
pub fn live_backends(secret: u32) -> Vec<Arc<dyn MappingBackend>> {
    vec![
        Arc::new(UdpMappingBackend::pcp().with_secret(secret)),
        Arc::new(UdpMappingBackend::nat_pmp()),
        Arc::new(UpnpMappingBackend::new()),
    ]
}
