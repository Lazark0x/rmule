//! **Address Learning** (ADR-0084): the core-owned, sans-I/O store of *where
//! rmule is* on the wire — the sibling of [`Reachability`](crate::reachability),
//! which keeps *whether rmule can be reached*.
//!
//! One store turns typed [`AddressObservation`]s into one **External Endpoint**
//! verdict per **Address Family** and socket role, by descending confidence
//! tier with per-source freshness. It runs no clock, owns no socket and reads
//! no config: `observe(observation, now)` in, [`EndpointVerdict`] out. The
//! clock lives at the edge, on [`SharedAddressLearning`], exactly as the Kad
//! driver maps real time onto the sans-I/O node's explicit scale.
//!
//! **A peer's claim about our address is a vote, never adopted on its own.**
//! Two independent controls enforce that, and they are not the same control:
//!
//! - the **ladder** decides which source outranks which, so two Kad strangers
//!   can never outvote the server that assigned our High-ID;
//! - the **local-interface corroboration filter** decides whether a reflected
//!   IPv6 address may be adopted at all — only an address this host actually
//!   holds can be adopted, so corroboration only ever picks *which of our own*
//!   addresses the outside world sees. It is the security control, and it is
//!   why a hostile peer cannot make rmule advertise someone else's address.
//!
//! Addresses are keyed by family and ports by role, because that is how they
//! are observed: a server High-ID and a Kad `0x58` name an address and no
//! port, a Kad `0x61` names a port and no address, and one port pair serves
//! both families (the IPv6 dialect's rule). A verdict joins the two.
//!
//! Disagreement is a fact, not an error: when two fresh tiers disagree the
//! higher one wins and the disagreement surfaces as a [`NatHint`], never
//! silently overwritten.
//!
//! This file is the **vocabulary** — the types every feeder and reader names.
//! [`store`] holds the store itself and the shared handle, [`ladder`] the
//! per-tier rules one ladder applies, [`admissible`] the single definition of
//! an address the outside world can route to, and [`advertised`] the one
//! chooser that turns a verdict plus a reachability verdict into what rmule
//! actually claims.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use rmule_primitives::{AddressFamily, PeerEndpoint};

mod admissible;
mod advertised;
mod ladder;
mod store;
#[cfg(test)]
mod tests;

pub(crate) use advertised::{AdvertReachability, AdvertisedEndpoints};
pub(crate) use store::{AddressLearning, SharedAddressLearning};

/// Fold a peer's `CT_MOD_YOUR_IP` reflection into the store as one **peer
/// vote** (ADR-0084/0087).
///
/// A peer telling us our own address is a *vote*, never an adoption: the
/// quorum needs three distinct observers inside its window, and the store's
/// locally-assigned filter is what stops any number of them making us
/// advertise an address we do not hold. The vote is keyed on the address we
/// *observed* the peer at, never on the hash it claims — a hash costs nothing
/// to invent, an address costs a socket.
///
/// Only the hash form of the tag ever reaches here: the integer form names an
/// IPv4 and is refused at the tag reader, because one unverified peer deciding
/// our public IPv4 would decide whether we believe we are firewalled.
pub(crate) fn record_peer_ipv6_vote(
    addresses: &SharedAddressLearning,
    peer: rmule_primitives::PeerEndpoint,
    identity: &rmule_peer::PeerIdentity,
) {
    let Some(reflected) = identity.reflected_ipv6() else {
        return;
    };
    addresses.observe(AddressObservation::peer_vote(
        peer.ip(),
        std::net::IpAddr::V6(reflected),
    ));
}

/// Which of rmule's own sockets an observation speaks about (ADR-0084). Every
/// role binds one **Family Pair**, so a role has one port and up to two
/// addresses.
///
/// There are two roles because rmule binds two sockets that anyone sends *to*:
/// the eD2k listener and the one UDP socket. Kad had a role of its own until
/// the sockets unified (ADR-0057): it bound a second UDP port, so a Kad `0x58`
/// and a server `0x9F` were observations about two different mappings and
/// could not corroborate each other. They now name one bind, so a Kad observed
/// port, a server observation and a router's grant are votes on **one External
/// Endpoint** — which is what lets a buddy's view of us be the view a NAT-T
/// punch has to reach. The server-UDP socket is deliberately absent: it only
/// ever answers datagrams we sent, so nobody addresses it and nothing maps it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SocketRole {
    /// The eD2k peer listener — the port a hello, a login and a `0x95`
    /// advertise.
    Tcp,
    /// The one client-UDP port: peer reasks, server status pings, the direct
    /// callback, the NAT-T transport frames and the Kad node all ride it
    /// (ADR-0057).
    Udp,
}

impl SocketRole {
    /// Every role, in ladder-report order — the order diagnostics rows and the
    /// **Advertised Endpoints** chooser walk.
    pub(crate) const ALL: [Self; 2] = [Self::Tcp, Self::Udp];

    /// The same socket as `rmule-net` names it when stating what a
    /// **Half-Bound Pair** costs. The bind table keys on this
    /// enum — the roles whose external endpoint is learned — while the
    /// consequence table keys on every role rmule binds a pair for,
    /// server-UDP included; the two meet here and nowhere else.
    pub(crate) const fn pair_role(self) -> rmule_net::family::PairRole {
        match self {
            Self::Tcp => rmule_net::family::PairRole::Ed2kListener,
            Self::Udp => rmule_net::family::PairRole::ClientUdp,
        }
    }
}

impl std::fmt::Display for SocketRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        })
    }
}

/// A source's confidence grade — its rung on a family's ladder (ADR-0084).
/// The grade is payload-free so a verdict can name the tier that produced it
/// without carrying that source's identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConfidenceTier {
    /// The operator said so. Never expires, outranks everything.
    Override,
    /// The connected server: the `OP_IDCHANGE` High-ID for IPv4, a
    /// `CT_MOD_YOUR_IP` reflection on an IPv6 session for IPv6. It is
    /// literally the address peers dial, and it lives as long as the session.
    /// A Low ID never reaches this tier — see [`LowIdReport`](Self::LowIdReport).
    Server,
    /// The Kad self-check: the `0x58` observed IP and the `0x61` observed UDP
    /// port. Holds only on two consecutive agreeing reports from distinct
    /// observers.
    KadCheck,
    /// A peer's `CT_MOD_YOUR_IP` vote in a hello, keyed on the observer's own
    /// address. IPv6 only, and only for an address this host holds.
    PeerVote,
    /// The external address and port a PCP / NAT-PMP / UPnP-IGD lease
    /// returned. Lives as long as the lease.
    MappingGrant,
    /// The address a server's `OP_IDCHANGE` reports for us with a **Low ID**
    /// (ADR-0084). A Low ID is the server
    /// saying it could not reach us there, so this is the weakest reflection:
    /// IPv4 only, below the mapping grant, session-lived like `Server`.
    LowIdReport,
    /// A global-unicast address on a local interface — the no-NAT case, and
    /// the corroboration filter's evidence.
    Interface,
}

impl ConfidenceTier {
    /// This tier's height on `family`'s **address** ladder, lower is stronger,
    /// or `None` when the tier is not a source of addresses in that family.
    ///
    /// IPv4 refuses [`PeerVote`](Self::PeerVote) outright: `CT_MOD_YOUR_IP`'s
    /// integer form lets one unverified peer decide what a client believes its
    /// own address to be — and a client wrong about its own address is wrong
    /// about whether it is firewalled. rmule follows emule-qt and aMule, not
    /// eMuleAI. IPv6 has no Kad and takes no address from a pinhole grant, so
    /// both are absent there.
    const fn address_rank(self, family: AddressFamily) -> Option<u8> {
        match (family, self) {
            (_, Self::Override) => Some(0),
            (_, Self::Server) => Some(1),
            (AddressFamily::V4, Self::KadCheck) => Some(2),
            (AddressFamily::V4, Self::MappingGrant) => Some(3),
            (AddressFamily::V4, Self::LowIdReport) => Some(4),
            (AddressFamily::V4, Self::Interface) => Some(5),
            (AddressFamily::V6, Self::PeerVote) => Some(2),
            (AddressFamily::V6, Self::Interface) => Some(3),
            (AddressFamily::V4, Self::PeerVote)
            | (AddressFamily::V6, Self::KadCheck | Self::MappingGrant | Self::LowIdReport) => None,
        }
    }

    /// This tier's height on the **port** ladder, lower is stronger, or `None`
    /// when the tier observes no port.
    ///
    /// One ladder serves both families: one port pair applies to both, so a
    /// role's port is learned once. Every port-observing source is an IPv4
    /// surface today (`0x61`, a mapping grant), which is why the order is the
    /// IPv4 ladder's.
    const fn port_rank(self) -> Option<u8> {
        match self {
            Self::Override => Some(0),
            Self::Server => Some(1),
            Self::KadCheck => Some(2),
            Self::MappingGrant => Some(3),
            Self::PeerVote | Self::LowIdReport | Self::Interface => None,
        }
    }
}

/// Where one observation came from, carrying the identity that source's rule
/// needs — and nothing else. The observer is always an *address*: a user hash
/// costs nothing to invent, so no quorum is ever keyed on one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationSource {
    /// The operator's configured external address.
    Override,
    /// The connected server.
    Server,
    /// The connected server, reporting our address alongside a Low ID.
    LowIdReport,
    /// A Kad node answering our own firewall self-check.
    KadCheck {
        /// The node that reported — the two-agree rule's key.
        observer: IpAddr,
    },
    /// A peer reflecting our address back in its hello.
    PeerVote {
        /// The peer's own source address — the quorum's key.
        observer: IpAddr,
    },
    /// A port-mapping lease.
    MappingGrant {
        /// How long the router said the mapping lives.
        lease: Duration,
    },
}

impl ObservationSource {
    /// The confidence grade this source carries.
    const fn tier(self) -> ConfidenceTier {
        match self {
            Self::Override => ConfidenceTier::Override,
            Self::Server => ConfidenceTier::Server,
            Self::LowIdReport => ConfidenceTier::LowIdReport,
            Self::KadCheck { .. } => ConfidenceTier::KadCheck,
            Self::PeerVote { .. } => ConfidenceTier::PeerVote,
            Self::MappingGrant { .. } => ConfidenceTier::MappingGrant,
        }
    }

    const fn observer(self) -> Option<IpAddr> {
        match self {
            Self::KadCheck { observer } | Self::PeerVote { observer } => Some(observer),
            Self::Override | Self::Server | Self::LowIdReport | Self::MappingGrant { .. } => None,
        }
    }

    const fn lease(self) -> Option<Duration> {
        match self {
            Self::MappingGrant { lease } => Some(lease),
            _ => None,
        }
    }

    /// Whether this source is the outside world telling us our own address —
    /// the claims the corroboration filter governs.
    const fn is_reflection(self) -> bool {
        matches!(
            self,
            Self::Server | Self::LowIdReport | Self::KadCheck { .. } | Self::PeerVote { .. }
        )
    }
}

/// One fact about our own address or port, from one source — the only input
/// to the store.
///
/// The three shapes are what the wire actually observes: a server High-ID and
/// a Kad `0x58` name an address, a Kad `0x61` names a port, and a mapping
/// grant or an override names both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressObservation {
    /// Our external address in the family the address itself names.
    Address {
        /// Who observed it.
        source: ObservationSource,
        /// The address observed.
        address: IpAddr,
    },
    /// The external port one of our sockets is reached at.
    Port {
        /// Who observed it.
        source: ObservationSource,
        /// Which socket it is the port of.
        role: SocketRole,
        /// The port observed.
        port: u16,
    },
    /// Address and port together, for one socket.
    Endpoint {
        /// Who observed it.
        source: ObservationSource,
        /// Which socket it is the endpoint of.
        role: SocketRole,
        /// The endpoint observed.
        endpoint: PeerEndpoint,
    },
}

impl AddressObservation {
    /// The public IPv4 the connected server assigned us (`OP_IDCHANGE`
    /// High-ID) — literally the address peers dial.
    #[must_use]
    pub fn server_high_id(address: Ipv4Addr) -> Self {
        Self::Address {
            source: ObservationSource::Server,
            address: IpAddr::V4(address),
        }
    }

    /// The address a Low-ID `OP_IDCHANGE` reports for us — a
    /// [`LowIdReport`](ConfidenceTier::LowIdReport), never the High-ID tier.
    #[must_use]
    pub fn low_id_report(address: Ipv4Addr) -> Self {
        Self::Address {
            source: ObservationSource::LowIdReport,
            address: IpAddr::V4(address),
        }
    }

    /// The address the connected server reflected back at us — the
    /// `CT_MOD_YOUR_IP` tag of `OP_SERVERIDENT` on an IPv6-connected session
    /// (ADR-0087 lands the reader).
    #[must_use]
    pub const fn server_reflection(address: IpAddr) -> Self {
        Self::Address {
            source: ObservationSource::Server,
            address,
        }
    }

    /// A Kad `0x58` firewall response's observed IP, from the node that
    /// answered our own check.
    #[must_use]
    pub const fn kad_observed_address(observer: Ipv4Addr, address: Ipv4Addr) -> Self {
        Self::Address {
            source: ObservationSource::KadCheck {
                observer: IpAddr::V4(observer),
            },
            address: IpAddr::V4(address),
        }
    }

    /// A Kad `0x61` pong's observed source port — how a node learns the Kad
    /// UDP port a NAT maps it to.
    #[must_use]
    pub const fn kad_observed_port(observer: Ipv4Addr, port: u16) -> Self {
        Self::Port {
            source: ObservationSource::KadCheck {
                observer: IpAddr::V4(observer),
            },
            role: SocketRole::Udp,
            port,
        }
    }

    /// A peer's `CT_MOD_YOUR_IP` vote in its hello, keyed on the address the
    /// hello arrived from (ADR-0087 lands the reader).
    #[must_use]
    pub const fn peer_vote(observer: IpAddr, address: IpAddr) -> Self {
        Self::Address {
            source: ObservationSource::PeerVote { observer },
            address,
        }
    }

    /// The external endpoint a PCP / NAT-PMP / UPnP-IGD lease granted for one
    /// socket — **the seam port mapping enters by** (ADR-0086).
    #[must_use]
    pub const fn mapping_grant(role: SocketRole, endpoint: PeerEndpoint, lease: Duration) -> Self {
        Self::Endpoint {
            source: ObservationSource::MappingGrant { lease },
            role,
            endpoint,
        }
    }

    const fn source(self) -> ObservationSource {
        match self {
            Self::Address { source, .. }
            | Self::Port { source, .. }
            | Self::Endpoint { source, .. } => source,
        }
    }
}

/// The operator's external-address override, per **Address Family**
/// (ADR-0084). Configured, never learned; outranks every observation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExternalAddressOverride {
    /// The external IPv4 to use regardless of what any source reports.
    pub v4: Option<Ipv4Addr>,
    /// The external IPv6 to use regardless of what any source reports. Not
    /// subject to the corroboration filter: an operator stating an address is
    /// not a stranger claiming one.
    pub v6: Option<Ipv6Addr>,
}

/// What the store currently knows about one socket's **External Endpoint**.
///
/// Adverts, hello tags, login tags and Kad publish require [`Known`]; the UDP
/// crypt keys may use [`Stale`], so a server reconnect never blanks the key
/// mid-reask (ADR-0046's `public_ip_known` gate).
///
/// [`Known`]: Self::Known
/// [`Stale`]: Self::Stale
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointVerdict {
    /// A fresh tier holds.
    Known {
        /// Where the outside world reaches this socket.
        endpoint: PeerEndpoint,
        /// The tier that produced the address.
        tier: ConfidenceTier,
    },
    /// Every source has aged out, but a last-known value exists.
    Stale {
        /// The last endpoint any tier held.
        endpoint: PeerEndpoint,
        /// When that holding lapsed.
        since: Instant,
    },
    /// Nothing has ever been learned.
    Unknown,
}

impl EndpointVerdict {
    /// The endpoint only while a fresh tier holds it — what every advert
    /// reads.
    #[must_use]
    pub const fn known(self) -> Option<PeerEndpoint> {
        match self {
            Self::Known { endpoint, .. } => Some(endpoint),
            Self::Stale { .. } | Self::Unknown => None,
        }
    }

    /// The tier that produced a fresh verdict.
    #[must_use]
    pub const fn tier(self) -> Option<ConfidenceTier> {
        match self {
            Self::Known { tier, .. } => Some(tier),
            Self::Stale { .. } | Self::Unknown => None,
        }
    }
}

/// A diagnostics-level fact that our sources do not agree about where we are
/// — the trace of a NAT rmule cannot see directly (ADR-0084). Published,
/// never resolved by overwriting: the higher tier still wins the verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatHint {
    /// Two fresh tiers hold different addresses for the same family.
    Disagreement {
        /// The tier the verdict took.
        adopted_tier: ConfidenceTier,
        /// The address the verdict took.
        adopted: IpAddr,
        /// The tier that disagreed.
        dissenting_tier: ConfidenceTier,
        /// The address it reported instead.
        dissenting: IpAddr,
    },
    /// A port-mapping grant returned an external address that is itself
    /// private: the gateway rmule mapped sits behind a second NAT, so no
    /// mapping on it can make this node reachable.
    DoubleNat {
        /// The unroutable address the gateway called external.
        granted: IpAddr,
    },
    /// A port-mapping grant returned a carrier-grade NAT address
    /// (`100.64/10`, RFC 6598): the ISP, not the router, holds the public
    /// address, and no port mapping reaches past it.
    CarrierGradeNat {
        /// The address the gateway called external.
        granted: IpAddr,
    },
    /// A reflection reported an address this host holds locally and the
    /// outside world cannot route — the reply never left the NAT, so the
    /// observer is inside it.
    Hairpin {
        /// The address the observer claimed to see.
        reflected: IpAddr,
        /// Which tier reflected it.
        tier: ConfidenceTier,
    },
}

/// What the store did with one observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationOutcome {
    /// Remembered; it may or may not be enough for its tier to hold.
    Recorded,
    /// Refused: a peer's vote about an IPv4 address is not a source. One
    /// unverified peer must never decide what this client believes its own
    /// address to be (ADR-0084, following emule-qt and aMule over eMuleAI).
    Ipv4PeerVoteRefused,
    /// Refused: the address is not one the outside world can route, so it
    /// cannot be anybody's External Endpoint. A [`NatHint`] usually records
    /// what it was instead.
    NotPubliclyUsable,
    /// Refused: a peer voted for an IPv6 address this host does not hold.
    /// The corroboration filter would drop it at every read anyway, so it is
    /// never remembered — a remembered one would take a slot an honest vote
    /// needs and outrank that vote in the quorum count (kno's
    /// `PublicIPv6Corroboration.h` keeps no state for an unheld value).
    UnheldPeerVoteRefused,
    /// Refused: the observation named port `0`, which is no port (ADR-0084).
    /// Recorded, it would count as a dissenting observer in the Own Mapping.
    PortZeroRefused,
}

/// What one `OP_IDCHANGE` established as our public IPv4, as the store took it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssignedAddress {
    /// Ours: the address a High ID is, or the server's report beside a Low
    /// one.
    Ours(Ipv4Addr),
    /// Neither the id nor a report names one.
    Unnamed,
    /// A Low ID's report named the server's own address, which the store
    /// refuses as ours (ADR-0084): a server is never us. The value is the
    /// server's address.
    ServerOwnRefused(Ipv4Addr),
}
