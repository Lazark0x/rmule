//! The **Source Sighting**: one channel's statement that a peer has a file — a
//! server answer, a source exchange, a link or a Kad source row — and the one
//! road it names, with whatever the channel carried beside it. A download takes
//! every source through this one value, so no channel keeps a copy of its own.
//!
//! What a row says is a **Source Claim**; a sighting is a claim and the
//! [`Informant`] who stated it. A wire reader that cannot know who sent the
//! bytes yields claims, and the reader that knows the sender makes each a
//! sighting by naming it (ADR-0085), so no sighting exists without one.

use super::{PeerSource, SourceCryptOptions};
use crate::{ClientId, Informant, Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint, UserHash};

/// How a sighted source is reached: exactly one road, the one the channel that
/// named it proved. A Kad row's two callback roads are unconstructible from an
/// eD2k record, and an eD2k record names no buddy, so the road says which
/// channel's rules the rest of the sighting is read by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceRoad {
    /// An eD2k source record — a High ID, a Low ID or a **Sentinel Source**'s
    /// IPv6 — as a server answer, a source exchange, a link or a direct Kad row
    /// (type 1/4, or one rescued to its `ip6`) names it.
    Record(PeerSource),
    /// A firewalled Kad publisher behind its serving buddy (a type-3/5 row):
    /// its buddy relays a callback (ADR-0061).
    Buddy {
        /// The serving buddy the row named.
        buddy: SightedBuddy,
        /// The publisher's Kad UDP endpoint as the storer observed it — the one
        /// value on the row that tells two firewalled publishers apart.
        kad_udp: Ipv4Endpoint,
        /// The published eD2k TCP port.
        tcp_port: u16,
    },
    /// A firewalled Kad publisher that takes a `0x95` **Direct UDP Callback** at
    /// its own Kad UDP endpoint (a type-6 row: bit 3 stated, the endpoint
    /// observed).
    DirectUdpCallback {
        /// Where the `0x95` goes: the storer's observation of the publisher.
        kad_udp: Ipv4Endpoint,
        /// The published eD2k TCP port.
        tcp_port: u16,
    },
}

/// A Kad publisher's serving buddy, as its source row names it.
///
/// The ID travels as its sixteen wire-order bytes: this crate sits below the Kad
/// crate, whose `KadId` they are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SightedBuddy {
    /// The buddy relationship ID (`~publisherKadID`), in Kad wire order.
    pub buddy_id: [u8; 16],
    /// The buddy's UDP endpoint, when the row named a usable one; without it a
    /// walk toward [`Self::buddy_id`] is the only way to the buddy.
    pub buddy_udp: Option<Ipv4Endpoint>,
}

/// What one channel's row says about a source: its road, and the optional
/// crypt material the channel carried (ADR-0042). A v1 source exchange or a plain
/// server answer carries neither; exchange version ≥ 2 adds the target's
/// [`UserHash`], version 4 a [`SourceCryptOptions`] byte; a Kad row carries its
/// publisher's User Hash and its `TAG_ENCRYPTION` connect-options byte. rmule
/// needs the target's User Hash **before dialing** to derive the peer
/// obfuscation key, so it can only obfuscate-dial a source that carried one.
///
/// A channel that can name both families — an ExtSX record, a serve client
/// whose hello named its IPv6, a Kad row's `ip6` — gives a source its **IPv6
/// Half** (ADR-0087): one source with two addresses, never two sources, because
/// both are the same peer and which one gets dialed is the Dial Chooser's call.
///
/// A claim names nobody as having said it: [`Self::stated_by`] makes it the
/// [`SourceSighting`] a download takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceClaim {
    road: SourceRoad,
    user_hash: Option<UserHash>,
    crypt_options: Option<SourceCryptOptions>,
    ipv6_half: Option<Ipv6Endpoint>,
    server: Option<Ipv4Endpoint>,
}

impl SourceClaim {
    /// An eD2k source record with whatever crypt material its channel carried.
    #[must_use]
    pub const fn new(
        source: PeerSource,
        user_hash: Option<UserHash>,
        crypt_options: Option<SourceCryptOptions>,
    ) -> Self {
        Self::by_road(SourceRoad::Record(source), user_hash, crypt_options)
    }

    /// A source on any road, with whatever crypt material its channel carried —
    /// for a Kad row, its connect-options byte.
    #[must_use]
    pub const fn by_road(
        road: SourceRoad,
        user_hash: Option<UserHash>,
        crypt_options: Option<SourceCryptOptions>,
    ) -> Self {
        Self {
            road,
            user_hash,
            crypt_options,
            ipv6_half: None,
            server: None,
        }
    }

    /// This claim as `informant`'s word: the **Source Sighting** a download
    /// takes, judged against whoever stated it (ADR-0085).
    #[must_use]
    pub const fn stated_by(self, informant: Informant) -> SourceSighting {
        SourceSighting {
            claim: self,
            informant,
        }
    }

    /// The same source with its **IPv6 Half**: the IPv6 endpoint it is also
    /// reachable at beside its road. An IPv6-only record *is* its IPv6, so for
    /// one this is a no-op and [`Self::ipv6`] keeps reading one address, not
    /// two.
    #[must_use]
    pub const fn with_ipv6_half(mut self, ipv6: Option<Ipv6Endpoint>) -> Self {
        if !matches!(self.road, SourceRoad::Record(PeerSource::Ipv6(_))) {
            self.ipv6_half = ipv6;
        }
        self
    }

    /// The same source with the server its row names it logged into — a
    /// source-exchange row's `[srvIP4][srvPort2]`, one per row (aMule
    /// `CPartFile::AddClientSources`). A Low ID means something only together
    /// with the server that assigned it, so this is the namespace it is read
    /// in. A channel that names no server per row leaves `None`.
    #[must_use]
    pub const fn with_server(mut self, server: Option<Ipv4Endpoint>) -> Self {
        self.server = server;
        self
    }

    /// The same claim on another eD2k record, keeping what the channel
    /// carried — the shape an address judged at ingest leaves behind. A record
    /// that is an IPv6 address drops the half, which it now is.
    #[must_use]
    pub const fn with_record(mut self, source: PeerSource) -> Self {
        self.road = SourceRoad::Record(source);
        if matches!(source, PeerSource::Ipv6(_)) {
            self.ipv6_half = None;
        }
        self
    }

    /// A record with no crypt material — a v1 source-exchange entry or a
    /// server-lookup source, which can only ever be dialed plaintext.
    #[must_use]
    pub const fn plain(source: PeerSource) -> Self {
        Self::new(source, None, None)
    }

    /// The road the channel named.
    #[must_use]
    pub const fn road(self) -> SourceRoad {
        self.road
    }

    /// The server the row names its source logged into, when its channel
    /// names one per row ([`Self::with_server`]).
    #[must_use]
    pub const fn server(self) -> Option<Ipv4Endpoint> {
        self.server
    }

    /// The eD2k source record underneath, or `None` for a Kad row reachable
    /// only by a callback, which has no record form.
    #[must_use]
    pub const fn peer_source(self) -> Option<PeerSource> {
        match self.road {
            SourceRoad::Record(source) => Some(source),
            SourceRoad::Buddy { .. } | SourceRoad::DirectUdpCallback { .. } => None,
        }
    }

    /// The target's user hash, when the channel carried one.
    #[must_use]
    pub const fn user_hash(self) -> Option<UserHash> {
        self.user_hash
    }

    /// The advertised crypt stance, when the channel carried one: a
    /// source-exchange crypt byte, or a Kad row's connect-options byte.
    #[must_use]
    pub const fn crypt_options(self) -> Option<SourceCryptOptions> {
        self.crypt_options
    }

    /// The source's IPv6 endpoint, wherever it is held: the **IPv6 Half**
    /// beside its road, or the address of an IPv6-only record. One accessor, so
    /// no reader has to know which shape the source arrived in.
    #[must_use]
    pub const fn ipv6(self) -> Option<Ipv6Endpoint> {
        match (self.ipv6_half, self.road) {
            (Some(endpoint), _) | (None, SourceRoad::Record(PeerSource::Ipv6(endpoint))) => {
                Some(endpoint)
            }
            _ => None,
        }
    }

    /// The client id an IPv4-network party knows the source by, or `None` for
    /// an IPv6 record or a Kad callback row, which have none.
    #[must_use]
    pub const fn client_id(self) -> Option<ClientId> {
        match self.road {
            SourceRoad::Record(source) => source.client_id(),
            SourceRoad::Buddy { .. } | SourceRoad::DirectUdpCallback { .. } => None,
        }
    }

    /// The Low ID a server callback must name, or `None` for a source that
    /// carries an address of its own or is in no server's namespace (see
    /// [`PeerSource::low_id`]).
    #[must_use]
    pub const fn low_id(self) -> Option<ClientId> {
        match self.road {
            SourceRoad::Record(source) => source.low_id(),
            SourceRoad::Buddy { .. } | SourceRoad::DirectUdpCallback { .. } => None,
        }
    }

    /// The port the source listens on for eD2k TCP.
    #[must_use]
    pub const fn tcp_port(self) -> u16 {
        match self.road {
            SourceRoad::Record(source) => source.tcp_port(),
            SourceRoad::Buddy { tcp_port, .. } | SourceRoad::DirectUdpCallback { tcp_port, .. } => {
                tcp_port
            }
        }
    }

    /// The address to dial, or `None` for a source reachable only by a
    /// callback (see [`PeerSource::as_peer_endpoint`]).
    #[must_use]
    pub const fn as_peer_endpoint(self) -> Option<PeerEndpoint> {
        match self.road {
            SourceRoad::Record(source) => source.as_peer_endpoint(),
            SourceRoad::Buddy { .. } | SourceRoad::DirectUdpCallback { .. } => None,
        }
    }

    /// The Kad UDP endpoint a Kad callback row's publisher was observed at,
    /// or `None` for an eD2k record.
    #[must_use]
    pub const fn kad_udp(self) -> Option<Ipv4Endpoint> {
        match self.road {
            SourceRoad::Record(_) => None,
            SourceRoad::Buddy { kad_udp, .. } | SourceRoad::DirectUdpCallback { kad_udp, .. } => {
                Some(kad_udp)
            }
        }
    }

    /// The serving buddy a type-3/5 Kad row named, or `None` on any other road.
    #[must_use]
    pub const fn buddy(self) -> Option<SightedBuddy> {
        match self.road {
            SourceRoad::Buddy { buddy, .. } => Some(buddy),
            SourceRoad::Record(_) | SourceRoad::DirectUdpCallback { .. } => None,
        }
    }

    /// The endpoint an IP filter judges this claim by: the dialable one
    /// when there is one, else a Kad row's observed publisher address. aMule
    /// filters a Kad row on its `SOURCEIP` before it branches on source type
    /// (`CDownloadQueue::KademliaSearchFile`, `src/DownloadQueue.cpp:1713`), so
    /// a firewalled row is filtered on the same address a direct one is.
    #[must_use]
    pub fn filter_endpoint(self) -> Option<PeerEndpoint> {
        self.as_peer_endpoint()
            .or_else(|| self.kad_udp().map(PeerEndpoint::V4))
    }

    /// The crypt side this claim states — its crypt byte's stance and its
    /// User Hash — which a dial meets with ours by aMule's outbound rule
    /// ([`PeerCrypt::outbound`](crate::PeerCrypt::outbound), ADR-0049).
    #[must_use]
    pub const fn peer_crypt(self) -> crate::PeerCrypt {
        crate::PeerCrypt::from_record(self.crypt_options, self.user_hash)
    }
}

/// One channel's sighting of a source: a [`SourceClaim`] and the [`Informant`]
/// who stated it, which a loopback address is judged against (ADR-0085).
///
/// Every constructor names the informant, and none defaults to rmule's own: a
/// producer that read a source off the network cannot forget to say who sent
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSighting {
    claim: SourceClaim,
    informant: Informant,
}

impl SourceSighting {
    /// An eD2k source record with whatever crypt material its channel
    /// carried, as `informant`'s word.
    #[must_use]
    pub const fn new(
        source: PeerSource,
        user_hash: Option<UserHash>,
        crypt_options: Option<SourceCryptOptions>,
        informant: Informant,
    ) -> Self {
        SourceClaim::new(source, user_hash, crypt_options).stated_by(informant)
    }

    /// A source on any road, as `informant`'s word ([`SourceClaim::by_road`]).
    #[must_use]
    pub const fn by_road(
        road: SourceRoad,
        user_hash: Option<UserHash>,
        crypt_options: Option<SourceCryptOptions>,
        informant: Informant,
    ) -> Self {
        SourceClaim::by_road(road, user_hash, crypt_options).stated_by(informant)
    }

    /// A record with no crypt material, as `informant`'s word
    /// ([`SourceClaim::plain`]).
    #[must_use]
    pub const fn plain(source: PeerSource, informant: Informant) -> Self {
        SourceClaim::plain(source).stated_by(informant)
    }

    /// What the sighting's row said, with nobody named as having said it —
    /// the form a wire writer takes, since no wire carries an informant.
    #[must_use]
    pub const fn claim(self) -> SourceClaim {
        self.claim
    }

    /// Whose word this sighting is.
    #[must_use]
    pub const fn informant(self) -> Informant {
        self.informant
    }

    /// The same sighting with its **IPv6 Half** ([`SourceClaim::with_ipv6_half`]).
    #[must_use]
    pub const fn with_ipv6_half(mut self, ipv6: Option<Ipv6Endpoint>) -> Self {
        self.claim = self.claim.with_ipv6_half(ipv6);
        self
    }

    /// The same sighting with the server its row names it logged into
    /// ([`SourceClaim::with_server`]).
    #[must_use]
    pub const fn with_server(mut self, server: Option<Ipv4Endpoint>) -> Self {
        self.claim = self.claim.with_server(server);
        self
    }

    /// The same sighting on another eD2k record, by the same informant
    /// ([`SourceClaim::with_record`]).
    #[must_use]
    pub const fn with_record(mut self, source: PeerSource) -> Self {
        self.claim = self.claim.with_record(source);
        self
    }

    /// The road the channel named.
    #[must_use]
    pub const fn road(self) -> SourceRoad {
        self.claim.road()
    }

    /// The server the row names its source logged into
    /// ([`SourceClaim::server`]).
    #[must_use]
    pub const fn server(self) -> Option<Ipv4Endpoint> {
        self.claim.server()
    }

    /// The eD2k source record underneath ([`SourceClaim::peer_source`]).
    #[must_use]
    pub const fn peer_source(self) -> Option<PeerSource> {
        self.claim.peer_source()
    }

    /// The target's user hash, when the channel carried one.
    #[must_use]
    pub const fn user_hash(self) -> Option<UserHash> {
        self.claim.user_hash()
    }

    /// The advertised crypt stance, when the channel carried one.
    #[must_use]
    pub const fn crypt_options(self) -> Option<SourceCryptOptions> {
        self.claim.crypt_options()
    }

    /// The source's IPv6 endpoint, wherever it is held ([`SourceClaim::ipv6`]).
    #[must_use]
    pub const fn ipv6(self) -> Option<Ipv6Endpoint> {
        self.claim.ipv6()
    }

    /// The client id an IPv4-network party knows the source by
    /// ([`SourceClaim::client_id`]).
    #[must_use]
    pub const fn client_id(self) -> Option<ClientId> {
        self.claim.client_id()
    }

    /// The Low ID a server callback must name ([`SourceClaim::low_id`]).
    #[must_use]
    pub const fn low_id(self) -> Option<ClientId> {
        self.claim.low_id()
    }

    /// The port the source listens on for eD2k TCP.
    #[must_use]
    pub const fn tcp_port(self) -> u16 {
        self.claim.tcp_port()
    }

    /// The address to dial ([`SourceClaim::as_peer_endpoint`]).
    #[must_use]
    pub const fn as_peer_endpoint(self) -> Option<PeerEndpoint> {
        self.claim.as_peer_endpoint()
    }

    /// The Kad UDP endpoint a Kad callback row's publisher was observed at
    /// ([`SourceClaim::kad_udp`]).
    #[must_use]
    pub const fn kad_udp(self) -> Option<Ipv4Endpoint> {
        self.claim.kad_udp()
    }

    /// The serving buddy a type-3/5 Kad row named ([`SourceClaim::buddy`]).
    #[must_use]
    pub const fn buddy(self) -> Option<SightedBuddy> {
        self.claim.buddy()
    }

    /// The endpoint an IP filter judges this sighting by
    /// ([`SourceClaim::filter_endpoint`]).
    #[must_use]
    pub fn filter_endpoint(self) -> Option<PeerEndpoint> {
        self.claim.filter_endpoint()
    }

    /// The crypt side this sighting states ([`SourceClaim::peer_crypt`]).
    #[must_use]
    pub const fn peer_crypt(self) -> crate::PeerCrypt {
        self.claim.peer_crypt()
    }
}
