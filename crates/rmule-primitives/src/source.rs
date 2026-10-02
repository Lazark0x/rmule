//! Sources for a file: the target a lookup asks about, a source as a server
//! hands it over (High ID, Low ID, or a sentinel-carried IPv6 endpoint), the
//! crypt options a source advertises, and the richer source-exchange form
//! peers trade among themselves.

mod sentinel;

pub use sentinel::SourceListTail;

use crate::{ClientId, CryptStance, FileHash, Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint, UserHash};

/// What a source lookup asks about: a file hash and the size that goes with
/// it.
///
/// The size travels because the protocol's large-file handling depends on it —
/// which request encoding is legal, and which sources are even eligible, both
/// follow from the size, so a hash alone cannot form a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SourceLookupTarget {
    file_hash: FileHash,
    file_size: u64,
}

impl SourceLookupTarget {
    /// A lookup target from the file's hash and size.
    #[must_use]
    pub const fn new(file_hash: FileHash, file_size: u64) -> Self {
        Self {
            file_hash,
            file_size,
        }
    }

    /// The file being looked up.
    #[must_use]
    pub const fn file_hash(self) -> FileHash {
        self.file_hash
    }

    /// Its size in bytes.
    #[must_use]
    pub const fn file_size(self) -> u64 {
        self.file_size
    }
}

/// A source as a server hands it over — the three things a source record can
/// name (ADR-0085): a High ID, which *is* an IPv4 address; a Low ID, which is
/// an opaque number a callback must broker; or — behind the record's
/// `0xFFFFFFFF` **Sentinel Source** id — an IPv6 endpoint. Whether a source is
/// dialable follows from the variant, never from a separate field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PeerSource {
    /// A directly dialable IPv4 source: the High ID unpacked into its address,
    /// with the record's TCP port.
    HighId(Ipv4Endpoint),
    /// A source reachable only by callback through its server.
    LowId {
        /// The server-assigned Low ID, unique per server.
        id: ClientId,
        /// The port the record carried — meaningless for a callback.
        port: u16,
    },
    /// An IPv6 source, read from the address its sentinel record carries
    /// inline as its last field.
    Ipv6(Ipv6Endpoint),
}

impl PeerSource {
    /// The 32-bit id field value that marks an IPv6 sentinel record
    /// (`IPV6_SOURCE_SENTINEL`); never a real High ID.
    pub const IPV6_SENTINEL: u32 = 0xFFFF_FFFF;

    /// Classify a classic record's id and port: a High ID becomes the IPv4
    /// endpoint it packs, anything below the Low-ID ceiling stays a Low ID.
    /// The sentinel is not an id this can classify: a wire reader goes through
    /// [`Self::from_record`], which refuses it, and builds [`Self::Ipv6`] from
    /// the record's inline address instead.
    #[must_use]
    pub const fn new(client_id: ClientId, tcp_port: u16) -> Self {
        if client_id.is_high_id() {
            let octets = client_id.as_u32().to_le_bytes();
            Self::HighId(Ipv4Endpoint::new(
                std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]),
                tcp_port,
            ))
        } else {
            Self::LowId {
                id: client_id,
                port: tcp_port,
            }
        }
    }

    /// The 32-bit id field exactly as the record carries it: the packed High
    /// ID, the Low ID, or the IPv6 sentinel. The encoder's view.
    #[must_use]
    pub const fn wire_id(self) -> u32 {
        match self {
            Self::HighId(endpoint) => u32::from_le_bytes(endpoint.ip.octets()),
            Self::LowId { id, .. } => id.as_u32(),
            Self::Ipv6(_) => Self::IPV6_SENTINEL,
        }
    }

    /// The client id an IPv4-network party knows this source by, or `None`
    /// for an IPv6 source, which has none — its sentinel names nothing.
    #[must_use]
    pub const fn client_id(self) -> Option<ClientId> {
        match self {
            Self::HighId(_) | Self::LowId { .. } => Some(ClientId::from_u32(self.wire_id())),
            Self::Ipv6(_) => None,
        }
    }

    /// The IPv4 endpoint a High ID unpacks to, or `None` for a source that
    /// packs no 32-bit address.
    #[must_use]
    pub const fn high_id(self) -> Option<Ipv4Endpoint> {
        match self {
            Self::HighId(endpoint) => Some(endpoint),
            Self::LowId { .. } | Self::Ipv6(_) => None,
        }
    }

    /// The Low ID a callback must name, or `None` for a source with an
    /// address of its own.
    #[must_use]
    pub const fn low_id(self) -> Option<ClientId> {
        match self {
            Self::LowId { id, .. } => Some(id),
            Self::HighId(_) | Self::Ipv6(_) => None,
        }
    }

    /// The port the record carried — the listen port of a dialable source.
    #[must_use]
    pub const fn tcp_port(self) -> u16 {
        match self {
            Self::HighId(endpoint) => endpoint.port,
            Self::LowId { port, .. } => port,
            Self::Ipv6(endpoint) => endpoint.port,
        }
    }

    /// Whether reaching this source needs a callback through its server.
    #[must_use]
    pub const fn is_low_id(self) -> bool {
        matches!(self, Self::LowId { .. })
    }

    /// Whether this source is an IPv4 address that can be dialed directly.
    #[must_use]
    pub const fn is_high_id(self) -> bool {
        matches!(self, Self::HighId(_))
    }

    /// The address to dial, or `None` for a Low ID source — whose id is not an
    /// address, so there is nothing to dial and a callback is the only route.
    /// An IPv6 source *has* an address; whether the dialer speaks its family
    /// is the caller's decision, not this value's.
    #[must_use]
    pub const fn as_peer_endpoint(self) -> Option<PeerEndpoint> {
        match self {
            Self::HighId(endpoint) => Some(PeerEndpoint::V4(endpoint)),
            Self::LowId { .. } => None,
            Self::Ipv6(endpoint) => Some(PeerEndpoint::V6(endpoint)),
        }
    }
}

/// A source's obfuscation stance, as the `OP_ANSWERSOURCES` (source-exchange)
/// crypt-options byte carries it in exchange version 4 (ADR-0042). The three
/// low bits are pinned from aMule `CPartFile::CreateSrcInfoPacket` @ `377ec8d9`
/// (`(requires << 2) | (requests << 1) | supports`); rmule reads `supports` to
/// decide whether a source-exchange candidate may be obfuscate-dialed.
///
/// **`[pending]`**: the bit layout is source-read, not yet confirmed byte-for-byte
/// against a capture (a captured interop run is the gate), so treat every bit as `[pending]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SourceCryptOptions(u8);

impl SourceCryptOptions {
    /// Wrap the options byte as it arrived.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Self {
        Self(byte)
    }

    /// The byte, unchanged — every bit is preserved, including the five this
    /// crate has no meaning for.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self.0
    }

    /// The three crypt bits as a [`CryptStance`], through its ladder (a
    /// higher light without the lower reads dark, as aMule's getters read
    /// them) — the stance [`PeerCrypt`](crate::PeerCrypt) meets ours with.
    #[must_use]
    pub const fn crypt_stance(self) -> CryptStance {
        CryptStance::new(
            self.supports_crypt(),
            self.requests_crypt(),
            self.requires_crypt(),
        )
    }

    /// Bit 0 (`0x01`): the source supports the obfuscation crypt layer. This is
    /// the gate for obfuscate-dialing it — a source that does not support crypt
    /// is dialed plaintext regardless of local policy.
    #[must_use]
    pub const fn supports_crypt(self) -> bool {
        self.0 & 0x01 != 0
    }

    /// Bit 1 (`0x02`): the source requests obfuscation.
    #[must_use]
    pub const fn requests_crypt(self) -> bool {
        self.0 & 0x02 != 0
    }

    /// Bit 2 (`0x04`): the source requires obfuscation.
    #[must_use]
    pub const fn requires_crypt(self) -> bool {
        self.0 & 0x04 != 0
    }

    /// Bit 3 (`0x08`): the source accepts a **direct UDP callback**
    /// (`CONNECT_OPT_DIRECT_UDP_CALLBACK`, ADR-0047). Read only where the byte
    /// really is a connect-options byte — a Kad source row's `TAG_ENCRYPTION`
    /// or a hello/callback options byte — never from a source-exchange record,
    /// whose high bit is overloaded (see [`Self::supports_natt_utp`]).
    ///
    /// Source: eMule 0.70b `srchybrid/kademlia/kademlia/Prefs.cpp`
    /// `CPrefs::GetMyConnectOptions` and aMule (Fork Pin `ab483654`)
    /// `src/kademlia/kademlia/Prefs.cpp:214-233`, which assemble exactly
    /// `0x08 | 0x04 | 0x02 | 0x01`. aMule gates its own type-6 row on this bit
    /// (`src/DownloadQueue.cpp:1789`).
    #[must_use]
    pub const fn supports_direct_udp_callback(self) -> bool {
        self.0 & 0x08 != 0
    }

    /// Bit 7 (`0x80`): the source speaks eMuleAI's **uTP NAT-T**
    /// (`CONNECT_OPT_NAT_TRAVERSAL_UTP`).
    ///
    /// **Context-sensitive, deliberately not defaulted anywhere.** In a
    /// *source-exchange* record the same bit position means "the source's user
    /// hash follows", not NAT-T (amule#1177 c/5467736438), so this reader
    /// is called only where the byte is a genuine connect-options byte. Today
    /// that is one site: a Kad source row's `TAG_ENCRYPTION`, which eMuleAI
    /// fills from the *global* `GetMyConnectOptions`
    /// (`srchybrid/OtherFunctions.cpp`, reached via
    /// `srchybrid/kademlia/kademlia/Prefs.cpp` `CPrefs::GetMyConnectOptions` →
    /// `::GetMyConnectOptions`, publish site
    /// `srchybrid/kademlia/kademlia/Search.cpp:913`) and which therefore
    /// carries `0x80`/`0x40`. eMule 0.70b and aMule use the *Kad-local*
    /// assembly and never set them, so a `false` here is "this publisher does
    /// not speak NAT-T", never "nobody does".
    #[must_use]
    pub const fn supports_natt_utp(self) -> bool {
        self.0 & 0x80 != 0
    }

    /// Bit 6 (`0x40`): the source speaks eMuleAI's **QUIC NAT-T**
    /// (`CONNECT_OPT_NAT_TRAVERSAL_QUIC`). Same context rule as
    /// [`Self::supports_natt_utp`]; rmule reads it to record the advert, not to
    /// select a transport (uTP is the dependable floor).
    #[must_use]
    pub const fn supports_natt_quic(self) -> bool {
        self.0 & 0x40 != 0
    }
}

/// A source learned from `OP_ANSWERSOURCES` (source exchange), carrying the
/// optional crypt material that higher exchange versions add (ADR-0042). A v1
/// source (or a server-lookup source) carries neither; exchange version ≥ 2 adds
/// the target's [`UserHash`], and version 4 adds a [`SourceCryptOptions`] byte.
/// rmule needs the target's User Hash **before dialing** to derive the peer
/// obfuscation key, so it can only obfuscate-dial a source that carried one.
///
/// A channel that can name both families — an ExtSX record, a serve client
/// whose hello named its IPv6 — gives a classic source its **IPv6 Half**
/// (ADR-0087): one source with two addresses, never two sources, because both
/// are the same peer and which one gets dialed is the Dial Chooser's call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExchangedSource {
    source: PeerSource,
    user_hash: Option<UserHash>,
    crypt_options: Option<SourceCryptOptions>,
    ipv6_half: Option<Ipv6Endpoint>,
}

impl ExchangedSource {
    /// A source with whatever crypt material its exchange version carried.
    #[must_use]
    pub const fn new(
        source: PeerSource,
        user_hash: Option<UserHash>,
        crypt_options: Option<SourceCryptOptions>,
    ) -> Self {
        Self {
            source,
            user_hash,
            crypt_options,
            ipv6_half: None,
        }
    }

    /// The same source with its **IPv6 Half**: the IPv6 endpoint it is also
    /// reachable at beside its client id. Only a High or Low ID has a half to
    /// carry — an IPv6-only source *is* its IPv6, so for one this is a no-op
    /// and [`Self::ipv6`] keeps reading one address, not two.
    #[must_use]
    pub const fn with_ipv6_half(mut self, ipv6: Option<Ipv6Endpoint>) -> Self {
        if !matches!(self.source, PeerSource::Ipv6(_)) {
            self.ipv6_half = ipv6;
        }
        self
    }

    /// A source with no crypt material — a v1 source-exchange entry or a
    /// server-lookup source, which can only ever be dialed plaintext.
    #[must_use]
    pub const fn plain(source: PeerSource) -> Self {
        Self::new(source, None, None)
    }

    /// The plain source underneath, without the exchange extras.
    #[must_use]
    pub const fn peer_source(self) -> PeerSource {
        self.source
    }

    /// The target's user hash, when the exchange version carried one.
    #[must_use]
    pub const fn user_hash(self) -> Option<UserHash> {
        self.user_hash
    }

    /// The advertised crypt stance, when the exchange version carried one.
    #[must_use]
    pub const fn crypt_options(self) -> Option<SourceCryptOptions> {
        self.crypt_options
    }

    /// The source's IPv6 endpoint, wherever it is held: the **IPv6 Half**
    /// beside a client id, or the address of an IPv6-only source. One
    /// accessor, so no reader has to know which shape the source arrived in.
    #[must_use]
    pub const fn ipv6(self) -> Option<Ipv6Endpoint> {
        match (self.ipv6_half, self.source) {
            (Some(endpoint), _) | (None, PeerSource::Ipv6(endpoint)) => Some(endpoint),
            (None, PeerSource::HighId(_) | PeerSource::LowId { .. }) => None,
        }
    }

    // Delegators so a candidate reads like the `PeerSource` it wraps.
    /// The client id an IPv4-network party knows the source by, or `None` for
    /// an IPv6 source.
    #[must_use]
    pub const fn client_id(self) -> Option<ClientId> {
        self.source.client_id()
    }

    /// The Low ID a callback must name, or `None` for a source that carries an
    /// address of its own (see [`PeerSource::low_id`]).
    #[must_use]
    pub const fn low_id(self) -> Option<ClientId> {
        self.source.low_id()
    }

    /// The port the source listens on.
    #[must_use]
    pub const fn tcp_port(self) -> u16 {
        self.source.tcp_port()
    }

    /// The address to dial, or `None` for a Low ID source (see
    /// [`PeerSource::as_peer_endpoint`]).
    #[must_use]
    pub const fn as_peer_endpoint(self) -> Option<PeerEndpoint> {
        self.source.as_peer_endpoint()
    }

    /// The crypt side this record states — its crypt byte's stance and its
    /// User Hash — which a dial meets with ours by aMule's outbound rule
    /// ([`PeerCrypt::outbound`](crate::PeerCrypt::outbound), ADR-0049).
    #[must_use]
    pub const fn peer_crypt(self) -> crate::PeerCrypt {
        crate::PeerCrypt::from_record(self.crypt_options, self.user_hash)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn a_classic_record_classifies_by_the_low_id_ceiling_and_re_encodes() {
        let high = PeerSource::new(ClientId::from_u32(u32::from_le_bytes([10, 0, 0, 9])), 4662);
        assert_eq!(
            high,
            PeerSource::HighId(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 9), 4662))
        );
        assert_eq!(high.wire_id(), u32::from_le_bytes([10, 0, 0, 9]));
        assert!(high.low_id().is_none());

        let low = PeerSource::new(ClientId::from_u32(77), 4662);
        assert_eq!(low.low_id(), Some(ClientId::from_u32(77)));
        assert!(low.as_peer_endpoint().is_none());
        assert_eq!(low.client_id(), Some(ClientId::from_u32(77)));
    }

    #[test]
    fn an_ipv6_source_has_an_address_but_no_client_id() {
        let v6 = PeerSource::Ipv6(Ipv6Endpoint::new(Ipv6Addr::LOCALHOST, 4662));
        assert_eq!(v6.wire_id(), PeerSource::IPV6_SENTINEL);
        assert!(v6.client_id().is_none());
        assert!(!v6.is_high_id() && !v6.is_low_id());
        assert_eq!(
            v6.as_peer_endpoint(),
            Some(PeerEndpoint::V6(Ipv6Endpoint::new(
                Ipv6Addr::LOCALHOST,
                4662
            )))
        );
    }
}
