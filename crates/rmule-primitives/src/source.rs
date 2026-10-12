//! Sources for a file: the target a lookup asks about, a source as a server
//! hands it over (High ID, Low ID, or a sentinel-carried IPv6 endpoint), the
//! crypt options a source advertises, and the **Source Sighting** every
//! channel delivers a source as.

mod sentinel;
mod sighting;

pub use sentinel::SourceListTail;
pub use sighting::{SightedBuddy, SourceRoad, SourceSighting};

use crate::{ClientId, CryptStance, FileHash, Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint};

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
