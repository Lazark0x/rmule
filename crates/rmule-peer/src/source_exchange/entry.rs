//! The per-entry source-exchange codec shared by every `OP_ANSWERSOURCES` /
//! `OP_ANSWERSOURCES2` list in both directions (ADR-0055): the four wire
//! versions with their strides and field carriage
//! ([`SourceExchangeVersion`]), the decoded entry pairing a source's
//! provenance with its declaring server ([`SourceExchangeEntry`]), and the
//! version-parameterized encode/decode of one entry. Strides and the
//! hybrid-id rule are pinned from aMule `CKnownFile::CreateSrcInfoPacket` /
//! `CPartFile::AddClientSources` @ `4e8f2b3c`.

use std::net::Ipv4Addr;

use rmule_primitives::{
    ClientId, ExchangedSource, Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint, PeerSource,
    SourceCryptOptions, UserHash,
};

/// Per-source strides by source-exchange version, pinned from aMule
/// `CKnownFile::CreateSrcInfoPacket` / `CPartFile::AddClientSources` @
/// `4e8f2b3c`. Each source starts with the quintet
/// `[id u32][tcp port u16][server ip u32][server port u16]`; higher versions
/// append fields — see [`SourceExchangeVersion::entry_stride`].
const V1_SOURCE_LEN: usize = 12;
const V2_SOURCE_LEN: usize = V1_SOURCE_LEN + UserHash::BYTE_LEN; // 28
const V4_SOURCE_LEN: usize = V2_SOURCE_LEN + 1; // 29

/// The four source-exchange entry versions the wire format defines, pinned
/// from aMule's `SOURCEEXCHANGE2_VERSION = 4` (`Constants.h`) and the
/// `byUsedVersion` / `uPacketSXVersion` values `CreateSrcInfoPacket` /
/// `AddClientSources` actually produce (never 0, never above 4). One codec
/// serves every version in both directions — the "one version-parameterized
/// codec" ADR-0055 calls for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SourceExchangeVersion {
    /// Id, TCP port, and the declaring server — nothing that identifies the
    /// source beyond where it sits.
    V1,
    /// Adds the target's User Hash.
    V2,
    /// Structurally v2: same stride, same fields.
    V3,
    /// Adds the crypt-options byte.
    V4,
}

impl SourceExchangeVersion {
    /// Parse a wire version byte. Valid only for `1..=4` — aMule's SX2 bound
    /// check (`uClientSXVersion > SOURCEEXCHANGE2_VERSION || uClientSXVersion
    /// == 0`, `PartFile.cpp::AddClientSources` @4e8f2b3c).
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::V1),
            2 => Some(Self::V2),
            3 => Some(Self::V3),
            4 => Some(Self::V4),
            _ => None,
        }
    }

    /// The byte this version rides as on the wire.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
            Self::V3 => 3,
            Self::V4 => 4,
        }
    }

    /// This version's per-source byte stride.
    #[must_use]
    pub const fn entry_stride(self) -> usize {
        match self {
            Self::V1 => V1_SOURCE_LEN,
            Self::V2 | Self::V3 => V2_SOURCE_LEN,
            Self::V4 => V4_SOURCE_LEN,
        }
    }

    /// v≥2 entries append the target's User Hash.
    #[must_use]
    pub const fn carries_user_hash(self) -> bool {
        matches!(self, Self::V2 | Self::V3 | Self::V4)
    }

    /// v4 entries append the crypt-options byte.
    #[must_use]
    pub const fn carries_crypt_options(self) -> bool {
        matches!(self, Self::V4)
    }

    /// v≥3 entries carry a HighID's client id byte-swapped from ed2k order
    /// into "hybrid" (network) order. aMule's own comment names the reason:
    /// "Clients send ID's the Hyrbid format so highID clients with *.*.*.0
    /// won't be falsely switched to a lowID" (`PartFile.cpp::
    /// AddClientSources` @4e8f2b3c). A LowID is a small server-assigned
    /// integer, not an IP, so its magnitude is scheme-invariant — only a
    /// HighID's octets ever get swapped, matching `CUpDownClient`'s own
    /// constructor (`BaseClient.cpp` @4e8f2b3c: the swap is gated on
    /// `!IsLowID`, never applied unconditionally).
    ///
    /// **pending**: source-read from the C++, not capture-confirmed against a
    /// real SX2 exchange.
    #[must_use]
    pub const fn uses_hybrid_id(self) -> bool {
        matches!(self, Self::V3 | Self::V4)
    }
}

/// Encode one source entry at `version`'s stride, appending to `out`. Shared
/// by [`AnswerSources::encode_packet`](super::AnswerSources::encode_packet) and
/// [`AnswerSources2::encode_packet`](super::AnswerSources2::encode_packet) —
/// the version-parameterized codec both opcodes and both directions share.
/// Server IP/port are written as zero: no served source carries a per-client
/// server endpoint, so the serve path zero-fills the field. A source missing
/// the user hash or crypt-options a higher version requires (e.g. encoding a
/// plain source at v4) fills the gap with the honest default — zero hash, no
/// crypt support — rather than fabricating data the source never carried.
pub(super) fn encode_source_entry(
    out: &mut Vec<u8>,
    source: ExchangedSource,
    version: SourceExchangeVersion,
) {
    // A hybrid-id version writes a High ID big-endian; a Low ID rides as-is.
    // (So would an IPv6 source's sentinel id — the classic exchange has no
    // address block for it, which is why the serve path never hands one over.)
    let peer_source = source.peer_source();
    let wire_id = if version.uses_hybrid_id() && peer_source.is_high_id() {
        peer_source.wire_id().swap_bytes()
    } else {
        peer_source.wire_id()
    };
    out.extend_from_slice(&wire_id.to_le_bytes());
    out.extend_from_slice(&source.tcp_port().to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // server ip (untracked)
    out.extend_from_slice(&0u16.to_le_bytes()); // server port (untracked)
    if version.carries_user_hash() {
        let hash = source
            .user_hash()
            .unwrap_or(UserHash::from_bytes([0; UserHash::BYTE_LEN]));
        out.extend_from_slice(hash.as_bytes());
    }
    if version.carries_crypt_options() {
        let crypt = source
            .crypt_options()
            .unwrap_or(SourceCryptOptions::from_byte(0));
        out.push(crypt.as_byte());
    }
}

/// One decoded source-answer entry, pairing the [`ExchangedSource`]
/// provenance (ADR-0046) with the server it declares itself registered on
/// (ADR-0055). Every version's wire entry carries `[srvIP4][srvPort2]` right
/// after `[id][port]`, and both [`AnswerSources`](super::AnswerSources)
/// (`0x82`) and [`AnswerSources2`](super::AnswerSources2) (`0x84`) carry the
/// full entry, so the consume-side Low-ID sanity/routing rule
/// (`sanitize_and_route`) reads it without a second, divergent parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceExchangeEntry {
    source: ExchangedSource,
    server: Option<Ipv4Endpoint>,
}

impl SourceExchangeEntry {
    /// Pair a source with the server it declared itself registered on. An
    /// ExtSX record's IPv6 half rides inside the source
    /// ([`ExchangedSource::with_ipv6_half`]); a classic entry has no address
    /// block, so its source never carries one.
    #[must_use]
    pub const fn new(source: ExchangedSource, server: Option<Ipv4Endpoint>) -> Self {
        Self { source, server }
    }

    /// The source's IPv6 endpoint when the record carried a usable one — its
    /// `CT_MOD_IP_V6` address at the record's single port, since the protocol
    /// has no way to express a different port per family.
    ///
    /// Present alongside a High ID for a dual-stack source, alongside a Low ID
    /// for a firewalled one that is nevertheless dialable over IPv6, and
    /// *inside* [`PeerSource::Ipv6`] when the record named no usable IPv4 at
    /// all — see [`ExchangedSource::ipv6`].
    #[must_use]
    pub const fn ipv6(self) -> Option<Ipv6Endpoint> {
        self.source.ipv6()
    }

    /// An entry with no declared server — the shape every served entry takes,
    /// since the serve path writes the server fields as zero.
    #[must_use]
    pub const fn plain(source: ExchangedSource) -> Self {
        Self::new(source, None)
    }

    /// The provenance half alone, for a caller with no use for the server.
    #[must_use]
    pub const fn source(self) -> ExchangedSource {
        self.source
    }

    /// The server this source is registered on, or `None` when the entry's
    /// `[srvIP4][srvPort2]` fields are both zero — "no server known", the
    /// same sentinel `PeerIdentity::from_hello_body` applies to a hello's
    /// own `connected_server`.
    #[must_use]
    pub const fn server(self) -> Option<Ipv4Endpoint> {
        self.server
    }

    // Delegators so an entry reads like the `ExchangedSource` it wraps
    // (mirroring `ExchangedSource`'s own delegation onto `PeerSource`).
    /// The source's own id on the IPv4 network, or `None` for an IPv6 source.
    #[must_use]
    pub const fn client_id(self) -> Option<ClientId> {
        self.source.client_id()
    }

    /// The TCP port it advertises.
    #[must_use]
    pub const fn tcp_port(self) -> u16 {
        self.source.tcp_port()
    }

    /// Its User Hash, when the entry's version carried one.
    #[must_use]
    pub const fn user_hash(self) -> Option<UserHash> {
        self.source.user_hash()
    }

    /// Its advertised obfuscation options, when the version carried them.
    #[must_use]
    pub const fn crypt_options(self) -> Option<SourceCryptOptions> {
        self.source.crypt_options()
    }

    /// Where to dial it, or `None` for a Low-ID source that cannot be dialed.
    #[must_use]
    pub const fn as_peer_endpoint(self) -> Option<PeerEndpoint> {
        self.source.as_peer_endpoint()
    }

    /// The crypt side this entry states — its stance and User Hash — which a
    /// dial meets with ours by aMule's outbound rule
    /// ([`PeerCrypt::outbound`](rmule_primitives::PeerCrypt::outbound),
    /// ADR-0049).
    #[must_use]
    pub const fn peer_crypt(self) -> rmule_primitives::PeerCrypt {
        self.source.peer_crypt()
    }
}

/// Read an entry's `[srvIP4 4][srvPort2 2]` fields at `bytes[6..12]`, present
/// in every version — the same u32-little-endian-as-IPv4-octets wire
/// convention `PeerSource::as_peer_endpoint` decodes a client id with.
fn decode_source_server(bytes: &[u8]) -> Option<Ipv4Endpoint> {
    let ip_raw = u32::from_le_bytes(bytes[6..10].try_into().expect("stride-checked"));
    let port = u16::from_le_bytes([bytes[10], bytes[11]]);
    if ip_raw == 0 && port == 0 {
        return None;
    }
    let octets = ip_raw.to_le_bytes();
    Some(Ipv4Endpoint::new(
        Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]),
        port,
    ))
}

/// Decode one `version`-strided source entry from `bytes`, which is exactly
/// `version.entry_stride()` long — the caller validates total geometry
/// first.
fn decode_source_entry(bytes: &[u8], version: SourceExchangeVersion) -> SourceExchangeEntry {
    let raw = u32::from_le_bytes(bytes[0..4].try_into().expect("stride-checked"));
    // LowID-vs-HighID is decided on the as-received bytes, before any swap: a
    // LowID's magnitude is scheme-invariant, and a HighID's raw wire value
    // stays >= the threshold under either byte order (barring a leftmost
    // dotted octet of 0, which never occurs for a routable address — the
    // exact asymmetry the hybrid encoding exploits). aMule's own
    // `IsLowID(dwID)` checks the same raw, pre-swap value
    // (`PartFile.cpp::AddClientSources` @4e8f2b3c).
    let is_high_id = ClientId::from_u32(raw).is_high_id();
    let id = if version.uses_hybrid_id() && is_high_id {
        ClientId::from_u32(raw.swap_bytes())
    } else {
        ClientId::from_u32(raw)
    };
    let tcp_port = u16::from_le_bytes([bytes[4], bytes[5]]);
    let server = decode_source_server(bytes);
    let source = PeerSource::new(id, tcp_port);
    let user_hash = version.carries_user_hash().then(|| {
        let mut hash = [0u8; UserHash::BYTE_LEN];
        hash.copy_from_slice(&bytes[12..12 + UserHash::BYTE_LEN]);
        UserHash::from_bytes(hash)
    });
    let crypt_options = version
        .carries_crypt_options()
        .then(|| SourceCryptOptions::from_byte(bytes[V2_SOURCE_LEN]));
    SourceExchangeEntry::new(
        ExchangedSource::new(source, user_hash, crypt_options),
        server,
    )
}

/// Decode `count` consecutive `version`-strided entries from `body`. The
/// caller has already validated `body.len() == count as usize *
/// version.entry_stride()`.
pub(super) fn decode_source_entries(
    body: &[u8],
    count: u16,
    version: SourceExchangeVersion,
) -> Vec<SourceExchangeEntry> {
    let stride = version.entry_stride();
    (0..count as usize)
        .map(|i| decode_source_entry(&body[i * stride..(i + 1) * stride], version))
        .collect()
}
