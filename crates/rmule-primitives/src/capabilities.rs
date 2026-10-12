//! Single-source capability registry (ADR-0047).
//!
//! Every advertising surface — the server-login tags (`CT_SERVER_FLAGS`,
//! `CT_EMULE_VERSION` in `rmule-ed2k`) and the peer-hello capability block
//! (`MiscOptions1`/`MiscOptions2`, `CT_EMULE_VERSION` in `rmule-peer`) —
//! derives from this module instead of assembling bits per-site. A
//! feature-cluster spec that ships flips one entry here and every surface
//! updates coherently; the Honest Capability Advertisement invariant
//! (advertise exactly what dispatch handles, ADR-0047) gets a single
//! enforcement point.
//!
//! The registry holds *feature facts*, never wire encodings: tag ids and
//! bit offsets stay in the surface crates (`rmule-ed2k` packs `SRVCAP_*`
//! flags, `rmule-peer` packs `MiscOptions` nibbles), keeping this crate
//! free of per-protocol canonical ids.

/// rmule's protocol-obfuscation stance for one connection surface
/// (ADR-0042): the three crypt lights every advert derives from.
///
/// The cumulative dependency rule (aMule `BaseClient.cpp`:
/// `requests &= supports; requires &= requests`) is applied at
/// construction, so a higher tier can never be lit without the lower —
/// the ladder is enforced once here rather than per advert site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptStance {
    supports: bool,
    requests: bool,
    requires: bool,
}

impl CryptStance {
    /// No crypt capability advertised at all (obfuscation off).
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            supports: false,
            requests: false,
            requires: false,
        }
    }

    /// Build a stance, collapsing dishonest ladders: `requests` without
    /// `supports` (or `requires` without `requests`) darkens the higher
    /// light instead of advertising a tier rmule would not honour.
    #[must_use]
    pub const fn new(supports: bool, requests: bool, requires: bool) -> Self {
        let requests = requests && supports;
        let requires = requires && requests;
        Self {
            supports,
            requests,
            requires,
        }
    }

    /// rmule accepts the obfuscation crypt layer on this surface.
    #[must_use]
    pub const fn supports(self) -> bool {
        self.supports
    }

    /// rmule initiates obfuscation when possible.
    #[must_use]
    pub const fn requests(self) -> bool {
        self.requests
    }

    /// rmule refuses plaintext.
    #[must_use]
    pub const fn requires(self) -> bool {
        self.requires
    }
}

/// The `CT_EMULE_VERSION` word rmule advertises is aMule 2.3.3's own, not
/// rmule's own version. Wire-citizen doctrine: rmule presents as a
/// byte-faithful aMule 2.3.3 peer, and Lugdunum-family eservers gate login on a
/// minimum client version — a 0.x major is rejected "your client is too old".
/// aMule builds the identical word on BOTH surfaces this registry feeds — the
/// server login (`ServerConnect.cpp#L253-256`, `(SO_AMULE<<24)` present) and
/// the peer hello (`BaseClient.cpp#L1077-1082`):
///   `(SO_AMULE << 24) | make_full_ed2k_version(MJR, MIN, UPDATE)`,
/// with `make_full_ed2k_version(a,b,c) = (a<<17)|(b<<10)|(c<<7)`
/// (`OtherFunctions.h#L334`) → `0x0304_0D80`. This is a wire-identity field,
/// not a dispatchable capability bit, so it sits outside the Honest Capability
/// Advertisement invariant (ADR-0047 govern feature bits, which still
/// track shipped dispatch reality); see the ADR-0047 amendment.
const PARITY_SOFT_ID: u32 = 3; // SO_AMULE (ClientSoftware.h#L33)
const PARITY_VERSION_MAJOR: u32 = 2; // VERSION_MJR (ClientVersion.h#L56)
const PARITY_VERSION_MINOR: u32 = 3; // VERSION_MIN (ClientVersion.h#L57)
const PARITY_VERSION_UPDATE: u32 = 3; // VERSION_UPDATE (ClientVersion.h#L58)

/// The shipped-feature registry plus per-connection policy (ADR-0047).
///
/// Shipped facts are methods returning constants — they cannot be
/// misconstructed, and a feature spec that ships flips exactly one
/// return value here (e.g. multipacket, ADR-0054, flips its entry when its
/// handlers ship). Policy (the crypt stance) is injected at construction
/// because it is runtime configuration, not shipped reality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    crypt: CryptStance,
}

impl Capabilities {
    /// The registry with `crypt` policy applied. Everything else is the
    /// shipped set — fixed at compile time, changed only by the feature
    /// spec that ships the capability.
    #[must_use]
    pub const fn shipped(crypt: CryptStance) -> Self {
        Self { crypt }
    }

    /// This surface's crypt stance (policy, not shipped fact).
    #[must_use]
    pub const fn crypt(self) -> CryptStance {
        self.crypt
    }

    /// rmule inflates packed `0xD4` server frames
    /// (`rmule_ed2k::compressed_frame::inflate_server_packet`), so the
    /// server may compress toward us.
    #[must_use]
    pub const fn accepts_compressed_server_frames(self) -> bool {
        true
    }

    /// rmule decodes compact numeric tag names (`0x80`-flagged, "new
    /// tags") — `rmule_primitives::tag` handles both encodings on decode.
    #[must_use]
    pub const fn accepts_new_tags(self) -> bool {
        true
    }

    /// rmule's `Ed2kText` is byte-preserving, so UTF-8 strings from the
    /// server pass through unmangled.
    #[must_use]
    pub const fn accepts_unicode(self) -> bool {
        true
    }

    /// 64-bit file sizes are dispatched end-to-end (search, get-sources,
    /// links) — gated per-server on the granted large-files flag.
    #[must_use]
    pub const fn supports_large_files(self) -> bool {
        true
    }

    /// `CAPABLE_AUXPORT` tells a server this client acts on an "aux port
    /// login": when the login came through an auxiliary port, the server's
    /// `OP_IDCHANGE` names its standard port, and aMule replaces the row's
    /// port with it and keeps the dialed one in the row's aux-ports list
    /// (`ServerSocket.cpp:289-311`, `Server.cpp:233-241`). The managed server
    /// list does the same (ADR-0080, "Aux ports"), so the claim is true.
    #[must_use]
    pub const fn supports_aux_port(self) -> bool {
        true
    }

    /// eMule extended-protocol data-compression version (peer transfer,
    /// ADR-0055).
    #[must_use]
    pub const fn data_compression_version(self) -> u8 {
        1
    }

    /// Source-exchange SX1 version nibble (ADR-0038, ADR-0055). `3` is
    /// aMule's own value (`BaseClient.cpp#L1089` @4e8f2b3c) — honest because
    /// rmule both consumes and *serves* the exchange (registry rule: the bit
    /// tracks dispatch reality, never aspires ahead of it).
    #[must_use]
    pub const fn source_exchange_version(self) -> u8 {
        3
    }

    /// SX2 source exchange — `OP_REQUESTSOURCES2`/`OP_ANSWERSOURCES2`
    /// (`SupportsSourceEx2`, ADR-0055). True because of the serve callback:
    /// rmule answers a peer's SX2 request with a packed `0x84`, so
    /// advertising the bit is truthful (the peer-hello surface packs it into
    /// `MiscOptions2` bit 10).
    #[must_use]
    pub const fn supports_source_exchange2(self) -> bool {
        true
    }

    /// Extended-requests version: `1` — every name ask rmule
    /// sends carries its own part status, and every name ask it reads may.
    /// The level on the wire is the lower of the two ends' claims: aMule's
    /// asker writes at the uploader's claim (`DownloadClient.cpp`
    /// `SendFileRequest`) and its uploader reads at the asker's
    /// (`UploadClient.cpp` `ProcessExtendedInfo`), so with both at or above
    /// rmule's `1` the two meet there. Not `2`: that level adds a
    /// complete-source count rmule does not keep. A `0` here costs every
    /// source-exchange answer for a complete file: aMule clears the asker's
    /// part status on a v0 name ask and then refuses the ask on a part-count
    /// mismatch (`KnownFile.cpp` `CreateSrcInfoPacket`, stock 2.3.3 `:929`).
    #[must_use]
    pub const fn extended_requests_version(self) -> u8 {
        1
    }

    /// AICH version (ADR-0039): rmule both recovers corrupt
    /// blocks and answers peers' recovery requests.
    #[must_use]
    pub const fn aich_version(self) -> u8 {
        1
    }

    /// Peer-UDP protocol version — aMule's own `4` (ADR-0057). Lit in the peer
    /// hello's `MiscOptions1` UDP nibble (bits [24..28)) **only when rmule binds
    /// the shared client-UDP socket and its reask uploader serves**, so the
    /// value is a shipped fact here while the *decision to advertise* stays a
    /// runtime honest-advertisement gate at the hello-build site — a peer's
    /// `UDPReaskForDownload` gate keys on this nibble together with the
    /// `CT_EMULE_UDPPORTS` port, so lighting one without the other (or without a
    /// live socket) would invite a datagram rmule cannot answer.
    #[must_use]
    pub const fn peer_udp_version(self) -> u8 {
        4
    }

    /// Kad2 protocol version — `8`, the same number the Kad node puts in its own
    /// `KADEMLIA2_HELLO` (`rmule_kad::KadNode::KAD_VERSION`, capture-proven
    /// against aMule 2.3.3). Lit in the peer hello's `MiscOptions2` low nibble
    /// **only while a Kad node is actually running**, which the surface reads off
    /// the live `CT_EMULE_UDPPORTS` Kad half — aMule's own
    /// `Kademlia::IsRunning() ? kadPort : 0` gate, applied to the version too.
    ///
    /// Two counterparty decisions read this nibble, and an under-advertised `0`
    /// silently loses both: aMule refuses to bootstrap Kad from a peer whose
    /// hello says `<= 1` (`BaseClient.cpp` `ConnectionEstablished`), and it acks a
    /// firewall-check connect-back with the *legacy* UDP `0x59` instead of
    /// `OP_KAD_FWTCPCHECK_ACK` unless the nibble reads `>= 7`
    /// (`ClientList.cpp`'s `KS_CONNECTED_FWCHECK`) — so the modern ack path
    /// ADR-0058 specifies would never be taken against a v8 counterparty.
    ///
    /// The value cannot be read from `rmule-kad` (this crate is below it), so the
    /// registry carries the number and the Kad node's own constant is the
    /// cross-check; the two are asserted equal in `rmule-kad`'s tests.
    #[must_use]
    pub const fn kad_version(self) -> u8 {
        8
    }

    /// Bundled file negotiation — `OP_MULTIPACKET`/`OP_MULTIPACKET_EXT`
    /// request, `OP_MULTIPACKETANSWER` reply (ADR-0054). Fan-in to the
    /// session's existing serve/consume handlers and `0x93` composition
    /// both ship, so the advert is true here with them (registry rule: bits
    /// never aspirational). Bundle *emission* (rmule sending `0x92`/`0xA4`
    /// as the requester) is deferred and does not gate this bit — a peer's
    /// `SupportMultiPacket()` reads only the bit rmule advertises about
    /// itself, not whether rmule also bundles its own outbound requests.
    #[must_use]
    pub const fn supports_multipacket(self) -> bool {
        true
    }

    /// Secure User Identification version *bitmask* (bit 0 = V1, bit 1 =
    /// V2) advertised when a keypair is present — `3`, exactly what real
    /// eMule/aMule send (`CryptoAvailable() ? 3 : 0`, 2026-07-06
    /// capture; ADR-0041). Whether to light it at all stays a policy
    /// decision of the surface (key presence).
    #[must_use]
    pub const fn secure_ident_versions_mask(self) -> u8 {
        3
    }

    /// The `CT_EMULE_VERSION` word, aMule 2.3.3 parity value `0x0304_0D80`:
    /// `(soft_id << 24) | (major << 17) | (minor << 10) | (update << 7)`.
    /// Shared verbatim by the server-login and peer-hello surfaces — aMule
    /// emits the same expression on both. See the `PARITY_*` constants above
    /// for the masquerade rationale and source citations.
    #[must_use]
    pub const fn emule_version_word(self) -> u32 {
        (PARITY_SOFT_ID << 24)
            | (PARITY_VERSION_MAJOR << 17)
            | (PARITY_VERSION_MINOR << 10)
            | (PARITY_VERSION_UPDATE << 7)
    }
}

#[cfg(test)]
mod tests {
    use super::{Capabilities, CryptStance};

    #[test]
    fn emule_version_word_is_amule_233_parity() {
        // aMule 2.3.3 builds (SO_AMULE<<24) | make_full_ed2k_version(2,3,3)
        //   = (3<<24) | (2<<17)|(3<<10)|(3<<7) = 0x0304_0D80,
        // the identical expression on server login (ServerConnect.cpp#L253)
        // and peer hello (BaseClient.cpp#L1077). rmule advertises the same
        // word so a min-version-gating eserver (Lugdunum) accepts the login
        // instead of rejecting rmule's own version as "too old".
        let caps = Capabilities::shipped(CryptStance::disabled());
        assert_eq!(caps.emule_version_word(), 0x0304_0D80);
    }

    #[test]
    fn crypt_stance_applies_the_cumulative_ladder() {
        let requires_without_support = CryptStance::new(false, false, true);
        assert!(!requires_without_support.requires());
        assert!(!requires_without_support.requests());
        assert!(!requires_without_support.supports());

        let requests_without_support = CryptStance::new(false, true, false);
        assert!(!requests_without_support.requests());

        let requires_without_request = CryptStance::new(true, false, true);
        assert!(requires_without_request.supports());
        assert!(
            !requires_without_request.requires(),
            "requires collapses without requests"
        );

        let full = CryptStance::new(true, true, true);
        assert!(full.supports() && full.requests() && full.requires());
        assert_eq!(
            CryptStance::disabled(),
            CryptStance::new(false, false, false)
        );
    }
}
