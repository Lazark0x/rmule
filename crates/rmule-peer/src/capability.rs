//! eMule client capability bitsets advertised in the peer hello.
//!
//! `MiscOptions1` / `MiscOptions2` are the **Capability Block**
//! (`CONTEXT.md`): two `u32` tag values packing the eMule extended-protocol
//! feature versions a peer supports. Bit offsets are pinned from aMule
//! `BaseClient.cpp` (`SendHelloTypePacket` / `ProcessHelloTypePacket`) at
//! commit `377ec8d9`; behaviour is cited and rewritten, never ported
//! (ADR-0004).
//!
//! The IPv6 dialect's third word, `CT_MOD_MISCOPTIONS` (`0xAA`), lives in
//! `mod_misc`: it obeys a different rule from these two — a **Static
//! Capability Claim**, advertised whether or not the capability currently has
//! anything to say (ADR-0087).

mod mod_misc;

pub use self::mod_misc::ModMiscOptions;

use rmule_primitives::{Capabilities, CryptStance, Tag, TagName, TagValue};

use crate::hello::hello_int;

/// eMule capability tag id `CT_EMULE_MISCOPTIONS1`. Canonical eMule
/// constant; its sibling `CT_EMULE_VERSION` (`0xFB`) is source-confirmed at
/// `377ec8d9` (`docs/reference/notes/ed2k-welcome-packets.md`). Re-confirmed
/// against a real captured hello at the interop step.
pub(crate) const CT_EMULE_MISCOPTIONS1: u8 = 0xFA;

/// eMule capability tag id `CT_EMULE_UDPPORTS`. Canonical eMule constant
/// (`opcodes.h`), sibling of `CT_EMULE_MISCOPTIONS1` (`0xFA`). Its int value
/// packs two UDP ports — the **Kad** UDP port in the high 16 bits, the client
/// UDP port in the low 16 (aMule `BaseClient.cpp` `ProcessHelloTypePacket`).
/// Re-confirmed against a real captured hello at the interop step (the same
/// `[pending]` bar as the surrounding extended-hello tags).
pub(crate) const CT_EMULE_UDPPORTS: u8 = 0xF9;

/// The `CT_EMULE_MISCOPTIONS1` capability bitset advertised in a peer hello:
/// a `u32` packing eMule extended-protocol feature versions. Bit offsets are
/// pinned from aMule `BaseClient.cpp` (`SendHelloTypePacket` /
/// `ProcessHelloTypePacket`) at commit `377ec8d9`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MiscOptions1(u32);

impl MiscOptions1 {
    /// Wrap the raw `CT_EMULE_MISCOPTIONS1` tag value.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// The raw word.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Advertised data-compression version (`0` = unsupported). Bits
    /// [20..24): aMule `(flags >> 4*5) & 0x0f`.
    #[must_use]
    pub const fn data_compression_version(self) -> u8 {
        ((self.0 >> 20) & 0x0f) as u8
    }

    /// Advertised source-exchange version (`0` = unsupported). Bits [12..16):
    /// aMule `(flags >> 4*3) & 0x0f`.
    #[must_use]
    pub const fn source_exchange_version(self) -> u8 {
        ((self.0 >> 12) & 0x0f) as u8
    }

    /// Advertised extended-requests version (`0` = none). Bits [8..12):
    /// aMule `m_byExtendedRequestsVer = (flags >> 4*2) & 0x0f`. Decides whether
    /// a name ask carries the asker's part status — see
    /// [`ExtendedRequests::negotiated`](crate::ExtendedRequests::negotiated).
    #[must_use]
    pub const fn extended_requests_version(self) -> u8 {
        ((self.0 >> 8) & 0x0f) as u8
    }

    /// This word with the source-exchange nibble (bits [12..16)) replaced by
    /// `nibble`'s low four bits, every other field untouched. Diagnostic/
    /// capture use only — see [`Self::override_source_exchange_version`].
    #[must_use]
    const fn with_source_exchange_version(self, nibble: u8) -> Self {
        Self((self.0 & !(0x0f << 12)) | (((nibble & 0x0f) as u32) << 12))
    }

    /// Diagnostic/capture-only: patch `tags`' `CT_EMULE_MISCOPTIONS1` entry
    /// (if present) so it advertises `nibble` as the source-exchange version
    /// instead of whatever [`Self::rmule_advertised`] put there — every other
    /// capability field is untouched. ADR-0055's "consume `0x82` v3" capture
    /// recipe needs this: aMule's SX1 serve path answers at the *requester's*
    /// (rmule's own) advertised nibble
    /// ([`KnownFile.cpp#L938`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/KnownFile.cpp#L938)),
    /// so pinning it to 3 (aMule's own default,
    /// [`BaseClient.cpp#L1089`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/BaseClient.cpp#L1089))
    /// for one diagnostic connection is what exercises the v3 geometry.
    /// Production stays at the registry's Honest Capability Advertisement
    /// (nibble 1) unless a caller opts in via
    /// `PeerSession::with_source_exchange_capture_override`. A no-op when
    /// `tags` carries no `CT_EMULE_MISCOPTIONS1` entry.
    pub fn override_source_exchange_version(tags: &mut [Tag], nibble: u8) {
        for tag in tags.iter_mut() {
            if tag.name().id() == Some(CT_EMULE_MISCOPTIONS1)
                && let TagValue::U32(bits) = tag.value()
            {
                *tag = Self::from_bits(*bits)
                    .with_source_exchange_version(nibble)
                    .to_tag();
            }
        }
    }

    /// Diagnostic/capture-only: patch `tags`' `CT_EMULE_MISCOPTIONS1` entry
    /// (if present) to advertise `level` as the extended-requests version —
    /// see `PeerSession::with_extended_requests_capture_override`. A no-op
    /// when `tags` carries no `CT_EMULE_MISCOPTIONS1` entry.
    pub fn override_extended_requests_version(tags: &mut [Tag], level: u8) {
        for tag in tags.iter_mut() {
            if tag.name().id() == Some(CT_EMULE_MISCOPTIONS1)
                && let TagValue::U32(bits) = tag.value()
            {
                *tag = Self::from_bits((*bits & !(0x0f << 8)) | (u32::from(level & 0x0f) << 8))
                    .to_tag();
            }
        }
    }

    /// Advertised UDP-protocol version (`0` = no peer-UDP support). Bits
    /// [24..28): aMule `m_byUDPVer = (flags >> 4*6) & 0x0f`. Gates the reask
    /// quartet's version-conditional fields (ADR-0057): a pinger with UDP
    /// version > 3 carries a part-status bitfield, > 2 a complete-source
    /// count, and the uploader's `OP_REASKACK` includes our part status only
    /// for a UDPv4 (`> 3`) waiter.
    #[must_use]
    pub const fn udp_version(self) -> u8 {
        ((self.0 >> 24) & 0x0f) as u8
    }

    /// Advertised AICH version (`0` = unsupported). Bits [29..32): aMule
    /// `(flags >> ((4*7)+1)) & 0x07` — a 3-bit field, not 4.
    #[must_use]
    pub const fn aich_version(self) -> u8 {
        ((self.0 >> 29) & 0x07) as u8
    }

    /// Advertised Secure User Identification version (`0` = unsupported,
    /// `1` = V1, `2` = V2). Bits [16..20): aMule
    /// `m_bySupportSecIdent = (flags >> 4*4) & 0x0f` (ADR-0041).
    #[must_use]
    pub const fn secure_identification_version(self) -> u8 {
        ((self.0 >> 16) & 0x0f) as u8
    }

    /// Bit 1: `SupportMultiPacket` — bundled file negotiation
    /// (`OP_MULTIPACKET`/`OP_MULTIPACKETANSWER`, ADR-0054). A single flag
    /// bit, unlike the nibble-wide version fields above.
    #[must_use]
    pub const fn supports_multipacket(self) -> bool {
        (self.0 >> 1) & 1 != 0
    }

    /// Extract a peer's advertised `MiscOptions1` from its hello tags, or
    /// `None` when the peer sent no `CT_EMULE_MISCOPTIONS1` tag (a non-eMule
    /// or pre-extended client).
    #[must_use]
    pub fn from_tags(tags: &[Tag]) -> Option<Self> {
        hello_int(tags, CT_EMULE_MISCOPTIONS1).map(Self::from_bits)
    }

    /// rmule's own honestly-advertised `MiscOptions1`, derived from the
    /// capability registry (ADR-0047): data-compression version,
    /// source-exchange version, and AICH version; every
    /// other capability field 0 — Honest Capability Advertisement
    /// (ADR-0047/0055/0038). Secure User Identification stays off here; see
    /// [`rmule_advertised_with_secure_ident`](Self::rmule_advertised_with_secure_ident).
    #[must_use]
    pub const fn rmule_advertised() -> Self {
        Self::rmule_advertised_with_secure_ident(false)
    }

    /// rmule's advertised block with the Secure User Identification nibble
    /// (bits [16..20)) lit to the registry's version mask iff `secure_ident`
    /// — the nibble is a bitmask (bit 0 = V1, bit 1 = V2), and 3 is exactly
    /// what real eMule/aMule send (`CryptoAvailable() ? 3 : 0`, confirmed
    /// against the 2026-07-06 capture). Advertising 2 alone would tell an
    /// eMule peer rmule cannot do V1 and skew its version choice. Honest
    /// Capability Advertisement (ADR-0041): rmule advertises SUI only when
    /// the application supplied a keypair, so a peer never asks us to sign a
    /// challenge we have no key for. Whether a key is present is runtime
    /// policy, so it stays a parameter; every advertised *value* comes from
    /// the registry.
    #[must_use]
    pub const fn rmule_advertised_with_secure_ident(secure_ident: bool) -> Self {
        // The registry instance only carries crypt policy, which this
        // word does not encode (crypt lives in `MiscOptions2`).
        let caps = Capabilities::shipped(CryptStance::disabled());
        let base = ((caps.aich_version() as u32) << 29)
            | ((caps.data_compression_version() as u32) << 20)
            | ((caps.source_exchange_version() as u32) << 12)
            | ((caps.extended_requests_version() as u32) << 8)
            | ((caps.supports_multipacket() as u32) << 1);
        if secure_ident {
            Self(base | ((caps.secure_ident_versions_mask() as u32) << 16))
        } else {
            Self(base)
        }
    }

    /// This word with the UDP-protocol nibble (bits [24..28)) set to `nibble`'s
    /// low four bits, every other field untouched. Folded in at the hello-build
    /// site (not inside [`Self::rmule_advertised`]) because advertising a
    /// peer-UDP version is a runtime honest-advertisement decision — truthful
    /// only once rmule binds the shared client-UDP socket and its reask uploader
    /// serves (ADR-0057), exactly like the paired `CT_EMULE_UDPPORTS` port.
    #[must_use]
    pub const fn with_udp_version(self, nibble: u8) -> Self {
        Self((self.0 & !(0x0f << 24)) | (((nibble & 0x0f) as u32) << 24))
    }

    /// Encode as a `CT_EMULE_MISCOPTIONS1` hello tag (compact numeric name).
    #[must_use]
    pub fn to_tag(self) -> Tag {
        Tag::new(
            TagName::compact_id(CT_EMULE_MISCOPTIONS1),
            TagValue::U32(self.0),
        )
    }
}

/// The peer hello's `CT_EMULE_UDPPORTS` (`0xF9`) advert: the **Kad** UDP port in
/// the high 16 bits, the **client** UDP port in the low 16 (aMule
/// `BaseClient.cpp` `SendHelloTypePacket` — `0x12401240` when both are 4672).
///
/// Honest Capability Advertisement (ADR-0047): rmule advertises the ports it has
/// **actually bound and serves on**, never a hardcoded default. A caller
/// constructs this only when the shared client-UDP socket is live and the reask
/// uploader answers (`client_udp` = the socket's real bound port); the Kad half
/// is the running Kad node's UDP port, or `0` when Kad is not running — exactly
/// aMule's `Kademlia::IsRunning() ? kadPort : 0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpPortsAdvert {
    client_udp: u16,
    kad_udp: u16,
}

impl UdpPortsAdvert {
    /// Bind the two real ports. `kad_udp` is `0` when Kad is not running.
    #[must_use]
    pub const fn new(client_udp: u16, kad_udp: u16) -> Self {
        Self {
            client_udp,
            kad_udp,
        }
    }

    /// The Kad node's UDP port, or `0` when no Kad node is running — the live
    /// signal every other Kad-conditional half of a hello reads (aMule's
    /// `Kademlia::IsRunning() ? kadPort : 0`).
    #[must_use]
    pub const fn kad_udp(self) -> u16 {
        self.kad_udp
    }

    /// The client-UDP (reask) port, or `0` when no such socket is bound.
    #[must_use]
    pub const fn client_udp(self) -> u16 {
        self.client_udp
    }

    /// The packed `u32`: Kad port high 16, client port low 16.
    #[must_use]
    pub const fn packed(self) -> u32 {
        ((self.kad_udp as u32) << 16) | (self.client_udp as u32)
    }

    /// Reconstruct from a [`packed`](Self::packed) word — the inverse split
    /// (client = low 16, Kad = high 16), for a shared runtime cell that carries
    /// the advert as one atomic `u32`.
    #[must_use]
    pub const fn from_packed(word: u32) -> Self {
        Self {
            client_udp: (word & 0xFFFF) as u16,
            kad_udp: (word >> 16) as u16,
        }
    }

    /// Whether both halves are `0` — nothing to advertise, so the tag is omitted
    /// rather than emitted as a zero word (the `MiscOptions2::is_empty` pattern).
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.client_udp == 0 && self.kad_udp == 0
    }

    /// Encode as a `CT_EMULE_UDPPORTS` hello tag (compact numeric name).
    #[must_use]
    pub fn to_tag(self) -> Tag {
        Tag::new(
            TagName::compact_id(CT_EMULE_UDPPORTS),
            TagValue::U32(self.packed()),
        )
    }
}

/// eMule capability tag id `CT_EMULE_MISCOPTIONS2`. Capture-corrected: a live
/// aMule 2.3.3 hello (interop run `1784926262`) carries it as tag
/// `0xFE`, closing the earlier `[pending]` `0x55` misread — consistent with the
/// contiguous eMule tag block `0xF9 CT_EMULE_UDPPORTS` … `0xFE
/// CT_EMULE_MISCOPTIONS2` observed on the same wire.
pub(crate) const CT_EMULE_MISCOPTIONS2: u8 = 0xFE;

/// The `CT_EMULE_MISCOPTIONS2` capability bitset advertised in a peer hello: a
/// `u32` whose crypt-layer bits announce rmule's protocol-obfuscation stance
/// (ADR-0042). Bit offsets are source-read from aMule `BaseClient.cpp` @
/// `377ec8d9` (`SupportsCryptLayer` at bit 7, `Requests` at bit 8, `Requires` at
/// bit 9) and are **pending** — their only validator is a real aMule choosing
/// to obfuscate-dial rmule. rmule writes the crypt bits, the Kad
/// version, ExtMultiPacket, SourceExchange2 and the direct-UDP-callback bit;
/// every other `MiscOptions2` capability stays 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MiscOptions2(u32);

impl MiscOptions2 {
    /// Wrap the raw `CT_EMULE_MISCOPTIONS2` tag value.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Bit 7: the peer supports the obfuscation crypt layer (accepts obfuscated
    /// inbound). aMule `(misc2 >> 7) & 1`.
    #[must_use]
    pub const fn supports_crypt_layer(self) -> bool {
        (self.0 >> 7) & 1 != 0
    }

    /// Bit 8: the peer requests obfuscation (initiates it when possible). aMule
    /// `(misc2 >> 8) & 1`.
    #[must_use]
    pub const fn requests_crypt_layer(self) -> bool {
        (self.0 >> 8) & 1 != 0
    }

    /// Bit 9: the peer requires obfuscation (refuses plaintext). aMule
    /// `(misc2 >> 9) & 1`.
    #[must_use]
    pub const fn requires_crypt_layer(self) -> bool {
        (self.0 >> 9) & 1 != 0
    }

    /// Bit 5: `SupportExtMultiPacket` — the extended `OP_MULTIPACKET_EXT`
    /// (`0xA4`) bundle form that carries `file_size` (ADR-0054). aMule
    /// selects `0xA4` over the base `0x92` on this bit alone.
    #[must_use]
    pub const fn supports_multipacket_ext(self) -> bool {
        (self.0 >> 5) & 1 != 0
    }

    /// This word with the **Kad version** nibble (bits [0..4)) set to `nibble`'s
    /// low four bits, every other field untouched. Folded in at the hello-build
    /// site rather than in a static advert because it is a runtime honest-
    /// advertisement decision — truthful only while a Kad node is running, which
    /// the surface reads off the paired `CT_EMULE_UDPPORTS` Kad half (aMule's
    /// `Kademlia::IsRunning() ? kadPort : 0`).
    #[must_use]
    pub const fn with_kad_version(self, nibble: u8) -> Self {
        Self((self.0 & !0x0f) | ((nibble & 0x0f) as u32))
    }

    /// Advertised Kad protocol version (`0` = not a Kad2 node). Bits [0..4):
    /// aMule `m_byKadVersion = temptag.GetInt() & 0x0f`
    /// ([`BaseClient.cpp` `ProcessHelloTypePacket`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/BaseClient.cpp)).
    /// The **ed2k→Kad handoff** (ADR-0067) reads it: a peer bootstraps Kad
    /// only when its version is `> 1` (a v0/v1 peer cannot really participate in
    /// Kad2). The offset is `[pending]` on the same capture as the surrounding
    /// crypt bits.
    #[must_use]
    pub const fn kad_version(self) -> u8 {
        (self.0 & 0x0f) as u8
    }

    /// Bit 12: `SupportsDirectUDPCallback` — the peer accepts an
    /// `OP_DIRECTCALLBACKREQ` (`0x95`) at its Kad UDP port and will dial back
    /// (ADR-0061 route 2). aMule reads it as
    /// `m_fDirectUDPCallback = (temptag.GetInt() >> 12) & 0x01`
    /// ([`BaseClient.cpp#L588`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/BaseClient.cpp#L588))
    /// and lights it only when it is Kad-running, TCP-firewalled and
    /// **verified UDP-open** (`:1131`) — the exact position a direct callback is
    /// the right route for.
    ///
    /// rmule's **own** advert lights it through
    /// [`Self::with_direct_udp_callback`], from core's **Self Reach** at each
    /// hello — the same Kad-only test aMule writes, and the one its
    /// `0x95` consume gate answers to.
    ///
    /// The offset stays source-read (`[pending]` with the surrounding bits), and
    /// the one capture of it so far recorded it **clear**: the hello a firewalled
    /// stock aMule spoke on the link it opened *in answer to* rmule's `0x95`
    /// carries `MiscOptions2 = 0x00000438` (interop flow N, fixture
    /// `tests/fixtures/direct_callback/captured/`). That is not a contradiction
    /// but an asymmetry worth knowing: the advert additionally demands
    /// `!IsFirewalledUDP(true) && IsVerified()`, which needs helper nodes to
    /// settle, while the **receive** gate (`ClientUDPSocket.cpp:286`) asks only
    /// `IsRunning() && IsFirewalled()`. A peer can therefore honour a direct
    /// callback it never advertised it would honour — and rmule, gating route 2
    /// on the advert, would not have tried. That is aMule parity: aMule would not
    /// have tried either.
    #[must_use]
    pub const fn supports_direct_udp_callback(self) -> bool {
        (self.0 >> 12) & 1 != 0
    }

    /// Bit 10: `SupportsSourceEx2` — the peer accepts SX2 source exchange
    /// (`OP_REQUESTSOURCES2` / `OP_ANSWERSOURCES2`, ADR-0055). aMule
    /// `(misc2 >> 10) & 1`. The serve version pick reads this bit of the
    /// *requester's* hello to decide whether an SX2 request earns a `0x84`
    /// answer or falls to the SX1 `0x82` path.
    #[must_use]
    pub const fn supports_source_exchange2(self) -> bool {
        (self.0 >> 10) & 1 != 0
    }

    /// Light bit 12, `SupportsDirectUDPCallback`, when `accepts` — aMule's
    /// hello writer (`BaseClient.cpp:1131-1132`, `4e8f2b3c`): Kad running,
    /// Kad TCP firewalled, Kad UDP verified open. Applied at the
    /// hello-building call site from a live fact, like the Kad-version
    /// nibble; `false` leaves the word untouched.
    #[must_use]
    pub const fn with_direct_udp_callback(self, accepts: bool) -> Self {
        Self(self.0 | ((accepts as u32) << 12))
    }

    /// Fold the ADR-0047 registry's always-shipped ExtMultiPacket bit (bit
    /// 5, ADR-0054) into this crypt-stance word. Applied at
    /// the hello-building call site rather than inside
    /// [`Self::rmule_advertised`]: multipacket support does not depend on
    /// crypt policy, and folding it into the pure-crypt constructor would
    /// make [`Self::is_empty`] false for every crypt stance, breaking its
    /// "collapsed crypt ladder ⇒ empty" contract.
    #[must_use]
    pub const fn with_multipacket_ext(self) -> Self {
        let caps = Capabilities::shipped(CryptStance::disabled());
        Self(self.0 | ((caps.supports_multipacket() as u32) << 5))
    }

    /// Fold the ADR-0047 registry's `SupportsSourceEx2` bit (bit 10, ADR-0055)
    /// into this crypt-stance word — the peer-hello projection of
    /// [`Capabilities::supports_source_exchange2`]. Applied at the
    /// hello-building call site alongside [`Self::with_multipacket_ext`], for
    /// the same reason: SX2 support does not depend on crypt policy, so a
    /// dark crypt stance still advertises the capability.
    #[must_use]
    pub const fn with_source_exchange2(self) -> Self {
        let caps = Capabilities::shipped(CryptStance::disabled());
        Self(self.0 | ((caps.supports_source_exchange2() as u32) << 10))
    }

    /// rmule's honestly-advertised crypt stance. The cumulative dependency
    /// rule (aMule `BaseClient.cpp`: `requests &= supports; requires &=
    /// requests`) is enforced by [`CryptStance`] at construction, so a higher
    /// tier can never be lit without the lower — Honest Capability
    /// Advertisement (ADR-0047). `supports` is lit only when rmule genuinely
    /// accepts obfuscated inbound.
    #[must_use]
    pub const fn rmule_advertised(supports: bool, requests: bool, requires: bool) -> Self {
        Self::from_stance(CryptStance::new(supports, requests, requires))
    }

    /// Pack a registry [`CryptStance`] into the `MiscOptions2` crypt bits —
    /// the peer-hello projection of the single-source capability registry
    /// (ADR-0047).
    #[must_use]
    pub const fn from_stance(stance: CryptStance) -> Self {
        Self(
            ((stance.supports() as u32) << 7)
                | ((stance.requests() as u32) << 8)
                | ((stance.requires() as u32) << 9),
        )
    }

    /// Whether this word advertises no capability at all — rmule omits the tag
    /// entirely rather than emitting an all-zero `MiscOptions2` (it implements
    /// only the crypt bits).
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Extract a peer's advertised `MiscOptions2`, or `None` when absent.
    #[must_use]
    pub fn from_tags(tags: &[Tag]) -> Option<Self> {
        hello_int(tags, CT_EMULE_MISCOPTIONS2).map(Self::from_bits)
    }

    /// Encode as a `CT_EMULE_MISCOPTIONS2` hello tag (compact numeric name).
    #[must_use]
    pub fn to_tag(self) -> Tag {
        Tag::new(
            TagName::compact_id(CT_EMULE_MISCOPTIONS2),
            TagValue::U32(self.0),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{CT_EMULE_UDPPORTS, MiscOptions1, MiscOptions2, UdpPortsAdvert};
    use rmule_primitives::{Tag, TagName, TagValue};

    #[test]
    fn udp_ports_advert_packs_kad_high_client_low() {
        // aMule's pinned wire fact: both ports 4672 → 0x1240_1240, Kad in
        // the high 16, client in the low 16. Distinct ports catch a swapped
        // half.
        assert_eq!(UdpPortsAdvert::new(4672, 4672).packed(), 0x1240_1240);
        assert_eq!(UdpPortsAdvert::new(0x1234, 0xABCD).packed(), 0xABCD_1234);
        // Kad not running (aMule `IsRunning() ? kadPort : 0`): only the client
        // half rides.
        assert_eq!(UdpPortsAdvert::new(0x1240, 0).packed(), 0x0000_1240);
        // The tag carries the packed word under the canonical 0xF9 id.
        let tag = UdpPortsAdvert::new(0x1240, 0).to_tag();
        assert_eq!(tag.name().id(), Some(CT_EMULE_UDPPORTS));
        assert_eq!(tag.value(), &TagValue::U32(0x0000_1240));
        // Nothing bound ⇒ nothing to advertise.
        assert!(UdpPortsAdvert::new(0, 0).is_empty());
        assert!(!UdpPortsAdvert::new(0x1240, 0).is_empty());
    }

    #[test]
    fn with_udp_version_sets_only_its_nibble() {
        // Bits [24..28): the write must land in the same nibble the reader
        // (`udp_version`) extracts, leaving every other advertised field intact.
        let base = MiscOptions1::rmule_advertised();
        let with_udp = base.with_udp_version(4);
        assert_eq!(with_udp.udp_version(), 4);
        assert_eq!(
            with_udp.data_compression_version(),
            base.data_compression_version()
        );
        assert_eq!(
            with_udp.source_exchange_version(),
            base.source_exchange_version()
        );
        assert_eq!(with_udp.aich_version(), base.aich_version());
        assert_eq!(with_udp.supports_multipacket(), base.supports_multipacket());
    }

    #[test]
    fn rmule_advertises_honest_compression_source_exchange_and_aich() {
        let opts = MiscOptions1::rmule_advertised();
        // Honest Capability Advertisement (ADR-0047/0055/0038): data-compression
        // v1 (bits [20..24)), source-exchange nibble 3 (bits [12..16), aMule's
        // own value — ADR-0055), extended-requests v1 (bits [8..12)),
        // AICH v1 (bits [29..32)), multipacket (bit 1, ADR-0054), nothing else.
        assert_eq!(
            opts,
            MiscOptions1::from_bits((1 << 29) | (1 << 20) | (3 << 12) | (1 << 8) | (1 << 1))
        );
        assert_eq!(opts.extended_requests_version(), 1);
        assert_eq!(opts.data_compression_version(), 1);
        assert_eq!(opts.source_exchange_version(), 3);
        assert_eq!(opts.aich_version(), 1);
        assert!(opts.supports_multipacket());
        // Round-trips as a CT_EMULE_MISCOPTIONS1 hello tag.
        let tag = opts.to_tag();
        assert_eq!(
            MiscOptions1::from_tags(std::slice::from_ref(&tag)),
            Some(opts)
        );
    }

    #[test]
    fn source_exchange_version_isolates_its_nibble() {
        // Bits [12..16): aMule `(flags >> 4*3) & 0x0f`. Neighbouring fields are
        // set so a wrong offset or mask reads the wrong nibble and fails.
        let raw = (1u32 << 20)   // data-compression version
            | (5u32 << 12)       // source-exchange version  <- under test
            | (3u32 << 8); // extended-requests version
        assert_eq!(MiscOptions1::from_bits(raw).source_exchange_version(), 5);
    }

    #[test]
    fn with_source_exchange_version_patches_only_its_nibble() {
        let base = MiscOptions1::rmule_advertised();
        let patched = base.with_source_exchange_version(3);
        assert_eq!(patched.source_exchange_version(), 3);
        // Every other field survives untouched.
        assert_eq!(
            patched.data_compression_version(),
            base.data_compression_version()
        );
        assert_eq!(patched.aich_version(), base.aich_version());
        assert_eq!(patched.supports_multipacket(), base.supports_multipacket());
    }

    #[test]
    fn override_source_exchange_version_patches_the_tag_in_place() {
        let mut tags = vec![MiscOptions1::rmule_advertised().to_tag()];
        MiscOptions1::override_source_exchange_version(&mut tags, 3);
        let patched = MiscOptions1::from_tags(&tags).expect("tag still present");
        assert_eq!(patched.source_exchange_version(), 3);
    }

    #[test]
    fn override_source_exchange_version_is_a_no_op_without_the_tag() {
        // A hello with no CT_EMULE_MISCOPTIONS1 tag (non-eMule peer stance)
        // stays untouched rather than gaining a fabricated capability tag.
        let mut tags = vec![Tag::new(TagName::compact_id(0x01), TagValue::U8(7))];
        MiscOptions1::override_source_exchange_version(&mut tags, 3);
        assert_eq!(tags.len(), 1);
        assert_eq!(MiscOptions1::from_tags(&tags), None);
    }

    #[test]
    fn extracted_from_hello_tags_among_other_tags() {
        // A real hello carries several tags; the extractor must pick the
        // `CT_EMULE_MISCOPTIONS1` (0xFA) u32 tag and ignore the rest.
        let tags = vec![
            Tag::new(TagName::compact_id(0x01), TagValue::U8(7)), // unrelated tag
            Tag::new(TagName::compact_id(0xFA), TagValue::U32(1 << 20)), // misc-options1
        ];
        let opts = MiscOptions1::from_tags(&tags).expect("misc-options1 present");
        assert_eq!(opts.data_compression_version(), 1);
    }

    #[test]
    fn data_compression_version_isolates_its_nibble() {
        // Pinned from aMule `ProcessHelloTypePacket` @ `377ec8d9`:
        // `m_byDataCompVer = (flags >> 4*5) & 0x0f` — bits [20..24).
        // A composite value sets neighbouring fields too, so a wrong
        // offset or mask would read the wrong nibble and fail.
        let raw = (2u32 << 29)   // AICH version
            | (4u32 << 24)       // UDP version
            | (1u32 << 20)       // data-compression version  <- under test
            | (3u32 << 12); // source-exchange version
        let opts = MiscOptions1::from_bits(raw);
        assert_eq!(opts.data_compression_version(), 1);
    }

    #[test]
    fn udp_version_isolates_its_nibble() {
        // Bits [24..28): aMule `m_byUDPVer = (flags >> 4*6) & 0x0f`. Neighbours
        // (data-compression [20..24), AICH [29..32)) are set so a wrong offset
        // or mask reads the wrong nibble and fails.
        let raw = (1u32 << 20)   // data-compression version
            | (4u32 << 24)       // UDP version  <- under test
            | (2u32 << 29); // AICH version
        assert_eq!(MiscOptions1::from_bits(raw).udp_version(), 4);
    }

    #[test]
    fn misc_options2_isolates_the_crypt_bits() {
        // Crypt bits are 7/8/9 (aMule `(misc2 >> 7/8/9) & 1`). Set only bit 8 with
        // its neighbours (6, 10) also set, so a wrong offset reads the wrong bit.
        let raw = (1u32 << 6) | (1u32 << 8) | (1u32 << 10);
        let opts = MiscOptions2::from_bits(raw);
        assert!(!opts.supports_crypt_layer(), "bit 7 clear");
        assert!(opts.requests_crypt_layer(), "bit 8 set");
        assert!(!opts.requires_crypt_layer(), "bit 9 clear");
    }

    #[test]
    fn kad_version_isolates_the_low_nibble() {
        // aMule `m_byKadVersion = (misc2 >> 0) & 0x0f` — the low nibble. The
        // crypt bits (7/8/9) and ext-multipacket (5) are set alongside, so a
        // wrong offset or mask reads them instead of the Kad version.
        let raw = (1u32 << 9) | (1u32 << 7) | (1u32 << 5) | 0x08;
        assert_eq!(MiscOptions2::from_bits(raw).kad_version(), 8);
        // A word with no Kad-version nibble reads 0 (a non-Kad2 peer).
        assert_eq!(MiscOptions2::from_bits(1u32 << 7).kad_version(), 0);
    }

    #[test]
    fn rmule_advertised_applies_the_cumulative_crypt_dependency_rule() {
        // Honest ladder (aMule: requests &= supports; requires &= requests): a
        // higher tier is never lit without the lower.
        let requires_without_support = MiscOptions2::rmule_advertised(false, false, true);
        assert!(
            requires_without_support.is_empty(),
            "requires collapses without supports"
        );

        let requests_without_support = MiscOptions2::rmule_advertised(false, true, false);
        assert!(
            requests_without_support.is_empty(),
            "requests collapses without supports"
        );

        let supported = MiscOptions2::rmule_advertised(true, false, false);
        assert!(supported.supports_crypt_layer());
        assert!(!supported.requests_crypt_layer());
        assert!(!supported.requires_crypt_layer());

        let required = MiscOptions2::rmule_advertised(true, true, true);
        assert!(required.supports_crypt_layer());
        assert!(required.requests_crypt_layer());
        assert!(required.requires_crypt_layer());
    }

    #[test]
    fn misc_options2_round_trips_as_a_hello_tag() {
        let opts = MiscOptions2::rmule_advertised(true, true, false);
        let tag = opts.to_tag();
        assert_eq!(tag.name().id(), Some(0xFE));
        assert_eq!(
            MiscOptions2::from_tags(std::slice::from_ref(&tag)),
            Some(opts)
        );
        // A hello without the tag yields None.
        assert_eq!(MiscOptions2::from_tags(&[]), None);
    }

    #[test]
    fn with_multipacket_ext_lights_bit_five_without_disturbing_crypt_bits() {
        // ADR-0054: ExtMultiPacket doesn't depend on crypt policy, so it
        // folds in regardless of the crypt stance underneath — including a
        // fully-dark one, which `is_empty()` would otherwise call empty.
        let dark = MiscOptions2::rmule_advertised(false, false, false).with_multipacket_ext();
        assert!(dark.supports_multipacket_ext());
        assert!(!dark.supports_crypt_layer());
        assert!(
            !dark.is_empty(),
            "the ext-multipacket bit makes the word non-empty even with crypt fully dark"
        );

        let lit = MiscOptions2::rmule_advertised(true, true, true).with_multipacket_ext();
        assert!(lit.supports_multipacket_ext());
        assert!(lit.requires_crypt_layer());
    }
}
