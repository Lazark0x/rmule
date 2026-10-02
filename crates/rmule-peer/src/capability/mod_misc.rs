//! `CT_MOD_MISCOPTIONS` (`0xAA`) — the **Static Capability Claim** the IPv6
//! dialect's mod family carries in every hello (ADR-0087).
//!
//! This word is unlike [`MiscOptions1`](super::MiscOptions1) /
//! [`MiscOptions2`](super::MiscOptions2) in one way that matters: it is
//! *static*. rmule claims the bits it implements on every hello, whether or
//! not it currently holds an IPv6 address, because peers read an absent bit as
//! "no support" and would then never send an IPv6 source. What is *true now*
//! rides in `CT_MOD_IP_V6` instead — the bit says what rmule can do, the tag
//! says what holds (ADR-0047's Honest Capability Advertisement, applied to a
//! two-channel advert).
//!
//! Received bits are masked to the set rmule has a meaning for. A dropped bit
//! then reads as **absent**, not as unknown — a different and weaker claim,
//! which is the honest one: rmule cannot act on a capability it does not model.

use rmule_primitives::{CT_MOD_MISCOPTIONS, Tag, TagName, TagValue};

/// Bit 0 `MODMISC_EXTENDED_XS`: the peer reads and writes the **ExtSX** record
/// form, the IPv6 dialect's source-exchange carrier.
const EXTENDED_XS: u32 = 1 << 0;
/// Bit 1 `MODMISC_NAT_TRAVERSAL`: uTP NAT traversal (ADR-0091).
const NAT_TRAVERSAL: u32 = 1 << 1;
/// Bit 2 `MODMISC_IPV6`: the peer speaks the IPv6 dialect.
const IPV6: u32 = 1 << 2;
/// Bit 3 `MODMISC_SERVING_BUDDY_PULL`. Not implemented.
const SERVING_BUDDY_PULL: u32 = 1 << 3;
/// Bit 4 `MODMISC_NAT_TRAVERSAL_QUIC` (ADR-0091). Dark until a live
/// QUIC handshake is proven against eMuleAI or kno's build: an optimistic bit
/// 4 costs *the peer* a 1500 ms CAPS stall on every attempt, so claiming it
/// early is a cost rmule exports rather than pays.
const NAT_TRAVERSAL_QUIC: u32 = 1 << 4;
/// Bit 5 `MODMISC_EXTXS_SKIPTAGS`: the peer skips an unknown ExtSX tag by type
/// instead of abandoning the packet, so it is safe to send the optional
/// `USERHASH`/`CONOPTS` tags to.
const EXTXS_SKIPTAGS: u32 = 1 << 5;

/// The bits rmule has a meaning for — aMule's `MOD_MISCOPT_KNOWN_MASK`
/// (`0x1F`) plus the spec's bit 5, spelled out bit by bit so the mask and the
/// layout cannot drift. Bit 10 (`MODMISC_HTTPCACHE`) is outside it
/// deliberately: rmule has no HTTP cache, so reading the bit would claim a
/// knowledge it does not have.
const KNOWN_MASK: u32 =
    EXTENDED_XS | NAT_TRAVERSAL | IPV6 | SERVING_BUDDY_PULL | NAT_TRAVERSAL_QUIC | EXTXS_SKIPTAGS;
const _: () = assert!(KNOWN_MASK == 0x3F, "aMule's 0x1F plus the spec's bit 5");

/// The `CT_MOD_MISCOPTIONS` bitset — what a peer of the IPv6 dialect's mod
/// family claims it can do, masked to the bits rmule models.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ModMiscOptions(u32);

impl ModMiscOptions {
    /// Read a received word, masking away every bit rmule has no meaning for.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits & KNOWN_MASK)
    }

    /// The masked word.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// rmule's **Static Capability Claim**:
    /// `EXTXS | NAT_TRAVERSAL | IPV6 | EXTXS_SKIPTAGS`.
    ///
    /// Bit 1 rides per ADR-0091: rmule speaks the `0xB2 0x00` uTP
    /// tunnel and demuxes the envelope on its advertised client-UDP port.
    /// Bit 4 stays dark — rmule is uTP-only exactly like an eMuleAI build with
    /// no QUIC runtime, and the bit flips only when a live handshake proves
    /// it. The buddy-pull bit is not implemented at all. Nothing here is
    /// conditional on holding an address: the claim is what rmule *can* speak.
    #[must_use]
    pub const fn rmule_claim() -> Self {
        Self(EXTENDED_XS | NAT_TRAVERSAL | IPV6 | EXTXS_SKIPTAGS)
    }

    /// What this word claims about NAT-T, as the pair the CAPS negotiation
    /// reads (bits 1 and 4 together — the *combination* is what decides
    /// whether a silent endpoint may be treated as legacy-uTP-only).
    #[must_use]
    pub const fn natt_claim(self) -> crate::natt::HelloNattClaim {
        crate::natt::HelloNattClaim {
            utp: self.0 & NAT_TRAVERSAL != 0,
            quic: self.0 & NAT_TRAVERSAL_QUIC != 0,
        }
    }

    /// The peer reads and writes **ExtSX** records (bit 0). Gates both halves:
    /// rmule emits the extended form only to such a peer, and only such a peer
    /// could have sent one.
    #[must_use]
    pub const fn supports_ext_sx(self) -> bool {
        self.0 & EXTENDED_XS != 0
    }

    /// The peer speaks the IPv6 dialect (bit 2). A claim, never a fact — the
    /// fact is the peer's `CT_MOD_IP_V6` tag.
    #[must_use]
    pub const fn supports_ipv6(self) -> bool {
        self.0 & IPV6 != 0
    }

    /// The peer skips an unknown ExtSX tag rather than abandoning the whole
    /// answer (bit 5). Gates *emission* of the optional `CT_EMULE_USERHASH` /
    /// `CT_EMULE_CONOPTS` tags only; both are accepted from anybody.
    #[must_use]
    pub const fn skips_unknown_ext_sx_tags(self) -> bool {
        self.0 & EXTXS_SKIPTAGS != 0
    }

    /// Whether the word claims nothing — an all-dark advert, which rides as no
    /// tag at all on a surface that omits empty capability words.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Read the claim from a hello's tags, or `None` when the peer sent none
    /// (every pre-mod client).
    #[must_use]
    pub fn from_tags(tags: &[Tag]) -> Option<Self> {
        crate::hello::hello_int(tags, CT_MOD_MISCOPTIONS).map(Self::from_bits)
    }

    /// Encode as the hello's `CT_MOD_MISCOPTIONS` tag, in the old-format
    /// length-prefixed name spelling the dialect's worked hex carries
    /// (`03 01 00 AA …`).
    #[must_use]
    pub fn to_tag(self) -> Tag {
        Tag::new(
            TagName::length_prefixed_id(CT_MOD_MISCOPTIONS),
            TagValue::U32(self.0),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The spec's worked hex: `EXTXS | IPV6` = `5`, written as an old-format
    /// `TAGTYPE_UINT32` under a length-prefixed `0xAA` name.
    #[test]
    fn the_claim_tag_encodes_to_the_specs_worked_bytes() {
        let claim = ModMiscOptions::from_bits(EXTENDED_XS | IPV6);
        assert_eq!(
            claim.to_tag().encode(),
            vec![0x03, 0x01, 0x00, 0xAA, 0x05, 0x00, 0x00, 0x00]
        );
    }

    /// rmule's own claim: ExtSX, uTP NAT-T, IPv6, skip-tags. Bit 4 is the
    /// one that must stay dark — it is a promise to serve QUIC, and a peer
    /// believing it pays 1500 ms per attempt to find out otherwise.
    #[test]
    fn rmules_claim_lights_utp_nat_traversal_and_leaves_quic_dark() {
        let claim = ModMiscOptions::rmule_claim();
        assert_eq!(claim.bits(), 0x27);
        assert!(claim.supports_ext_sx());
        assert!(claim.supports_ipv6());
        assert!(claim.skips_unknown_ext_sx_tags());
        assert!(claim.natt_claim().utp);
        assert!(!claim.natt_claim().quic);
        assert_eq!(claim.bits() & NAT_TRAVERSAL_QUIC, 0);
        assert_eq!(claim.bits() & SERVING_BUDDY_PULL, 0);
    }

    /// A peer's claim is read as the pair the negotiation needs, both bits
    /// independently.
    #[test]
    fn a_peers_natt_claim_reads_both_bits() {
        let both = ModMiscOptions::from_bits(NAT_TRAVERSAL | NAT_TRAVERSAL_QUIC).natt_claim();
        assert!(both.utp && both.quic);
        assert!(!both.is_legacy_utp_only());
        let legacy = ModMiscOptions::from_bits(NAT_TRAVERSAL).natt_claim();
        assert!(legacy.is_legacy_utp_only());
        let none = ModMiscOptions::from_bits(EXTENDED_XS).natt_claim();
        assert!(!none.claims_any());
    }

    /// An unknown bit is dropped on receipt, so it reads as absent rather than
    /// as a capability rmule might act on. Bit 10 (`HTTPCACHE`) is the live
    /// example — the dialect defines it and rmule does not implement it.
    #[test]
    fn received_bits_outside_the_known_set_are_masked_away() {
        let received = ModMiscOptions::from_bits(0xFFFF_FFFF);
        assert_eq!(received.bits(), 0x3F);
        assert_eq!(ModMiscOptions::from_bits(1 << 10).bits(), 0);
        assert!(ModMiscOptions::from_bits(1 << 10).is_empty());
    }

    /// A hello with no claim tag reads as `None`, not as an all-dark claim:
    /// "said nothing" and "said no" are different, and only the second is a
    /// statement a peer made.
    #[test]
    fn a_hello_without_the_tag_reads_as_no_claim_at_all() {
        let claim = ModMiscOptions::rmule_claim();
        let tags = vec![
            Tag::new(TagName::compact_id(0x01), TagValue::U32(7)),
            claim.to_tag(),
        ];
        assert_eq!(ModMiscOptions::from_tags(&tags), Some(claim));
        assert_eq!(ModMiscOptions::from_tags(&tags[..1]), None);
    }
}
