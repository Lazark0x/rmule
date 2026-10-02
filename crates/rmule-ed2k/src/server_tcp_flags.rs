//! `SRV_TCPFLG_*` projected onto its consumers: the [`ServerGrants`] a
//! session reads once at `OP_IDCHANGE`. The typed word itself,
//! [`ServerTcpFlags`], lives in `rmule-primitives` beside the UDP word;
//! each grant's consumer site is pinned in
//! `docs/reference/notes/ed2k-login.md`. Cite-and-rewrite only (ADR-0004).

use rmule_primitives::ServerTcpFlags;

/// What the connected server granted this session (ADR-0047): every
/// `SRV_TCPFLG_*` bit projected once at `OP_IDCHANGE` onto the consumer
/// that gates on it, instead of raw-bit reads at each site. A session that
/// has not seen flags (no IDCHANGE yet, or the bare 4-byte reply) holds the
/// `Default` — nothing granted, every gated path takes its legacy form.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ServerGrants {
    /// `COMPRESSION`: the server speaks packed `0xD4` frames toward rmule
    /// and reads the compressed-capable offer-id magic (aMule
    /// `KnownFile.cpp` — complete `0xFBFBFBFB`/`0xFBFB`, incomplete
    /// `0xFCFCFCFC`/`0xFCFC`). Consumer: the packed-frames codec.
    pub compression: bool,
    /// `NEWTAGS`: offers may use the compact new-eD2k tag form (aMule
    /// `WriteNewEd2kTag`). Consumer: the offer tag codec's variant choice.
    pub new_tags: bool,
    /// `UNICODE`: strings toward the server encode as UTF-8 (aMule
    /// `GetUnicodeSupport()` → `utf8strRaw`). Consumer: the same offer/
    /// search string codec.
    pub unicode: bool,
    /// `RELATEDSEARCH`: the server answers related-search queries. No rmule
    /// feature reads it — modelled for parity completeness (aMule
    /// `GetRelatedSearchSupport()`).
    pub related_search: bool,
    /// `TYPETAGINTEGER`: offers may carry the integer `FT_FILETYPE` tag
    /// (aMule `CreateOfferedFilePacket`). Consumer: the offer tag codec's
    /// variant choice.
    pub type_tag_integer: bool,
    /// `LARGEFILES`: 64-bit sizes in offers and get-sources (aMule
    /// `SupportsLargeFilesTCP()`). Consumer: the session's large-file
    /// command gates.
    pub large_files: bool,
    /// `TCPOBFUSCATION`: together with a non-zero obfuscation TCP port (the
    /// IDCHANGE extension or the `0x97` reply) this feeds ADR-0042's
    /// server-crypt dial (aMule `SupportsObfuscationTCP()`, which also ORs
    /// in the UDP-side advert).
    pub tcp_obfuscation: bool,
    /// `IPV6`: the server speaks the emule-qt IPv6 extension (ADR-0087 §4.2).
    /// **No rmule path gates on it** — the sentinel reader is always active and
    /// the login tag is gated on rmule's own address — so this is what a
    /// capable server looks like from the outside, not a permission.
    pub ipv6: bool,
}

impl From<ServerTcpFlags> for ServerGrants {
    fn from(flags: ServerTcpFlags) -> Self {
        Self {
            compression: flags.supports_compression(),
            new_tags: flags.supports_new_tags(),
            unicode: flags.supports_unicode(),
            related_search: flags.supports_related_search(),
            type_tag_integer: flags.supports_type_tag_integer(),
            large_files: flags.supports_large_files(),
            tcp_obfuscation: flags.supports_tcp_obfuscation(),
            ipv6: flags.supports_ipv6(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type GrantRead = fn(ServerGrants) -> bool;

    #[test]
    fn each_wire_bit_projects_onto_exactly_its_grant() {
        // The (bit, projection) table IS the parity claim: aMule
        // `Client2Server/TCP.h` values routed per `Server.h`'s predicates.
        let cases: [(u32, GrantRead); 8] = [
            (0x0000_0001, |g| g.compression),
            (0x0000_0008, |g| g.new_tags),
            (0x0000_0010, |g| g.unicode),
            (0x0000_0040, |g| g.related_search),
            (0x0000_0080, |g| g.type_tag_integer),
            (0x0000_0100, |g| g.large_files),
            (0x0000_0400, |g| g.tcp_obfuscation),
            (0x0000_4000, |g| g.ipv6),
        ];
        for (bit, grant) in cases {
            let granted = ServerGrants::from(ServerTcpFlags::from_bits(bit));
            assert!(grant(granted), "bit {bit:#010x} grants its consumer");
            let others = ServerGrants::from(ServerTcpFlags::from_bits(!bit));
            assert!(!grant(others), "bit {bit:#010x} is granted by no other");
        }
    }

    /// The live word a third party measured from an IPv6-capable server over
    /// *both* families (`tcpFlags = 0x000045DD`, amule#1177 → ed2k-server#12):
    /// the capability is not gated on the arrival family, which is the
    /// behaviour a client should be able to rely on.
    ///
    /// Evidence: **deterministic tier, awaiting a pinned IPv6 server** — a relayed
    /// measurement, not bytes rmule captured.
    #[test]
    fn the_live_ipv6_server_flag_word_reads_the_extension_bit() {
        let granted = ServerGrants::from(ServerTcpFlags::from_bits(0x0000_45DD));
        assert!(granted.ipv6);
        assert!(granted.compression, "0x45DD still grants what it granted");
        assert!(granted.large_files);
        assert!(granted.tcp_obfuscation);
    }

    #[test]
    fn unknown_bits_grant_nothing_but_stay_readable() {
        // Bits outside aMule's modelled set (0x02, 0x200, …) must not light
        // any grant, and the raw word survives for diagnostics.
        let flags = ServerTcpFlags::from_bits(0x0000_0202);
        assert_eq!(ServerGrants::from(flags), ServerGrants::default());
        assert_eq!(flags.bits(), 0x0000_0202);
    }
}
