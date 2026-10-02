//! The server's two capability flag words: `SRV_TCPFLG_*`, the TCP-session
//! grants of its `OP_IDCHANGE` reply (payload bytes 4..8, ADR-0047), and
//! `SRV_UDPFLG_*`, the UDP flags of its `0x97` status answer (ADR-0052).
//! Wire values from aMule `src/include/protocol/ed2k/Client2Server/TCP.h`
//! and `UDP.h`; each grant's consumer site is pinned in
//! `docs/reference/notes/ed2k-login.md`. Cite-and-rewrite only (ADR-0004).
//!
//! Each word is a typed set over its raw bits: the named flags iterate in bit
//! order as a typed flag, and the bits no client names stay readable as such,
//! so a front end words the set without knowing a single mask.

/// The raw `SRV_TCPFLG_*` word, a transparent newtype: unknown bits are
/// preserved (`bits()`) and every modelled bit has a focused predicate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ServerTcpFlags(u32);

impl ServerTcpFlags {
    /// The server sends packed frames; a client that cannot inflate them
    /// must not claim the grant.
    pub const COMPRESSION: u32 = 0x0000_0001;
    /// The server reads the newer tag encodings.
    pub const NEWTAGS: u32 = 0x0000_0008;
    /// The server reads Unicode strings.
    pub const UNICODE: u32 = 0x0000_0010;
    /// The server answers related-file searches.
    pub const RELATEDSEARCH: u32 = 0x0000_0040;
    /// The server wants the file-type constraint as an integer tag rather
    /// than a string.
    pub const TYPETAGINTEGER: u32 = 0x0000_0080;
    /// The server indexes files past 4 GiB.
    pub const LARGE_FILES: u32 = 0x0000_0100;
    /// The server accepts obfuscated TCP connections.
    pub const TCPOBFUSCATION: u32 = 0x0000_0400;
    /// The server speaks the emule-qt IPv6 extension (ADR-0087 §4.2): it may
    /// publish **Sentinel Sources**, carry the `OP_SERVERIDENT` IPv6 tags, and
    /// relay `OP_CALLBACKREQUESTED_IPV6`.
    ///
    /// Not gated on. The asymmetry is deliberate and matches the reference
    /// implementation: rmule's inline sentinel reader is always active and its
    /// login tag is gated on rmule's own advertise state, so a server that
    /// never echoes this bit still interoperates. Reading it makes a capable
    /// server *visible* — to diagnostics, and to a future decision that wants
    /// to know before it asks.
    pub const IPV6: u32 = 0x0000_4000;

    /// Wrap the advertised word. Unknown bits are kept, not masked.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// The word as advertised.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether [`Self::COMPRESSION`] is set.
    #[must_use]
    pub const fn supports_compression(self) -> bool {
        self.0 & Self::COMPRESSION != 0
    }

    /// Whether [`Self::NEWTAGS`] is set.
    #[must_use]
    pub const fn supports_new_tags(self) -> bool {
        self.0 & Self::NEWTAGS != 0
    }

    /// Whether [`Self::UNICODE`] is set.
    #[must_use]
    pub const fn supports_unicode(self) -> bool {
        self.0 & Self::UNICODE != 0
    }

    /// Whether [`Self::RELATEDSEARCH`] is set.
    #[must_use]
    pub const fn supports_related_search(self) -> bool {
        self.0 & Self::RELATEDSEARCH != 0
    }

    /// Whether [`Self::TYPETAGINTEGER`] is set — which spelling a search's file-type constraint must use.
    #[must_use]
    pub const fn supports_type_tag_integer(self) -> bool {
        self.0 & Self::TYPETAGINTEGER != 0
    }

    /// Whether [`Self::LARGE_FILES`] is set — the gate on offering or searching for a file past 4 GiB.
    #[must_use]
    pub const fn supports_large_files(self) -> bool {
        self.0 & Self::LARGE_FILES != 0
    }

    /// Whether [`Self::TCPOBFUSCATION`] is set.
    #[must_use]
    pub const fn supports_tcp_obfuscation(self) -> bool {
        self.0 & Self::TCPOBFUSCATION != 0
    }

    /// Whether [`Self::IPV6`] is set — the server claims the IPv6 extension.
    #[must_use]
    pub const fn supports_ipv6(self) -> bool {
        self.0 & Self::IPV6 != 0
    }
}

/// One `SRV_TCPFLG_*` bit rmule names. Declaration order is bit order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ServerTcpFlag {
    /// [`ServerTcpFlags::COMPRESSION`].
    Compression = ServerTcpFlags::COMPRESSION,
    /// [`ServerTcpFlags::NEWTAGS`].
    NewTags = ServerTcpFlags::NEWTAGS,
    /// [`ServerTcpFlags::UNICODE`].
    Unicode = ServerTcpFlags::UNICODE,
    /// [`ServerTcpFlags::RELATEDSEARCH`].
    RelatedSearch = ServerTcpFlags::RELATEDSEARCH,
    /// [`ServerTcpFlags::TYPETAGINTEGER`].
    TypeTagInteger = ServerTcpFlags::TYPETAGINTEGER,
    /// [`ServerTcpFlags::LARGE_FILES`].
    LargeFiles = ServerTcpFlags::LARGE_FILES,
    /// [`ServerTcpFlags::TCPOBFUSCATION`].
    TcpObfuscation = ServerTcpFlags::TCPOBFUSCATION,
    /// [`ServerTcpFlags::IPV6`].
    Ipv6 = ServerTcpFlags::IPV6,
}

impl ServerTcpFlag {
    /// Every named flag, in bit order.
    pub const ALL: [Self; 8] = [
        Self::Compression,
        Self::NewTags,
        Self::Unicode,
        Self::RelatedSearch,
        Self::TypeTagInteger,
        Self::LargeFiles,
        Self::TcpObfuscation,
        Self::Ipv6,
    ];

    /// The flag's wire bit.
    #[must_use]
    pub const fn bit(self) -> u32 {
        self as u32
    }
}

impl ServerTcpFlags {
    /// Whether `flag` is set.
    #[must_use]
    pub const fn contains(self, flag: ServerTcpFlag) -> bool {
        self.0 & flag.bit() != 0
    }

    /// The named flags set in the word, in bit order.
    pub fn named(self) -> impl Iterator<Item = ServerTcpFlag> {
        ServerTcpFlag::ALL
            .into_iter()
            .filter(move |flag| self.contains(*flag))
    }

    /// The set bits no client names — a server's private bits.
    #[must_use]
    pub fn unnamed_bits(self) -> u32 {
        ServerTcpFlag::ALL
            .iter()
            .fold(self.0, |rest, flag| rest & !flag.bit())
    }
}

/// A server's advertised UDP capability flags, from the `0x97` reply's
/// `size >= 28` field (aMule `UDP.h` `SRV_UDPFLG_*`). Gates the get-sources
/// `0x94` upgrade (`EXT_GETSOURCES2`), global-search variant selection
/// (`EXT_GETFILES` / `LARGEFILES`, ADR-0051), and datagram crypt
/// (`UDPOBFUSCATION`, ADR-0046).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ServerUdpFlags(u32);

impl ServerUdpFlags {
    /// The server answers extended get-sources over UDP.
    pub const EXT_GETSOURCES: u32 = 0x0000_0001;
    /// The server answers global file searches over UDP.
    pub const EXT_GETFILES: u32 = 0x0000_0002;
    /// The server reads the newer tag encodings.
    pub const NEWTAGS: u32 = 0x0000_0008;
    /// The server reads Unicode strings.
    pub const UNICODE: u32 = 0x0000_0010;
    /// The server answers the second extended get-sources form — the one that
    /// carries file size, so large files resolve.
    pub const EXT_GETSOURCES2: u32 = 0x0000_0020;
    /// The server indexes files past 4 GiB.
    pub const LARGEFILES: u32 = 0x0000_0100;
    /// The server accepts obfuscated datagrams.
    pub const UDPOBFUSCATION: u32 = 0x0000_0200;
    /// The server accepts obfuscated TCP connections.
    pub const TCPOBFUSCATION: u32 = 0x0000_0400;
    /// The server speaks the emule-qt IPv6 extension over UDP (ADR-0087 §4.2):
    /// the same `0x4000` bit as the TCP `OP_IDCHANGE` word, and stated
    /// independently of it. Read, never gated on — a `0x9B` reply's sentinel
    /// records are gated by the *query's own source family*, because a UDP
    /// query carries no session state to gate on.
    pub const IPV6: u32 = 0x0000_4000;

    /// Wrap the advertised flag word. Unknown bits are kept, not masked — a
    /// future flag must survive a round trip.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// The flag word as advertised.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether [`Self::EXT_GETSOURCES`] is set.
    #[must_use]
    pub const fn supports_ext_get_sources(self) -> bool {
        self.0 & Self::EXT_GETSOURCES != 0
    }

    /// Whether [`Self::EXT_GETFILES`] is set.
    #[must_use]
    pub const fn supports_ext_get_files(self) -> bool {
        self.0 & Self::EXT_GETFILES != 0
    }

    /// Whether [`Self::NEWTAGS`] is set.
    #[must_use]
    pub const fn supports_new_tags(self) -> bool {
        self.0 & Self::NEWTAGS != 0
    }

    /// Whether [`Self::UNICODE`] is set.
    #[must_use]
    pub const fn supports_unicode(self) -> bool {
        self.0 & Self::UNICODE != 0
    }

    /// Whether [`Self::EXT_GETSOURCES2`] is set — the upgrade a large-file source lookup needs.
    #[must_use]
    pub const fn supports_ext_get_sources2(self) -> bool {
        self.0 & Self::EXT_GETSOURCES2 != 0
    }

    /// Whether [`Self::LARGEFILES`] is set.
    #[must_use]
    pub const fn supports_large_files(self) -> bool {
        self.0 & Self::LARGEFILES != 0
    }

    /// Whether [`Self::UDPOBFUSCATION`] is set — the gate on sending this server obfuscated datagrams.
    #[must_use]
    pub const fn supports_udp_obfuscation(self) -> bool {
        self.0 & Self::UDPOBFUSCATION != 0
    }

    /// Whether [`Self::TCPOBFUSCATION`] is set — the gate on dialing its obfuscated TCP port.
    #[must_use]
    pub const fn supports_tcp_obfuscation(self) -> bool {
        self.0 & Self::TCPOBFUSCATION != 0
    }

    /// Whether [`Self::IPV6`] is set — the server claims the IPv6 extension on
    /// its UDP surface too.
    #[must_use]
    pub const fn supports_ipv6(self) -> bool {
        self.0 & Self::IPV6 != 0
    }
}

/// One `SRV_UDPFLG_*` bit rmule names. Declaration order is bit order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ServerUdpFlag {
    /// [`ServerUdpFlags::EXT_GETSOURCES`].
    ExtGetSources = ServerUdpFlags::EXT_GETSOURCES,
    /// [`ServerUdpFlags::EXT_GETFILES`].
    ExtGetFiles = ServerUdpFlags::EXT_GETFILES,
    /// [`ServerUdpFlags::NEWTAGS`].
    NewTags = ServerUdpFlags::NEWTAGS,
    /// [`ServerUdpFlags::UNICODE`].
    Unicode = ServerUdpFlags::UNICODE,
    /// [`ServerUdpFlags::EXT_GETSOURCES2`].
    ExtGetSources2 = ServerUdpFlags::EXT_GETSOURCES2,
    /// [`ServerUdpFlags::LARGEFILES`].
    LargeFiles = ServerUdpFlags::LARGEFILES,
    /// [`ServerUdpFlags::UDPOBFUSCATION`].
    UdpObfuscation = ServerUdpFlags::UDPOBFUSCATION,
    /// [`ServerUdpFlags::TCPOBFUSCATION`].
    TcpObfuscation = ServerUdpFlags::TCPOBFUSCATION,
    /// [`ServerUdpFlags::IPV6`].
    Ipv6 = ServerUdpFlags::IPV6,
}

impl ServerUdpFlag {
    /// Every named flag, in bit order.
    pub const ALL: [Self; 9] = [
        Self::ExtGetSources,
        Self::ExtGetFiles,
        Self::NewTags,
        Self::Unicode,
        Self::ExtGetSources2,
        Self::LargeFiles,
        Self::UdpObfuscation,
        Self::TcpObfuscation,
        Self::Ipv6,
    ];

    /// The flag's wire bit.
    #[must_use]
    pub const fn bit(self) -> u32 {
        self as u32
    }
}

impl ServerUdpFlags {
    /// Whether `flag` is set.
    #[must_use]
    pub const fn contains(self, flag: ServerUdpFlag) -> bool {
        self.0 & flag.bit() != 0
    }

    /// The named flags set in the word, in bit order.
    pub fn named(self) -> impl Iterator<Item = ServerUdpFlag> {
        ServerUdpFlag::ALL
            .into_iter()
            .filter(move |flag| self.contains(*flag))
    }

    /// The set bits no client names — a server's private bits.
    #[must_use]
    pub fn unnamed_bits(self) -> u32 {
        ServerUdpFlag::ALL
            .iter()
            .fold(self.0, |rest, flag| rest & !flag.bit())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A front end words the named flags in the order `named` yields them, so
    /// `ALL` must hold each bit once, single-bit, ascending.
    #[test]
    fn named_flags_are_distinct_single_bits_in_bit_order() {
        let tcp: Vec<u32> = ServerTcpFlag::ALL.iter().map(|flag| flag.bit()).collect();
        let udp: Vec<u32> = ServerUdpFlag::ALL.iter().map(|flag| flag.bit()).collect();
        for bits in [tcp, udp] {
            assert!(bits.iter().all(|bit| bit.is_power_of_two()));
            assert!(bits.windows(2).all(|pair| pair[0] < pair[1]));
        }
    }

    #[test]
    fn a_word_splits_into_its_named_flags_and_the_bits_no_client_names() {
        // Related search, plus bits 2, 11, 12 and 31, which no client names.
        let tcp = ServerTcpFlags::from_bits(0x8000_1844);
        assert_eq!(
            tcp.named().collect::<Vec<_>>(),
            [ServerTcpFlag::RelatedSearch]
        );
        assert_eq!(tcp.unnamed_bits(), 0x8000_1804);
        let udp = ServerUdpFlags::from_bits(0x0000_0723);
        assert_eq!(
            udp.named().collect::<Vec<_>>(),
            [
                ServerUdpFlag::ExtGetSources,
                ServerUdpFlag::ExtGetFiles,
                ServerUdpFlag::ExtGetSources2,
                ServerUdpFlag::LargeFiles,
                ServerUdpFlag::UdpObfuscation,
                ServerUdpFlag::TcpObfuscation,
            ]
        );
        assert_eq!(udp.unnamed_bits(), 0);
    }
}
