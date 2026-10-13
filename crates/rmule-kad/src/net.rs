//! Shared network-admission primitives for the Kad surface: the IPv4 address
//! classifiers and the publish-tolerance gate the node, keyword store, notes
//! layer, and nodes.dat readers all apply.
//!
//! They live here rather than beside any one caller because the four
//! admission paths must agree byte for byte: a private copy in any of them
//! would be free to drift. The address classifiers are each the workspace's one
//! Reserved Range check ([`rmule_primitives::is_reserved_ipv4`], ADR-0085), read
//! for the question their caller asks.

use std::net::Ipv4Addr;

use crate::KadId;

/// The publish tolerance: a non-LAN publish is dropped unless the XOR distance's
/// most significant 32-bit word is at most this (aMule's `SEARCHTOLERANCE`).
/// Shared by the keyword (`0x43`), notes (`0x45`), and source publish-storer
/// gates, and by the Callback Walk's choice of whom to send the `0x52` to
/// (aMule's `CSearch::StorePacket` applies the one gate to every search type,
/// `Search.cpp:624-628`).
pub(crate) const PUBLISH_TOLERANCE: u32 = 0x0100_0000;

/// aMule's `IsLanIP` bypass, as the standard private/loopback ranges — the LAN
/// exemption every publish-tolerance gate shares.
pub(crate) fn is_lan_ip(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback()
}

/// The most significant 32-bit word of the XOR distance under the proven
/// `word_le_msw_first` order: bytes 0..4 read little-endian.
pub(crate) fn distance_top_word(own: KadId, key: KadId) -> u32 {
    let own_word = u32::from_le_bytes(own.as_bytes()[..4].try_into().expect("4 bytes"));
    let key_word = u32::from_le_bytes(key.as_bytes()[..4].try_into().expect("4 bytes"));
    own_word ^ key_word
}

/// aMule's `IsGoodIPPort` contact-admission gate, as the nodes.dat readers
/// apply it (the per-contact filter block, `RoutingZone.cpp#L193`; ADR-0066)
/// with the LAN filter on — Kad is a public-internet DHT: a contact is dialable
/// only with a nonzero port and a routable IP.
///
/// That is the one Reserved Range check every intake applies
/// ([`rmule_primitives::is_reserved_ipv4`], ADR-0085) plus the private ranges
/// and loopback ([`is_lan_ip`]), as aMule's `IsGoodIPPort` is `IsGoodIP` with
/// its LAN filter on (`NetworkFunctions.h:118-121`).
pub(crate) fn is_good_ip_port(ip: Ipv4Addr, port: u16) -> bool {
    port != 0 && !rmule_primitives::is_reserved_ipv4(ip) && !is_lan_ip(ip)
}

/// Whether some informant could make `ip` one host's address: it lies in no
/// Reserved Range, or it is loopback, which stands on an informant from this
/// host ([`rmule_primitives::Informant::admits`], ADR-0085).
///
/// A source row's `TAG_SOURCEIP` (the `0x95` target) is the storer's
/// observation of where the publish came from. The reader does not know the
/// storer, so it keeps only what some informant could vouch for, and the
/// Source Book gate judges the rest against the storer that answered: a storer
/// that shares a host with its publisher truly observes loopback, which is a
/// peer only when that storer is on our host too.
pub(crate) fn may_name_a_host(ip: Ipv4Addr) -> bool {
    rmule_primitives::Informant::Own.admits(std::net::IpAddr::V4(ip))
}

/// Whether a *claimed* IPv4 may be the target of a datagram rmule sends on
/// the claim alone: a source row's `TAG_SERVERIP`, the buddy a `0x52` or a
/// rendezvous goes to. It must lie in no Reserved Range
/// ([`rmule_primitives::is_reserved_ipv4`], ADR-0085), loopback included: the
/// buddy is a third party the row names, judged with no informant at hand, and
/// a row whose buddy has no endpoint is still walked to by the buddy's ID.
///
/// The private ranges are admitted: a LAN peer is a peer (ADR-0085). aMule
/// applies no filter to the buddy address (`DownloadQueue.cpp:1714` filters
/// only the source IP), and eMuleAI applies only its user IP filter
/// (`DownloadQueue.cpp:4932-4942`).
pub(crate) fn is_claimed_udp_target(ip: Ipv4Addr) -> bool {
    !rmule_primitives::is_reserved_ipv4(ip)
}
