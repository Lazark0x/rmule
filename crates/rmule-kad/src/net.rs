//! Shared network-admission primitives for the Kad surface: the IPv4 address
//! classifiers and the publish-tolerance gate the node, keyword store, notes
//! layer, and nodes.dat readers all apply.
//!
//! They live here rather than beside any one caller because the four
//! admission paths must agree byte for byte: a private copy in any of them
//! would be free to drift.

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
/// Rejects the unspecified address (`0.0.0.0`), the loopback and RFC1918
/// private ranges (via [`is_lan_ip`]), and the link-local block (`169.254/16`)
/// — exactly the ranges aMule's `IsGoodIP`/`IsLANIP` refuse, none of which can
/// host a live Kad node. aMule's `IsGoodIP` filters no further, so multicast,
/// broadcast, and the `240/4` reserved block are deliberately *not* rejected
/// here either: adding them would drop contacts aMule would load, diverging
/// from its routing-table admission.
pub(crate) fn is_good_ip_port(ip: Ipv4Addr, port: u16) -> bool {
    port != 0 && !ip.is_unspecified() && !is_lan_ip(ip) && !ip.is_link_local()
}

/// Whether an IPv4 can name one remote host at all. It refuses `0.0.0.0`
/// and everything from `224.0.0.0` up: multicast (`224/4`) and the reserved
/// `240/4`, which holds the limited broadcast `255.255.255.255`. That is
/// also eMuleAI's `UINT_MAX` stand-in for an IPv6 address in a 32-bit field
/// (`CAddress::ToUInt32`, eMuleAI `Address.cpp:91-92`).
///
/// A source row's `TAG_SOURCEIP` (the `0x95` target) passes this gate
/// alone. That address is the storer's observation of where the publish
/// came from, not a claim, and a storer that shares a host with its
/// publisher truly observes loopback.
pub(crate) fn is_unicast_host(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && ip.octets()[0] < 224
}

/// Whether a *claimed* IPv4 may be the target of a datagram rmule sends on
/// the claim alone: a source row's `TAG_SERVERIP`, the buddy a `0x52` or a
/// rendezvous goes to. It must be [`is_unicast_host`] and also neither
/// loopback nor link-local, so a row cannot aim rmule at its own host or at
/// its link.
///
/// The private ranges stay admitted. rmule's Kad serves LAN peers (the
/// [`is_lan_ip`] tolerance bypass), and the counterparties do not filter
/// the buddy address by range. aMule applies no filter to it
/// (`DownloadQueue.cpp:1714` filters only the source IP), and eMuleAI
/// applies only its user IP filter (`DownloadQueue.cpp:4932-4942`). Refusing
/// them is a node-wide LAN policy that no ADR has made.
pub(crate) fn is_claimed_udp_target(ip: Ipv4Addr) -> bool {
    is_unicast_host(ip) && !ip.is_loopback() && !ip.is_link_local()
}
