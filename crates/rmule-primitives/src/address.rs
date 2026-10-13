//! The **Reserved Range** check and the **Informant** it is judged against
//! (ADR-0085): the one place rmule decides whether an address somebody stated
//! can be one peer's address.
//!
//! A server's source list, a source exchange, a Kad row and a link all arrive
//! as somebody's word. An address in a range no remote host can be reached at
//! is refused wherever it enters, by this one check, so no intake can drift
//! from another. Loopback alone depends on who said it: it names the host that
//! reads it, so it is a peer only when its Informant shares our host.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether `ip` lies in an IPv4 **Reserved Range**, one no remote host can be
/// reached at:
///
/// - `0.0.0.0/8`, "this network" (RFC 1122 §3.2.1.3): a source address only,
///   never a destination;
/// - `127.0.0.0/8`, loopback: it names the host that reads it;
/// - `169.254.0.0/16`, link-local: it carries no interface, so it names a
///   different host on every link;
/// - `224.0.0.0/4`, multicast, and `240.0.0.0/4`, reserved, which holds the
///   limited broadcast `255.255.255.255`: no one host.
///
/// Every other unicast range passes, the private (RFC 1918), carrier-grade
/// (RFC 6598) and documentation ones included: each names one host.
#[must_use]
pub const fn is_reserved_ipv4(ip: Ipv4Addr) -> bool {
    let [first, second, ..] = ip.octets();
    first == 0 || first == 127 || (first == 169 && second == 254) || first >= 224
}

/// Whether `ip` lies in an IPv6 **Reserved Range**: the unspecified address,
/// loopback, link-local (`fe80::/10`, which no claim can scope) or multicast
/// (`ff00::/8`). An IPv4-mapped address (`::ffff:a.b.c.d`) is the IPv4 host it
/// wraps and is judged by [`is_reserved_ipv4`].
#[must_use]
pub const fn is_reserved_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_reserved_ipv4(mapped);
    }
    ip.is_unspecified() || ip.is_loopback() || ip.is_unicast_link_local() || ip.is_multicast()
}

/// Whether `ip` lies in a **Reserved Range** of its family
/// ([`is_reserved_ipv4`], [`is_reserved_ipv6`]).
#[must_use]
pub const fn is_reserved_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_reserved_ipv4(ip),
        IpAddr::V6(ip) => is_reserved_ipv6(ip),
    }
}

/// Whether `ip` is loopback in either family, a mapped one included.
const fn is_loopback(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback(),
    }
}

/// Who stated an address: rmule itself, or a party on the network.
///
/// A loopback address is relative to its reader. From a party on this host it
/// names this host truly; from a remote party it names that party's host, and
/// taken here it would aim rmule at its own.
///
/// No informant is assumed: every sighting names its own, so a producer that
/// read an address off the network cannot leave it as rmule's word by default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Informant {
    /// rmule's own word: a link the operator gave, a seed the node remembers,
    /// or a source the embedding program injected.
    Own,
    /// A party at this address: a server, a Kad storer, or a peer.
    Party(IpAddr),
}

impl Informant {
    /// Whether this informant stands on this host.
    #[must_use]
    pub const fn is_on_this_host(self) -> bool {
        match self {
            Self::Own => true,
            Self::Party(ip) => is_loopback(ip),
        }
    }

    /// Whether `claim`, stated by this informant, may stand as one peer's
    /// address: it lies in no Reserved Range, or it is loopback and this
    /// informant is on this host.
    #[must_use]
    pub const fn admits(self, claim: IpAddr) -> bool {
        !is_reserved_address(claim) || (is_loopback(claim) && self.is_on_this_host())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    /// The range edges: each reserved block refuses its first and last
    /// address, and the address beside it passes.
    #[test]
    fn a_reserved_range_refuses_its_edges_and_admits_its_neighbours() {
        for reserved in [
            "0.0.0.0",
            "0.0.0.5",
            "0.255.255.255",
            "127.0.0.1",
            "127.255.255.255",
            "169.254.0.0",
            "169.254.255.255",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fe80::1",
            "febf::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:255.255.255.255",
        ] {
            assert!(is_reserved_address(ip(reserved)), "{reserved} is reserved");
        }
        for host in [
            "1.0.0.0",
            "126.255.255.255",
            "128.0.0.0",
            "169.253.255.255",
            "169.255.0.0",
            "223.255.255.255",
            "10.0.0.8",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "39.1.2.3",
            "192.0.2.1",
            "198.18.0.1",
            "fec0::1",
            "fd00::1",
            "2001:db8::1",
            "::ffff:198.51.100.7",
        ] {
            assert!(!is_reserved_address(ip(host)), "{host} names one host");
        }
    }

    /// Loopback stands only on an informant from this host; every other
    /// reserved address is refused whoever stated it.
    #[test]
    fn loopback_stands_only_on_an_informant_from_this_host() {
        let local = [
            Informant::Own,
            Informant::Party(ip("127.0.0.1")),
            Informant::Party(ip("::1")),
            Informant::Party(ip("::ffff:127.0.0.9")),
        ];
        let remote = [
            Informant::Party(ip("198.51.100.7")),
            Informant::Party(ip("2001:db8::7")),
            Informant::Party(ip("192.168.1.1")),
        ];
        for informant in local {
            assert!(informant.admits(ip("127.0.0.1")), "{informant:?}");
            assert!(informant.admits(ip("::1")), "{informant:?}");
        }
        for informant in remote {
            assert!(!informant.admits(ip("127.0.0.1")), "{informant:?}");
            assert!(!informant.admits(ip("::ffff:127.0.0.1")), "{informant:?}");
            assert!(informant.admits(ip("10.0.0.8")), "a LAN peer is a peer");
        }
        for informant in local.into_iter().chain(remote) {
            for refused in ["0.0.0.5", "169.254.1.1", "224.0.0.1", "255.255.255.255"] {
                assert!(!informant.admits(ip(refused)), "{informant:?} {refused}");
            }
        }
    }
}
