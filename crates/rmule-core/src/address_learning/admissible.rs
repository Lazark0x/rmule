//! What may become an **External Endpoint** at all (ADR-0084): the store's
//! single definition of an address the outside world can route to, and the two
//! classifications a refusal turns into a **NAT Hint**.
//!
//! One definition, applied to every source. An operator who types a private
//! address, a gateway that grants one, and a peer that reflects one are all
//! refused by the same rule — which is the point: an address that cannot be
//! reached is nobody's endpoint, however authoritative the source.

use std::net::IpAddr;

/// Whether the outside world can route to `address` — the store's single
/// definition of what may become an **External Endpoint**.
///
/// IPv4 refuses exactly the ranges aMule's `IsGoodIP`/`IsLANIP` refuse
/// (unspecified, loopback, RFC 1918, link-local) plus RFC 6598 carrier-grade
/// NAT, which ADR-0086 grades `Degraded` for the same reason: no mapping on
/// the router reaches past it. The documentation ranges are deliberately
/// *not* refused — aMule routes them, and refusing them would make rmule
/// reject addresses a live peer would accept.
///
/// IPv6 defers to the dialect's own
/// [`is_usable_tag_identity`](rmule_primitives::is_usable_tag_identity)
/// (ADR-0087): a link-local or unique-local address carries no scope on the
/// wire, so advertising one would name two different hosts to two different
/// readers. One rule, one definition — the store and the hello tag refuse the
/// same addresses by construction.
pub(super) fn is_publicly_usable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_private()
                && !ip.is_link_local()
                && !ip.is_broadcast()
                && !ip.is_multicast()
                && !is_carrier_grade_nat(IpAddr::V4(ip))
        }
        IpAddr::V6(ip) => rmule_primitives::is_usable_tag_identity(ip),
    }
}

/// RFC 6598's shared address space, `100.64.0.0/10` — the ISP's carrier-grade
/// NAT pool.
pub(super) fn is_carrier_grade_nat(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            octets[0] == 100 && (64..=127).contains(&octets[1])
        }
        IpAddr::V6(_) => false,
    }
}
