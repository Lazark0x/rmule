//! The **Gateway Source** (ADR-0086): the one place rmule asks which box its
//! default route points at, and from which local address it must be spoken to.
//!
//! PCP and NAT-PMP have no discovery of their own — both RFCs say to send to
//! the default router — so the whole UDP half of port mapping rests on this
//! lookup. Two facts make it a seam rather than a constant:
//!
//! - **The synthesized `<prefix>::1` is not the router.** A v6 default route is
//!   via a *link-local* next hop with a zone index, and guessing `.1` reaches
//!   nothing. So a gateway carries its scope id, and a source that cannot find
//!   a route answers with nothing rather than a guess.
//! - **The source address is part of the request.** Over IPv6 the kernel, left
//!   to choose, answers a link-local next hop from a link-local source, and
//!   gateways refuse those with `NOT_AUTHORIZED` — even for a state-free
//!   probe. So the local address rides along and the backend pins it.
//!
//! The testkit fakes this and the harness pins it, which is what lets the whole
//! mapping subsystem run with no route table in sight.

use std::net::IpAddr;

use rmule_primitives::AddressFamily;

/// One default-route next hop, and how to speak to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Gateway {
    /// The next hop itself.
    pub address: IpAddr,
    /// The IPv6 zone index a link-local next hop must be scoped by. `None` for
    /// IPv4 and for a global-scope v6 next hop.
    pub scope_id: Option<u32>,
    /// The local address a request to this gateway must be sent from — the
    /// address a PCP request also names as its client address.
    pub local_address: IpAddr,
}

impl Gateway {
    /// The family this gateway is reached in.
    #[must_use]
    pub const fn family(&self) -> AddressFamily {
        match self.address {
            IpAddr::V4(_) => AddressFamily::V4,
            IpAddr::V6(_) => AddressFamily::V6,
        }
    }

    /// An IPv4 gateway reached from `local_address`.
    #[must_use]
    pub const fn v4(address: std::net::Ipv4Addr, local_address: std::net::Ipv4Addr) -> Self {
        Self {
            address: IpAddr::V4(address),
            scope_id: None,
            local_address: IpAddr::V4(local_address),
        }
    }
}

/// The seam behind which default-route lookup lives: a runtime reads the route
/// table, the testkit answers from a script, the harness names the gateway
/// outright.
pub trait GatewaySource: Send + Sync + std::fmt::Debug {
    /// Every default-route next hop this host currently has, at most one per
    /// **Address Family**.
    ///
    /// An empty answer is a legitimate one — a host with no default route (a
    /// container on an internal network) maps nothing, and that is a fact to
    /// report rather than an error to raise.
    fn gateways(&self) -> Vec<Gateway>;
}

/// The live lookup, over `netdev` (MIT) with its `gateway` feature — the same
/// crate the **Interface Source** already enumerates with, so route and
/// address lookup do not pull two dependencies that disagree about what an
/// interface is.
///
/// `netdev` resolves the default interface and reports the device its default
/// route points at; the interface's own index is the zone a link-local v6 next
/// hop is scoped by, and its first address in the matching family is what the
/// request is sent from.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemGateways;

impl GatewaySource for SystemGateways {
    fn gateways(&self) -> Vec<Gateway> {
        let Ok(interface) = netdev::get_default_interface() else {
            return Vec::new();
        };
        let Some(device) = interface.gateway.as_ref() else {
            return Vec::new();
        };
        let mut gateways = Vec::new();
        if let (Some(next_hop), Some(local)) = (
            device.ipv4.first().copied(),
            interface.ipv4.first().map(|net| net.addr()),
        ) {
            gateways.push(Gateway::v4(next_hop, local));
        }
        if let (Some(next_hop), Some(local)) = (
            device.ipv6.first().copied(),
            // The source address must be routable: a link-local source is
            // exactly what the gateway refuses, so a host holding only a
            // link-local v6 has no usable v6 gateway rather than a broken one.
            interface
                .ipv6
                .iter()
                .map(|net| net.addr())
                .find(|address| !address.is_loopback() && !is_link_local_v6(*address)),
        ) {
            gateways.push(Gateway {
                address: IpAddr::V6(next_hop),
                scope_id: is_link_local_v6(next_hop).then_some(interface.index),
                local_address: IpAddr::V6(local),
            });
        }
        gateways
    }
}

/// Whether `address` is in `fe80::/10` — the scope a next hop needs a zone
/// index for, and the scope a request must never be sent *from*.
const fn is_link_local_v6(address: std::net::Ipv6Addr) -> bool {
    let octets = address.octets();
    octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn a_gateway_names_the_family_of_its_next_hop() {
        let v4 = Gateway::v4(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 50),
        );
        assert_eq!(v4.family(), AddressFamily::V4);
        let v6 = Gateway {
            address: IpAddr::V6("fe80::1".parse().expect("literal")),
            scope_id: Some(4),
            local_address: IpAddr::V6("2001:db8::5".parse().expect("literal")),
        };
        assert_eq!(v6.family(), AddressFamily::V6);
    }

    #[test]
    fn link_local_detection_covers_the_whole_fe80_over_10_block() {
        // The boundary matters: `febf::` is still link-local and `fec0::` (the
        // deprecated site-local block) is not, so a naive `fe80` prefix test
        // would scope the wrong next hops.
        for (address, expected) in [
            ("fe80::1", true),
            ("febf:ffff::1", true),
            ("fec0::1", false),
            ("2001:db8::1", false),
        ] {
            let parsed: Ipv6Addr = address.parse().expect("literal");
            assert_eq!(is_link_local_v6(parsed), expected, "{address}");
        }
    }

    #[test]
    fn the_system_lookup_never_reports_a_gateway_it_cannot_speak_from() {
        // The one property that holds on every host this runs on, CI included:
        // an empty answer is legitimate, but a reported gateway always carries
        // a source address of its own family — a pair the backend can actually
        // bind.
        for gateway in SystemGateways.gateways() {
            assert_eq!(
                gateway.family(),
                match gateway.local_address {
                    IpAddr::V4(_) => AddressFamily::V4,
                    IpAddr::V6(_) => AddressFamily::V6,
                },
                "gateway {gateway:?} pairs families that cannot talk"
            );
        }
    }
}
