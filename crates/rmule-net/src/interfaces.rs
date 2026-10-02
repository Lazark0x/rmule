//! The **Interface Source** (ADR-0084): the one place rmule asks the OS which
//! addresses this host holds.
//!
//! Core's **Address Learning** store needs the local address set for two
//! different jobs, and keeping them behind one seam is what lets a test drive
//! both without a network:
//!
//! - it is a **tier** of its own — a global-unicast address held locally is
//!   the no-NAT answer, and the IPv6 dialect's fourth tier;
//! - it is the **corroboration filter's evidence** — a reflected IPv6 address
//!   is adopted only when this host also holds it, which is what stops a
//!   hostile peer talking rmule into advertising someone else's address.
//!
//! Enumeration is I/O, so it lives here rather than in the sans-I/O store, and
//! it is a *snapshot*: the caller polls (at startup, on every server connect,
//! and on a five-minute tick) and hands the result to the store wholesale. An
//! address absent from a later snapshot is one this host no longer holds, so a
//! prefix renumber or an RFC 4941 privacy rotation is noticed by construction
//! rather than by a watcher rmule would have to keep correct.

use std::net::IpAddr;

/// The seam behind which local interface enumeration lives: a runtime
/// implements it with an enumeration crate, the testkit fakes it, and the
/// harness pins it.
pub trait InterfaceSource: Send + Sync + std::fmt::Debug {
    /// Every address this host currently holds, in interface order. The
    /// implementation filters out what the OS says is unusable (an address
    /// still running duplicate-address detection, one that lost it, or one
    /// whose preferred lifetime has expired); deciding which of the survivors
    /// is *publicly* usable is the store's job, not this seam's.
    fn addresses(&self) -> Vec<IpAddr>;
}

/// The live enumeration, over `netdev` (MIT).
///
/// Only interfaces that are up and are not loopback contribute. IPv6
/// addresses additionally drop the states an address can be in while it is not
/// yet — or no longer — a legitimate source address: `tentative` (duplicate
/// address detection still running), `duplicated` (it failed), and
/// `deprecated` (preferred lifetime expired, so new connections must not use
/// it). Advertising any of those would name an address the world's replies
/// could not come back to.
///
/// The flags are only as good as `netdev`'s source for them. On Linux they
/// come from netlink (`IFA_F_*`); when netlink is unavailable `netdev` 0.46
/// falls back to `getifaddrs`, whose Linux flag reader is a stub returning
/// no flags (`src/interface/ipv6_addr_flags.rs:59-62`), so there every IPv6
/// address passes this filter, and a deprecated or tentative one can reach
/// the store's interface tier. Nothing at this seam can tell the two cases
/// apart.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemInterfaces;

impl InterfaceSource for SystemInterfaces {
    fn addresses(&self) -> Vec<IpAddr> {
        let mut addresses = Vec::new();
        for interface in netdev::get_interfaces() {
            if !interface.is_up() || interface.is_loopback() {
                continue;
            }
            addresses.extend(interface.ipv4.iter().map(|net| IpAddr::V4(net.addr())));
            for (index, net) in interface.ipv6.iter().enumerate() {
                let usable = interface
                    .ipv6_addr_flags
                    .get(index)
                    .is_none_or(|flags| !flags.tentative && !flags.duplicated && !flags.deprecated);
                if usable {
                    addresses.push(IpAddr::V6(net.addr()));
                }
            }
        }
        addresses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_enumeration_never_reports_a_loopback_address() {
        // The one property that holds on every host this runs on, CI included:
        // an address set may legitimately be empty (a container with only
        // loopback), but loopback itself is never an interface rmule could be
        // reached at, and the corroboration filter would happily corroborate
        // one if it leaked through.
        let addresses = SystemInterfaces.addresses();
        assert!(
            addresses.iter().all(|address| !address.is_loopback()),
            "loopback leaked into the interface set: {addresses:?}"
        );
    }
}
