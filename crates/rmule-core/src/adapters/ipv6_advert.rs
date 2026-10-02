//! The **Advertised IPv6** (ADR-0084/0087): the one cell carrying the
//! Advertised Endpoints chooser's IPv6 verdict to everything that acts on it.
//!
//! Four surfaces read it, and none of them may reach a different answer:
//!
//! * the peer hello's `CT_MOD_IP_V6` tag — the *fact* a peer treats as
//!   "reachable over IPv6", as distinct from the `CT_MOD_MISCOPTIONS` claim bit;
//! * a Kad source publish's `ip6` tag;
//! * the **Dial Chooser**, whose rung-0 rule needs *our* address as much as the
//!   peer's;
//! * source ingest, which admits an IPv6 source only when there is an address
//!   to dial it from.
//!
//! It is a **view over the owner** rather than a cell (ADR-0084 "Own address ownership"):
//! every read settles the one Advertised Endpoints
//! chooser against Address Learning and the server's probe verdict, so a
//! prefix renumber, an RFC 4941 rotation, a peer-vote quorum or a server
//! reflection reaches the very next hello, login, Kad publish and dial with no
//! refresh step to miss. It was a cell the actor re-published once per
//! front-end command, which left an idle serving core naming an address it
//! had stopped holding.
//!
//! Empty is the honest default: rmule has learned no address it can be reached
//! at, so it names none, and an IPv6 source it could not dial back from is not
//! pooled.

use std::net::Ipv6Addr;

use crate::address_learning::SharedAddressLearning;
use crate::reachability::SharedIpv6Probe;

/// The chooser's IPv6 verdict, read from its owner by every surface that acts
/// on it.
#[derive(Clone, Default)]
pub(crate) struct SharedIpv6Advert {
    addresses: SharedAddressLearning,
    probe: SharedIpv6Probe,
}

impl SharedIpv6Advert {
    /// A view over `addresses` gated by the connected server's `probe` — the
    /// session cell's own pair, so the login and every hello read one answer.
    pub(crate) fn over(addresses: SharedAddressLearning, probe: SharedIpv6Probe) -> Self {
        Self { addresses, probe }
    }

    /// The address rmule may name and dial from right now, or `None`.
    pub(crate) fn get(&self) -> Option<Ipv6Addr> {
        self.addresses.advertised_ipv6(self.probe.get())
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use rmule_net::family::FamilyBinds;
    use rmule_primitives::AddressFamily;

    use super::*;
    use crate::address_learning::SocketRole;
    use crate::reachability::Ipv6Probe;

    /// The Advertised IPv6 follows its owner with no refresh step:
    /// the session cell's view — the one the login reads and the
    /// builder hands every hello, the Kad publisher and both dial roads —
    /// names a v6 the moment the store holds one, drops it the moment the
    /// interface renumbers away, and withholds it while the server has probed
    /// us unreachable.
    #[test]
    fn the_advertised_ipv6_follows_the_store_and_the_probe_with_no_refresh() {
        let session = crate::server_session::SharedServerSession::default();
        let addresses = session.own_identity().addresses().clone();
        let advert = session.ipv6_advert();
        assert_eq!(advert.get(), None, "nothing learned: name nothing");

        addresses.record_bind(
            SocketRole::Tcp,
            &FamilyBinds {
                bound: vec![AddressFamily::V4, AddressFamily::V6],
                refused: Vec::new(),
            },
            4662,
        );
        let gua: Ipv6Addr = "2001:db8:501::1".parse().expect("an IPv6 literal");
        addresses.refresh_interfaces(&[IpAddr::V6(gua)]);
        assert_eq!(advert.get(), Some(gua), "a Known v6 is named at once");

        session.ipv6_probe().set(Ipv6Probe::ProbedUnreachable);
        assert_eq!(advert.get(), None, "the server probed it unreachable");
        session.ipv6_probe().clear();

        let renumbered: Ipv6Addr = "2001:db8:501::2".parse().expect("an IPv6 literal");
        addresses.refresh_interfaces(&[IpAddr::V6(renumbered)]);
        assert_eq!(
            advert.get(),
            Some(renumbered),
            "a renumber reaches the next read, not the next command"
        );
    }

    /// Every hello names the owner's current IPv6: the Hello
    /// Adverts a road built its options from once still state the address the
    /// store holds when the *next* connection is met — `CT_MOD_IP_V6` follows
    /// a renumber with no command in between.
    #[test]
    fn every_hello_names_the_owner_s_current_ipv6() {
        let addresses = SharedAddressLearning::new();
        let adverts = crate::adapters::HelloAdverts {
            ipv6: SharedIpv6Advert::over(addresses.clone(), SharedIpv6Probe::default()),
            ..crate::adapters::HelloAdverts::default()
        };
        let hello_ipv6 = || {
            adverts
                .connect_options(rmule_primitives::PeerCrypt::unknown())
                .ipv6
        };
        addresses.record_bind(
            SocketRole::Tcp,
            &FamilyBinds {
                bound: vec![AddressFamily::V4, AddressFamily::V6],
                refused: Vec::new(),
            },
            4662,
        );
        assert_eq!(hello_ipv6(), None);

        let first: Ipv6Addr = "2001:db8:501::a".parse().expect("an IPv6 literal");
        addresses.refresh_interfaces(&[IpAddr::V6(first)]);
        assert_eq!(hello_ipv6(), Some(first));

        let rotated: Ipv6Addr = "2001:db8:501::b".parse().expect("an IPv6 literal");
        addresses.refresh_interfaces(&[IpAddr::V6(rotated)]);
        assert_eq!(
            hello_ipv6(),
            Some(rotated),
            "the next hello, not a stale copy"
        );
    }
}
