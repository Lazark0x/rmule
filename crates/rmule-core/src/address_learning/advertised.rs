//! The **Advertised Endpoints** chooser (ADR-0084): the one core-side place
//! that turns *where we are* plus *whether we can be reached* into what rmule
//! actually claims on the wire.
//!
//! Every advert — the ADR-0047 connect-options bits, the hello / login /
//! ExtSX tags, the Kad publish tags — reads this, and no advert site reads
//! Address Learning or Reachability on its own. Three facts have to agree
//! before rmule names an endpoint, and keeping them in one function is what
//! stops three near-duplicate policies growing:
//!
//! 1. the family's **Family Pair** actually came up for that role (what bound,
//!    never what was configured — a refused bind is silently absent);
//! 2. the store's verdict is `Known`, not merely `Stale`;
//! 3. for IPv6, the server has not probed us unreachable.
//!
//! Honest Capability Advertisement applied to our own position: rmule never
//! names an endpoint it has not learned, and never one it has been told does
//! not work.

use std::time::Instant;

use rmule_primitives::{AddressFamily, PeerEndpoint};

use super::{AddressLearning, SocketRole};
use crate::reachability::{Ipv6Probe, TcpReachability};

/// The [`Reachability`](crate::reachability::Reachability) facts the chooser
/// reads. A value rather than a borrow: the store is task-local to the Kad
/// pump that owns it, so its verdicts reach the orchestrator as published
/// levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdvertReachability {
    /// Our own TCP verdict under the ≥2-ack rule.
    pub(crate) tcp: TcpReachability,
    /// The server-probed IPv6 verdict (`ST_IPV6_STATUS`, ADR-0087).
    pub(crate) ipv6: Ipv6Probe,
}

impl AdvertReachability {
    /// The honest fresh-node posture: TCP unproven, IPv6 unprobed.
    pub(crate) const fn unproven() -> Self {
        Self {
            tcp: TcpReachability::Firewalled,
            ipv6: Ipv6Probe::Unknown,
        }
    }
}

/// What rmule advertises right now, settled once so every surface reads the
/// same answer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct AdvertisedEndpoints {
    /// Indexed `[family][role]` — `None` where any of the three gates closed.
    endpoints: [[Option<PeerEndpoint>; SocketRole::ALL.len()]; 2],
    /// Whether the IPv6 half may be named at all (ADR-0087's
    /// `shouldAdvertisePublicIPv6`).
    advertises_ipv6: bool,
    /// Whether peers can actually dial our TCP listener.
    tcp_dialable: bool,
}

impl AdvertisedEndpoints {
    /// Settle the advert from the store and the reachability verdicts.
    pub(crate) fn choose(store: &AddressLearning, reach: AdvertReachability, now: Instant) -> Self {
        let mut chosen = Self {
            advertises_ipv6: reach.ipv6 != Ipv6Probe::ProbedUnreachable,
            tcp_dialable: reach.tcp.is_reachable(),
            ..Self::default()
        };
        for (family_index, family) in [AddressFamily::V4, AddressFamily::V6]
            .into_iter()
            .enumerate()
        {
            if family == AddressFamily::V6 && !chosen.advertises_ipv6 {
                continue;
            }
            for (role_index, role) in SocketRole::ALL.into_iter().enumerate() {
                if !store.bound(role, family) {
                    continue;
                }
                chosen.endpoints[family_index][role_index] =
                    store.endpoint(family, role, now).known();
            }
        }
        chosen
    }

    /// The endpoint rmule advertises for one socket in one family, or `None`
    /// when it advertises none.
    pub(crate) fn endpoint(&self, family: AddressFamily, role: SocketRole) -> Option<PeerEndpoint> {
        let family_index = match family {
            AddressFamily::V4 => 0,
            AddressFamily::V6 => 1,
        };
        self.endpoints[family_index][SocketRole::ALL.iter().position(|it| *it == role)?]
    }

    /// Whether rmule may name an IPv6 of its own at all — ADR-0087's
    /// `shouldAdvertisePublicIPv6`: a confident address that the server has
    /// not probed unreachable. A client that can *parse* IPv6 sources but
    /// holds no confident address of its own still cannot say so; that
    /// asymmetry is the dialect's, not rmule's.
    pub(crate) fn advertises_ipv6(&self) -> bool {
        self.advertises_ipv6 && self.endpoint(AddressFamily::V6, SocketRole::Tcp).is_some()
    }

    /// The IPv6 address rmule may name and dial from — the **Advertised
    /// IPv6**, and the one input the Dial Chooser's rung-0 AND needs from our
    /// side (ADR-0087). `None` whenever [`advertises_ipv6`](Self::advertises_ipv6)
    /// is false, so the tag, the Kad publish and the dial can never disagree
    /// about whether we hold an address.
    pub(crate) fn advertised_ipv6(&self) -> Option<std::net::Ipv6Addr> {
        self.advertises_ipv6()
            .then(|| self.endpoint(AddressFamily::V6, SocketRole::Tcp))
            .flatten()
            .and_then(|endpoint| endpoint.as_v6())
            .map(|endpoint| endpoint.ip)
    }

    /// The IPv4 TCP endpoint peers can actually dial: Known *and* proven
    /// reachable. The ADR-0047 connect-options bits and the ADR-0061 route
    /// chooser read this rather than the raw verdict — an endpoint nobody can
    /// reach is not an advertisement, it is a dead invitation.
    pub(crate) fn dialable_tcp(&self) -> Option<PeerEndpoint> {
        self.tcp_dialable
            .then(|| self.endpoint(AddressFamily::V4, SocketRole::Tcp))
            .flatten()
    }
}
