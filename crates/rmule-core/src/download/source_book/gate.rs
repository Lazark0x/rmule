//! The **Source Book**'s intake gate: the Reserved Range check, the IP filter
//! and the address family, judged per half of one sighting before the book's
//! other blocks (ADR-0085, ADR-0090). The caller lends a [`Gate`] for the one
//! call — the filter's current view and our Dial Position — so the book stays
//! pure and a reload applies from the next sighting.

use rmule_primitives::{PeerEndpoint, SourceSighting};

use super::Blocked;
use crate::dialable::{DialPosition, admit_halves};
use crate::ip_filter::{IpFilter, admits_source};

/// What a sighting is judged by, borrowed for one call.
#[derive(Clone, Copy)]
pub(crate) struct Gate<'a> {
    /// The IP filter's view (aMule `CPartFile::AddSources`): a filtered
    /// address never enters a download's pool.
    pub(crate) filter: &'a IpFilter,
    /// Our Known IPv6, which decides whether an IPv6 address can be dialed
    /// from here (ADR-0087).
    pub(crate) dial: DialPosition,
}

impl Gate<'_> {
    /// The sighting with its addresses judged, or why nothing of it passes.
    ///
    /// Each half is judged on its own ([`admit_halves`]), first by the
    /// Reserved Range check against the sighting's Informant (aMule's
    /// `IsGoodIP`, which runs before its filter), then by the IP filter: a
    /// refused IPv6 half is dropped from the sighting, a refused client id
    /// leaves the source on its IPv6 half, both refused blocks it. Then the one
    /// address left is judged by family — an IPv6 address needs an IPv6 of ours
    /// to be dialed from — and by both checks again for a sighting that named no
    /// pair, which is how a Kad callback row is judged by the publisher address
    /// it was observed at. A Low-ID row has no address to judge and passes: its
    /// real address is enforced later at the accept and dial gates (aMule's
    /// `!IsLowID`).
    pub(crate) fn judge(&self, sighting: SourceSighting) -> Result<SourceSighting, Blocked> {
        let informant = sighting.informant();
        let stands = |half: PeerEndpoint| informant.admits(half.ip());
        let judged = admit_halves(sighting, stands).ok_or(Blocked::Reserved)?;
        let judged = admit_halves(judged, |half| admits_source(self.filter, Some(half)))
            .ok_or(Blocked::IpFiltered)?;
        let endpoint = judged.filter_endpoint();
        if endpoint.is_some_and(|endpoint| !stands(endpoint)) {
            return Err(Blocked::Reserved);
        }
        if let Some(PeerEndpoint::V6(half)) = endpoint
            && !self.dial.can_dial_ipv6()
        {
            tracing::debug!(
                %half,
                "dropping an IPv6 source: this node holds no IPv6 to dial it from"
            );
            return Err(Blocked::FamilyUnreachable);
        }
        if !admits_source(self.filter, endpoint) {
            return Err(Blocked::IpFiltered);
        }
        Ok(judged)
    }

    /// Whether any half of `sighting` passes the gate.
    pub(crate) fn admits(&self, sighting: SourceSighting) -> bool {
        self.judge(sighting).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use rmule_primitives::{
        Informant, Ipv4Endpoint, Ipv6Endpoint, PeerSource, SightedBuddy, SourceClaim,
        SourceCryptOptions, SourceRoad, UserHash,
    };

    use super::*;

    fn gate(filter: &IpFilter) -> Gate<'_> {
        Gate {
            filter,
            dial: DialPosition {
                known_ipv6: Some("2001:db8::1".parse().unwrap()),
            },
        }
    }

    fn at(ip: Ipv4Addr) -> Ipv4Endpoint {
        Ipv4Endpoint::new(ip, 4662)
    }

    fn party(ip: [u8; 4]) -> Informant {
        Informant::Party(IpAddr::V4(Ipv4Addr::from(ip)))
    }

    /// The shapes the channels hand the gate for a source at `ip`: a server
    /// answer, a source-exchange row with its hash and server, a Kad direct
    /// row with its connect options, and the two Kad callback rows, named by
    /// the endpoint the storer observed. Each test names who stated them.
    fn shapes(ip: Ipv4Addr) -> [SourceClaim; 5] {
        let hash = Some(UserHash::from_bytes([0x5A; 16]));
        let observed = Ipv4Endpoint::new(ip, 4672);
        let buddy = SightedBuddy {
            buddy_id: [0xB0; 16],
            buddy_udp: None,
        };
        [
            SourceClaim::plain(PeerSource::HighId(at(ip))),
            SourceClaim::new(PeerSource::HighId(at(ip)), hash, None)
                .with_server(Some(at(Ipv4Addr::new(45, 55, 200, 1)))),
            SourceClaim::new(
                PeerSource::HighId(at(ip)),
                hash,
                Some(SourceCryptOptions::from_byte(0x01)),
            ),
            SourceClaim::by_road(
                SourceRoad::DirectUdpCallback {
                    kad_udp: observed,
                    tcp_port: 4662,
                },
                hash,
                Some(SourceCryptOptions::from_byte(0x08)),
            ),
            SourceClaim::by_road(
                SourceRoad::Buddy {
                    buddy,
                    kad_udp: observed,
                    tcp_port: 4662,
                },
                hash,
                None,
            ),
        ]
    }

    /// Loopback, broadcast and `0.0.0.5` are blocked from every channel a
    /// remote party speaks on; a public and a LAN address pass (ADR-0085).
    #[test]
    fn a_reserved_address_is_blocked_from_every_channel_and_a_lan_one_passes() {
        let filter = IpFilter::default();
        let remote = party([198, 51, 100, 9]);
        for reserved in [
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(0, 0, 0, 5),
        ] {
            for claim in shapes(reserved) {
                assert_eq!(
                    gate(&filter).judge(claim.stated_by(remote)),
                    Err(Blocked::Reserved),
                    "{claim:?}"
                );
            }
        }
        for host in [Ipv4Addr::new(45, 55, 200, 8), Ipv4Addr::new(10, 0, 0, 8)] {
            for claim in shapes(host) {
                assert!(gate(&filter).admits(claim.stated_by(remote)));
            }
        }
    }

    /// A loopback source passes from rmule itself and from a party on this
    /// host, and from nobody else.
    #[test]
    fn loopback_passes_only_from_an_informant_on_this_host() {
        let filter = IpFilter::default();
        for claim in shapes(Ipv4Addr::LOCALHOST) {
            assert!(
                gate(&filter).admits(claim.stated_by(Informant::Own)),
                "rmule's own: {claim:?}"
            );
            assert!(
                gate(&filter).admits(claim.stated_by(party([127, 0, 0, 1]))),
                "a party on this host: {claim:?}"
            );
            assert_eq!(
                gate(&filter).judge(claim.stated_by(party([45, 55, 200, 7]))),
                Err(Blocked::Reserved)
            );
        }
    }

    /// Each half is judged on its own: a reserved half drops, and the source
    /// stands on its other address.
    #[test]
    fn a_reserved_half_drops_and_its_sibling_stands() {
        let filter = IpFilter::default();
        let remote = party([198, 51, 100, 9]);
        let public_v6 = Ipv6Endpoint::new("2a01:4f8::7".parse().unwrap(), 4662);
        let loopback_v6 = Ipv6Endpoint::new(std::net::Ipv6Addr::LOCALHOST, 4662);
        let dual = |v4: Ipv4Addr, v6| {
            SourceSighting::plain(PeerSource::HighId(at(v4)), remote).with_ipv6_half(Some(v6))
        };

        let judged = gate(&filter)
            .judge(dual(Ipv4Addr::LOCALHOST, public_v6))
            .expect("the IPv6 half stands");
        assert_eq!(judged.peer_source(), Some(PeerSource::Ipv6(public_v6)));

        let public_v4 = Ipv4Addr::new(45, 55, 200, 8);
        let judged = gate(&filter)
            .judge(dual(public_v4, loopback_v6))
            .expect("the IPv4 half stands");
        assert_eq!(
            judged.peer_source(),
            Some(PeerSource::HighId(at(public_v4)))
        );
        assert_eq!(judged.ipv6(), None, "the reserved half is dropped");

        let low_id = SourceSighting::plain(
            PeerSource::new(rmule_primitives::ClientId::from_u32(42), 4662),
            remote,
        )
        .with_ipv6_half(Some(loopback_v6));
        let judged = gate(&filter).judge(low_id).expect("a Low ID's roads stand");
        assert_eq!(judged.ipv6(), None, "its rung-0 half is dropped");
    }

    /// An `ipfilter.dat` naming one family of a dual-stack source drops that
    /// half only: the filter judges each address on its own, never the pair
    /// (ADR-0085).
    #[test]
    fn a_filtered_half_of_either_family_leaves_the_other_standing() {
        let (filter, _) = IpFilter::from_texts(
            &[b"203.0.113.0-203.0.113.255,0,v4\n2001:db8::/32,0,v6\n".as_slice()],
            127,
            true,
            true,
        );
        let blocked_v6 = Ipv6Endpoint::new("2001:db8::7".parse().unwrap(), 4662);
        let open_v6 = Ipv6Endpoint::new("2a01:4f8::7".parse().unwrap(), 4662);
        let blocked_v4 = Ipv4Addr::new(203, 0, 113, 7);
        let open_v4 = Ipv4Addr::new(45, 55, 200, 8);
        let dual = |v4: Ipv4Addr, v6| {
            SourceSighting::plain(PeerSource::HighId(at(v4)), party([45, 55, 200, 1]))
                .with_ipv6_half(Some(v6))
        };

        let judged = gate(&filter).judge(dual(open_v4, blocked_v6)).unwrap();
        assert_eq!(judged.peer_source(), Some(PeerSource::HighId(at(open_v4))));
        assert_eq!(judged.ipv6(), None, "the filtered IPv6 half is dropped");

        let judged = gate(&filter).judge(dual(blocked_v4, open_v6)).unwrap();
        assert_eq!(judged.peer_source(), Some(PeerSource::Ipv6(open_v6)));

        assert_eq!(
            gate(&filter).judge(dual(blocked_v4, blocked_v6)),
            Err(Blocked::IpFiltered)
        );
    }
}
