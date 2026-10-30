//! The **Source Book**'s intake gate: a sighting that names us, then the
//! Reserved Range check, the IP filter and the address family, judged per half
//! of one sighting, before the book's other blocks (ADR-0085, ADR-0090). The
//! caller lends a [`Gate`] for the one call — the filter's current view, our
//! Dial Position and our **Own Position** — so the book stays pure and a
//! reload or a login applies from the next sighting.

use std::net::Ipv4Addr;

use rmule_primitives::{
    ClientId, Ipv4Endpoint, PeerEndpoint, PeerSource, SourceRoad, SourceSighting, UserHash,
};

use super::Blocked;
use crate::dialable::{DialPosition, admit_halves};
use crate::ip_filter::{IpFilter, admits_source};
use crate::own_identity::ConnectedSession;

/// What the gate reads of us, taken once per batch from the owner of each
/// fact: the facts aMule's `CanAddSource`, `CheckAndAddSource` and Kad intake
/// compare a source with (stock 2.3.3 `PartFile.cpp:1575-1625`,
/// `DownloadQueue.cpp:612-619`, `:1569`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct OwnPosition {
    /// Our User Hash.
    pub(crate) user_hash: Option<UserHash>,
    /// The live session's id and server.
    pub(crate) session: Option<ConnectedSession>,
    /// Our external IPv4, as **Address Learning** holds it.
    pub(crate) public_ip: Option<Ipv4Addr>,
    /// The port our serve listener holds; `None` with no listener, where
    /// nothing of ours answers at any port.
    pub(crate) tcp_port: Option<u16>,
}

impl OwnPosition {
    /// Whether `sighting` names us, its Low ID read in the server `namespace`
    /// and an IPv6 address against `known_ipv6`. One half naming us proves
    /// the pair ours.
    fn names(
        &self,
        sighting: SourceSighting,
        namespace: Option<Ipv4Endpoint>,
        known_ipv6: Option<std::net::Ipv6Addr>,
    ) -> bool {
        if sighting.user_hash().is_some() && sighting.user_hash() == self.user_hash {
            return true;
        }
        let our_port = |port| self.tcp_port == Some(port);
        let our_ipv6 = sighting
            .ipv6()
            .is_some_and(|half| known_ipv6 == Some(half.ip) && our_port(half.port));
        our_ipv6
            || match sighting.road() {
                SourceRoad::Record(PeerSource::HighId(at)) => {
                    (self.our_address(at.ip) && our_port(at.port))
                        || (self.holds_low_id() && self.public_ip == Some(at.ip))
                }
                SourceRoad::Record(PeerSource::LowId { id, .. }) => {
                    self.is_our_low_id(id, namespace)
                }
                SourceRoad::Record(PeerSource::Ipv6(at)) => {
                    known_ipv6 == Some(at.ip) && our_port(at.port)
                }
                SourceRoad::Buddy {
                    kad_udp, tcp_port, ..
                }
                | SourceRoad::DirectUdpCallback { kad_udp, tcp_port } => {
                    self.our_address(kad_udp.ip) && our_port(tcp_port)
                }
            }
    }

    /// Whether `ip` is the address Address Learning holds for us, or the one
    /// our High ID spells.
    fn our_address(&self, ip: Ipv4Addr) -> bool {
        self.public_ip == Some(ip)
            || self.session.is_some_and(|session| {
                session.client_id == ClientId::from_u32(u32::from_le_bytes(ip.octets()))
            })
    }

    fn holds_low_id(&self) -> bool {
        self.session
            .is_some_and(|session| session.client_id.is_low_id())
    }

    /// Whether `id`, read in `namespace`, is the Low ID our session holds: a
    /// Low ID is unique per server, so nothing short of that server proves it.
    fn is_our_low_id(&self, id: ClientId, namespace: Option<Ipv4Endpoint>) -> bool {
        self.holds_low_id()
            && self.session.is_some_and(|session| {
                session.client_id == id && session.server.is_some() && session.server == namespace
            })
    }
}

/// What a sighting is judged by, borrowed for one call.
#[derive(Clone, Copy)]
pub(crate) struct Gate<'a> {
    /// The IP filter's view (aMule `CPartFile::AddSources`): a filtered
    /// address never enters a download's pool.
    pub(crate) filter: &'a IpFilter,
    /// Our Known IPv6, which decides whether an IPv6 address can be dialed
    /// from here (ADR-0087).
    pub(crate) dial: DialPosition,
    /// What a sighting that names us is told by (ADR-0090).
    pub(crate) own: OwnPosition,
}

impl Gate<'_> {
    /// The sighting with its addresses judged, or why nothing of it passes;
    /// `namespace` is the server its Low-ID row is minted in.
    ///
    /// A sighting that names us passes nothing ([`OwnPosition`]). Otherwise
    /// each half is judged on its own ([`admit_halves`]), first by the
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
    pub(crate) fn judge(
        &self,
        sighting: SourceSighting,
        namespace: Option<Ipv4Endpoint>,
    ) -> Result<SourceSighting, Blocked> {
        if self.own.names(sighting, namespace, self.dial.known_ipv6) {
            return Err(Blocked::Ourselves);
        }
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
        self.judge(sighting, None).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use rmule_primitives::{
        ClientId, Informant, Ipv4Endpoint, Ipv6Endpoint, PeerSource, SightedBuddy, SourceClaim,
        SourceCryptOptions, SourceRoad, UserHash,
    };

    use super::*;

    fn gate(filter: &IpFilter) -> Gate<'_> {
        Gate {
            filter,
            dial: DialPosition {
                known_ipv6: Some("2001:db8::1".parse().unwrap()),
            },
            own: OwnPosition::default(),
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
                    gate(&filter).judge(claim.stated_by(remote), None),
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
                gate(&filter).judge(claim.stated_by(party([45, 55, 200, 7])), None),
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
            .judge(dual(Ipv4Addr::LOCALHOST, public_v6), None)
            .expect("the IPv6 half stands");
        assert_eq!(judged.peer_source(), Some(PeerSource::Ipv6(public_v6)));

        let public_v4 = Ipv4Addr::new(45, 55, 200, 8);
        let judged = gate(&filter)
            .judge(dual(public_v4, loopback_v6), None)
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
        let judged = gate(&filter)
            .judge(low_id, None)
            .expect("a Low ID's roads stand");
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

        let judged = gate(&filter)
            .judge(dual(open_v4, blocked_v6), None)
            .unwrap();
        assert_eq!(judged.peer_source(), Some(PeerSource::HighId(at(open_v4))));
        assert_eq!(judged.ipv6(), None, "the filtered IPv6 half is dropped");

        let judged = gate(&filter)
            .judge(dual(blocked_v4, open_v6), None)
            .unwrap();
        assert_eq!(judged.peer_source(), Some(PeerSource::Ipv6(open_v6)));

        assert_eq!(
            gate(&filter).judge(dual(blocked_v4, blocked_v6), None),
            Err(Blocked::IpFiltered)
        );
    }
    const OUR_PORT: u16 = 4662;
    const OUR_SERVER: Ipv4Endpoint = Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 1), 4661);
    const OUR_ADDRESS: Ipv4Addr = Ipv4Addr::new(45, 55, 200, 8);

    fn hash(byte: u8) -> UserHash {
        UserHash::from_bytes([byte; 16])
    }

    /// We, logged into [`OUR_SERVER`] under `client_id`, at [`OUR_ADDRESS`]
    /// and listening on [`OUR_PORT`], with the hash `0x77…`.
    fn us(client_id: ClientId) -> OwnPosition {
        OwnPosition {
            user_hash: Some(hash(0x77)),
            session: Some(ConnectedSession {
                server: Some(OUR_SERVER),
                client_id,
            }),
            public_ip: Some(OUR_ADDRESS),
            tcp_port: Some(OUR_PORT),
        }
    }

    fn high_id() -> ClientId {
        ClientId::from_u32(u32::from_le_bytes(OUR_ADDRESS.octets()))
    }

    fn low_id() -> ClientId {
        ClientId::from_u32(42)
    }

    fn judged_as(
        own: OwnPosition,
        sighting: SourceSighting,
        namespace: Option<Ipv4Endpoint>,
    ) -> Result<SourceSighting, Blocked> {
        let filter = IpFilter::default();
        Gate {
            own,
            ..gate(&filter)
        }
        .judge(sighting, namespace)
    }

    fn high_id_row(at: Ipv4Endpoint) -> SourceSighting {
        SourceSighting::plain(PeerSource::HighId(at), party([198, 51, 100, 9]))
    }

    /// aMule's `CheckAndAddSource` (stock 2.3.3 `DownloadQueue.cpp:612-619`)
    /// reads the hash of whatever reaches a file: a row naming ours is refused
    /// on every road, and a row naming another stands.
    #[test]
    fn a_row_naming_our_user_hash_is_refused_on_every_road() {
        let own = us(high_id());
        let elsewhere = Ipv4Addr::new(203, 0, 113, 7);
        let ours = Some(hash(0x77));
        let rows = shapes(elsewhere).map(|shape| match shape.road() {
            SourceRoad::Record(source) => SourceClaim::new(source, ours, None),
            road => SourceClaim::by_road(road, ours, None),
        });
        for row in rows {
            assert_eq!(
                judged_as(own, row.stated_by(party([198, 51, 100, 9])), None),
                Err(Blocked::Ourselves),
                "{row:?}"
            );
        }
        assert!(judged_as(own, high_id_row(at(elsewhere)), None).is_ok());
    }

    /// Our Low ID names us only on the server that assigned it: another
    /// server's id 42 is another peer (`PartFile.cpp:1596-1598`).
    #[test]
    fn our_low_id_is_ours_only_on_our_own_server() {
        let own = us(low_id());
        let row = SourceSighting::plain(PeerSource::new(low_id(), 4662), party([45, 55, 200, 1]));
        assert_eq!(
            judged_as(own, row, Some(OUR_SERVER)),
            Err(Blocked::Ourselves)
        );
        let other_server = Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 201, 2), 4661);
        assert!(judged_as(own, row, Some(other_server)).is_ok());
        assert!(
            judged_as(own, row, None).is_ok(),
            "no namespace proves it ours"
        );
    }

    /// While we hold a Low ID, our public address is ours at any port
    /// (`PartFile.cpp:1599-1601`); while we hold a High ID only our port is,
    /// and another port at our address is a peer behind our NAT
    /// (`:1603-1605`).
    #[test]
    fn our_address_is_ours_at_any_port_only_while_we_hold_a_low_id() {
        let another_port = Ipv4Endpoint::new(OUR_ADDRESS, 4711);
        let our_port = Ipv4Endpoint::new(OUR_ADDRESS, OUR_PORT);
        for at in [another_port, our_port] {
            assert_eq!(
                judged_as(us(low_id()), high_id_row(at), None),
                Err(Blocked::Ourselves),
                "{at}"
            );
        }
        assert_eq!(
            judged_as(us(high_id()), high_id_row(our_port), None),
            Err(Blocked::Ourselves)
        );
        assert!(judged_as(us(high_id()), high_id_row(another_port), None).is_ok());
    }

    /// With no session, the address **Address Learning** holds stands in for
    /// Kad's (`DownloadQueue.cpp:1569`, `PartFile.cpp:1609-1615`).
    #[test]
    fn our_address_at_our_port_is_ours_with_no_session() {
        let own = OwnPosition {
            session: None,
            ..us(high_id())
        };
        assert_eq!(
            judged_as(
                own,
                high_id_row(Ipv4Endpoint::new(OUR_ADDRESS, OUR_PORT)),
                None
            ),
            Err(Blocked::Ourselves)
        );
    }

    /// aMule's Kad intake reads every row type (`DownloadQueue.cpp:1569`): a
    /// callback row at our address and port is our own publish coming back,
    /// and one at another port is not ours.
    #[test]
    fn a_kad_callback_row_at_our_address_and_port_is_ours() {
        let observed = Ipv4Endpoint::new(OUR_ADDRESS, 4672);
        let row = |tcp_port| {
            SourceClaim::by_road(
                SourceRoad::DirectUdpCallback {
                    kad_udp: observed,
                    tcp_port,
                },
                None,
                Some(SourceCryptOptions::from_byte(0x08)),
            )
            .stated_by(party([198, 51, 100, 9]))
        };
        assert_eq!(
            judged_as(us(high_id()), row(OUR_PORT), None),
            Err(Blocked::Ourselves)
        );
        assert!(judged_as(us(high_id()), row(4711), None).is_ok());
    }

    /// Our Known IPv6 at our port is ours, and one half naming us proves the
    /// pair ours: the sibling is not kept.
    #[test]
    fn one_half_naming_us_refuses_the_whole_pair() {
        let own = us(high_id());
        let our_v6 = Ipv6Endpoint::new("2001:db8::1".parse().unwrap(), OUR_PORT);
        let elsewhere = at(Ipv4Addr::new(203, 0, 113, 7));
        assert_eq!(
            judged_as(
                own,
                high_id_row(elsewhere).with_ipv6_half(Some(our_v6)),
                None
            ),
            Err(Blocked::Ourselves)
        );
        let v6_row = SourceSighting::plain(PeerSource::Ipv6(our_v6), party([198, 51, 100, 9]));
        assert_eq!(judged_as(own, v6_row, None), Err(Blocked::Ourselves));
        let our_v4 = high_id_row(Ipv4Endpoint::new(OUR_ADDRESS, OUR_PORT));
        let other_v6 = Ipv6Endpoint::new("2a01:4f8::7".parse().unwrap(), 4662);
        assert_eq!(
            judged_as(own, our_v4.with_ipv6_half(Some(other_v6)), None),
            Err(Blocked::Ourselves)
        );
    }
}
