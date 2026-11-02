//! What may become an **External Endpoint** at all, how a verdict ages from
//! Known through Stale, and what the sources' disagreements say about the NAT
//! in the path.

use super::*;

// ----------------------------------------------------------- admissibility

#[test]
fn an_unroutable_address_is_never_an_external_endpoint() {
    let mut store = bound_store();
    let now = Instant::now();
    for address in [
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(100, 80, 0, 1)),
    ] {
        assert_eq!(
            store.observe(AddressObservation::server_reflection(address), now),
            ObservationOutcome::NotPubliclyUsable,
            "{address} is not an address the outside world can route"
        );
    }
    for address in [
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        assert_eq!(
            store.observe(AddressObservation::server_reflection(address), now),
            ObservationOutcome::NotPubliclyUsable,
            "{address} carries no scope on the wire, so it names two hosts"
        );
    }
    assert_eq!(
        store.endpoint(AddressFamily::V4, SocketRole::Tcp, now),
        EndpointVerdict::Unknown
    );
}

#[test]
fn an_interface_refresh_keeps_only_routable_addresses() {
    let mut store = bound_store();
    let now = Instant::now();
    store.refresh_interfaces(&[
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        v6(1),
    ]);
    assert_eq!(
        store.endpoint(AddressFamily::V4, SocketRole::Tcp, now),
        EndpointVerdict::Unknown,
        "a NATted host holds no public IPv4 of its own"
    );
    assert_eq!(
        store
            .endpoint(AddressFamily::V6, SocketRole::Tcp, now)
            .known()
            .map(|endpoint| endpoint.ip()),
        Some(v6(1)),
        "the first global-unicast address is the IPv6 tier-4 answer"
    );
}

// ------------------------------------------------------------- freshness

#[test]
fn a_disconnect_leaves_the_last_known_address_stale_rather_than_blank() {
    // The rejected "hard reset to Unknown on top-tier loss": blanking would
    // drop the UDP crypt key on every server reconnect for no reason.
    let mut store = bound_store();
    let start = Instant::now();
    store.observe(AddressObservation::server_high_id(ipv4(v4(9))), start);
    let ended = start + Duration::from_secs(10);
    store.end_server_session(ended);

    let later = ended + Duration::from_secs(1);
    assert_eq!(
        store.endpoint(AddressFamily::V4, SocketRole::Tcp, later),
        EndpointVerdict::Stale {
            endpoint: PeerEndpoint::V4(Ipv4Endpoint::new(ipv4(v4(9)), TCP_PORT)),
            since: ended,
        }
    );
}

#[test]
fn a_low_id_reassignment_withdraws_the_address_rather_than_staling_it() {
    // A Low ID is the server *contradicting* itself, not a source ageing out:
    // it says we hold no public address at all. Keeping the old value would
    // re-arm the UDP crypt send with a key no peer can reproduce.
    let mut store = bound_store();
    let now = Instant::now();
    store.observe_server_assigned(high_id(ipv4(v4(9))), Some(ipv4(v4(9))), None, now);
    assert!(
        store
            .endpoint(AddressFamily::V4, SocketRole::Tcp, now)
            .known()
            .is_some()
    );

    store.observe_server_assigned(rmule_primitives::ClientId::from_u32(0), None, None, now);
    assert_eq!(
        store.endpoint(AddressFamily::V4, SocketRole::Tcp, now),
        EndpointVerdict::Unknown
    );
}

/// Measured: logged in Low ID to ed2k-rust, which writes its own
/// address into `OP_IDCHANGE`'s reported-IP field, a server's own address
/// must not outrank the gateway's grant. A Low-ID report ranks below the grant,
/// and one naming the connected server is refused outright.
#[test]
fn a_low_id_report_yields_to_a_grant_and_never_names_the_server() {
    let low_id = rmule_primitives::ClientId::from_u32(86_256);
    let server = v4(222);
    let grant = || {
        AddressObservation::mapping_grant(
            SocketRole::Tcp,
            PeerEndpoint::V4(Ipv4Endpoint::new(ipv4(v4(4)), TCP_PORT)),
            Duration::from_secs(3600),
        )
    };
    let adopted = |store: &AddressLearning, now| {
        store
            .endpoint(AddressFamily::V4, SocketRole::Tcp, now)
            .known()
            .map(|endpoint| endpoint.ip())
    };

    // Alone, a report is what aMule's `SetPublicIP(dwServerReportedIP)`
    // keeps: the only fresh rung, so it is adopted.
    let mut store = bound_store();
    let now = Instant::now();
    assert_eq!(
        store.observe_server_assigned(low_id, Some(ipv4(v4(7))), Some(server), now),
        crate::address_learning::AssignedAddress::Ours(ipv4(v4(7)))
    );
    assert_eq!(adopted(&store, now), Some(v4(7)));
    // Beside a grant it is the weaker claim.
    store.observe(grant(), now);
    assert_eq!(adopted(&store, now), Some(v4(4)), "the grant outranks it");

    // The measured case: the report names the server itself.
    let mut store = bound_store();
    store.observe(grant(), now);
    store.observe_server_assigned(low_id, Some(ipv4(server)), Some(server), now);
    assert_eq!(adopted(&store, now), Some(v4(4)));
    assert_eq!(
        store.nat_hint(AddressFamily::V4, now),
        None,
        "a refused report is not a dissenting rung"
    );
    let mut store = bound_store();
    assert_eq!(
        store.observe_server_assigned(low_id, Some(ipv4(server)), Some(server), now),
        crate::address_learning::AssignedAddress::ServerOwnRefused(ipv4(server)),
        "the refusal names the server's address, for the login step"
    );
    assert_eq!(
        store.endpoint(AddressFamily::V4, SocketRole::Tcp, now),
        EndpointVerdict::Unknown,
        "refused even when nothing else holds: unknown beats wrong"
    );

    // A High ID later withdraws the report; the High ID is the Server tier.
    let mut store = bound_store();
    store.observe_server_assigned(low_id, Some(ipv4(v4(7))), Some(server), now);
    store.observe_server_assigned(high_id(ipv4(v4(9))), Some(ipv4(v4(9))), Some(server), now);
    assert_eq!(
        store.nat_hint(AddressFamily::V4, now),
        None,
        "no Low-ID report is left to dissent"
    );
    assert_eq!(adopted(&store, now), Some(v4(9)));
}

#[test]
fn a_mapping_grant_lives_exactly_as_long_as_its_lease() {
    let mut store = bound_store();
    let start = Instant::now();
    let lease = Duration::from_secs(3600);
    store.observe(
        AddressObservation::mapping_grant(
            SocketRole::Tcp,
            PeerEndpoint::V4(Ipv4Endpoint::new(ipv4(v4(4)), 40_000)),
            lease,
        ),
        start,
    );
    assert_eq!(
        store.endpoint(AddressFamily::V4, SocketRole::Tcp, start),
        EndpointVerdict::Known {
            endpoint: PeerEndpoint::V4(Ipv4Endpoint::new(ipv4(v4(4)), 40_000)),
            tier: ConfidenceTier::MappingGrant,
        },
        "a grant names both halves at once"
    );

    let expired = start + lease + Duration::from_secs(1);
    assert_eq!(
        store.endpoint(AddressFamily::V4, SocketRole::Tcp, expired),
        EndpointVerdict::Stale {
            endpoint: PeerEndpoint::V4(Ipv4Endpoint::new(ipv4(v4(4)), TCP_PORT)),
            since: start + lease,
        },
        "the lapsed grant leaves its address stale and its port back on the floor"
    );
}

/// The instant `next_lapse` names is the one the lease ages the verdict at,
/// so a reader that caches the verdict and reads again then sees it move.
#[test]
fn the_next_lapse_is_where_a_lease_turns_the_verdict_stale() {
    let mut store = bound_store();
    let start = Instant::now();
    let lease = Duration::from_secs(600);
    let endpoint = PeerEndpoint::V4(Ipv4Endpoint::new(ipv4(v4(9)), TCP_PORT));
    store.observe(
        AddressObservation::mapping_grant(SocketRole::Tcp, endpoint, lease),
        start,
    );
    let lapse = store.next_lapse(start).expect("a lease lapses");
    assert_eq!(lapse, start + lease);
    let before = lapse - Duration::from_millis(1);
    assert_eq!(
        store.endpoint(AddressFamily::V4, SocketRole::Tcp, before),
        EndpointVerdict::Known {
            endpoint,
            tier: ConfidenceTier::MappingGrant,
        }
    );
    assert_eq!(
        store.endpoint(AddressFamily::V4, SocketRole::Tcp, lapse),
        EndpointVerdict::Stale {
            endpoint,
            since: lapse,
        }
    );
}

// ------------------------------------------------------------- NAT hints

/// Three Kad observers naming three ports learn no port, but say the NAT maps
/// per destination: the Own Mapping moves alone, and the Own Address
/// Generation wakes for it.
#[test]
fn an_own_mapping_moved_alone_wakes_the_own_address_generation() {
    let store = SharedAddressLearning::new();
    let mut generation = store.own_address_changed();
    for (who, port) in [(1, KAD_PORT), (2, KAD_PORT + 1)] {
        store.observe(AddressObservation::kad_observed_port(
            ipv4(observer(who)),
            port,
        ));
    }
    generation.borrow_and_update();
    store.observe(AddressObservation::kad_observed_port(
        ipv4(observer(3)),
        KAD_PORT + 2,
    ));
    assert_eq!(store.learned_port(SocketRole::Udp), None);
    assert_eq!(
        store.own_mapping(SocketRole::Udp),
        OwnMapping::EndpointDependent
    );
    assert!(
        generation
            .has_changed()
            .expect("the store holds the sender")
    );
}

#[test]
fn two_fresh_tiers_that_disagree_publish_a_hint_without_losing_the_verdict() {
    let mut store = bound_store();
    let now = Instant::now();
    store.observe(AddressObservation::server_high_id(ipv4(v4(9))), now);
    store.observe(
        AddressObservation::mapping_grant(
            SocketRole::Tcp,
            PeerEndpoint::V4(Ipv4Endpoint::new(ipv4(v4(4)), TCP_PORT)),
            Duration::from_secs(3600),
        ),
        now,
    );

    assert_eq!(
        store
            .endpoint(AddressFamily::V4, SocketRole::Tcp, now)
            .known()
            .map(|endpoint| endpoint.ip()),
        Some(v4(9)),
        "the higher tier still wins"
    );
    assert_eq!(
        store.nat_hint(AddressFamily::V4, now),
        Some(NatHint::Disagreement {
            adopted_tier: ConfidenceTier::Server,
            adopted: v4(9),
            dissenting_tier: ConfidenceTier::MappingGrant,
            dissenting: v4(4),
        }),
        "and the disagreement is a published fact, not a silent overwrite"
    );
}

#[test]
fn agreeing_tiers_raise_no_hint() {
    let mut store = bound_store();
    let now = Instant::now();
    store.observe(AddressObservation::server_high_id(ipv4(v4(9))), now);
    store.observe(
        AddressObservation::mapping_grant(
            SocketRole::Tcp,
            PeerEndpoint::V4(Ipv4Endpoint::new(ipv4(v4(9)), TCP_PORT)),
            Duration::from_secs(3600),
        ),
        now,
    );
    assert_eq!(store.nat_hint(AddressFamily::V4, now), None);
}

#[test]
fn a_grant_of_a_private_external_address_reads_as_a_second_nat() {
    let mut store = bound_store();
    let now = Instant::now();
    let granted = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    assert_eq!(
        store.observe(
            AddressObservation::mapping_grant(
                SocketRole::Tcp,
                PeerEndpoint::V4(Ipv4Endpoint::new(ipv4(granted), TCP_PORT)),
                Duration::from_secs(3600),
            ),
            now,
        ),
        ObservationOutcome::NotPubliclyUsable
    );
    assert_eq!(
        store.nat_hint(AddressFamily::V4, now),
        Some(NatHint::DoubleNat { granted })
    );
}

#[test]
fn a_grant_in_the_carrier_grade_range_names_the_isp_not_the_router() {
    let mut store = bound_store();
    let now = Instant::now();
    let granted = IpAddr::V4(Ipv4Addr::new(100, 80, 0, 1));
    store.observe(
        AddressObservation::mapping_grant(
            SocketRole::Tcp,
            PeerEndpoint::V4(Ipv4Endpoint::new(ipv4(granted), TCP_PORT)),
            Duration::from_secs(3600),
        ),
        now,
    );
    assert_eq!(
        store.nat_hint(AddressFamily::V4, now),
        Some(NatHint::CarrierGradeNat { granted })
    );
}

/// A refused reflection is a hairpin only when it names an address this host
/// holds: a private address somebody else's LAN uses says nothing about our
/// path, and names no hint.
#[test]
fn a_reflection_of_our_own_lan_address_reads_as_a_hairpinned_path() {
    let mut store = bound_store();
    let now = Instant::now();
    let reflected = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    store.observe(
        AddressObservation::kad_observed_address(ipv4(observer(1)), ipv4(reflected)),
        now,
    );
    assert_eq!(
        store.nat_hint(AddressFamily::V4, now),
        None,
        "nothing here holds that address"
    );
    store.refresh_interfaces(&[reflected]);
    store.observe(
        AddressObservation::kad_observed_address(ipv4(observer(1)), ipv4(reflected)),
        now,
    );
    assert_eq!(
        store.nat_hint(AddressFamily::V4, now),
        Some(NatHint::Hairpin {
            reflected,
            tier: ConfidenceTier::KadCheck,
        }),
        "the observer saw our LAN address, so its reply never left the NAT"
    );
}

/// ADR-0091's self-punch guard asks *exactly* "is this one of my addresses".
/// Its sibling `interfaces_hold_locally` widens to loopback and every
/// enumerated address for hairpin detection; this one must not, or a node with nothing learned yet
/// would call every private-looking punch target "ourselves" — the loopback
/// comparison amule#1177 correction 4 is about.
#[test]
fn the_self_punch_guard_matches_our_interfaces_exactly_and_nothing_wider() {
    let mut store = AddressLearning::new();
    assert!(!store.holds_interface(IpAddr::V4(Ipv4Addr::LOCALHOST)));

    store.refresh_interfaces(&[v4(7), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))]);
    assert!(store.holds_interface(v4(7)));
    assert!(!store.holds_interface(v4(8)));
    assert!(!store.holds_interface(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert!(!store.holds_interface(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
}

/// Port `0` is no port: refused at `observe`, so it can neither hold the Kad
/// rung nor dissent in the Own Mapping.
#[test]
fn a_port_of_zero_is_refused() {
    let mut store = bound_store();
    let now = Instant::now();
    for observer_ip in [observer(1), observer(2), observer(3)] {
        assert_eq!(
            store.observe(
                AddressObservation::kad_observed_port(ipv4(observer_ip), 0),
                now,
            ),
            ObservationOutcome::PortZeroRefused
        );
    }
    assert_eq!(store.learned_port(SocketRole::Udp, now), None);
    assert_eq!(store.own_mapping(SocketRole::Udp, now), OwnMapping::Unknown);
}
