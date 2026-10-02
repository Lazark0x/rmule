//! The **Advertised Endpoints** chooser — what rmule actually claims on the
//! wire once the store and **Reachability** are both consulted — and the
//! shared handle that is the store's clock edge.

use super::*;

// --------------------------------------------------- the advertised endpoints

#[test]
fn an_advert_names_only_a_family_the_role_actually_bound() {
    // What bound, never what was configured: a host whose `::` bind was
    // refused has no IPv6 to advertise however much it learned.
    let mut store = AddressLearning::new();
    let now = Instant::now();
    store.record_bind(
        SocketRole::Tcp,
        &FamilyBinds {
            bound: vec![AddressFamily::V4],
            refused: vec![(
                AddressFamily::V6,
                std::io::ErrorKind::AddrNotAvailable,
                "no route".to_owned(),
            )],
        },
        TCP_PORT,
    );
    store.refresh_interfaces(&[v4(5), v6(1)]);

    let advert = AdvertisedEndpoints::choose(&store, AdvertReachability::unproven(), now);
    assert_eq!(
        advert.endpoint(AddressFamily::V4, SocketRole::Tcp),
        Some(PeerEndpoint::V4(Ipv4Endpoint::new(ipv4(v4(5)), TCP_PORT)))
    );
    assert_eq!(advert.endpoint(AddressFamily::V6, SocketRole::Tcp), None);
    assert!(!advert.advertises_ipv6());
}

#[test]
fn a_stale_endpoint_is_never_advertised() {
    let mut store = bound_store();
    let start = Instant::now();
    store.observe(AddressObservation::server_high_id(ipv4(v4(9))), start);
    store.end_server_session(start);

    let later = start + Duration::from_secs(1);
    assert!(
        matches!(
            store.endpoint(AddressFamily::V4, SocketRole::Tcp, later),
            EndpointVerdict::Stale { .. }
        ),
        "the crypt key may still use it"
    );
    let advert = AdvertisedEndpoints::choose(&store, AdvertReachability::unproven(), later);
    assert_eq!(
        advert.endpoint(AddressFamily::V4, SocketRole::Tcp),
        None,
        "but an advert may not"
    );
}

#[test]
fn a_probed_unreachable_ipv6_suppresses_the_ipv6_half_alone() {
    let mut store = bound_store();
    let now = Instant::now();
    store.refresh_interfaces(&[v4(5), v6(1)]);

    let reachable = AdvertisedEndpoints::choose(
        &store,
        AdvertReachability {
            tcp: TcpReachability::Open,
            ipv6: Ipv6Probe::ProbedReachable,
        },
        now,
    );
    assert!(reachable.advertises_ipv6());

    let suppressed = AdvertisedEndpoints::choose(
        &store,
        AdvertReachability {
            tcp: TcpReachability::Open,
            ipv6: Ipv6Probe::ProbedUnreachable,
        },
        now,
    );
    assert!(!suppressed.advertises_ipv6());
    assert_eq!(
        suppressed.endpoint(AddressFamily::V6, SocketRole::Tcp),
        None
    );
    assert_eq!(
        suppressed.endpoint(AddressFamily::V4, SocketRole::Tcp),
        Some(PeerEndpoint::V4(Ipv4Endpoint::new(ipv4(v4(5)), TCP_PORT))),
        "the IPv4 half is untouched"
    );
}

#[test]
fn a_firewalled_node_knows_its_tcp_endpoint_but_offers_no_dial() {
    let mut store = bound_store();
    let now = Instant::now();
    store.observe(AddressObservation::server_high_id(ipv4(v4(9))), now);

    let firewalled = AdvertisedEndpoints::choose(&store, AdvertReachability::unproven(), now);
    assert!(
        firewalled
            .endpoint(AddressFamily::V4, SocketRole::Tcp)
            .is_some(),
        "the address is known either way"
    );
    assert_eq!(
        firewalled.dialable_tcp(),
        None,
        "an endpoint nobody can reach is a dead invitation, not an advert"
    );

    let open = AdvertisedEndpoints::choose(
        &store,
        AdvertReachability {
            tcp: TcpReachability::Open,
            ipv6: Ipv6Probe::Unknown,
        },
        now,
    );
    assert_eq!(
        open.dialable_tcp(),
        Some(PeerEndpoint::V4(Ipv4Endpoint::new(ipv4(v4(9)), TCP_PORT)))
    );
}

// ------------------------------------------------------------ the shared edge

#[test]
fn the_shared_handle_is_where_the_clock_enters() {
    let shared = SharedAddressLearning::new();
    assert!(shared.is_empty());
    shared.record_bind(SocketRole::Tcp, &both_families(), TCP_PORT);
    shared.observe(AddressObservation::server_high_id(ipv4(v4(9))));

    assert_eq!(
        shared
            .endpoint(AddressFamily::V4, SocketRole::Tcp)
            .known()
            .map(|endpoint| endpoint.ip()),
        Some(v4(9))
    );
    assert!(!shared.is_empty());
}
