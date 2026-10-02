//! The IPv4 ladder's rungs and the Kad self-check's two-agree rule: which
//! source outranks which, and what it takes for a Kad report to hold at all.

use super::*;

// ---------------------------------------------------------------- IPv4 ladder

#[test]
fn an_unbound_role_with_no_observation_is_unknown() {
    let store = AddressLearning::new();
    let now = Instant::now();
    assert_eq!(
        store.endpoint(AddressFamily::V4, SocketRole::Tcp, now),
        EndpointVerdict::Unknown
    );
}

#[test]
fn the_bound_port_is_the_floor_a_learned_address_lands_on() {
    // Nothing observes our TCP port — no NAT names one, and the server's
    // High-ID carries an address only. The port the listener actually bound is
    // the honest answer, and without it a known address could never become an
    // endpoint at all.
    let mut store = bound_store();
    let now = Instant::now();
    store.observe(AddressObservation::server_high_id(ipv4(v4(9))), now);

    assert_eq!(
        store.endpoint(AddressFamily::V4, SocketRole::Tcp, now),
        EndpointVerdict::Known {
            endpoint: PeerEndpoint::V4(Ipv4Endpoint::new(ipv4(v4(9)), TCP_PORT)),
            tier: ConfidenceTier::Server,
        }
    );
}

#[test]
fn the_ipv4_ladder_descends_override_server_kad_grant_interface() {
    // Every rung of ADR-0084's IPv4 ladder, added weakest-first: each stronger
    // source must take the verdict from the one below it, and none may be
    // outvoted by a weaker one.
    let mut store = bound_store();
    let now = Instant::now();
    let tier = |store: &AddressLearning| {
        store
            .endpoint(AddressFamily::V4, SocketRole::Tcp, now)
            .tier()
            .expect("a fresh tier holds")
    };

    store.refresh_interfaces(&[v4(5)]);
    assert_eq!(tier(&store), ConfidenceTier::Interface);

    store.observe(
        AddressObservation::mapping_grant(
            SocketRole::Tcp,
            PeerEndpoint::V4(Ipv4Endpoint::new(ipv4(v4(4)), TCP_PORT)),
            Duration::from_secs(3600),
        ),
        now,
    );
    assert_eq!(tier(&store), ConfidenceTier::MappingGrant);

    store.observe(
        AddressObservation::kad_observed_address(ipv4(observer(1)), ipv4(v4(3))),
        now,
    );
    store.observe(
        AddressObservation::kad_observed_address(ipv4(observer(2)), ipv4(v4(3))),
        now,
    );
    assert_eq!(tier(&store), ConfidenceTier::KadCheck);

    store.observe(AddressObservation::server_high_id(ipv4(v4(2))), now);
    assert_eq!(tier(&store), ConfidenceTier::Server);

    store.set_override(
        ExternalAddressOverride {
            v4: Some(ipv4(v4(1))),
            v6: None,
        },
        now,
    );
    assert_eq!(tier(&store), ConfidenceTier::Override);
    assert_eq!(
        store
            .endpoint(AddressFamily::V4, SocketRole::Tcp, now)
            .known()
            .map(|endpoint| endpoint.ip()),
        Some(v4(1))
    );
}

#[test]
fn an_ipv6_pinhole_grant_leaves_the_ipv4_nat_s_mismatched_udp_port_alone() {
    // One port ladder per role serves both families. The mapper installs the
    // IPv4 rows before the IPv6 ones, so a pinhole grant — whose port is
    // always the one we bound — landed last and replaced the IPv4 NAT's
    // shifted UDP port, and the v4 endpoint then named a port no NAT forwards.
    let mut store = bound_store();
    let now = Instant::now();
    let lease = Duration::from_secs(3600);
    store.refresh_interfaces(&[v6(5)]);
    store.observe(
        AddressObservation::mapping_grant(
            SocketRole::Udp,
            PeerEndpoint::V4(Ipv4Endpoint::new(ipv4(v4(4)), 40_000)),
            lease,
        ),
        now,
    );
    let IpAddr::V6(pinhole) = v6(5) else {
        unreachable!("an IPv6 fixture")
    };
    store.observe(
        AddressObservation::mapping_grant(
            SocketRole::Udp,
            PeerEndpoint::V6(rmule_primitives::Ipv6Endpoint::new(pinhole, KAD_PORT)),
            lease,
        ),
        now,
    );

    assert_eq!(store.learned_port(SocketRole::Udp, now), Some(40_000));
    assert_eq!(
        store
            .endpoint(AddressFamily::V4, SocketRole::Udp, now)
            .known()
            .map(|endpoint| endpoint.port()),
        Some(40_000)
    );
}

#[test]
fn two_kad_strangers_never_outvote_the_server() {
    // The rejected "source-agnostic majority vote": two agreeing Kad nodes
    // form a quorum, and must still lose to the server that assigned the
    // High-ID — it is literally the address peers dial.
    let mut store = bound_store();
    let now = Instant::now();
    store.observe(AddressObservation::server_high_id(ipv4(v4(9))), now);
    store.observe(
        AddressObservation::kad_observed_address(ipv4(observer(1)), ipv4(v4(7))),
        now,
    );
    store.observe(
        AddressObservation::kad_observed_address(ipv4(observer(2)), ipv4(v4(7))),
        now,
    );

    assert_eq!(
        store
            .endpoint(AddressFamily::V4, SocketRole::Tcp, now)
            .known()
            .map(|endpoint| endpoint.ip()),
        Some(v4(9))
    );
}

// ------------------------------------------------------------- Kad two-agree

#[test]
fn one_kad_report_is_a_candidate_and_two_agreeing_ones_hold() {
    let mut store = bound_store();
    let now = Instant::now();
    store.observe(
        AddressObservation::kad_observed_address(ipv4(observer(1)), ipv4(v4(7))),
        now,
    );
    assert_eq!(
        store.endpoint(AddressFamily::V4, SocketRole::Udp, now),
        EndpointVerdict::Unknown,
        "a lone report is a candidate, never a verdict"
    );

    store.observe(
        AddressObservation::kad_observed_address(ipv4(observer(2)), ipv4(v4(7))),
        now,
    );
    assert_eq!(
        store
            .endpoint(AddressFamily::V4, SocketRole::Udp, now)
            .tier(),
        Some(ConfidenceTier::KadCheck)
    );
}

#[test]
fn the_same_kad_observer_reporting_twice_is_still_one_opinion() {
    let mut store = bound_store();
    let now = Instant::now();
    for _ in 0..3 {
        store.observe(
            AddressObservation::kad_observed_address(ipv4(observer(1)), ipv4(v4(7))),
            now,
        );
    }
    assert_eq!(
        store.endpoint(AddressFamily::V4, SocketRole::Udp, now),
        EndpointVerdict::Unknown
    );
}

#[test]
fn a_kad_port_two_of_three_observers_name_holds_across_a_dissent_between_them() {
    // aMule's `SetExternKadPort` (`Prefs.cpp:305-316`) compares a new answer
    // with *every* earlier one of the round, not just the last: 5000, 6000,
    // 5000 adopts 5000. A dissent is one more candidate, never a reset.
    let mut store = bound_store();
    let now = Instant::now();
    for (who, port) in [(1, 5000), (2, 6000)] {
        store.observe(
            AddressObservation::kad_observed_port(ipv4(observer(who)), port),
            now,
        );
    }
    assert_eq!(
        store.learned_port(SocketRole::Udp, now),
        None,
        "no two agree yet"
    );

    store.observe(
        AddressObservation::kad_observed_port(ipv4(observer(3)), 5000),
        now,
    );
    assert_eq!(store.learned_port(SocketRole::Udp, now), Some(5000));
}

#[test]
fn the_newest_kad_port_is_the_candidate_so_a_changed_mapping_needs_its_own_two() {
    // A mapping that moved: the old port's agreement does not outvote the new
    // port's first report — until a second observer names the new one.
    let mut store = bound_store();
    let now = Instant::now();
    for (who, port) in [(1, 5000), (2, 5000), (3, 6000)] {
        store.observe(
            AddressObservation::kad_observed_port(ipv4(observer(who)), port),
            now,
        );
    }
    assert_eq!(store.learned_port(SocketRole::Udp, now), None);
    assert_eq!(
        store.port(SocketRole::Udp, now),
        Some(KAD_PORT),
        "with nothing learned the bound port is the floor"
    );

    store.observe(
        AddressObservation::kad_observed_port(ipv4(observer(4)), 6000),
        now,
    );
    assert_eq!(store.learned_port(SocketRole::Udp, now), Some(6000));
}

#[test]
fn a_round_boundary_forgets_the_port_ladder_s_kad_reports_so_one_fresh_report_alone_adopts_nothing()
{
    // ADR-0084's amendment: aMule starts every round's observer lists
    // empty (`FindExternKadPort(true)`, `Prefs.cpp:305-322`), so a report
    // backed only by votes from before the boundary must not count once one
    // has passed. The IPv4 address ladder's own two-agree rung is a
    // completely separate `BTreeMap` entry, so the boundary must leave it be
    // ("the address votes and other roles untouched").
    let mut store = bound_store();
    let now = Instant::now();
    for (who, port) in [(1, 5000), (2, 5000)] {
        store.observe(
            AddressObservation::kad_observed_port(ipv4(observer(who)), port),
            now,
        );
    }
    store.observe(
        AddressObservation::kad_observed_address(ipv4(observer(1)), ipv4(v4(7))),
        now,
    );
    store.observe(
        AddressObservation::kad_observed_address(ipv4(observer(2)), ipv4(v4(7))),
        now,
    );
    assert_eq!(store.learned_port(SocketRole::Udp, now), Some(5000));

    store.forget_kad_port_round(SocketRole::Udp);
    assert_eq!(
        store.learned_port(SocketRole::Udp, now),
        None,
        "the boundary forgot both reports; the port needs two fresh ones again"
    );
    assert_eq!(
        store
            .endpoint(AddressFamily::V4, SocketRole::Udp, now)
            .tier(),
        Some(ConfidenceTier::KadCheck),
        "the address ladder's own agreement is untouched by the port boundary"
    );

    store.observe(
        AddressObservation::kad_observed_port(ipv4(observer(3)), 5000),
        now,
    );
    assert_eq!(
        store.learned_port(SocketRole::Udp, now),
        None,
        "one report from after the boundary is a candidate alone, never a verdict"
    );
}

#[test]
fn a_kad_report_ages_out_of_its_thirty_minute_window() {
    let mut store = bound_store();
    let start = Instant::now();
    store.observe(
        AddressObservation::kad_observed_address(ipv4(observer(1)), ipv4(v4(7))),
        start,
    );
    store.observe(
        AddressObservation::kad_observed_address(ipv4(observer(2)), ipv4(v4(7))),
        start,
    );

    let inside = start + OBSERVATION_WINDOW - Duration::from_secs(1);
    assert_eq!(
        store
            .endpoint(AddressFamily::V4, SocketRole::Udp, inside)
            .tier(),
        Some(ConfidenceTier::KadCheck),
        "still inside the window"
    );

    let outside = start + OBSERVATION_WINDOW + Duration::from_secs(1);
    assert!(
        matches!(
            store.endpoint(AddressFamily::V4, SocketRole::Udp, outside),
            EndpointVerdict::Stale { .. }
        ),
        "outside it the last-known value survives as stale, never as Known"
    );
}

#[test]
fn the_own_mapping_reads_whether_one_round_s_observers_disagree() {
    // ADR-0091's amendment: a symmetric NAT gives each Kad observer its
    // own external port, and that disagreement — which the two-agree rung
    // discards — is the whole signal. It is one round's: the boundary forgets
    // it, and a report past the window no longer speaks.
    let mut store = bound_store();
    let now = Instant::now();
    for (who, port) in [(1, 31_004), (2, 50_219), (3, 7_781)] {
        store.observe(
            AddressObservation::kad_observed_port(ipv4(observer(who)), port),
            now,
        );
    }
    assert_eq!(
        store.own_mapping(SocketRole::Udp, now),
        OwnMapping::EndpointDependent
    );

    store.forget_kad_port_round(SocketRole::Udp);
    assert_eq!(store.own_mapping(SocketRole::Udp, now), OwnMapping::Unknown);

    for who in [4, 5] {
        store.observe(
            AddressObservation::kad_observed_port(ipv4(observer(who)), KAD_PORT),
            now,
        );
    }
    assert_eq!(
        store.own_mapping(SocketRole::Udp, now),
        OwnMapping::EndpointIndependent
    );
    assert_eq!(
        store.own_mapping(SocketRole::Udp, now + OBSERVATION_WINDOW),
        OwnMapping::Unknown,
        "reports past the 30-minute window say nothing"
    );
}
