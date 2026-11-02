//! The peer quorum and the local-interface corroboration filter — the two
//! halves of "a peer's claim about our address is a vote, never adopted on its
//! own". They are separate controls: the quorum decides *whether enough
//! strangers agree*, the filter decides *whether the address is even ours*.

use super::*;

// ------------------------------------------------------------- peer quorum

#[test]
fn three_distinct_peers_within_the_window_carry_an_ipv6_quorum() {
    let mut store = bound_store();
    let now = Instant::now();
    store.refresh_interfaces(&[v6(1)]);
    // The interface rung already holds it, so prove the quorum by its tier.
    for index in 0..2u8 {
        store.observe(AddressObservation::peer_vote(observer(index), v6(1)), now);
        assert_eq!(
            store
                .endpoint(AddressFamily::V6, SocketRole::Tcp, now)
                .tier(),
            Some(ConfidenceTier::Interface),
            "fewer than three observers is not a quorum"
        );
    }
    store.observe(AddressObservation::peer_vote(observer(2), v6(1)), now);
    assert_eq!(
        store
            .endpoint(AddressFamily::V6, SocketRole::Tcp, now)
            .tier(),
        Some(ConfidenceTier::PeerVote)
    );
}

#[test]
fn one_peer_voting_three_times_is_not_a_quorum() {
    // The quorum is keyed on the observer's own source address, and one
    // observer holding one socket is one opinion however often it speaks.
    let mut store = bound_store();
    let now = Instant::now();
    store.refresh_interfaces(&[v6(1)]);
    for _ in 0..4 {
        store.observe(AddressObservation::peer_vote(observer(1), v6(1)), now);
    }
    assert_eq!(
        store
            .endpoint(AddressFamily::V6, SocketRole::Tcp, now)
            .tier(),
        Some(ConfidenceTier::Interface)
    );
}

#[test]
fn a_peer_vote_about_an_ipv4_address_is_refused_outright() {
    // `CT_MOD_YOUR_IP`'s integer form: one unverified peer would decide what
    // this client believes its own address to be — and a client wrong about
    // its own address is wrong about whether it is firewalled. rmule follows
    // emule-qt and aMule, not eMuleAI.
    let mut store = bound_store();
    let now = Instant::now();
    for index in 0..3u8 {
        assert_eq!(
            store.observe(AddressObservation::peer_vote(observer(index), v4(7)), now),
            ObservationOutcome::Ipv4PeerVoteRefused
        );
    }
    assert_eq!(
        store.endpoint(AddressFamily::V4, SocketRole::Tcp, now),
        EndpointVerdict::Unknown
    );
}

#[test]
fn a_quorum_lapses_when_its_third_newest_vote_leaves_the_window() {
    let mut store = bound_store();
    let start = Instant::now();
    store.refresh_interfaces(&[v6(1), v6(2)]);
    // Three votes for :2 (the address the interface rung would not pick).
    for index in 0..3u8 {
        store.observe(
            AddressObservation::peer_vote(observer(index), v6(2)),
            start + Duration::from_secs(u64::from(index)),
        );
    }
    let tier_at = |store: &AddressLearning, at: Instant| {
        store
            .endpoint(AddressFamily::V6, SocketRole::Tcp, at)
            .tier()
    };
    assert_eq!(tier_at(&store, start), Some(ConfidenceTier::PeerVote));

    // The quorum survives until the *third-newest* supporting vote — the one
    // that makes it a quorum at all — leaves the window.
    let lapse = start + OBSERVATION_WINDOW;
    assert_eq!(
        tier_at(&store, lapse - Duration::from_secs(1)),
        Some(ConfidenceTier::PeerVote)
    );
    assert_eq!(
        tier_at(&store, lapse + Duration::from_secs(1)),
        Some(ConfidenceTier::Interface),
        "the quorum lapsed back to the address this host can prove it holds"
    );
}

#[test]
fn a_ninth_observer_evicts_the_oldest_remembered_vote() {
    let mut store = bound_store();
    let now = Instant::now();
    store.refresh_interfaces(&[v6(1)]);
    for index in 0..u8::try_from(OBSERVERS_REMEMBERED + 1).expect("small") {
        store.observe(AddressObservation::peer_vote(observer(index), v6(1)), now);
    }
    // Eight observers remembered, all agreeing: the quorum still holds, and
    // the memory is bounded rather than growing with every hello.
    assert_eq!(
        store
            .endpoint(AddressFamily::V6, SocketRole::Tcp, now)
            .tier(),
        Some(ConfidenceTier::PeerVote)
    );
}

#[test]
fn unheld_votes_are_refused_and_cannot_evict_an_honest_quorum() {
    // Eight remembered votes of any value used to be filtered by interface
    // only at read time: eight votes for an address we do not hold evicted
    // the honest quorum, won the ranking, and were then dropped — leaving the
    // Interface tier's first pick instead of the address the world sees.
    let mut store = bound_store();
    let now = Instant::now();
    store.refresh_interfaces(&[v6(1), v6(2)]);
    for index in 0..3u8 {
        store.observe(AddressObservation::peer_vote(observer(index), v6(2)), now);
    }
    for index in 10..10 + u8::try_from(OBSERVERS_REMEMBERED).expect("small") {
        assert_eq!(
            store.observe(
                AddressObservation::peer_vote(observer(index), v6(0xbad)),
                now
            ),
            ObservationOutcome::UnheldPeerVoteRefused
        );
    }
    assert_eq!(
        store.endpoint(AddressFamily::V6, SocketRole::Tcp, now),
        EndpointVerdict::Known {
            endpoint: PeerEndpoint::V6(rmule_primitives::Ipv6Endpoint::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
                TCP_PORT
            )),
            tier: ConfidenceTier::PeerVote,
        }
    );
}

#[test]
fn observers_inside_one_ipv6_prefix_are_one_vote() {
    // One /64 holds any number of /128s. Keyed per address, a single host
    // was a quorum on its own; keyed by its accounting prefix, it is one.
    let mut store = bound_store();
    let now = Instant::now();
    store.refresh_interfaces(&[v6(1)]);
    for host in 0xa..0xdu16 {
        let observer = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x77, 0, 0, 0, 0, host));
        store.observe(AddressObservation::peer_vote(observer, v6(1)), now);
    }
    assert_eq!(
        store
            .endpoint(AddressFamily::V6, SocketRole::Tcp, now)
            .tier(),
        Some(ConfidenceTier::Interface),
        "three addresses of one prefix are one observer"
    );
}

// ------------------------------------------- the local-interface corroboration

#[test]
fn a_reflected_ipv6_this_host_does_not_hold_is_never_adopted() {
    // The security control: peers are unauthenticated, so corroboration on its
    // own must never make rmule advertise a foreign address. Three honest-
    // looking observers are not enough — only an address this host actually
    // holds can be picked.
    let mut store = bound_store();
    let now = Instant::now();
    store.refresh_interfaces(&[v6(1)]);
    for index in 0..3u8 {
        store.observe(
            AddressObservation::peer_vote(observer(index), v6(0xbad)),
            now,
        );
    }
    assert_eq!(
        store
            .endpoint(AddressFamily::V6, SocketRole::Tcp, now)
            .known()
            .map(|endpoint| endpoint.ip()),
        Some(v6(1)),
        "corroboration picks which of our own addresses the world sees, nothing more"
    );
}

#[test]
fn a_server_reflected_ipv6_is_adopted_only_once_the_host_holds_it() {
    let mut store = bound_store();
    let now = Instant::now();
    store.observe(AddressObservation::server_reflection(v6(2)), now);
    assert_eq!(
        store.endpoint(AddressFamily::V6, SocketRole::Tcp, now),
        EndpointVerdict::Unknown,
        "even the server's reflection needs corroboration in IPv6"
    );

    store.refresh_interfaces(&[v6(1), v6(2)]);
    assert_eq!(
        store
            .endpoint(AddressFamily::V6, SocketRole::Tcp, now)
            .known()
            .map(|endpoint| endpoint.ip()),
        Some(v6(2)),
        "corroborated, the reflection outranks the interface's own first pick"
    );
}

#[test]
fn a_renumber_drops_an_adopted_reflection_at_the_next_refresh() {
    // RFC 4941 privacy rotation, or a prefix renumber: the address we adopted
    // is simply no longer held, and the next enumeration must unseat it.
    let mut store = bound_store();
    let now = Instant::now();
    store.refresh_interfaces(&[v6(2)]);
    store.observe(AddressObservation::server_reflection(v6(2)), now);
    assert_eq!(
        store
            .endpoint(AddressFamily::V6, SocketRole::Tcp, now)
            .tier(),
        Some(ConfidenceTier::Server)
    );

    store.refresh_interfaces(&[v6(3)]);
    assert_eq!(
        store
            .endpoint(AddressFamily::V6, SocketRole::Tcp, now)
            .known()
            .map(|endpoint| endpoint.ip()),
        Some(v6(3)),
        "the rotated-away address is gone; the held one takes over"
    );
}

#[test]
fn the_corroboration_filter_does_not_apply_to_ipv4() {
    // Behind NAT the external IPv4 is never on a local interface, so the same
    // filter would refuse every true answer. There the tier order is the
    // defence.
    let mut store = bound_store();
    let now = Instant::now();
    store.refresh_interfaces(&[]);
    store.observe(AddressObservation::server_high_id(ipv4(v4(9))), now);
    assert_eq!(
        store
            .endpoint(AddressFamily::V4, SocketRole::Tcp, now)
            .tier(),
        Some(ConfidenceTier::Server)
    );
}

#[test]
fn an_operator_override_needs_no_corroboration() {
    let mut store = bound_store();
    let now = Instant::now();
    store.set_override(
        ExternalAddressOverride {
            v4: None,
            v6: Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x5e)),
        },
        now,
    );
    assert_eq!(
        store
            .endpoint(AddressFamily::V6, SocketRole::Tcp, now)
            .tier(),
        Some(ConfidenceTier::Override),
        "an operator stating an address is not a stranger claiming one"
    );
}

// ---------------------------------------------- the hello's own vote fold

/// The fold from a peer's hello into the quorum (ADR-0087): three peers that
/// reflected our IPv6 back carry it, keyed on the address we *observed* each
/// of them at — never the user hash they claim, which costs nothing to invent.
/// A hello with no `CT_MOD_YOUR_IP` folds nothing.
#[test]
fn a_hellos_your_ip_reflection_is_one_vote_keyed_on_the_observed_peer() {
    let addresses = SharedAddressLearning::new();
    addresses.record_bind(SocketRole::Tcp, &both_families(), TCP_PORT);
    addresses.refresh_interfaces(&[v6(1)]);

    // A hello with no reflection: nothing to fold, so the interface rung still
    // owns the verdict.
    crate::address_learning::record_peer_ipv6_vote(&addresses, peer_at(1), &hello_identity(None));
    assert_eq!(
        addresses
            .endpoint(AddressFamily::V6, SocketRole::Tcp)
            .tier(),
        Some(ConfidenceTier::Interface),
    );

    // Three distinct observers reflecting the same address carry the quorum.
    for octet in 1..=3u8 {
        crate::address_learning::record_peer_ipv6_vote(
            &addresses,
            peer_at(octet),
            &hello_identity(Some("2001:db8::1")),
        );
    }
    assert_eq!(
        addresses
            .endpoint(AddressFamily::V6, SocketRole::Tcp)
            .tier(),
        Some(ConfidenceTier::PeerVote),
        "three observers, keyed on where we saw each of them"
    );
}

/// The same reflection from one peer dialled three times is still one vote:
/// the quorum keys on the observer's address.
#[test]
fn one_peer_reflecting_three_times_is_still_one_vote() {
    let addresses = SharedAddressLearning::new();
    addresses.record_bind(SocketRole::Tcp, &both_families(), TCP_PORT);
    addresses.refresh_interfaces(&[v6(1)]);

    for _ in 0..3 {
        crate::address_learning::record_peer_ipv6_vote(
            &addresses,
            peer_at(7),
            &hello_identity(Some("2001:db8::1")),
        );
    }
    assert_eq!(
        addresses
            .endpoint(AddressFamily::V6, SocketRole::Tcp)
            .tier(),
        Some(ConfidenceTier::Interface),
        "one observer is one opinion however often it repeats it"
    );
}

fn peer_at(octet: u8) -> rmule_primitives::PeerEndpoint {
    rmule_primitives::PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, octet), 4662))
}

/// A decoded hello identity carrying `reflected` as its `CT_MOD_YOUR_IP`.
fn hello_identity(reflected: Option<&str>) -> rmule_peer::PeerIdentity {
    let mut tags = Vec::new();
    if let Some(text) = reflected {
        let address: Ipv6Addr = text.parse().unwrap();
        tags.push(rmule_primitives::Tag::new(
            rmule_primitives::TagName::length_prefixed_id(rmule_primitives::CT_MOD_YOUR_IP),
            rmule_primitives::TagValue::Hash(address.octets()),
        ));
    }
    rmule_peer::PeerIdentity::from_hello_body(&rmule_peer::PeerHelloBody {
        user_hash: rmule_primitives::UserHash::from_bytes([0x11; 16]),
        client_id: rmule_primitives::ClientId::from_u32(0x0200_0002),
        tcp_port: 4662,
        tags,
        connected_server: Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0),
    })
}

// ------------------------------------------------------- mixed-age windows

/// Freshness before ranking (ADR-0084): five lapsed votes for one held
/// address do not outrank three fresh ones for another; the fresh quorum is
/// adopted.
#[test]
fn a_fresh_quorum_outranks_a_larger_lapsed_one() {
    let mut store = bound_store();
    let start = Instant::now();
    store.refresh_interfaces(&[v6(1), v6(2)]);
    for index in 10..15u8 {
        store.observe(AddressObservation::peer_vote(observer(index), v6(1)), start);
    }
    let now = start + OBSERVATION_WINDOW + Duration::from_secs(60);
    for index in 20..23u8 {
        store.observe(AddressObservation::peer_vote(observer(index), v6(2)), now);
    }
    assert_eq!(
        store.known_address(AddressFamily::V6, now),
        Some(v6(2)),
        "the fresh quorum holds"
    );
    assert_eq!(
        store.address_tier(AddressFamily::V6, now),
        Some(ConfidenceTier::PeerVote)
    );
}

/// The Kad address rung's window slides with every backer: a report whose
/// only agreeing backer has left the window is no agreement, and a fresh
/// second observer restores it.
#[test]
fn a_lapsed_backer_does_not_hold_a_fresh_kad_report() {
    let mut store = bound_store();
    let start = Instant::now();
    store.observe(
        AddressObservation::kad_observed_address(ipv4(observer(1)), ipv4(v4(7))),
        start,
    );
    let now = start + OBSERVATION_WINDOW + Duration::from_secs(60);
    store.observe(
        AddressObservation::kad_observed_address(ipv4(observer(2)), ipv4(v4(7))),
        now,
    );
    assert_eq!(store.known_address(AddressFamily::V4, now), None);
    assert_eq!(
        store.address(AddressFamily::V4, now),
        Some(v4(7)),
        "the agreement that lapsed is still the stale last-known"
    );
    store.observe(
        AddressObservation::kad_observed_address(ipv4(observer(3)), ipv4(v4(7))),
        now,
    );
    assert_eq!(store.known_address(AddressFamily::V4, now), Some(v4(7)));
    assert_eq!(
        store.address_tier(AddressFamily::V4, now),
        Some(ConfidenceTier::KadCheck)
    );
}
