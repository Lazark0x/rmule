//! The UDP firewall self-check: recruiting fresh helpers, folding their `0x62`
//! results into a verdict, the six-minute timeout, and the helper side this
//! node runs for other people's checks.

use std::time::Duration;

use rmule_kad::{
    Kad2Message, KadCommand, KadContact, KadEvent, KadId, KadInstant, KadNode, KadNodeConfig,
    KadNodeDiagnostic, KadNodeEndpoint, KadNodeStart, KadObfuscation, KadOutput, KadSelfCheck,
    UdpFirewallHelper, UserHash,
};
use rmule_primitives::Ipv4Endpoint;
use rmule_primitives::session::drain;
use rmule_primitives::{ClientEncryptKey, encrypt_datagram_client};
use rmule_testkit::kad_node::{
    OUR_INTERN_UDP, OWN_IP, T0, crypt_node, crypt_start, datagrams, deliver, diagnostics, endpoint,
    events, fixed_nonce, host_ip, id, node, our_key_for, self_checking_node, sent_messages, start,
};

/// End the **Extern Port Round** the way core's verdict does, so the helper
/// gate is open and these legs exercise the helper rules alone
/// (`node_extern_port` pins the round itself).
fn settle_extern_port(node: &mut KadNode) {
    node.handle_command(
        T0,
        KadCommand::SetExternalUdpPort {
            port: OUR_INTERN_UDP,
        },
    );
}

/// A fresh UDP-check helper candidate at `203.0.113.host` (TCP port `4700+host`).
fn udp_helper(host: u8, version: u8) -> UdpFirewallHelper {
    UdpFirewallHelper {
        endpoint: Ipv4Endpoint::new(host_ip(host), 4700 + u16::from(host)),
        id: id(host),
        version,
    }
}

/// The `UdpFirewallCheckRequested` events, as (dial endpoint, request payload).
fn udp_requests(outputs: &[KadOutput]) -> Vec<(Ipv4Endpoint, Vec<u8>)> {
    events(outputs)
        .into_iter()
        .filter_map(|event| match event {
            KadEvent::UdpFirewallCheckRequested { helper, request } => Some((helper, request)),
            _ => None,
        })
        .collect()
}

/// The helper-lookup target the tests arm: fixed, where a driver draws a
/// random one per lookup (aMule `FindNodeFWCheckUDP`'s `GetRandomUint128`).
fn helper_lookup_target() -> KadId {
    id(0x33)
}

/// The dial endpoints of the helpers engaged among `outputs`.
fn engaged(outputs: &[KadOutput]) -> Vec<Ipv4Endpoint> {
    udp_requests(outputs)
        .into_iter()
        .map(|(helper, _)| helper)
        .collect()
}

#[test]
fn the_helper_lookup_offers_its_answer_rows_to_the_udp_check_and_walks_no_further() {
    let mut node = KadNode::new(
        start().self_check(KadSelfCheck::new().with_udp_helper_lookup(helper_lookup_target)),
    );
    settle_extern_port(&mut node);
    let responder = endpoint(9, 4672);
    node.handle_command(
        T0,
        KadCommand::MergeContacts {
            contacts: vec![KadContact::new(id(9), responder, 4709, 8)],
        },
    );
    drain(|| node.poll_output());

    // Any Kad datagram is aMule's `CUDPFirewallTester::Connected()`: the
    // first one launches the helper lookup, asking for KADEMLIA_FIND_NODE
    // (eleven) contacts per query.
    deliver(&mut node, T0, responder, &Kad2Message::Ping);
    assert!(
        sent_messages(&drain(|| node.poll_output())).contains(&(
            responder,
            Kad2Message::LookupReq {
                count: 0x0B,
                target: id(0x33),
                check: id(9),
            }
        )),
        "the first contact launches the helper lookup"
    );

    // The answer names the responder itself (a routing-zone IP), a v5 node,
    // three fresh v8 nodes and ourselves.
    let row = |host: u8, version: u8| {
        KadContact::new(
            id(host),
            endpoint(host, 4672),
            4700 + u16::from(host),
            version,
        )
    };
    deliver(
        &mut node,
        T0,
        responder,
        &Kad2Message::LookupRes {
            target: id(0x33),
            contacts: vec![
                KadContact::new(id(9), responder, 4709, 8),
                row(1, 5),
                row(2, 8),
                row(3, 8),
                row(4, 8),
                KadContact::new(id(0xAA), endpoint(5, 4672), 4705, 8),
            ],
        },
    );
    let outputs = drain(|| node.poll_output());
    let helper = |host: u8| Ipv4Endpoint::new(host_ip(host), 4700 + u16::from(host));
    assert_eq!(
        engaged(&outputs),
        vec![helper(2), helper(3)],
        "the first two fresh rows, dialed at their TCP ports"
    );
    assert!(
        sent_messages(&outputs)
            .iter()
            .all(|(_, message)| !matches!(message, Kad2Message::LookupReq { .. })),
        "a helper row is a candidate for the tester, never a walk candidate"
    );

    // The third fresh row waited in the possible list: a cancelled helper
    // frees the slot it took (a failed one would not — it counts toward the
    // two), and ourselves is skipped on the way to it.
    node.handle_command(
        T0,
        KadCommand::UdpFirewallCheckCancelled {
            helper_ip: host_ip(2),
        },
    );
    assert_eq!(engaged(&drain(|| node.poll_output())), vec![helper(4)]);
}

#[test]
fn a_recheck_launches_a_fresh_helper_lookup() {
    let mut node = KadNode::new(
        start().self_check(KadSelfCheck::new().with_udp_helper_lookup(helper_lookup_target)),
    );
    settle_extern_port(&mut node);
    let responder = endpoint(9, 4672);
    node.handle_command(
        T0,
        KadCommand::MergeContacts {
            contacts: vec![KadContact::new(id(9), responder, 4709, 8)],
        },
    );
    drain(|| node.poll_output());

    // aMule's `ReCheckFirewallUDP` starts `FindNodeFWCheckUDP` itself; it
    // does not wait for the next datagram.
    assert!(node.recheck_reachability(T0));
    assert!(
        sent_messages(&drain(|| node.poll_output())).contains(&(
            responder,
            Kad2Message::LookupReq {
                count: 0x0B,
                target: id(0x33),
                check: id(9),
            }
        )),
        "the recheck launches the helper lookup"
    );
}

#[test]
fn the_hourly_recheck_launches_a_fresh_helper_lookup() {
    let mut node = KadNode::new(
        start().self_check(KadSelfCheck::new().with_udp_helper_lookup(helper_lookup_target)),
    );
    settle_extern_port(&mut node);
    let responder = endpoint(9, 4672);
    node.handle_command(
        T0,
        KadCommand::MergeContacts {
            contacts: vec![KadContact::new(id(9), responder, 4709, 8)],
        },
    );
    drain(|| node.poll_output());

    // aMule's hourly `RecheckFirewalled` pairs `SetRecheckIP` with
    // `CUDPFirewallTester::ReCheckFirewallUDP(false)` (`Kademlia.cpp:365-380`)
    // — the same pairing the external trigger above already applies. Before
    // this fix the hourly clock re-armed only the TCP self-check.
    let recheck_at = T0 + KadNode::FIREWALL_RECHECK_INTERVAL;
    node.tick(recheck_at);
    assert!(
        sent_messages(&drain(|| node.poll_output())).contains(&(
            responder,
            Kad2Message::LookupReq {
                count: 0x0B,
                target: id(0x33),
                check: id(9),
            }
        )),
        "the hourly recheck launches the helper lookup, not just the TCP check"
    );
}

#[test]
fn helpers_used_before_the_recheck_stay_ineligible_but_fresh_ones_are_engaged() {
    let mut node = self_checking_node();
    settle_extern_port(&mut node);
    node.offer_udp_firewall_helper(udp_helper(1, 8));
    drain(|| node.poll_output());
    node.consume_udp_firewall_failure(T0, host_ip(1));
    drain(|| node.poll_output());

    // aMule's `ReCheckFirewallUDP` never clears `m_usedTestClients` — the
    // never-reused rule is the whole point of that list, and the function
    // touches only the running/finished counters and the timers
    // (`UDPFirewallTester.cpp:200-219`).
    node.tick(T0 + KadNode::FIREWALL_RECHECK_INTERVAL);
    drain(|| node.poll_output());
    // The recheck reopened the Extern Port Round; its verdict comes back.
    settle_extern_port(&mut node);

    node.offer_udp_firewall_helper(udp_helper(1, 8));
    assert!(
        udp_requests(&drain(|| node.poll_output())).is_empty(),
        "a helper used before the recheck is not fresh again"
    );
    node.offer_udp_firewall_helper(udp_helper(2, 8));
    assert_eq!(
        engaged(&drain(|| node.poll_output())),
        vec![udp_helper(2, 8).endpoint],
        "a never-used helper is still engaged in the fresh round"
    );
}

#[test]
fn a_recheck_mid_test_aborts_it_and_a_late_result_from_before_lands_stale() {
    let mut node = self_checking_node();
    settle_extern_port(&mut node);
    node.offer_udp_firewall_helper(udp_helper(1, 8));
    drain(|| node.poll_output());
    // helper 1 is engaged now; no `0x62` has landed for it yet.

    // The hourly recheck fires while that check is still outstanding. aMule's
    // `ReCheckFirewallUDP` does not wait for it — it forcibly zeroes the
    // running/finished counters and starts a fresh round right away
    // (`UDPFirewallTester.cpp:200-212`), rather than letting the outstanding
    // check finish first.
    node.tick(T0 + KadNode::FIREWALL_RECHECK_INTERVAL);
    drain(|| node.poll_output());

    // helper 1's `0x62` finally arrives — for the round the recheck already
    // abandoned. aMule drops it rather than crediting the fresh round
    // (`SetUDPFWCheckResult`'s `m_fwChecksRunningUDP == 0` guard,
    // `UDPFirewallTester.cpp:135-149`): a stale positive must not open the
    // verdict on evidence the new round never asked for.
    node.handle_datagram(T0, endpoint(1, 12345), &[0xE4, 0x62, 0x00, 0x40, 0x12]);
    assert!(
        !events(&drain(|| node.poll_output()))
            .iter()
            .any(|event| matches!(event, KadEvent::UdpReachabilityOpen { .. })),
        "a result from before the recheck must not conclude the fresh round"
    );
}

#[test]
fn a_cancelled_helper_check_counts_neither_way_and_the_next_candidate_is_engaged() {
    let mut node = self_checking_node();
    settle_extern_port(&mut node);
    for host in 1..=3u8 {
        node.offer_udp_firewall_helper(udp_helper(host, 8));
    }
    drain(|| node.poll_output());

    // A dial that never reached the `0xA7` send is aMule's cancelled test
    // (`BaseClient.cpp:1730-1734`): no verdict, and the waiting candidate is
    // engaged in its place.
    node.handle_command(
        T0,
        KadCommand::UdpFirewallCheckCancelled {
            helper_ip: host_ip(1),
        },
    );
    let outputs = drain(|| node.poll_output());
    assert_eq!(
        engaged(&outputs),
        vec![udp_helper(3, 8).endpoint],
        "the cancelled slot goes to the next candidate"
    );
    assert!(
        !events(&outputs).contains(&KadEvent::UdpReachabilityFirewalled),
        "a cancellation is not a failure"
    );

    // Two real failures still conclude — the cancellation was not one of them.
    node.handle_command(
        T0,
        KadCommand::UdpFirewallCheckFailed {
            helper_ip: host_ip(2),
        },
    );
    assert!(events(&drain(|| node.poll_output())).is_empty());
    node.handle_command(
        T0,
        KadCommand::UdpFirewallCheckFailed {
            helper_ip: host_ip(3),
        },
    );
}

#[test]
fn a_biased_0x62_answer_counts_neither_way_and_the_next_candidate_is_engaged() {
    // aMule's `Process2FirewallUDP` gate treats a nonzero errorcode exactly
    // like a result on the wrong port: neither pass nor fail
    // (`KademliaUDPListener.cpp:1852-1878`, `UDPFirewallTester.cpp:135-175`).
    // A biased helper — rmule's helper-side roster rule, or aMule's own
    // routing-zone bias — therefore reads to the requester's tester as a
    // cancellation, not a failure: no verdict, and the waiting candidate is
    // engaged in its place.
    let mut node = self_checking_node();
    settle_extern_port(&mut node);
    for host in 1..=3u8 {
        node.offer_udp_firewall_helper(udp_helper(host, 8));
    }
    drain(|| node.poll_output());

    // Helper 1's `0x62`: errorcode 1 (biased), port 4672 (0x1240 LE) — the
    // port we hold either way, so only the errorcode decides this.
    node.handle_datagram(T0, endpoint(1, 12345), &[0xE4, 0x62, 0x01, 0x40, 0x12]);
    let outputs = drain(|| node.poll_output());
    assert_eq!(
        engaged(&outputs),
        vec![udp_helper(3, 8).endpoint],
        "the biased slot goes to the next candidate"
    );
    assert!(
        !events(&outputs).contains(&KadEvent::UdpReachabilityFirewalled),
        "a biased answer is not a failure"
    );

    // Two real failures still conclude — the biased answer was not one of them.
    node.handle_command(
        T0,
        KadCommand::UdpFirewallCheckFailed {
            helper_ip: host_ip(2),
        },
    );
    assert!(events(&drain(|| node.poll_output())).is_empty());
    node.handle_command(
        T0,
        KadCommand::UdpFirewallCheckFailed {
            helper_ip: host_ip(3),
        },
    );
    assert_eq!(
        events(&drain(|| node.poll_output())),
        vec![KadEvent::UdpReachabilityFirewalled]
    );
}

#[test]
fn the_request_carries_our_verify_key_for_the_helper_once_keys_are_armed() {
    let mut node = KadNode::new(crypt_start().self_check(KadSelfCheck::new()));
    settle_extern_port(&mut node);
    node.offer_udp_firewall_helper(udp_helper(1, 8));
    let key = our_key_for(endpoint(1, 0));
    let mut expected = vec![0x40, 0x12, 0x40, 0x12];
    expected.extend_from_slice(&key.to_le_bytes());
    assert_eq!(
        udp_requests(&drain(|| node.poll_output())),
        vec![(udp_helper(1, 8).endpoint, expected)],
        "BaseClient.cpp:3985 sends GetUDPVerifyKey(helper IP)"
    );
}

#[test]
fn the_udp_check_requests_only_fresh_helpers() {
    let mut node = self_checking_node();
    settle_extern_port(&mut node);
    // Core's Address Learning verdict rides in as a command; the node holds
    // no rule of its own about the extern port (ADR-0084).
    node.handle_command(T0, KadCommand::SetExternalUdpPort { port: 5000 });

    // A fresh v8 helper is engaged: the request carries our intern + extern Kad
    // UDP ports (LE) and a zero sender key (verify keys unarmed).
    node.offer_udp_firewall_helper(udp_helper(1, 8));
    assert_eq!(
        udp_requests(&drain(|| node.poll_output())),
        vec![(
            Ipv4Endpoint::new(host_ip(1), 4701),
            vec![0x40, 0x12, 0x88, 0x13, 0x00, 0x00, 0x00, 0x00],
        )]
    );

    // A legacy (v5) helper is skipped — UDP checks need version ≥ 6.
    node.offer_udp_firewall_helper(udp_helper(2, 5));
    assert!(udp_requests(&drain(|| node.poll_output())).is_empty());

    // A helper whose IP is already a routing-zone contact is not fresh — a known
    // contact could bias the result, so aMule never picks it.
    node.handle_command(
        T0,
        KadCommand::MergeContacts {
            contacts: vec![rmule_kad::KadContact::new(
                id(3),
                endpoint(3, 4703),
                4761,
                8,
            )],
        },
    );
    drain(|| node.poll_output());
    node.offer_udp_firewall_helper(udp_helper(3, 8));
    assert!(
        udp_requests(&drain(|| node.poll_output())).is_empty(),
        "a routing-zone IP is not a fresh helper"
    );
}

/// aMule's "not ourselves by public IP" rule (`UDPFirewallTester.cpp:272-276`)
/// holds with crypt unarmed too: core states the address whether or not
/// verify keys exist.
#[test]
fn the_udp_check_never_engages_a_helper_at_our_own_ip_with_crypt_unarmed() {
    let mut node = self_checking_node();
    settle_extern_port(&mut node);
    let own = udp_helper(7, 8);
    node.handle_command(
        T0,
        KadCommand::SetOwnPublicIp {
            public_ip: own.endpoint.ip,
        },
    );
    drain(|| node.poll_output());

    node.offer_udp_firewall_helper(own);
    assert!(
        udp_requests(&drain(|| node.poll_output())).is_empty(),
        "our own address is not a helper"
    );
    node.offer_udp_firewall_helper(udp_helper(8, 8));
    assert_eq!(udp_requests(&drain(|| node.poll_output())).len(), 1);
}

#[test]
fn the_udp_check_engages_at_most_two_helpers() {
    let mut node = self_checking_node();
    settle_extern_port(&mut node);
    // Three fresh helpers offered; only two are engaged (CLIENTSTOASK = 2).
    for host in 1..=3u8 {
        node.offer_udp_firewall_helper(udp_helper(host, 8));
    }
    assert_eq!(
        udp_requests(&drain(|| node.poll_output())).len(),
        2,
        "the two-helper budget caps the requests"
    );
}

#[test]
fn one_positive_0x62_opens_the_udp_verdict() {
    let mut node = self_checking_node();
    settle_extern_port(&mut node);
    node.offer_udp_firewall_helper(udp_helper(1, 8));
    drain(|| node.poll_output());

    // The helper reaches our intern port: a clean 0x62 (errorcode 0, port 4672).
    node.handle_datagram(T0, endpoint(1, 12345), &[0xE4, 0x62, 0x00, 0x40, 0x12]);
    assert_eq!(
        events(&drain(|| node.poll_output())),
        vec![
            KadEvent::HadContact {
                from: endpoint(1, 12345)
            },
            KadEvent::UdpReachabilityOpen {
                port: OUR_INTERN_UDP
            }
        ]
    );
}

#[test]
fn both_helper_failures_firewall_the_udp_verdict() {
    let mut node = self_checking_node();
    settle_extern_port(&mut node);
    node.offer_udp_firewall_helper(udp_helper(1, 8));
    node.offer_udp_firewall_helper(udp_helper(2, 8));
    drain(|| node.poll_output());

    // Both helpers' links end with no 0x62 — the second failure concludes firewalled.
    node.consume_udp_firewall_failure(T0, host_ip(1));
    assert!(
        events(&drain(|| node.poll_output())).is_empty(),
        "one failure is not yet a verdict"
    );
    node.consume_udp_firewall_failure(T0, host_ip(2));
    assert_eq!(
        events(&drain(|| node.poll_output())),
        vec![KadEvent::UdpReachabilityFirewalled]
    );
}

#[test]
fn the_udp_timeout_concludes_firewalled_only_with_a_firewalled_tcp_verdict() {
    let mut node = self_checking_node();
    settle_extern_port(&mut node);
    node.offer_udp_firewall_helper(udp_helper(1, 8));
    drain(|| node.poll_output());

    let timeout_at = T0 + Duration::from_secs(6 * 60);
    // TCP still reads reachable (the injected default): the UDP timeout must not
    // fire — a UDP-firewalled-but-TCP-open node has no need to conclude firewalled.
    node.tick(timeout_at);
    assert!(
        !events(&drain(|| node.poll_output()))
            .iter()
            .any(|e| matches!(e, KadEvent::UdpReachabilityFirewalled)),
        "TCP-open blocks the UDP timeout"
    );

    // Feed back a firewalled TCP verdict (the core store's projection): now the
    // six-minute timeout concludes firewalled.
    node.set_reachability(rmule_kad::KadReachability {
        udp_firewalled: false,
        tcp_firewalled: true,
        buddy_connected: false,
    });
    node.tick(timeout_at);
    assert_eq!(
        events(&drain(|| node.poll_output())),
        vec![KadEvent::UdpReachabilityFirewalled]
    );
}

#[test]
fn the_tcp_verdict_feedback_command_gates_the_udp_timeout_live() {
    // ADR-0058 breakdown 3, the TCP→node verdict feedback path: the
    // core store settles the ≥2-ack TCP verdict and feeds it back through the
    // command channel, so the sans-I/O node's six-minute UDP timeout gate sees the
    // live verdict — not the injected assume-open default. This is the pump's
    // `SetTcpReachability` round-trip, exercised through `handle_command`.
    let mut node = self_checking_node();
    settle_extern_port(&mut node);
    node.offer_udp_firewall_helper(udp_helper(1, 8));
    drain(|| node.poll_output());

    let timeout_at = T0 + Duration::from_secs(6 * 60);
    // The default injected verdict reads TCP-reachable, so the timeout is inert.
    node.handle_command(T0, KadCommand::SetTcpReachability { firewalled: false });
    node.tick(timeout_at);
    assert!(
        !events(&drain(|| node.poll_output()))
            .iter()
            .any(|e| matches!(e, KadEvent::UdpReachabilityFirewalled)),
        "a TCP-reachable feedback leaves the UDP timeout gated shut"
    );

    // The core store's firewalled TCP verdict, fed back through the command: now
    // the two self-checks compose and the timeout concludes firewalled.
    node.handle_command(
        timeout_at,
        KadCommand::SetTcpReachability { firewalled: true },
    );
    node.tick(timeout_at);
    assert_eq!(
        events(&drain(|| node.poll_output())),
        vec![KadEvent::UdpReachabilityFirewalled],
        "the fed-back firewalled TCP verdict opens the six-minute UDP timeout gate"
    );
}

#[test]
fn a_dormant_udp_check_neither_requests_nor_consumes() {
    let mut node = node(); // UDP tester dormant by default
    node.offer_udp_firewall_helper(udp_helper(1, 8));
    assert!(
        udp_requests(&drain(|| node.poll_output())).is_empty(),
        "a dormant check offers nothing"
    );
    // A 0x62 to a node that never checked is unrequested.
    node.handle_datagram(T0, endpoint(1, 12345), &[0xE4, 0x62, 0x00, 0x40, 0x12]);
    assert!(matches!(
        diagnostics(&drain(|| node.poll_output())).as_slice(),
        [KadNodeDiagnostic::UnrequestedFirewallResponse { opcode: 0x62, .. }]
    ));
}

#[test]
fn the_helper_responder_answers_0x62_to_each_tested_port() {
    let mut node = node();
    let requester = host_ip(9);
    // A request: intern 6000 (0x1770), extern 7000 (0x1B58), key 0xDEADBEEF.
    let request = [0x70, 0x17, 0x58, 0x1B, 0xEF, 0xBE, 0xAD, 0xDE];
    node.consume_udp_firewall_request(requester, &request, false);

    let out = drain(|| node.poll_output());
    // One 0x62 to the intern port, one to the distinct extern port — clean
    // errorcode (the requester is unknown to us, so unbiased).
    assert_eq!(
        datagrams(&out),
        vec![
            (
                KadNodeEndpoint::new(requester, 6000),
                vec![0xE4, 0x62, 0x00, 0x70, 0x17]
            ),
            (
                KadNodeEndpoint::new(requester, 7000),
                vec![0xE4, 0x62, 0x00, 0x58, 0x1B]
            ),
        ]
    );
    assert!(events(&out).contains(&KadEvent::FwCheckUdpAnswered {
        requester,
        biased: false
    }));
}

#[test]
fn the_helper_responder_flags_a_biased_result_for_a_known_requester() {
    let mut node = node();
    let requester = host_ip(9);
    // The requester is already a routing-zone contact — its result would be
    // biased, so the errorcode is 1 and it must discard it.
    node.handle_command(
        T0,
        KadCommand::MergeContacts {
            contacts: vec![rmule_kad::KadContact::new(
                id(9),
                endpoint(9, 4709),
                4761,
                8,
            )],
        },
    );
    drain(|| node.poll_output());
    // No distinct extern port (extern == intern) — a single result packet.
    let request = [0x70, 0x17, 0x70, 0x17, 0x00, 0x00, 0x00, 0x00];
    node.consume_udp_firewall_request(requester, &request, false);

    let out = drain(|| node.poll_output());
    assert_eq!(
        datagrams(&out),
        vec![(
            KadNodeEndpoint::new(requester, 6000),
            vec![0xE4, 0x62, 0x01, 0x70, 0x17]
        )],
        "biased errorcode 1, only the intern port"
    );
    assert!(events(&out).contains(&KadEvent::FwCheckUdpAnswered {
        requester,
        biased: true
    }));
}

#[test]
fn the_helper_responder_flags_a_biased_result_for_a_caller_the_peer_roster_knows() {
    // The requester is a stranger to our routing zone, but core's peer roster
    // says it is a caller we already have an active upload, download or chat
    // with (aMule `BaseClient.cpp:4002-4003`) — biased the same
    // way a routing-zone contact is.
    let mut node = node();
    let requester = host_ip(9);
    let request = [0x70, 0x17, 0x70, 0x17, 0x00, 0x00, 0x00, 0x00];
    node.consume_udp_firewall_request(requester, &request, true);

    let out = drain(|| node.poll_output());
    assert_eq!(
        datagrams(&out),
        vec![(
            KadNodeEndpoint::new(requester, 6000),
            vec![0xE4, 0x62, 0x01, 0x70, 0x17]
        )],
        "biased errorcode 1 from caller_known alone, no routing-zone contact needed"
    );
    assert!(events(&out).contains(&KadEvent::FwCheckUdpAnswered {
        requester,
        biased: true
    }));
}

#[test]
fn the_helper_responder_rejects_an_intern_port_of_zero() {
    let mut node = node();
    let requester = host_ip(9);
    // Intern port 0 — aMule rejects it, no 0x62 sent.
    let request = [0x00, 0x00, 0x58, 0x1B, 0x00, 0x00, 0x00, 0x00];
    node.consume_udp_firewall_request(requester, &request, false);
    let out = drain(|| node.poll_output());
    assert!(
        datagrams(&out).is_empty(),
        "no result for a zero intern port"
    );
    assert!(matches!(
        diagnostics(&out).as_slice(),
        [KadNodeDiagnostic::UnhonorableFirewallUdpRequest { .. }]
    ));
}

// --- the helper answer keys to the requester's carried key -----

#[test]
fn a_keyed_udp_firewall_request_draws_a_keyed_0x62() {
    // Documentation-derived; the wire met it in the UDP self-check's crypt
    // run (`udp_firewall_capture.rs`): a crypt-armed aMule requester decrypted
    // and accepted the keyed `0x62` an rmule helper built this way, and rmule's
    // encoder reproduces that datagram byte for byte. aMule keys the reply on
    // the value the `0xA7` carried and nothing else:
    // `ProcessFirewallCheckUDPRequest` passes `CKadUDPKey(senderKey, ourIP)` as
    // `targetKey` and `NULL` as `cryptTargetID` (`BaseClient.cpp:4008-4013`);
    // `CKadUDPKey::GetKeyValue(ourIP)` is `senderKey` verbatim because the key
    // is constructed and unwrapped against the same IP (`KadUDPKey.h`); the
    // listener forwards it as `nReceiverVerifyKey` with `bKad = true`
    // (`KademliaUDPListener.cpp:1880-1904`), which
    // `CMuleUDPSocket::SendPacket` turns into the KadVerifyKey family
    // (`MuleUDPSocket.cpp:271-274`). The sync word is little-endian per
    // `7a438aa`.
    let mut node = crypt_node();
    let requester = host_ip(9);
    let sender_key = 0xC0FF_EE11u32;
    // Intern 6000 (0x1770), extern == intern (a single result packet).
    let mut request = 6000u16.to_le_bytes().to_vec();
    request.extend_from_slice(&6000u16.to_le_bytes());
    request.extend_from_slice(&sender_key.to_le_bytes());
    node.consume_udp_firewall_request(requester, &request, false);
    let out = drain(|| node.poll_output());

    // The plain `0x62`: errorcode 0 (unbiased), port 6000 little-endian.
    let plain = vec![0xE4, 0x62, 0x00, 0x70, 0x17];
    let expected = encrypt_datagram_client(
        &plain,
        &ClientEncryptKey::KadVerify {
            verify_key: sender_key,
            receiver_verify_key: sender_key,
            sender_verify_key: our_key_for(endpoint(9, 0)),
        },
        &fixed_nonce(),
    );
    assert_eq!(
        datagrams(&out),
        vec![(KadNodeEndpoint::new(requester, 6000), expected)],
        "the 0x62 rides the KadVerify family keyed on the request's carried \
         sender key, echoed back, under our own key for the requester"
    );
}

#[test]
fn a_keyless_udp_firewall_request_stays_plaintext_even_with_obfuscation_armed() {
    // The `0xA7` carried no verify key (a plaintext requester, or one whose
    // own verify keys are unarmed): `CMuleUDPSocket::SendPacket`'s
    // `bKad && nReceiverVerifyKey != 0` encrypt gate
    // (`MuleUDPSocket.cpp:271-274`) never fires on a zero key, regardless of
    // our own obfuscation being armed.
    let mut node = crypt_node();
    let requester = host_ip(9);
    let request = [0x70, 0x17, 0x70, 0x17, 0x00, 0x00, 0x00, 0x00];
    node.consume_udp_firewall_request(requester, &request, false);
    assert_eq!(
        datagrams(&drain(|| node.poll_output())),
        vec![(
            KadNodeEndpoint::new(requester, 6000),
            vec![0xE4, 0x62, 0x00, 0x70, 0x17]
        )],
        "a keyless request draws a plaintext answer even though obfuscation is armed"
    );
}

#[test]
fn a_crypt_requiring_requester_decodes_the_keyed_0x62_and_its_tester_counts_it() {
    // Full round trip, both sides real: the requester's own UDP
    // firewall tester engages a helper — its `0xA7` carries our verify key for
    // the helper's IP (`engage_udp_helper`, `BaseClient.cpp:3982-3986`) — the
    // helper (a second real `KadNode`, itself verify-key-armed and
    // obfuscating) answers `0x62` keyed to that same value
    // (`BaseClient.cpp:4008-4013`), and the requester's `handle_datagram`
    // decrypts it via the KadVerifyKey family and folds it into its own
    // tester's verdict — proving the wire round-trips, not just the encode.
    let mut requester = KadNode::new(crypt_start().self_check(KadSelfCheck::new()));
    settle_extern_port(&mut requester);

    let helper_ip = host_ip(1);
    requester.offer_udp_firewall_helper(UdpFirewallHelper {
        endpoint: Ipv4Endpoint::new(helper_ip, 4701),
        id: id(1),
        version: 8,
    });
    let requests = udp_requests(&drain(|| requester.poll_output()));
    let (_, request_bytes) = requests
        .into_iter()
        .next()
        .expect("a fresh v8 helper is engaged");

    // The helper: a second real node, verify-key-armed, obfuscation on,
    // consuming the peer-TCP-bridged request exactly as core bridges it —
    // opaque bytes, the requester's IP, nothing else.
    let mut helper = KadNode::new(
        KadNodeStart::new(
            KadNodeConfig {
                id: id(1),
                tcp_port: 4761,
                udp_port: 4672,
                user_hash: UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
            },
            KadInstant::EPOCH,
        )
        .obfuscation(KadObfuscation::new(fixed_nonce).with_verify_keys(0x1EE7_5EED, helper_ip)),
    );
    helper.consume_udp_firewall_request(OWN_IP, &request_bytes, false);
    let helper_out = drain(|| helper.poll_output());
    let helper_datagrams = datagrams(&helper_out);
    assert_eq!(
        helper_datagrams.len(),
        1,
        "intern == extern by default: a single result packet"
    );
    let (to, keyed_0x62) = helper_datagrams.into_iter().next().unwrap();

    // Deliver the keyed answer to the requester exactly as it arrived on its
    // own Kad UDP socket, from the helper's Kad endpoint.
    let helper_endpoint = KadNodeEndpoint::new(helper_ip, to.udp_port());
    requester.handle_datagram(T0, helper_endpoint, &keyed_0x62);
    assert_eq!(
        events(&drain(|| requester.poll_output())),
        vec![
            KadEvent::HadContact {
                from: helper_endpoint
            },
            KadEvent::UdpReachabilityOpen {
                port: OUR_INTERN_UDP
            },
        ],
        "the requester decrypted the keyed 0x62 and its tester counted it open"
    );
}
