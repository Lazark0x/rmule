//! The TCP firewall self-check: the checks this node answers for strangers,
//! the version-gated ones it piggybacks on its own hello traffic, and the
//! budget, windows and hourly recheck that pace them.

use std::net::Ipv4Addr;

use rmule_kad::{
    Kad2Message, Kad2NodeInfo, KadEvent, KadInstant, KadNode, KadNodeDiagnostic, KadNodeEndpoint,
    KadOutput,
};
use rmule_primitives::session::drain;
use rmule_primitives::{Ipv4Endpoint, UserHash};
use rmule_testkit::kad_node::{
    T0, datagrams, deliver, diagnostics, endpoint, events, host_ip, id, node, self_checking_node,
};

#[test]
fn a_legacy_firewall_check_answers_0x58_and_requests_a_udp_acked_dial_back() {
    let mut node = node();
    // A 0x50 from 203.0.113.7:5000 (UDP) advertising TCP port 4662 (0x1236 LE).
    let requester = endpoint(7, 5000);
    node.handle_datagram(T0, requester, &[0xE4, 0x50, 0x36, 0x12]);

    let outputs = drain(|| node.poll_output());
    // The 0x58 response carries the requester's observed IP low-octet-first
    // (aMule's WriteUInt32 / reversed dotted octets — capture-pinned),
    // back to its UDP source (aMule answers regardless of the dial-back).
    assert_eq!(
        datagrams(&outputs),
        vec![(requester, vec![0xE4, 0x58, 1, 7, 55, 45])]
    );
    // The dial-back command targets the advertised TCP port; a legacy 0x50
    // carries no connect-options — the UDP-0x59 ack signal.
    assert_eq!(
        events(&outputs),
        vec![
            KadEvent::HadContact { from: requester },
            KadEvent::DialBackRequested {
                requester: Ipv4Endpoint::new(host_ip(7), 4662),
                connect_options: None,
                user_hash: None,
            }
        ]
    );
}

#[test]
fn a_v7_firewall_check_forwards_connect_options_for_the_tcp_link_ack() {
    let mut node = node();
    let requester = endpoint(7, 5000);
    // 0x53: <tcpport 4662 LE><userhash 16><connectoptions 0x03>.
    let mut datagram = vec![0xE4, 0x53, 0x36, 0x12];
    datagram.extend_from_slice(&[0xAB; 16]);
    datagram.push(0x03);
    node.handle_datagram(T0, requester, &datagram);

    let outputs = drain(|| node.poll_output());
    // 0x58 body is the requester IP low-octet-first (as captured).
    assert_eq!(
        datagrams(&outputs),
        vec![(requester, vec![0xE4, 0x58, 1, 7, 55, 45])]
    );
    // A v7+ 0x53 forwards its connect-options and the requester's own User
    // Hash — the OP_KAD_FWTCPCHECK_ACK (TCP-link ack) signal plus the
    // dial-back's crypt key basis.
    assert_eq!(
        events(&outputs),
        vec![
            KadEvent::HadContact { from: requester },
            KadEvent::DialBackRequested {
                requester: Ipv4Endpoint::new(host_ip(7), 4662),
                connect_options: Some(0x03),
                user_hash: Some(UserHash::from_bytes([0xAB; UserHash::BYTE_LEN])),
            }
        ]
    );
}

// ---- Reachability requester cycle (ADR-0058 execution breakdown 2) ----
//
// The requester is dormant unless armed with the self-check start-up, so
// the routing-only tests above are untouched. Once armed, it piggybacks
// version-gated `0x50`/`0x53` checks on hello traffic, tracks their 180 s
// windows, consumes `0x58`/`0x59` (and, via core, `OP_KAD_FWTCPCHECK_ACK`), and
// rechecks hourly — emitting the store-projected reachability events.

/// The `0x50`/`0x53` firewall checks a node piggybacked, filtered out of the
/// hello traffic they ride on (they are not `Kad2Message`s).
fn firewall_emissions(outputs: &[KadOutput]) -> Vec<(KadNodeEndpoint, Vec<u8>)> {
    datagrams(outputs)
        .into_iter()
        .filter(|(_, bytes)| matches!(bytes.get(1), Some(0x50 | 0x53)))
        .collect()
}

/// rmule's own v7+ check: `<0xE4><0x53><tcpport 4662 LE><userhash [0xEE;16]>
/// <connectoptions>`. With no byte stated by the driver the connect options
/// are zero: no crypt to key a dial-back with, no direct callback.
fn expected_v7_check() -> Vec<u8> {
    expected_v7_check_with(0x00)
}

fn expected_v7_check_with(connect_options: u8) -> Vec<u8> {
    let mut bytes = vec![0xE4, 0x53, 0x36, 0x12];
    bytes.extend_from_slice(&[0xEE; 16]);
    bytes.push(connect_options);
    bytes
}

/// A stranger's hello from `host`, arming its firewall-check window on
/// `203.0.113.host`.
fn hello_from(node: &mut KadNode, now: KadInstant, host: u8, version: u8) {
    let peer = Kad2NodeInfo {
        id: id(host),
        tcp_port: 4761,
        version,
        udp_port_tag: None,
        misc_options: 0,
    };
    deliver(
        node,
        now,
        endpoint(host, 4700 + u16::from(host)),
        &Kad2Message::HelloReq(peer),
    );
}

#[test]
fn an_armed_node_piggybacks_a_version_gated_check_on_hello_traffic() {
    let mut node = self_checking_node();

    // A modern (v8) peer: we answer its hello, then piggyback the extended 0x53
    // check advertising our port, User Hash, and (zero) connect-options.
    hello_from(&mut node, T0, 1, 8);
    assert_eq!(
        firewall_emissions(&drain(|| node.poll_output())),
        vec![(endpoint(1, 4701), expected_v7_check())]
    );

    // A legacy (v6) peer: the two-byte 0x50 check, just our port.
    hello_from(&mut node, T0, 2, 6);
    assert_eq!(
        firewall_emissions(&drain(|| node.poll_output())),
        vec![(endpoint(2, 4702), vec![0xE4, 0x50, 0x36, 0x12])]
    );
}

/// The check names our crypt stance, as aMule's
/// `GetMyConnectOptions(true, false)` does (`KademliaUDPListener.cpp:182`), so
/// the helper can dial back obfuscated under a policy that requires it. The
/// crypt bits of the publish byte, never its direct-callback or NAT-T bits.
#[test]
fn a_check_names_the_crypt_bits_of_the_stated_connect_options() {
    let mut node = self_checking_node();
    // Required (0x07), plus a direct-callback bit (0x08) and uTP (0x80) the
    // check must not carry.
    node.handle_command(
        T0,
        rmule_kad::KadCommand::SetPublishConnectOptions {
            options: Some(0x8F),
        },
    );
    hello_from(&mut node, T0, 1, 8);
    assert_eq!(
        firewall_emissions(&drain(|| node.poll_output())),
        vec![(endpoint(1, 4701), expected_v7_check_with(0x07))]
    );
}

#[test]
fn a_dormant_firewall_neither_checks_nor_consumes_and_adds_no_timer() {
    let mut node = node(); // firewall dormant by default
    hello_from(&mut node, T0, 1, 8);
    assert!(
        firewall_emissions(&drain(|| node.poll_output())).is_empty(),
        "a dormant requester piggybacks nothing"
    );
    // A firewall response to a node that never checks is unrequested.
    node.handle_datagram(T0, endpoint(3, 5000), &[0xE4, 0x59]);
    assert!(matches!(
        diagnostics(&drain(|| node.poll_output())).as_slice(),
        [KadNodeDiagnostic::UnrequestedFirewallResponse { opcode: 0x59, .. }]
    ));
    assert!(
        node.next_wake().is_none(),
        "a dormant firewall adds no wake"
    );
}

#[test]
fn the_emission_budget_caps_piggybacked_checks_at_four() {
    let mut node = self_checking_node();
    // Four peers hello us; each check is counted by a 0x58 (its observed-IP body
    // is immaterial). After the fourth, the budget is spent.
    for host in 1..=4u8 {
        hello_from(&mut node, T0, host, 8);
        assert_eq!(
            firewall_emissions(&drain(|| node.poll_output())).len(),
            1,
            "peer {host} is still within the budget"
        );
        node.handle_datagram(
            T0,
            endpoint(host, 4700 + u16::from(host)),
            &[0xE4, 0x58, 198, 51, 100, 1],
        );
        drain(|| node.poll_output());
    }
    hello_from(&mut node, T0, 5, 8);
    assert!(
        firewall_emissions(&drain(|| node.poll_output())).is_empty(),
        "the fifth peer gets no check — the budget is spent"
    );
}

#[test]
fn a_windowed_0x58_counts_but_an_unrequested_one_is_diagnosed() {
    let mut node = self_checking_node();
    hello_from(&mut node, T0, 1, 8);
    drain(|| node.poll_output());

    // A 0x58 from the checked IP (any port) counts the recheck without proving
    // a leg — the store's ack rule is driven by 0x59/0xA9, not 0x58 — and
    // states its body as an Address Learning observation, keyed on the
    // *responder*, not on the address it claims (ADR-0084).
    node.handle_datagram(T0, endpoint(1, 9999), &[0xE4, 0x58, 198, 51, 100, 7]);
    // The `0x58` body is aMule's `WriteUInt32` — low-octet-first — so these
    // four bytes name `7.100.51.198`, not `198.51.100.7`.
    assert_eq!(
        events(&drain(|| node.poll_output())),
        vec![KadEvent::AddressObserved {
            observer: host_ip(1),
            address: Ipv4Addr::new(7, 100, 51, 198),
        }]
    );

    // A 0x58 from an IP we never checked is unrequested — and a stranger's
    // claim about our address is not an observation either.
    node.handle_datagram(T0, endpoint(9, 5000), &[0xE4, 0x58, 198, 51, 100, 7]);
    let outputs = drain(|| node.poll_output());
    assert!(matches!(
        diagnostics(&outputs).as_slice(),
        [KadNodeDiagnostic::UnrequestedFirewallResponse { opcode: 0x58, .. }]
    ));
    assert!(
        !events(&outputs)
            .iter()
            .any(|event| matches!(event, KadEvent::AddressObserved { .. }))
    );
}

#[test]
fn a_0x59_ack_proves_a_connect_back_leg_unguarded() {
    let mut node = self_checking_node();
    // aMule's `ProcessFirewalledAckResponse` counts the legacy UDP ack with no
    // window guard — any well-formed 0x59 proves a reachability leg.
    node.handle_datagram(T0, endpoint(3, 5000), &[0xE4, 0x59]);
    assert_eq!(
        events(&drain(|| node.poll_output())),
        vec![
            KadEvent::HadContact {
                from: endpoint(3, 5000)
            },
            KadEvent::ReachabilityConnectBack
        ]
    );
}

#[test]
fn a_tcp_ack_is_counted_only_within_its_check_window() {
    let mut node = self_checking_node();
    hello_from(&mut node, T0, 1, 8);
    drain(|| node.poll_output());

    // An OP_KAD_FWTCPCHECK_ACK from the checked IP proves a leg (core bridges it
    // here from the Kad-ignorant peer session, carrying the peer's IP).
    node.consume_tcp_firewall_ack(T0, host_ip(1));
    assert_eq!(
        events(&drain(|| node.poll_output())),
        vec![KadEvent::ReachabilityConnectBack]
    );

    // An ack from an unchecked IP is discarded, and says so...
    let stranger = host_ip(9);
    node.consume_tcp_firewall_ack(T0, stranger);
    assert_eq!(
        events(&drain(|| node.poll_output())),
        vec![KadEvent::Diagnostic(
            KadNodeDiagnostic::UnrequestedFirewallAck { from: stranger }
        )]
    );
    // ...and so is one at the 180 s window boundary (strict `<`).
    let helper = host_ip(1);
    node.consume_tcp_firewall_ack(T0 + KadNode::FIREWALL_CHECK_WINDOW, helper);
    assert_eq!(
        events(&drain(|| node.poll_output())),
        vec![KadEvent::Diagnostic(
            KadNodeDiagnostic::UnrequestedFirewallAck { from: helper }
        )],
        "the window boundary is already expired"
    );
}

#[test]
fn an_armed_node_wakes_for_the_recheck_and_a_window_precedes_it() {
    let mut node = self_checking_node();
    // A known extern port closes the Extern Port Round and its 15 s cadence.
    node.handle_command(T0, rmule_kad::KadCommand::SetExternalUdpPort { port: 4672 });
    // With no outstanding TCP checks and TCP not yet firewalled, the UDP tester's
    // six-minute timeout does not yet contribute a wake — it settles a verdict
    // only once the TCP verdict is also firewalled (ADR-0058 breakdown 3, the
    // `tcp_firewalled` conclude gate) — so the earliest wake is the hourly recheck.
    assert_eq!(
        node.next_wake(),
        Some(T0 + KadNode::FIREWALL_RECHECK_INTERVAL)
    );
    // A piggybacked TCP check's 180 s window comes first of all.
    hello_from(&mut node, T0, 1, 8);
    drain(|| node.poll_output());
    assert_eq!(node.next_wake(), Some(T0 + KadNode::FIREWALL_CHECK_WINDOW));
}

#[test]
fn the_hourly_recheck_reopens_emission() {
    let mut node = self_checking_node();
    // Spend the budget (four hellos, each 0x58-answered) at boot.
    for host in 1..=4u8 {
        hello_from(&mut node, T0, host, 8);
        node.handle_datagram(
            T0,
            endpoint(host, 4700 + u16::from(host)),
            &[0xE4, 0x58, 198, 51, 100, 1],
        );
        drain(|| node.poll_output());
    }
    // At the hourly boundary the recheck fires — the sole event the store
    // snapshots its verdict on.
    node.tick(T0 + KadNode::FIREWALL_RECHECK_INTERVAL);
    assert_eq!(
        events(&drain(|| node.poll_output())),
        vec![
            KadEvent::ExternPortRoundStarted,
            KadEvent::ReachabilityRecheckStarted,
        ]
    );
    // Emission reopens: the next hello carries a check again.
    let now = T0 + KadNode::FIREWALL_RECHECK_INTERVAL;
    hello_from(&mut node, now, 6, 8);
    assert_eq!(firewall_emissions(&drain(|| node.poll_output())).len(), 1);
}

#[test]
fn an_unmet_recheck_concludes_when_its_last_window_lapses() {
    let mut node = self_checking_node();
    let recheck_at = T0 + KadNode::FIREWALL_RECHECK_INTERVAL;
    node.tick(recheck_at);
    assert_eq!(
        events(&drain(|| node.poll_output())),
        vec![
            KadEvent::ExternPortRoundStarted,
            KadEvent::ReachabilityRecheckStarted,
        ]
    );
    // One peer is checked during the recheck, but its 0x58 never comes.
    hello_from(&mut node, recheck_at, 1, 8);
    drain(|| node.poll_output());
    // The window lapsing with the budget unspent concludes the recheck (no more
    // acks can arrive), settling the store on its ≥2-ack rule.
    node.tick(recheck_at + KadNode::FIREWALL_CHECK_WINDOW);
    assert_eq!(
        events(&drain(|| node.poll_output())),
        vec![KadEvent::ReachabilityRecheckConcluded]
    );
}

#[test]
fn a_recheck_concludes_when_four_responses_spend_its_budget() {
    let mut node = self_checking_node();
    let recheck_at = T0 + KadNode::FIREWALL_RECHECK_INTERVAL;
    node.tick(recheck_at);
    drain(|| node.poll_output()); // RecheckStarted

    // Four checked peers each answer 0x58; the fourth spends the in-flight
    // recheck's budget and concludes it exactly once.
    for host in 1..=4u8 {
        hello_from(&mut node, recheck_at, host, 8);
        node.handle_datagram(
            recheck_at,
            endpoint(host, 4700 + u16::from(host)),
            &[0xE4, 0x58, 198, 51, 100, 1],
        );
    }
    let concluded = events(&drain(|| node.poll_output()))
        .into_iter()
        .filter(|event| matches!(event, KadEvent::ReachabilityRecheckConcluded))
        .count();
    assert_eq!(
        concluded, 1,
        "the budget-spending response concludes the recheck once"
    );
}

#[test]
fn a_malformed_firewall_check_is_diagnosed_and_answers_nothing() {
    let mut node = node();
    // A 0x50 with a trailing byte breaks aMule's exact-2 size gate.
    node.handle_datagram(T0, endpoint(7, 5000), &[0xE4, 0x50, 0x36, 0x12, 0x00]);

    let outputs = drain(|| node.poll_output());
    // No 0x58, no dial-back — a silent refusal plus the diagnostic (and the
    // silent→heard edge: the envelope itself was well-formed).
    assert_eq!(
        outputs.len(),
        2,
        "only the edge and the diagnostic, no response, no dial-back: {outputs:?}"
    );
    assert!(matches!(
        diagnostics(&outputs).as_slice(),
        [KadNodeDiagnostic::MalformedFirewallCheck { .. }]
    ));
}

// The UDP firewall self-check (ADR-0058 requester, breakdown 3) arms alongside
// the TCP check with the same the self-check start-up. It engages up to two
// FRESH helpers over peer-TCP (`OP_FWCHECKUDPREQ`), consumes their `0x62`
// results, concludes open on one positive / firewalled on both failing, and
// firewalled-by-timeout after six minutes only when the TCP verdict is also
// firewalled. The helper-responder half answers a peer's request with `0x62`.

#[test]
fn an_external_recheck_reopens_emission_and_pushes_the_scheduled_one_an_hour_out() {
    // ADR-0086's amendment: a port-mapping grant that lands on the exact ports
    // means the firewalled verdict is stale *now*, not in an hour. Neither
    // reference implementation has this entry point at all.
    let mut node = self_checking_node();
    for host in 1..=4u8 {
        hello_from(&mut node, T0, host, 8);
        node.handle_datagram(
            T0,
            endpoint(host, 4700 + u16::from(host)),
            &[0xE4, 0x58, 198, 51, 100, 1],
        );
        drain(|| node.poll_output());
    }
    let at = T0 + std::time::Duration::from_secs(120);
    assert!(
        node.recheck_reachability(at),
        "the budget was spent, so a grant's recheck runs"
    );
    assert_eq!(
        events(&drain(|| node.poll_output())),
        vec![
            KadEvent::ExternPortRoundStarted,
            KadEvent::ReachabilityRecheckStarted,
        ],
        "core folds the same event the hourly cadence emits"
    );
    hello_from(&mut node, at, 6, 8);
    assert_eq!(
        firewall_emissions(&drain(|| node.poll_output())).len(),
        1,
        "emission reopened"
    );
    // The scheduled check moved out rather than stacking on top of this one.
    node.tick(T0 + KadNode::FIREWALL_RECHECK_INTERVAL);
    assert!(
        events(&drain(|| node.poll_output()))
            .iter()
            .all(|event| *event != KadEvent::ReachabilityRecheckStarted),
        "the hourly check is now an hour past the external one"
    );
}

#[test]
fn external_rechecks_are_one_at_a_time_and_at_most_one_per_five_minutes() {
    // An Exact grant, a gateway epoch reset and an operator command can land
    // within seconds; each recheck spends four helper lookups, and repeating
    // that makes this node look like a flood source to the peers whose answers
    // it needs.
    let mut node = self_checking_node();
    assert!(node.recheck_reachability(T0));
    drain(|| node.poll_output());
    assert!(
        !node.recheck_reachability(T0 + std::time::Duration::from_secs(1)),
        "a recheck is already in flight"
    );
    // Spend this recheck's budget so it concludes, then the spacing is the only
    // guard left — and it still refuses inside five minutes.
    for host in 1..=4u8 {
        hello_from(&mut node, T0, host, 8);
        node.handle_datagram(
            T0,
            endpoint(host, 4700 + u16::from(host)),
            &[0xE4, 0x58, 198, 51, 100, 1],
        );
        drain(|| node.poll_output());
    }
    assert!(
        !node.recheck_reachability(T0 + std::time::Duration::from_secs(299)),
        "inside the five-minute spacing"
    );
    assert!(
        node.recheck_reachability(T0 + std::time::Duration::from_secs(300)),
        "at the boundary the next external trigger is honoured"
    );
}

/// A trigger the spacing refuses is owed, not dropped (ADR-0093, "Kad after
/// the listener or a mapping appears"): a mapping grant or a High ID landing
/// just after the last external recheck still changed what a check would find,
/// so the node runs it once the spacing ends instead of waiting out the hour.
#[test]
fn an_external_trigger_refused_inside_the_spacing_runs_when_the_spacing_ends() {
    let mut node = self_checking_node();
    assert!(node.recheck_reachability(T0));
    drain(|| node.poll_output());
    for host in 1..=4u8 {
        hello_from(&mut node, T0, host, 8);
        node.handle_datagram(
            T0,
            endpoint(host, 4700 + u16::from(host)),
            &[0xE4, 0x58, 198, 51, 100, 1],
        );
        drain(|| node.poll_output());
    }
    assert!(
        !node.recheck_reachability(T0 + std::time::Duration::from_secs(60)),
        "inside the five-minute spacing"
    );
    drain(|| node.poll_output());
    node.tick(T0 + std::time::Duration::from_secs(299));
    assert!(
        !events(&drain(|| node.poll_output())).contains(&KadEvent::ReachabilityRecheckStarted),
        "still inside the spacing"
    );
    node.tick(T0 + std::time::Duration::from_secs(300));
    assert!(
        events(&drain(|| node.poll_output())).contains(&KadEvent::ReachabilityRecheckStarted),
        "the owed recheck runs at the spacing's end"
    );
}

#[test]
fn a_dormant_node_has_no_verdict_for_an_external_recheck_to_refresh() {
    let mut node = node();
    assert!(!node.recheck_reachability(T0));
    assert!(drain(|| node.poll_output()).is_empty());
}

#[test]
fn a_recheck_hello_probes_contacts_so_its_reopened_budget_is_actually_spent() {
    // ADR-0086's claim — an Exact mapping grant refreshes the verdict instead of
    // waiting an hour — needs the reopened budget to be *spent*, and checks only
    // ride hello exchanges. aMule's zone small timer supplies that traffic
    // continuously; this node's hello cadence is join-scoped and silent
    // exactly when a recheck matters, so the recheck makes its own.
    let mut node = self_checking_node();
    // Two strangers hello in and become contacts.
    hello_from(&mut node, T0, 1, 8);
    hello_from(&mut node, T0, 2, 8);
    drain(|| node.poll_output());

    let at = T0 + std::time::Duration::from_secs(600);
    assert!(node.recheck_reachability(at));
    assert_eq!(
        probes(&drain(|| node.poll_output())),
        vec![endpoint(1, 4701), endpoint(2, 4702)],
        "the recheck hello-probes its contacts"
    );

    // Each answered probe carries the reopened check, which is what a helper
    // dials back on.
    for host in 1..=2u8 {
        hello_res_from(&mut node, at, host);
    }
    let checks = firewall_emissions(&drain(|| node.poll_output()));
    assert_eq!(
        checks,
        vec![
            (endpoint(1, 4701), expected_v7_check()),
            (endpoint(2, 4702), expected_v7_check()),
        ],
        "both answers piggyback the reopened check"
    );
}

#[test]
fn a_rechecks_probe_round_never_exceeds_the_emission_budget() {
    // A probe past the budget could not carry a check, so a big routing table
    // must not turn one recheck into a table-wide hello burst.
    let mut node = self_checking_node();
    for host in 1..=8u8 {
        hello_from(&mut node, T0, host, 8);
    }
    drain(|| node.poll_output());

    assert!(node.recheck_reachability(T0 + std::time::Duration::from_secs(600)));
    assert_eq!(
        probes(&drain(|| node.poll_output())).len(),
        KadNode::FIREWALL_CHECKS as usize
    );
}

/// A solicited hello response from `host`, answering this node's own probe.
fn hello_res_from(node: &mut KadNode, now: KadInstant, host: u8) {
    deliver(
        node,
        now,
        endpoint(host, 4700 + u16::from(host)),
        &Kad2Message::HelloRes(Kad2NodeInfo {
            id: id(host),
            tcp_port: 4761,
            version: 8,
            udp_port_tag: None,
            misc_options: 0,
        }),
    );
}

/// The hello probes among `outputs`, by destination.
fn probes(outputs: &[KadOutput]) -> Vec<KadNodeEndpoint> {
    datagrams(outputs)
        .into_iter()
        .filter(|(_, bytes)| bytes.get(1) == Some(&0x11))
        .map(|(to, _)| to)
        .collect()
}

#[test]
fn a_recheck_refused_as_already_in_flight_still_feeds_the_unfinished_round() {
    // The mapping set can grow a row between two installs seconds apart, so the
    // second Exact grant is news even though the first round is still open: its
    // outstanding checks went out against a position that has changed. The
    // "one at a time" guard still refuses to restart the round, but the round
    // gets the traffic its unspent budget is waiting for — and only for the
    // contacts that are not already being probed.
    let mut node = self_checking_node();
    hello_from(&mut node, T0, 1, 8);
    hello_from(&mut node, T0, 2, 8);
    drain(|| node.poll_output());

    assert!(node.recheck_reachability(T0));
    assert_eq!(probes(&drain(|| node.poll_output())).len(), 2);
    // Contact 1 answers (so its probe is done); contact 2's is still outstanding.
    hello_res_from(&mut node, T0, 1);
    drain(|| node.poll_output());

    let again = T0 + std::time::Duration::from_secs(1);
    assert!(!node.recheck_reachability(again), "no second round starts");
    assert_eq!(
        probes(&drain(|| node.poll_output())),
        vec![endpoint(1, 4701)],
        "the answered contact is re-probed; the outstanding one is not duplicated"
    );
}

#[test]
fn a_spent_budget_probes_nothing_because_no_hello_could_carry_a_check() {
    // The spacing guard refuses a trigger whose predecessor already concluded by
    // spending its budget. Probing then would emit hellos that carry no check at
    // all, so it emits none.
    let mut node = self_checking_node();
    for host in 1..=4u8 {
        hello_from(&mut node, T0, host, 8);
    }
    drain(|| node.poll_output());
    assert!(node.recheck_reachability(T0));
    drain(|| node.poll_output());
    for host in 1..=4u8 {
        hello_res_from(&mut node, T0, host);
        node.handle_datagram(
            T0,
            endpoint(host, 4700 + u16::from(host)),
            &[0xE4, 0x58, 198, 51, 100, 1],
        );
        drain(|| node.poll_output());
    }

    let again = T0 + std::time::Duration::from_secs(60);
    assert!(!node.recheck_reachability(again), "inside the spacing");
    assert!(datagrams(&drain(|| node.poll_output())).is_empty());
}

#[test]
fn a_mutual_firewall_check_earns_the_0x58_but_no_dial_back() {
    // Measured live: two nodes that check each other inside one
    // hello burst collide. The dial-back hands the requester a socket its own
    // responder adopts instead of dialing, and our close tears that client down
    // before it can ack — so both checks end proving nothing. Answer `0x58`
    // (which costs nothing and counts the peer's recheck), refuse the dial.
    let mut node = self_checking_node();
    // Our own check goes out first, on the hello this peer answered.
    hello_from(&mut node, T0, 7, 8);
    assert_eq!(firewall_emissions(&drain(|| node.poll_output())).len(), 1);

    // Now its check arrives from the same IP.
    let requester = endpoint(7, 4707);
    let mut datagram = vec![0xE4, 0x53, 0x36, 0x12];
    datagram.extend_from_slice(&[0xAB; 16]);
    datagram.push(0x00);
    node.handle_datagram(T0, requester, &datagram);
    let outputs = drain(|| node.poll_output());
    assert_eq!(
        datagrams(&outputs),
        vec![(requester, vec![0xE4, 0x58, 1, 7, 55, 45])],
        "the observed-IP answer still goes out"
    );
    assert!(
        !events(&outputs)
            .iter()
            .any(|event| matches!(event, KadEvent::DialBackRequested { .. })),
        "no dial-back while our own check on that IP is outstanding"
    );
    assert_eq!(
        diagnostics(&outputs),
        vec![KadNodeDiagnostic::DialBackRefusedMutualCheck { from: requester }]
    );

    // Once our window lapses the collision is gone and the dial-back resumes.
    let later = T0 + KadNode::FIREWALL_CHECK_WINDOW;
    node.handle_datagram(later, requester, &datagram);
    assert!(
        events(&drain(|| node.poll_output()))
            .iter()
            .any(|event| matches!(event, KadEvent::DialBackRequested { .. })),
    );
}

/// Every emitted check tells core whom it awaits a connect-back from and for
/// how long (ADR-0046 "Test Connections"): the listener admits that helper's
/// plain dial under `Required` for exactly the window the node judges its ack
/// by — aMule's `AddKadFirewallRequest`, 180 s.
#[test]
fn every_emitted_check_names_its_helper_and_window() {
    let mut node = self_checking_node();
    hello_from(&mut node, T0, 1, 8);
    let asked: Vec<KadEvent> = events(&drain(|| node.poll_output()))
        .into_iter()
        .filter(|event| matches!(event, KadEvent::ReachabilityCheckAsked { .. }))
        .collect();
    assert_eq!(
        asked,
        vec![KadEvent::ReachabilityCheckAsked {
            helper: host_ip(1),
            helper_id: id(1),
            helper_udp_port: 4701,
            connect_options: Some(0),
            answerable_for: std::time::Duration::from_secs(180),
        }]
    );
}
