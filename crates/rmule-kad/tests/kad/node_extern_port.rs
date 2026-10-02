//! **Extern Kad Port** discovery: the `0x60` pings our UDP
//! self-check sends while it does not yet know the port a NAT maps our Kad
//! socket to, the `0x61` answers it states as observations, and the gate that
//! holds every helper back until core's Address Learning verdict has come in —
//! so the `0xA7` carries the learned port, not the intern one. aMule
//! `ab483654`: `Kademlia.cpp:223-243`, `Prefs.cpp:291-334`,
//! `UDPFirewallTester.cpp:200-222, 252-256`.

use std::net::Ipv4Addr;
use std::time::Duration;

use rmule_kad::{
    Kad2Message, KadCommand, KadContact, KadEvent, KadNode, KadNodeDiagnostic, KadNodeEndpoint,
    KadOutput, UdpFirewallHelper,
};
use rmule_primitives::Ipv4Endpoint;
use rmule_primitives::session::drain;
use rmule_testkit::kad_node::{
    OUR_INTERN_UDP, T0, datagrams, deliver, diagnostics, endpoint, events, hello, id, node,
};

/// The port the gateway maps our Kad socket to in these tests.
const MAPPED: u16 = 14672;

fn helper(host: u8) -> UdpFirewallHelper {
    UdpFirewallHelper {
        endpoint: Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, host), 4700 + u16::from(host)),
        id: id(host),
        version: 8,
    }
}

/// The `0xA7` bodies the node asked core to deliver, as (helper, intern, extern).
fn requests(outputs: &[KadOutput]) -> Vec<(Ipv4Endpoint, u16, u16)> {
    events(outputs)
        .into_iter()
        .filter_map(|event| match event {
            KadEvent::UdpFirewallCheckRequested { helper, request } => Some((
                helper,
                u16::from_le_bytes([request[0], request[1]]),
                u16::from_le_bytes([request[2], request[3]]),
            )),
            _ => None,
        })
        .collect()
}

/// Where the node sent a `0x60`. Read off the raw datagrams: a hello answer
/// rides with a firewall check the plain message decoder does not model.
fn pings(outputs: &[KadOutput]) -> Vec<KadNodeEndpoint> {
    datagrams(outputs)
        .into_iter()
        .filter(|(_, bytes)| bytes == &Kad2Message::Ping.encode().encode())
        .map(|(to, _)| to)
        .collect()
}

fn observations(outputs: &[KadOutput]) -> Vec<(Ipv4Addr, u16)> {
    events(outputs)
        .into_iter()
        .filter_map(|event| match event {
            KadEvent::UdpPortObserved { observer, port } => Some((observer, port)),
            _ => None,
        })
        .collect()
}

/// A node with the self-check armed and three v8 contacts to ask.
fn armed() -> KadNode {
    let mut node = node();
    node.enable_firewall_self_check(T0);
    node.handle_command(
        T0,
        KadCommand::MergeContacts {
            contacts: (1..=3)
                .map(|host| KadContact::new(id(host), endpoint(host, 4672), 4662, 8))
                .collect(),
        },
    );
    drain(|| node.poll_output());
    node
}

fn after(secs: u64) -> rmule_kad::KadInstant {
    T0 + Duration::from_secs(secs)
}

#[test]
fn the_self_check_pings_one_contact_for_our_extern_port_every_fifteen_seconds() {
    let mut node = armed();

    node.tick(T0);
    let first = pings(&drain(|| node.poll_output()));
    assert_eq!(first.len(), 1, "one contact asked per round of the cadence");

    node.tick(after(14));
    assert!(pings(&drain(|| node.poll_output())).is_empty());
    assert!(
        node.next_wake().is_some_and(|wake| wake <= after(15)),
        "the cadence wakes the node"
    );

    node.tick(after(15));
    let second = pings(&drain(|| node.poll_output()));
    assert_eq!(second.len(), 1);
    assert_ne!(
        second, first,
        "an unanswered contact is not asked twice while another is untried"
    );
}

#[test]
fn a_pong_to_our_ping_states_the_port_once_per_observer_and_a_stray_pong_states_nothing() {
    let mut node = armed();
    node.tick(T0);
    let asked = pings(&drain(|| node.poll_output()))[0];

    deliver(
        &mut node,
        T0,
        asked,
        &Kad2Message::Pong { udp_port: MAPPED },
    );
    assert_eq!(
        observations(&drain(|| node.poll_output())),
        vec![(asked.ip(), MAPPED)]
    );

    deliver(
        &mut node,
        T0,
        asked,
        &Kad2Message::Pong { udp_port: MAPPED },
    );
    assert!(
        observations(&drain(|| node.poll_output())).is_empty(),
        "one observer counts once per round (SetExternKadPort's IP scan)"
    );

    let stranger = endpoint(40, 4672);
    deliver(&mut node, T0, stranger, &Kad2Message::Pong { udp_port: 1 });
    let outputs = drain(|| node.poll_output());
    assert!(
        observations(&outputs).is_empty(),
        "never pinged, never heard"
    );
    assert!(diagnostics(&outputs).contains(&KadNodeDiagnostic::UnsolicitedPong { from: stranger }));
}

#[test]
fn helpers_wait_until_the_extern_port_is_known_and_the_0xa7_carries_it() {
    let mut node = armed();
    node.offer_udp_firewall_helper(helper(20));
    assert!(
        requests(&drain(|| node.poll_output())).is_empty(),
        "QueryNextClient returns while FindExternKadPort(false) holds"
    );

    // Core's Address Learning verdict comes back after the observations.
    node.handle_command(T0, KadCommand::SetExternalUdpPort { port: MAPPED });
    assert_eq!(
        requests(&drain(|| node.poll_output())),
        vec![(helper(20).endpoint, OUR_INTERN_UDP, MAPPED)]
    );

    node.tick(after(15));
    assert!(
        pings(&drain(|| node.poll_output())).is_empty(),
        "a known port ends the pinging"
    );
}

#[test]
fn a_zero_answer_keeps_the_gate_shut_until_three_observers_disagreed() {
    let mut node = armed();
    node.offer_udp_firewall_helper(helper(20));
    for (step, port) in [(0u64, 5001u16), (15, 5002), (30, 5003)] {
        node.tick(after(step));
        let asked = pings(&drain(|| node.poll_output()))[0];
        deliver(
            &mut node,
            after(step),
            asked,
            &Kad2Message::Pong { udp_port: port },
        );
        drain(|| node.poll_output());
        // No two agreed, so the store has no learned port to name.
        node.handle_command(after(step), KadCommand::SetExternalUdpPort { port: 0 });
        let engaged = requests(&drain(|| node.poll_output()));
        if step < 30 {
            assert!(engaged.is_empty(), "still asking after {step} s");
        } else {
            assert_eq!(
                engaged,
                vec![(helper(20).endpoint, OUR_INTERN_UDP, 0)],
                "three disagreeing answers: unreliable, the check runs on the intern port \
                 alone (Prefs.cpp:318-322)"
            );
        }
    }
    node.tick(after(45));
    assert!(pings(&drain(|| node.poll_output())).is_empty());
}

#[test]
fn a_recheck_forgets_the_round_and_asks_again() {
    let mut node = armed();
    node.handle_command(T0, KadCommand::SetExternalUdpPort { port: MAPPED });
    node.tick(T0);
    assert!(pings(&drain(|| node.poll_output())).is_empty());

    node.handle_command(after(60), KadCommand::RecheckReachability);
    drain(|| node.poll_output());
    node.offer_udp_firewall_helper(helper(20));
    node.tick(after(60));
    let outputs = drain(|| node.poll_output());
    assert_eq!(
        pings(&outputs).len(),
        1,
        "FindExternKadPort(true) reopened the round"
    );
    assert!(requests(&outputs).is_empty(), "and shut the gate again");
}

#[test]
fn a_recheck_marks_the_round_boundary_for_the_store_to_forget_its_votes_on() {
    // The node only states the boundary as an event — core's
    // Address Learning store owns forgetting the previous round's UDP-role
    // Kad reports, exactly as it owns the agreement rule itself.
    let mut node = armed();
    node.handle_command(T0, KadCommand::SetExternalUdpPort { port: MAPPED });
    drain(|| node.poll_output());

    node.handle_command(after(60), KadCommand::RecheckReachability);
    let boundaries = events(&drain(|| node.poll_output()))
        .into_iter()
        .filter(|event| *event == KadEvent::ExternPortRoundStarted)
        .count();
    assert_eq!(boundaries, 1, "one boundary per recheck, not once per tick");
}

#[test]
fn a_hello_from_a_v6_node_draws_a_ping_only_while_the_port_is_unknown() {
    let mut node = armed();
    let caller = endpoint(30, 4672);
    deliver(
        &mut node,
        T0,
        caller,
        &Kad2Message::HelloReq(hello(id(30), caller, 8, 0)),
    );
    assert!(pings(&drain(|| node.poll_output())).contains(&caller));

    node.handle_command(T0, KadCommand::SetExternalUdpPort { port: MAPPED });
    let late = endpoint(31, 4672);
    deliver(
        &mut node,
        T0,
        late,
        &Kad2Message::HelloReq(hello(id(31), late, 8, 0)),
    );
    assert!(!pings(&drain(|| node.poll_output())).contains(&late));
}

#[test]
fn a_reconcile_answer_of_zero_writes_through_once_the_round_has_settled() {
    // The store owns the port, the node a cache. Mid-round, a
    // zero answer must stand aside (see the disagreement test above) — but
    // once the round has settled, a later zero answer is the store's own
    // verdict (its 30-minute window aging out with no fresh observer) and
    // must write through, or the node keeps advertising a port the store no
    // longer holds.
    let mut node = armed();
    node.handle_command(T0, KadCommand::SetExternalUdpPort { port: MAPPED });
    node.offer_udp_firewall_helper(helper(20));
    assert_eq!(
        requests(&drain(|| node.poll_output())),
        vec![(helper(20).endpoint, OUR_INTERN_UDP, MAPPED)]
    );

    node.handle_command(after(1800), KadCommand::SetExternalUdpPort { port: 0 });
    node.offer_udp_firewall_helper(helper(21));
    assert_eq!(
        requests(&drain(|| node.poll_output())),
        vec![(helper(21).endpoint, OUR_INTERN_UDP, 0)],
        "the round already settled; the node's cache follows the store's expiry"
    );
}
