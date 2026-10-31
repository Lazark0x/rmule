//! Hello and ping: the sender a `HELLO_REQ` stores, the probe a `HELLO_RES`
//! answers, the eviction a mismatched identity earns, and the failure a silent
//! probed contact meets on tick.

use std::time::Duration;

use rmule_kad::{
    Kad2Message, Kad2NodeInfo, KadContactState, KadEvent, KadNode, KadNodeDiagnostic,
    KadNodeEndpoint, KadReachability, MISC_OPTIONS_TCP_FIREWALLED, MISC_OPTIONS_UDP_FIREWALLED,
};
use rmule_primitives::session::drain;
use rmule_testkit::kad_node::{
    T0, bootstrapped, deliver, diagnostics, endpoint, events, host_ip, id, info, node,
    sent_messages,
};

#[test]
fn hello_req_stores_the_sender_as_responded_and_answers_hello_res() {
    let mut node = node();
    deliver(
        &mut node,
        T0,
        endpoint(4, 4704),
        &Kad2Message::HelloReq(info(0x40, Some(4804))),
    );

    let outputs = drain(|| node.poll_output());
    let stored = node.routing_table().get(id(0x40)).expect("sender stored");
    assert_eq!(stored.state(), KadContactState::Responded);
    assert_eq!(
        stored.endpoint(),
        KadNodeEndpoint::new(host_ip(4), 4804),
        "the UDP-port tag overrides the datagram source port"
    );
    assert_eq!(stored.tcp_port(), 4761);

    // No ack-request: this plaintext node has no sender key to carry, and a
    // 0x22 cannot prove anything without one (ADR-0064).
    assert_eq!(
        sent_messages(&outputs),
        vec![(
            endpoint(4, 4704),
            Kad2Message::HelloRes(Kad2NodeInfo {
                id: id(0xAA),
                tcp_port: 4662,
                version: 8,
                udp_port_tag: None,
                misc_options: 0,
            })
        )]
    );
}

#[test]
fn hello_req_without_udp_tag_falls_back_to_the_datagram_source_port() {
    let mut node = node();
    deliver(
        &mut node,
        T0,
        endpoint(4, 4704),
        &Kad2Message::HelloReq(info(0x40, None)),
    );
    drain(|| node.poll_output());

    assert_eq!(
        node.routing_table()
            .get(id(0x40))
            .expect("sender stored")
            .endpoint(),
        endpoint(4, 4704)
    );
}

#[test]
fn probed_contact_answering_hello_res_becomes_responded_and_disarms_the_timer() {
    let mut node = node();
    let row = rmule_kad::KadContact::new(id(0x30), endpoint(3, 4703), 4761, 8);
    bootstrapped(&mut node, info(0x20, None), endpoint(2, 4702), vec![row]);

    deliver(
        &mut node,
        T0 + Duration::from_secs(1),
        endpoint(2, 4702),
        &Kad2Message::HelloRes(info(0x20, None)),
    );
    deliver(
        &mut node,
        T0 + Duration::from_secs(1),
        endpoint(3, 4703),
        &Kad2Message::HelloRes(info(0x30, None)),
    );

    let outputs = drain(|| node.poll_output());
    assert_eq!(
        events(&outputs),
        vec![
            KadEvent::ContactResponded { id: id(0x20) },
            KadEvent::ContactResponded { id: id(0x30) },
        ]
    );
    assert_eq!(
        node.routing_table()
            .get(id(0x30))
            .expect("still stored")
            .state(),
        KadContactState::Responded
    );
    assert!(node.next_wake().is_none(), "no probes left outstanding");
}

#[test]
fn unsolicited_hello_res_is_diagnosed_and_adds_nothing() {
    let mut node = node();
    deliver(
        &mut node,
        T0,
        endpoint(5, 4705),
        &Kad2Message::HelloRes(info(0x50, None)),
    );

    assert_eq!(
        diagnostics(&drain(|| node.poll_output())),
        vec![KadNodeDiagnostic::UnsolicitedHelloRes {
            from: endpoint(5, 4705)
        }]
    );
    assert!(node.routing_table().is_empty());
}

#[test]
fn hello_res_reporting_a_different_id_than_probed_evicts_the_suspect() {
    let mut node = node();
    let row = rmule_kad::KadContact::new(id(0x30), endpoint(3, 4703), 4761, 8);
    bootstrapped(&mut node, info(0x20, None), endpoint(2, 4702), vec![row]);

    // The endpoint we probed for 0x30 answers claiming to be 0x66.
    deliver(
        &mut node,
        T0 + Duration::from_secs(1),
        endpoint(3, 4703),
        &Kad2Message::HelloRes(info(0x66, None)),
    );

    let outputs = drain(|| node.poll_output());
    assert_eq!(
        diagnostics(&outputs),
        vec![KadNodeDiagnostic::HelloResIdMismatch {
            from: endpoint(3, 4703),
            expected: id(0x30),
            reported: id(0x66),
        }]
    );
    assert!(
        node.routing_table().get(id(0x30)).is_none(),
        "the confused/hostile endpoint's contact is evicted"
    );
    assert!(
        node.routing_table().get(id(0x66)).is_none(),
        "the claimed identity is not trusted either"
    );
}

#[test]
fn ping_is_answered_with_the_observed_source_port() {
    let mut node = node();
    deliver(&mut node, T0, endpoint(6, 4906), &Kad2Message::Ping);

    let outputs = drain(|| node.poll_output());
    assert_eq!(
        sent_messages(&outputs),
        vec![(endpoint(6, 4906), Kad2Message::Pong { udp_port: 4906 })]
    );
    assert!(
        node.routing_table().is_empty(),
        "a ping carries no identity"
    );
}

#[test]
fn unsolicited_pong_is_diagnosed() {
    let mut node = node();
    deliver(
        &mut node,
        T0,
        endpoint(6, 4906),
        &Kad2Message::Pong { udp_port: 4672 },
    );

    assert_eq!(
        diagnostics(&drain(|| node.poll_output())),
        vec![KadNodeDiagnostic::UnsolicitedPong {
            from: endpoint(6, 4906)
        }]
    );
}

#[test]
fn silent_probed_contact_fails_and_is_evicted_on_tick() {
    let mut node = node();
    let row = rmule_kad::KadContact::new(id(0x30), endpoint(3, 4703), 4761, 8);
    bootstrapped(&mut node, info(0x20, None), endpoint(2, 4702), vec![row]);
    // The responder answers its advertisement hello; 0x30 stays silent.
    deliver(
        &mut node,
        T0 + Duration::from_secs(1),
        endpoint(2, 4702),
        &Kad2Message::HelloRes(info(0x20, None)),
    );
    drain(|| node.poll_output());

    let deadline = T0 + KadNode::PROBE_TIMEOUT;
    node.tick(T0 + Duration::from_secs(2));
    assert!(
        drain(|| node.poll_output()).is_empty(),
        "a tick before the deadline is a no-op"
    );
    assert_eq!(node.next_wake(), Some(deadline));

    node.tick(deadline);
    assert_eq!(
        events(&drain(|| node.poll_output())),
        vec![
            KadEvent::ContactFailed { id: id(0x30) },
            KadEvent::ContactEvicted { id: id(0x30) },
        ]
    );
    assert!(node.routing_table().get(id(0x30)).is_none());
    assert!(node.next_wake().is_none());
}

#[test]
fn the_kad_version_the_peer_hello_advertises_is_the_one_this_node_speaks() {
    // Two crates carry the number: the capability registry (ADR-0047), because
    // the peer-hello surface sits below this crate and cannot read the constant,
    // and this node, which puts it on every `KADEMLIA2_HELLO`. A counterparty
    // reads the peer-hello nibble to decide whether to hand us a Kad bootstrap
    // hint and whether to ack a firewall-check connect-back over TCP or legacy
    // UDP, so the two drifting apart is an interop bug with no local symptom.
    assert_eq!(
        rmule_primitives::Capabilities::shipped(rmule_primitives::CryptStance::disabled())
            .kad_version(),
        KadNode::KAD_VERSION
    );
}

fn answered_hello(node: &mut KadNode, peer: u8, version: u8) -> Kad2NodeInfo {
    deliver(
        node,
        T0,
        endpoint(peer, 4704),
        &Kad2Message::HelloReq(Kad2NodeInfo {
            version,
            ..info(peer, Some(4704))
        }),
    );
    let outputs = drain(|| node.poll_output());
    sent_messages(&outputs)
        .into_iter()
        .find_map(|(_, message)| match message {
            Kad2Message::HelloRes(info) => Some(info),
            _ => None,
        })
        .expect("the hello is answered")
}

#[test]
fn a_firewalled_node_says_so_in_its_hello_to_a_v8_peer_and_only_there() {
    let mut node = node();
    node.set_reachability(KadReachability {
        udp_firewalled: true,
        tcp_firewalled: true,
        buddy_connected: false,
    });
    assert_eq!(
        answered_hello(&mut node, 4, 8).misc_options,
        MISC_OPTIONS_UDP_FIREWALLED | MISC_OPTIONS_TCP_FIREWALLED
    );
    assert_eq!(answered_hello(&mut node, 5, 7).misc_options, 0);
}

#[test]
fn a_udp_firewalled_sender_is_answered_and_never_stored() {
    let mut node = node();
    deliver(
        &mut node,
        T0,
        endpoint(4, 4704),
        &Kad2Message::HelloReq(Kad2NodeInfo {
            misc_options: MISC_OPTIONS_UDP_FIREWALLED,
            ..info(0x40, None)
        }),
    );
    let outputs = drain(|| node.poll_output());
    assert!(node.routing_table().get(id(0x40)).is_none());
    assert!(matches!(
        sent_messages(&outputs).as_slice(),
        [(_, Kad2Message::HelloRes(_))]
    ));
}

#[test]
fn a_tcp_firewalled_sender_is_still_stored() {
    let mut node = node();
    deliver(
        &mut node,
        T0,
        endpoint(4, 4704),
        &Kad2Message::HelloReq(Kad2NodeInfo {
            misc_options: MISC_OPTIONS_TCP_FIREWALLED,
            ..info(0x40, None)
        }),
    );
    assert!(node.routing_table().get(id(0x40)).is_some());
}
