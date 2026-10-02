//! The bootstrap exchange: what a `KADEMLIA2_BOOTSTRAP_REQ` draws out of this
//! node, what its response does to the routing table, and why an unsolicited
//! one changes nothing.

use rmule_kad::{
    Kad2Message, Kad2NodeInfo, KadCommand, KadContactState, KadEvent, KadNode, KadNodeDiagnostic,
};
use rmule_primitives::session::drain;
use rmule_testkit::kad_node::{
    T0, bootstrapped, deliver, diagnostics, endpoint, events, id, info, node, sent_messages,
};

#[test]
fn bootstrap_command_emits_a_bootstrap_req() {
    let mut node = node();
    node.handle_command(
        T0,
        KadCommand::Bootstrap {
            endpoint: endpoint(1, 4700),
        },
    );

    assert_eq!(
        sent_messages(&drain(|| node.poll_output())),
        vec![(endpoint(1, 4700), Kad2Message::BootstrapReq)]
    );
    assert_eq!(
        node.next_wake(),
        Some(T0 + KadNode::BOOTSTRAP_SOLICITATION_WINDOW),
        "the solicitation itself now arms a 180s out-track deadline (ADR-0064)"
    );
}

#[test]
fn bootstrap_response_adds_the_responder_live_and_probes_hearsay_rows() {
    let mut node = node();
    let row = rmule_kad::KadContact::new(id(0x30), endpoint(3, 4703), 4761, 8);
    let outputs = bootstrapped(&mut node, info(0x20, None), endpoint(2, 4702), vec![row]);

    // The responder answered from its endpoint: live, stored Responded.
    let responder = node
        .routing_table()
        .get(id(0x20))
        .expect("responder stored");
    assert_eq!(responder.state(), KadContactState::Responded);
    assert_eq!(responder.endpoint(), endpoint(2, 4702));

    // The row contact is hearsay: stored and being hello-probed.
    let hearsay = node.routing_table().get(id(0x30)).expect("row stored");
    assert_eq!(hearsay.state(), KadContactState::Pending);

    // One hello to the responder (advertises us), one probing the row contact.
    let hello = Kad2Message::HelloReq(Kad2NodeInfo {
        id: id(0xAA),
        tcp_port: 4662,
        version: 8,
        udp_port_tag: Some(4672),
        misc_options: 0,
    });
    assert_eq!(
        sent_messages(&outputs),
        vec![
            (endpoint(2, 4702), hello.clone()),
            (endpoint(3, 4703), hello)
        ]
    );
    assert_eq!(
        events(&outputs),
        vec![
            // The response is the node's first inbound datagram — the
            // silent→heard edge.
            KadEvent::HadContact {
                from: endpoint(2, 4702)
            },
            KadEvent::ContactAdded {
                id: id(0x20),
                endpoint: endpoint(2, 4702)
            },
            KadEvent::ContactAdded {
                id: id(0x30),
                endpoint: endpoint(3, 4703)
            },
        ]
    );

    // Probes arm the wake-up clock.
    assert_eq!(node.next_wake(), Some(T0 + KadNode::PROBE_TIMEOUT));
}

#[test]
fn unsolicited_bootstrap_response_is_diagnosed_and_adds_nothing() {
    let mut node = node();
    deliver(
        &mut node,
        T0,
        endpoint(2, 4702),
        &Kad2Message::BootstrapRes {
            sender: info(0x20, None),
            contacts: vec![rmule_kad::KadContact::new(
                id(0x30),
                endpoint(3, 4703),
                4761,
                8,
            )],
        },
    );

    let outputs = drain(|| node.poll_output());
    assert_eq!(
        diagnostics(&outputs),
        vec![KadNodeDiagnostic::UnsolicitedBootstrapRes {
            from: endpoint(2, 4702)
        }]
    );
    assert!(sent_messages(&outputs).is_empty());
    assert!(node.routing_table().is_empty(), "nothing may be added");
}

#[test]
fn bootstrap_rows_carrying_our_own_id_are_never_added_or_probed() {
    let mut node = node();
    let own_row = rmule_kad::KadContact::new(id(0xAA), endpoint(9, 4709), 4761, 8);
    let outputs = bootstrapped(
        &mut node,
        info(0x20, None),
        endpoint(2, 4702),
        vec![own_row],
    );

    assert!(node.routing_table().get(id(0xAA)).is_none());
    // Only the advertisement hello to the responder goes out.
    assert_eq!(sent_messages(&outputs).len(), 1);
}

#[test]
fn bootstrap_req_is_answered_with_own_info_and_responded_contacts_only() {
    let mut node = node();
    deliver(
        &mut node,
        T0,
        endpoint(4, 4704),
        &Kad2Message::HelloReq(info(0x40, None)),
    );
    drain(|| node.poll_output());

    deliver(&mut node, T0, endpoint(9, 4909), &Kad2Message::BootstrapReq);

    let sent = sent_messages(&drain(|| node.poll_output()));
    let [(to, Kad2Message::BootstrapRes { sender, contacts })] = sent.as_slice() else {
        panic!("expected exactly one bootstrap response, got {sent:?}");
    };
    assert_eq!(*to, endpoint(9, 4909));
    assert_eq!(
        *sender,
        Kad2NodeInfo {
            id: id(0xAA),
            tcp_port: 4662,
            version: 8,
            udp_port_tag: None,
            misc_options: 0,
        }
    );
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].id(), id(0x40));
    assert!(
        node.routing_table().get(id(0x99)).is_none(),
        "a bootstrap request carries no identity to add"
    );
}
