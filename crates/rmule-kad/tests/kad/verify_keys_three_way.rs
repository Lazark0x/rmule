//! The `0x22` three-way, both directions: what it takes for a contact to
//! verify through it, and what our own `0x22` owes a peer that asked for an
//! ack (aMule 2.3.3 `KademliaUDPListener.cpp`).

use rmule_kad::{Kad2Message, KadEvent, KadNodeDiagnostic, MISC_OPTIONS_ACK_REQUEST, decode_exact};
use rmule_primitives::{ClientDecryptKeys, decrypt_datagram_client};
use std::time::Duration;

use rmule_kad::KadNode;
use rmule_testkit::kad_node::{
    NODE_ID, T0, crypt_node, crypt_to_node, datagrams, diagnostics, drain_outputs, endpoint,
    events, fixed_nonce, hello, id, keyed_node, opened_messages, our_key_for, solicit_hello_res,
};

#[test]
fn the_0x22_three_way_verifies_a_contact_only_with_a_valid_receiver_key() {
    // Role A + C end to end (aMule `Process2HelloResponseAck`): our HELLO_RES
    // asks a v8 hello sender to prove its IP; its 0x22 verifies it only when
    // the ACK datagram itself echoes our receiver key. Three ACK forms, one
    // node each, from the same solicited state.
    let peer = endpoint(7, 5000);
    let hello_req = Kad2Message::HelloReq(hello(id(0xC1), peer, 8, 0))
        .encode()
        .encode();
    let ack = Kad2Message::HelloResAck { id: id(0xC1) }.encode().encode();

    let solicited = |outputs: &[rmule_kad::KadOutput]| {
        let sent = opened_messages(outputs, id(0xC1), None);
        let [(_, Kad2Message::HelloRes(res))] = sent.as_slice() else {
            panic!("one hello res: {sent:?}");
        };
        assert_eq!(
            res.misc_options & MISC_OPTIONS_ACK_REQUEST,
            MISC_OPTIONS_ACK_REQUEST
        );
    };

    // (a) keyed ACK echoing our key -> verified.
    let mut good = crypt_node();
    good.handle_datagram(T0, peer, &hello_req);
    solicited(&drain_outputs(&mut good));
    good.handle_datagram(
        T0,
        peer,
        &crypt_to_node(&ack, our_key_for(peer), 0xFEED_1111),
    );
    let outputs = drain_outputs(&mut good);
    assert!(
        good.routing_table()
            .get(id(0xC1))
            .expect("stored")
            .verified(),
        "the three-way completes: the contact is a Verified Contact"
    );
    assert!(events(&outputs).contains(&KadEvent::ContactVerified { id: id(0xC1) }));

    // (b) plaintext ACK -> consumed, never verifying (anyone can spoof a source
    //     IP they cannot receive at; only the key proves receipt).
    let mut plain = crypt_node();
    plain.handle_datagram(T0, peer, &hello_req);
    solicited(&drain_outputs(&mut plain));
    plain.handle_datagram(T0, peer, &ack);
    let outputs = drain_outputs(&mut plain);
    assert!(
        !plain
            .routing_table()
            .get(id(0xC1))
            .expect("stored")
            .verified(),
        "a plaintext 0x22 carries no proof"
    );
    assert_eq!(
        diagnostics(&outputs),
        vec![KadNodeDiagnostic::HelloResAckUnverified { from: peer }]
    );

    // (c) keyed ACK naming a DIFFERENT contact ID than the one we solicited ->
    //     rejected (aMule looks the ACK's own `remoteID` up and requires it to
    //     resolve at this IP).
    let mut mismatched = crypt_node();
    mismatched.handle_datagram(T0, peer, &hello_req);
    solicited(&drain_outputs(&mut mismatched));
    mismatched.handle_datagram(
        T0,
        peer,
        &crypt_to_node(
            &Kad2Message::HelloResAck { id: id(0x77) }.encode().encode(),
            our_key_for(peer),
            0xFEED_1111,
        ),
    );
    let outputs = drain_outputs(&mut mismatched);
    assert!(
        !mismatched
            .routing_table()
            .get(id(0xC1))
            .expect("stored")
            .verified(),
        "a 0x22 naming another ID never verifies the solicited contact"
    );
    assert_eq!(
        diagnostics(&outputs),
        vec![KadNodeDiagnostic::HelloResAckUnverified { from: peer }]
    );
}

#[test]
fn our_own_0x22_answers_a_keyed_ack_request_and_echoes_the_peers_key() {
    // Role B, the reverse leg: a responder's HELLO_RES asks US to prove our IP
    // and hands us its sender key. We must emit the 0x22 — and, with send
    // obfuscation on, key it so the responder reads `validReceiverKey`: the
    // trailer's receiver slot carries THEIR key, the sender slot ours.
    let mut node = keyed_node();
    node.enable_datagram_obfuscation(fixed_nonce);
    let responder = endpoint(3, 4700);
    let responder_key = 0xC0FF_EE01;
    solicit_hello_res(&mut node, responder, id(0xB0));

    let res = Kad2Message::HelloRes(hello(id(0xB0), responder, 8, MISC_OPTIONS_ACK_REQUEST))
        .encode()
        .encode();
    node.handle_datagram(T0, responder, &crypt_to_node(&res, 0, responder_key));
    let outputs = drain_outputs(&mut node);

    let wire_out = datagrams(&outputs);
    let [(to, wire)] = wire_out.as_slice() else {
        panic!("exactly one datagram (the 0x22): {wire_out:?}");
    };
    assert_eq!(*to, responder);

    // aMule sends its ACK `SendPacket(…, senderKey, NULL)`
    // (`KademliaUDPListener.cpp#L618`) — receiver-key family even toward a
    // stored contact; a KadID keys the send only on non-reply dispatches. The
    // genuine captured aMule 0x22 pins the same family bits 2, so rmule's
    // emitted marker must match that byte shape.
    assert_eq!(wire[0] & 0x03, 2, "the 0x22 rides the receiver-key family");
    let recovered = decrypt_datagram_client(
        wire,
        &ClientDecryptKeys {
            receiver_verify_key: Some(responder_key),
            ..Default::default()
        },
    )
    .expect("the responder decrypts our 0x22 with the key it handed us");
    let rmule_kad::KadDecoded::Plain(envelope) =
        decode_exact(&recovered.payload).expect("plaintext 0x22")
    else {
        panic!("unpacked");
    };
    assert_eq!(
        Kad2Message::decode(&envelope),
        Ok(Kad2Message::HelloResAck { id: NODE_ID }),
        "the 0x22 carries our own Kad ID"
    );
    assert_eq!(
        recovered.receiver_verify_key,
        Some(responder_key),
        "the trailer echoes the responder's key — its `validReceiverKey`"
    );
    assert_eq!(
        recovered.sender_verify_key,
        Some(our_key_for(responder)),
        "and hands the responder our own key for its IP"
    );
}

#[test]
fn an_unanswered_ack_request_is_pruned_at_its_window_so_a_late_0x22_is_unsolicited() {
    // Role A arms an outstanding ack-request at T0 (a v8 hello we could not
    // verify). Left unanswered, it must be pruned at its ACK_REQUEST_WINDOW
    // deadline in tick -- the same expiry discipline pending_probes and
    // outstanding_bootstraps keep -- rather than leak an entry forever.
    let mut node = crypt_node();
    let peer = endpoint(7, 5000);

    node.handle_datagram(
        T0,
        peer,
        &Kad2Message::HelloReq(hello(id(0xC1), peer, 8, 0))
            .encode()
            .encode(),
    );
    let sent = opened_messages(&drain_outputs(&mut node), id(0xC1), None);
    assert!(
        matches!(sent.as_slice(), [(_, Kad2Message::HelloRes(res))] if res.misc_options & MISC_OPTIONS_ACK_REQUEST != 0),
        "the v8 hello is answered with the ack-requesting HELLO_RES that arms the entry"
    );

    // Advance just past the window and tick: the unanswered entry is pruned.
    let after = T0 + KadNode::ACK_REQUEST_WINDOW + Duration::from_millis(1);
    node.tick(after);
    let _ = drain_outputs(&mut node);

    // The peer's matching 0x22 now arrives too late. With the entry pruned it
    // is unsolicited -- not the consumed-but-unverifying ACK it was inside the
    // window (contrast the solicited-ACK test above): the deadline changed the
    // verdict.
    node.handle_datagram(
        after,
        peer,
        &Kad2Message::HelloResAck { id: id(0xC1) }.encode().encode(),
    );
    assert_eq!(
        diagnostics(&drain_outputs(&mut node)),
        vec![KadNodeDiagnostic::UnsolicitedHelloResAck { from: peer }],
        "an expired ack-request makes its late 0x22 unsolicited"
    );
}
