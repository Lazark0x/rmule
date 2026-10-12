//! The gates aMule applies before it will answer an ack request, and the
//! port-53 sender-key exemption that lets a keyed datagram through the entry
//! gate a plaintext one is dropped by (ADR-0064 entry gate 1).

use rmule_kad::{
    Kad2Message, KadDecoded, KadNodeDiagnostic, MISC_OPTIONS_ACK_REQUEST, decode_exact,
};
use rmule_primitives::{ClientDecryptKeys, decrypt_datagram_client};
use rmule_testkit::kad_node::{
    T0, crypt_node, crypt_to_node, datagrams, diagnostics, drain_outputs, endpoint, hello, id,
    node, opened_messages, our_key_for, sent_messages, solicit_hello_res,
};

#[test]
fn a_zeroed_sender_key_trailer_never_draws_a_0x22() {
    // aMule treats verify key 0 as *no key* (`CKadUDPKey::IsEmpty`): a crypt
    // HELLO_RES whose trailer carries sender key 0 must take the silent
    // "Remote client demands ACK, but didn't send any sender key!" branch
    // (`KademliaUDPListener.cpp#L608`), exactly like a plaintext one.
    let mut node = crypt_node();
    let responder = endpoint(3, 4700);
    solicit_hello_res(&mut node, responder, id(0xB0));

    let res = Kad2Message::HelloRes(hello(id(0xB0), responder, 8, MISC_OPTIONS_ACK_REQUEST))
        .encode()
        .encode();
    node.handle_datagram(T0, responder, &crypt_to_node(&res, 0, 0));
    let outputs = drain_outputs(&mut node);

    assert!(
        !opened_messages(&outputs, id(0xB0), None)
            .iter()
            .any(|(_, m)| matches!(m, Kad2Message::HelloResAck { .. })),
        "a zero sender key is an absent sender key: no 0x22 may be emitted"
    );
}

#[test]
fn a_v7_ack_request_is_not_honored() {
    // aMule honors the misc-options ACK-request bit only from a version >= 8
    // hello (`AddContact2`, `KademliaUDPListener.cpp#L410`): v7 uses the
    // ping-with-key workaround instead, so an ACK toward it would be
    // off-protocol. A v7 HELLO_RES with the bit set and a real sender key must
    // stay unanswered.
    let mut node = crypt_node();
    let responder = endpoint(3, 4700);
    solicit_hello_res(&mut node, responder, id(0xB0));

    let res = Kad2Message::HelloRes(hello(id(0xB0), responder, 7, MISC_OPTIONS_ACK_REQUEST))
        .encode()
        .encode();
    node.handle_datagram(T0, responder, &crypt_to_node(&res, 0, 0xD00D_F00D));
    let outputs = drain_outputs(&mut node);

    assert!(
        !opened_messages(&outputs, id(0xB0), Some(0xD00D_F00D))
            .iter()
            .any(|(_, m)| matches!(m, Kad2Message::HelloResAck { .. })),
        "the ACK-request bit is only honored from a v>=8 hello"
    );
}

#[test]
fn an_ack_request_and_its_0x22_ride_only_keyed_datagrams() {
    // ADR-0064: the ACK's whole proof is a key in the crypt trailer, so
    // neither leg may go out plaintext. A node without send-obfuscation has no
    // verify keys either, so it never asks for or answers a `0x22`.
    let peer = endpoint(7, 5000);
    let hello_req = Kad2Message::HelloReq(hello(id(0xC1), peer, 8, 0))
        .encode()
        .encode();

    // Role A, plaintext: no sender key to carry, so no bit.
    let mut plain = node();
    plain.handle_datagram(T0, peer, &hello_req);
    let sent = sent_messages(&drain_outputs(&mut plain));
    let [(_, Kad2Message::HelloRes(res))] = sent.as_slice() else {
        panic!("one plaintext hello res: {sent:?}");
    };
    assert_eq!(res.misc_options & MISC_OPTIONS_ACK_REQUEST, 0);

    // Role A, obfuscated: the bit rides a HELLO_RES NodeID-keyed to the
    // requester whose trailer carries our sender key for its IP.
    let mut crypt = crypt_node();
    crypt.handle_datagram(T0, peer, &hello_req);
    let sent = datagrams(&drain_outputs(&mut crypt));
    let [(_, wire)] = sent.as_slice() else {
        panic!("one hello res: {sent:?}");
    };
    let opened = decrypt_datagram_client(
        wire,
        &ClientDecryptKeys {
            kad_id: Some(id(0xC1).as_bytes()),
            ..Default::default()
        },
    )
    .expect("NodeID-keyed to the requester");
    assert_eq!(opened.sender_verify_key, Some(our_key_for(peer)));
    let KadDecoded::Plain(envelope) = decode_exact(&opened.payload).expect("an envelope") else {
        panic!("unpacked");
    };
    let Ok(Kad2Message::HelloRes(res)) = Kad2Message::decode(&envelope) else {
        panic!("a hello res");
    };
    assert_eq!(
        res.misc_options & MISC_OPTIONS_ACK_REQUEST,
        MISC_OPTIONS_ACK_REQUEST
    );

    // Role B, plaintext: a keyed ack-request draws no 0x22 from a node with
    // no keys to echo.
    let mut plain = node();
    let responder = endpoint(3, 4700);
    solicit_hello_res(&mut plain, responder, id(0xB0));
    let request = Kad2Message::HelloRes(hello(id(0xB0), responder, 8, MISC_OPTIONS_ACK_REQUEST))
        .encode()
        .encode();
    plain.handle_datagram(T0, responder, &crypt_to_node(&request, 0, 0xC0FF_EE01));
    assert!(
        !sent_messages(&drain_outputs(&mut plain))
            .iter()
            .any(|(_, m)| matches!(m, Kad2Message::HelloResAck { .. })),
        "no plaintext 0x22"
    );
}

// --- the port-53 sender-key exemption (ADR-0064 entry gate 1, activated) ------

#[test]
fn a_port_53_crypt_datagram_with_a_sender_key_is_processed() {
    // aMule's DNS-confusion guard drops a source-port-53 datagram only when it
    // carries no sender key (`KademliaUDPListener.cpp#L216`): a keyed datagram
    // is exempt. The plaintext-degenerate drop-all-port-53 posture ends once
    // keys are armed.
    let mut keyed = node();
    let dns_alike = endpoint(7, 53);
    let ping = Kad2Message::Ping.encode().encode();

    keyed.handle_datagram(T0, dns_alike, &crypt_to_node(&ping, 0, 0xB00F_B00F));
    let outputs = drain_outputs(&mut keyed);

    assert_eq!(
        sent_messages(&outputs),
        vec![(dns_alike, Kad2Message::Pong { udp_port: 53 })],
        "a keyed port-53 datagram is exempt from the DNS-confusion drop"
    );
    assert!(
        !diagnostics(&outputs)
            .iter()
            .any(|d| matches!(d, KadNodeDiagnostic::Port53Dropped { .. })),
        "no port-53 drop for a keyed datagram"
    );

    // The unkeyed control still drops — the guard itself stays.
    let mut unkeyed = node();
    unkeyed.handle_datagram(T0, dns_alike, &ping);
    let outputs = drain_outputs(&mut unkeyed);
    assert_eq!(
        diagnostics(&outputs),
        vec![KadNodeDiagnostic::Port53Dropped { from: dns_alike }],
        "an unkeyed port-53 datagram still drops"
    );
    assert!(datagrams(&outputs).is_empty());
}
