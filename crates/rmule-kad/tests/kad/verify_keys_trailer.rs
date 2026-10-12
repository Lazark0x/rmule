//! What makes a receiver key "valid" (ADR-0064): the trailer-driven
//! `validReceiverKey`, anchored on a genuine stock aMule 2.3.3 datagram that
//! pins why the judgement reads the **trailer** and not the key family that
//! decrypted the datagram.

use rmule_kad::{Kad2Message, KadEvent, KadNodeDiagnostic, MISC_OPTIONS_ACK_REQUEST};
use rmule_primitives::{
    ClientDecryptKeys, ClientEncryptKey, decrypt_datagram_client, encrypt_datagram_client,
};
use rmule_testkit::kad_node::{
    T0, crypt_node, crypt_to_node, diagnostics, drain_outputs, endpoint, events, fixed_nonce,
    hello, id, node, opened_messages, our_key_for,
};

/// Genuine stock aMule 2.3.3 obfuscated Kad datagram (interop flow K
/// `kad-firewalled-buddy --kad-crypt`, run 1785065651 — the Kad-crypt capture):
/// a crypt `KADEMLIA2_PING` (`0x60`, payload `e4 60`) — the fixture's
/// `hello_req` filename is a historical mislabel kept for provenance.
/// It pins the two trailer facts this whole cluster is built on, and they are
/// the reason `validReceiverKey` is judged from the **trailer** rather than
/// from which key family decrypted the datagram:
///
/// 1. aMule keyed this ping on rmule's **Kad ID** (marker family bits `0`) and
///    *still* carried a live verify-key trailer. A family-based
///    `validReceiverKey` would therefore reject the very datagrams the
///    verification model exists for.
/// 2. Its **sender key is nonzero** (aMule handing rmule a key to echo back)
///    while its **receiver key is zero** — rmule was plaintext at capture time,
///    so it had never handed aMule a key. That is exactly the
///    `IsEmpty`/no-key sentinel this code treats as "absent".
#[test]
fn a_genuine_amule_kad_datagram_carries_its_verify_key_trailer_on_the_node_id_family() {
    let frame = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "tests/fixtures/kad_crypt/captured/amule-233-kad-crypt-20260726/hello_req_0x60_crypt.bin",
    ))
    .expect("read captured aMule Kad crypt frame");

    assert_eq!(
        frame[0] & 0x03,
        0,
        "aMule keyed this datagram on our Kad ID (family bits 0)"
    );
    let decrypted = decrypt_datagram_client(
        &frame,
        &ClientDecryptKeys {
            kad_id: Some(&[0xAAu8; 16]),
            ..Default::default()
        },
    )
    .expect("rmule decrypts the genuine aMule frame");

    assert_eq!(
        decrypted.receiver_verify_key,
        Some(0),
        "aMule had been handed no key by plaintext rmule: the no-key sentinel"
    );
    let sender_key = decrypted
        .sender_verify_key
        .expect("a NodeID-keyed aMule datagram still carries the trailer");
    assert_ne!(
        sender_key, 0,
        "aMule hands out a real sender key for us to echo back"
    );
}

// --- the trailer: what makes a receiver key "valid" --------------------------

#[test]
fn only_the_echoed_receiver_key_verifies_a_hello_sender() {
    // aMule's `validReceiverKey` is `GetUDPVerifyKey(ip) == receiverVerifyKey`
    // (`ClientUDPSocket.cpp#L100`): the sender must echo the key WE handed IT,
    // proving it receives at the IP it claims. A crypt hello with the right
    // echo verifies on add; the same hello with a wrong echo does not.
    let peer = endpoint(7, 5000);
    let hello_req = Kad2Message::HelloReq(hello(id(0xC1), peer, 8, 0))
        .encode()
        .encode();

    let mut verified = crypt_node();
    verified.handle_datagram(
        T0,
        peer,
        &crypt_to_node(&hello_req, our_key_for(peer), 0xFEED_1111),
    );
    let outputs = drain_outputs(&mut verified);
    assert!(
        verified
            .routing_table()
            .get(id(0xC1))
            .expect("stored")
            .verified(),
        "an echoed receiver key proves the sender's IP: verified on add"
    );
    assert!(
        events(&outputs).contains(&KadEvent::ContactVerified { id: id(0xC1) }),
        "the verification is observable"
    );
    // aMule requests the ACK only when it could NOT verify (`addedOrUpdated &&
    // !validReceiverKey`) — a key-verified hello draws a plain HELLO_RES.
    let sent = opened_messages(&outputs, id(0xC1), None);
    let [(_, Kad2Message::HelloRes(res))] = sent.as_slice() else {
        panic!("one hello res");
    };
    assert_eq!(
        res.misc_options & MISC_OPTIONS_ACK_REQUEST,
        0,
        "an already-verified sender is not asked for a 0x22"
    );

    // Wrong echo (a key for some other IP): no verification, ACK requested.
    let mut spoofed = crypt_node();
    spoofed.handle_datagram(
        T0,
        peer,
        &crypt_to_node(&hello_req, our_key_for(endpoint(200, 5000)), 0xFEED_1111),
    );
    let outputs = drain_outputs(&mut spoofed);
    assert!(
        !spoofed
            .routing_table()
            .get(id(0xC1))
            .expect("stored")
            .verified(),
        "a receiver key we never handed this IP proves nothing"
    );
    let sent = opened_messages(&outputs, id(0xC1), None);
    let [(_, Kad2Message::HelloRes(res))] = sent.as_slice() else {
        panic!("one hello res");
    };
    assert_eq!(
        res.misc_options & MISC_OPTIONS_ACK_REQUEST,
        MISC_OPTIONS_ACK_REQUEST,
        "an unverified sender is asked to complete the three-way"
    );
}

#[test]
fn an_unarmed_node_never_treats_a_trailer_as_a_valid_receiver_key() {
    // Without the key state there is no derivation to compare against, so
    // nothing can verify. Both shapes matter: a crypt datagram with a plausible
    // trailer, and — the sharper trap — a *plaintext* datagram, whose absent
    // trailer must not read as "matches our absent key".
    let peer = endpoint(7, 5000);
    let hello_req = Kad2Message::HelloReq(hello(id(0xC1), peer, 8, 0))
        .encode()
        .encode();

    for wire in [
        crypt_to_node(&hello_req, 0xDEAD_BEEF, 0xFEED_1111),
        hello_req.clone(),
    ] {
        let mut node = node();
        node.handle_datagram(T0, peer, &wire);
        let _ = drain_outputs(&mut node);
        assert!(
            !node
                .routing_table()
                .get(id(0xC1))
                .expect("stored")
                .verified(),
            "an unarmed node cannot verify anything"
        );
    }
}

#[test]
fn a_plaintext_datagram_never_reads_as_a_valid_receiver_key() {
    // The same trap on an *armed* node: a plaintext hello has no trailer at
    // all, and "no trailer" must never compare equal to our derived key. If it
    // did, every legacy peer would be trusted as IP-proven for free — the exact
    // spoofing the flag exists to stop.
    let mut node = crypt_node();
    let peer = endpoint(7, 5000);
    node.handle_datagram(
        T0,
        peer,
        &Kad2Message::HelloReq(hello(id(0xC1), peer, 8, 0))
            .encode()
            .encode(),
    );
    let _ = drain_outputs(&mut node);
    assert!(
        !node
            .routing_table()
            .get(id(0xC1))
            .expect("stored")
            .verified(),
        "a plaintext hello proves no IP"
    );
}

#[test]
fn a_peer_holding_only_our_handed_out_key_can_reach_us() {
    // The `KadVerifyKey` decrypt family (marker bits 2): a contact that lost our
    // Kad ID but kept the verify key we handed it still reaches us — aMule's
    // `currentTry == 2` receiver-key branch
    // (`EncryptedDatagramSocket.cpp#L191`). Without the family armed on the
    // receive side, such a datagram is undecodable garbage.
    let mut armed = crypt_node();
    let peer = endpoint(7, 5000);
    let ping = Kad2Message::Ping.encode().encode();
    let wire = encrypt_datagram_client(
        &ping,
        &ClientEncryptKey::KadVerify {
            verify_key: our_key_for(peer),
            receiver_verify_key: our_key_for(peer),
            sender_verify_key: 0xFEED_1111,
        },
        &fixed_nonce(),
    );

    armed.handle_datagram(T0, peer, &wire);
    let outputs = drain_outputs(&mut armed);

    assert_eq!(
        opened_messages(&outputs, id(7), Some(0xFEED_1111)),
        vec![(peer, Kad2Message::Pong { udp_port: 5000 })],
        "a receiver-key-keyed datagram decrypts and dispatches"
    );

    // An unarmed node offers no such family: the same bytes are undecodable.
    let mut unarmed = node();
    unarmed.handle_datagram(T0, peer, &wire);
    let outputs = drain_outputs(&mut unarmed);
    assert!(
        diagnostics(&outputs)
            .iter()
            .any(|d| matches!(d, KadNodeDiagnostic::UndecodableEnvelope { .. })),
        "without the key state the receiver-key family is not offered"
    );
}

/// aMule tries the receiver-verify-key family on every client datagram
/// whatever its own crypt setting (`EncryptedDatagramSocket.cpp:187-195`), so
/// a node that went plaintext keeps opening datagrams a peer keyed on the
/// verify key it was handed earlier. A receive-only node (policy `off`) opens
/// a hello keyed on that family, verifies the sender from the echoed key, and
/// answers in plaintext.
#[test]
fn a_receive_only_node_opens_a_datagram_keyed_on_the_verify_key_it_handed_out() {
    use rmule_kad::KadObfuscation;
    use rmule_primitives::DatagramNonce;
    use rmule_testkit::kad_node::{OWN_IP, SECRET, start};

    let peer = endpoint(7, 5000);
    let hello_req = Kad2Message::HelloReq(hello(id(0xC1), peer, 8, 0))
        .encode()
        .encode();
    let handed = our_key_for(peer);
    let keyed = encrypt_datagram_client(
        &hello_req,
        &ClientEncryptKey::KadVerify {
            verify_key: handed,
            receiver_verify_key: handed,
            sender_verify_key: 0,
        },
        &DatagramNonce {
            marker_byte: 0x42,
            random_key: 0x1357,
            padding: vec![],
        },
    );

    let mut off =
        rmule_kad::KadNode::new(start().obfuscation(KadObfuscation::receive_only(SECRET, OWN_IP)));
    off.handle_datagram(T0, peer, &keyed);
    let outputs = drain_outputs(&mut off);

    assert!(
        off.routing_table()
            .get(id(0xC1))
            .is_some_and(|c| c.verified()),
        "the hello was opened and its echoed key verified the sender"
    );
    let sent = opened_messages(&outputs, id(0xC1), None);
    assert!(
        matches!(sent.as_slice(), [(_, Kad2Message::HelloRes(_))]),
        "the answer left, and opens as plaintext"
    );

    let mut keyless = node();
    keyless.handle_datagram(T0, peer, &keyed);
    assert!(
        keyless.routing_table().get(id(0xC1)).is_none(),
        "a node holding no verify keys cannot open the same datagram"
    );
}
