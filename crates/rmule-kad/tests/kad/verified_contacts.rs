//! The verified-contact cluster (ADR-0064) on the **plaintext** path:
//! the `0x22` state machine, misc-options emission, and verified-only serving
//! as they behave for a node with no verify-key state armed — the posture rmule
//! presents to a keyless aMule and to the deterministic mesh.
//!
//! Online verification is key-coupled, so on this path the `0x22` consume and
//! the receiver-key verify are consumed-but-never-verifying, role A never asks
//! (no sender key to carry) and role B stays silent for want of one. The keyed half — where `validReceiverKey`,
//! the completed three-way, and the narrowing to verified-only serving actually
//! fire — is `verify_keys.rs`. The live handshake against a real aMule is
//! ADR-0064 capture recipe 3: documented, not faked.

use rmule_kad::opcode::KADEMLIA2_HELLO_RES_ACK;
use rmule_kad::{
    Kad2Message, Kad2NodeInfo, KadCommand, KadEvent, KadNode, KadNodeConfig, KadNodeDiagnostic,
    KadNodeEndpoint, KadOutput, MISC_OPTIONS_ACK_REQUEST, decode_exact,
};
use rmule_testkit::kad_node::{
    NODE_ID, T0, crypt_node, diagnostics_of, drain_outputs, endpoint, hello, id, opened_messages,
};

fn node() -> KadNode {
    KadNode::new(KadNodeConfig {
        id: NODE_ID,
        tcp_port: 4662,
        udp_port: 4672,
        user_hash: rmule_kad::UserHash::from_bytes([0xEE; 16]),
    })
}

fn feed(node: &mut KadNode, from: KadNodeEndpoint, message: &Kad2Message) {
    node.handle_datagram(T0, from, &message.encode().encode());
}

fn drain(node: &mut KadNode) -> (Vec<Kad2Message>, Vec<KadEvent>) {
    let mut messages = Vec::new();
    let mut events = Vec::new();
    for output in rmule_primitives::session::drain(|| node.poll_output()) {
        match output {
            KadOutput::Datagram { bytes, .. } => {
                let rmule_kad::KadDecoded::Plain(envelope) =
                    decode_exact(&bytes).expect("plaintext emission decodes")
                else {
                    panic!("the node never packs outbound datagrams");
                };
                messages.push(Kad2Message::decode(&envelope).expect("valid outbound message"));
            }
            KadOutput::Event(event) => events.push(event),
        }
    }
    (messages, events)
}

#[test]
fn an_unsolicited_0x22_is_dropped_without_verifying() {
    let mut node = node();
    let stranger = endpoint(9, 6000);

    // No prior HELLO_RES asked this endpoint to verify: its 0x22 is unsolicited.
    feed(
        &mut node,
        stranger,
        &Kad2Message::HelloResAck { id: id(0x99) },
    );
    let (messages, events) = drain(&mut node);

    assert!(messages.is_empty(), "an unsolicited ACK draws no reply");
    assert_eq!(
        diagnostics_of(&events),
        vec![KadNodeDiagnostic::UnsolicitedHelloResAck { from: stranger }]
    );
}

#[test]
fn hello_res_ack_is_a_wire_round_trip_of_self_id_and_an_empty_tag_list() {
    // The <selfID16><tagcnt=0> shape aMule emits and consumes.
    let ack = Kad2Message::HelloResAck { id: id(0x5A) };
    let envelope = ack.encode();
    assert_eq!(envelope.opcode(), KADEMLIA2_HELLO_RES_ACK);
    assert_eq!(
        envelope.payload().len(),
        17,
        "16-byte ID + a zero tag count"
    );
    assert_eq!(envelope.payload()[16], 0, "empty tag list");
    assert_eq!(Kad2Message::decode(&envelope), Ok(ack));
}

// --- role A gates: version floor and HELLO_REQ parity -------------------------

#[test]
fn a_pre_v8_hello_is_not_asked_to_verify() {
    // aMule uses the (unimplemented) legacy challenge / v7 ping below v8, so no
    // misc-options ack-request is set toward such a contact (ADR-0064).
    // Keyed and obfuscating, so only the version floor can withhold the bit.
    let mut node = crypt_node();
    let peer = endpoint(7, 5000);

    feed(
        &mut node,
        peer,
        &Kad2Message::HelloReq(hello(id(0xC1), peer, 7, 0)),
    );
    let sent = opened_messages(&drain_outputs(&mut node), id(0xC1), None);
    let [(_, Kad2Message::HelloRes(res))] = sent.as_slice() else {
        panic!("one hello res");
    };
    assert_eq!(res.misc_options, 0, "no ack-request toward a v7 contact");
}

#[test]
fn our_hello_req_never_requests_an_ack() {
    // Parity: only HELLO_RES asks for a verify ACK; the probe HELLO_REQ we send
    // while bootstrapping carries no misc-options.
    let mut node = node();
    let responder = endpoint(3, 4700);
    node.handle_command(
        T0,
        KadCommand::Bootstrap {
            endpoint: responder,
        },
    );
    let _ = drain(&mut node);

    // The responder answers, so the node stores it and probes it with a HELLO_REQ.
    feed(
        &mut node,
        responder,
        &Kad2Message::BootstrapRes {
            sender: Kad2NodeInfo {
                id: id(0xB0),
                tcp_port: 4662,
                version: 8,
                udp_port_tag: None,
                misc_options: 0,
            },
            contacts: vec![],
        },
    );
    let (messages, _) = drain(&mut node);
    let hello_req = messages
        .iter()
        .find_map(|m| match m {
            Kad2Message::HelloReq(info) => Some(info),
            _ => None,
        })
        .expect("the node probes the responder with a HELLO_REQ");
    assert_eq!(
        hello_req.misc_options, 0,
        "a HELLO_REQ never requests an ack"
    );
}

// --- role B: answer an ACK request only with a sender key ---------------------

#[test]
fn a_solicited_hello_res_asking_us_to_verify_is_silent_without_a_sender_key() {
    // Role B: a responder set bit 2 (it wants us to prove our IP). We answer with
    // a 0x22 only when we hold a sender key to reply under; the plaintext mesh
    // carries none, so aMule's silent log-drop applies — no 0x22 on the wire.
    let mut node = node();
    let responder = endpoint(3, 4700);
    node.handle_command(
        T0,
        KadCommand::Bootstrap {
            endpoint: responder,
        },
    );
    let _ = drain(&mut node);
    feed(
        &mut node,
        responder,
        &Kad2Message::BootstrapRes {
            sender: Kad2NodeInfo {
                id: id(0xB0),
                tcp_port: 4662,
                version: 8,
                udp_port_tag: None,
                misc_options: 0,
            },
            contacts: vec![],
        },
    );
    let _ = drain(&mut node); // stores + probes the responder

    // The responder answers our probe with a HELLO_RES that requests an ACK.
    feed(
        &mut node,
        responder,
        &Kad2Message::HelloRes(hello(id(0xB0), responder, 8, MISC_OPTIONS_ACK_REQUEST)),
    );
    let (messages, events) = drain(&mut node);

    assert!(
        !messages
            .iter()
            .any(|m| matches!(m, Kad2Message::HelloResAck { .. })),
        "no 0x22 is emitted without a sender key to reply under: {messages:?}"
    );
    assert!(
        events.contains(&KadEvent::ContactResponded { id: id(0xB0) }),
        "the responder is still recorded live"
    );
}

// --- the servable gate at the node: the interim keeps lookups answerable ------

#[test]
fn a_node_with_only_unverified_contacts_still_answers_lookups_from_the_interim() {
    // The node-level zero-servable cliff: contacts learned over the plaintext
    // mesh are Responded-but-unverified, yet a KADEMLIA2_REQ must still be
    // answered from them (the interim) — gating never starves the lookup.
    let mut node = node();
    for host in [10u8, 20, 30] {
        let peer = endpoint(host, 5000 + u16::from(host));
        feed(
            &mut node,
            peer,
            &Kad2Message::HelloReq(hello(id(host), peer, 8, 0)),
        );
    }
    let _ = drain(&mut node);
    assert!(
        node.routing_table().contacts().all(|c| !c.verified()),
        "the seeded contacts are all unverified"
    );

    let target = id(0x11);
    feed(
        &mut node,
        endpoint(10, 5010),
        &Kad2Message::LookupReq {
            count: 3,
            target,
            check: NODE_ID,
        },
    );
    let (messages, _) = drain(&mut node);
    let [Kad2Message::LookupRes { contacts, .. }] = messages.as_slice() else {
        panic!("one lookup res: {messages:?}");
    };
    assert!(
        !contacts.is_empty(),
        "the servable interim answers the lookup rather than emptying it"
    );
    // (The narrowing to verified-only serving needs a contact that actually
    // verifies, which this unkeyed node has no path to; it is proven at the
    // routing level in `routing_table.rs` and end to end in `verify_keys.rs`.)
}
