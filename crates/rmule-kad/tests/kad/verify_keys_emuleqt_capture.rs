//! The emule-qt half of the `0x22` three-way, anchored on the capture
//! (run `1790251066`): emule-qt keys its ack-request, and an ACK
//! only counts when it echoes that key. The bytes are evidence — never
//! regenerated, never hand-edited.

use std::net::Ipv4Addr;

use rmule_kad::{
    Kad2Message, Kad2NodeInfo, KadDecoded, KadInstant, KadNode, KadNodeConfig, KadNodeEndpoint,
    KadNodeStart, KadObfuscation, MISC_OPTIONS_ACK_REQUEST, decode_exact,
};
use rmule_primitives::{ClientDecryptKeys, DatagramSenderAddress, decrypt_datagram_client};
use rmule_testkit::kad_node::{T0, datagrams, drain_outputs, fixed_nonce, solicit_hello_res};

const RMULE_IP: Ipv4Addr = Ipv4Addr::new(45, 55, 200, 6);
const EMULEQT: KadNodeEndpoint = KadNodeEndpoint::new(Ipv4Addr::new(45, 55, 200, 10), 4672);

fn capture_frame(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/verify_keys/captured/emule-qt-73fff714-hello-res-ack-20260924")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn plain_message(bytes: &[u8]) -> Kad2Message {
    let KadDecoded::Plain(envelope) = decode_exact(bytes).expect("a Kad envelope") else {
        panic!("unpacked");
    };
    Kad2Message::decode(&envelope).expect("a Kad2 message")
}

fn hello_res(message: Kad2Message) -> Kad2NodeInfo {
    let Kad2Message::HelloRes(info) = message else {
        panic!("a HELLO_RES: {message:?}");
    };
    info
}

#[test]
fn emule_qt_keys_its_ack_request_so_only_a_keyed_0x22_can_answer_it() {
    // Pre-fix rmule: a plaintext HELLO_RES asking for an ACK (emule-qt: "demands
    // an ACK but sent no sender key") ...
    let rmule_res = capture_frame("rmule_hello_res_0x19_plain.bin");
    assert_eq!(rmule_res[0], 0xE4, "plaintext: no trailer, no sender key");
    let rmule = hello_res(plain_message(&rmule_res));
    assert_eq!(
        rmule.misc_options & MISC_OPTIONS_ACK_REQUEST,
        MISC_OPTIONS_ACK_REQUEST
    );

    // ... and a plaintext 0x22 (emule-qt: "invalid receiver key — dropped").
    let rmule_ack = capture_frame("rmule_hello_res_ack_0x22_plain.bin");
    assert_eq!(rmule_ack[0], 0xE4, "plaintext: no receiver key to echo");
    assert_eq!(
        plain_message(&rmule_ack),
        Kad2Message::HelloResAck { id: rmule.id }
    );

    // The reference shape: emule-qt's own ack-request rides a NodeID-keyed
    // datagram whose trailer carries its sender key.
    let qt_res = capture_frame("emuleqt_hello_res_0x19_crypt.bin");
    let opened = decrypt_datagram_client(
        &qt_res,
        &ClientDecryptKeys {
            kad_id: Some(rmule.id.as_bytes()),
            sender: DatagramSenderAddress::V4(EMULEQT.ip().octets()),
            ..Default::default()
        },
    )
    .expect("emule-qt keyed its HELLO_RES on rmule's Kad ID");
    let qt_key = opened.sender_verify_key.expect("a Kad trailer");
    assert_ne!(
        qt_key, 0,
        "emule-qt never asks for an ACK without a sender key"
    );
    let qt = hello_res(plain_message(&opened.payload));
    assert_eq!(
        qt.misc_options & MISC_OPTIONS_ACK_REQUEST,
        MISC_OPTIONS_ACK_REQUEST
    );

    // Replayed into rmule as it ran (rmule's Kad ID): with
    // send-obfuscation off (and so no verify keys) there is no 0x22 at all; with it on, the 0x22's
    // receiver slot echoes emule-qt's key — its `validReceiverKey`.
    let ack_for = |obfuscate: bool| {
        let start = KadNodeStart::new(
            KadNodeConfig {
                id: rmule.id,
                tcp_port: 4662,
                udp_port: 4672,
                user_hash: rmule_kad::UserHash::from_bytes([0xEE; 16]),
            },
            KadInstant::EPOCH,
        );
        let start = if obfuscate {
            start.obfuscation(
                KadObfuscation::new(fixed_nonce).with_verify_keys(0x4981_0498, RMULE_IP),
            )
        } else {
            start
        };
        let mut node = KadNode::new(start);
        solicit_hello_res(&mut node, EMULEQT, qt.id);
        node.handle_datagram(T0, EMULEQT, &qt_res);
        datagrams(&drain_outputs(&mut node))
            .into_iter()
            .filter_map(|(to, wire)| {
                let opened = decrypt_datagram_client(
                    &wire,
                    &ClientDecryptKeys {
                        receiver_verify_key: Some(qt_key),
                        ..Default::default()
                    },
                );
                let payload = opened.as_ref().map_or(wire.as_slice(), |o| &o.payload);
                matches!(plain_message(payload), Kad2Message::HelloResAck { .. })
                    .then(|| (to, opened.and_then(|o| o.receiver_verify_key)))
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(ack_for(false), vec![], "no plaintext 0x22");
    assert_eq!(ack_for(true), vec![(EMULEQT, Some(qt_key))]);
}
