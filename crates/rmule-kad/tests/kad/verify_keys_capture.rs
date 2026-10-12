//! The capture-anchored half of the verify-key cluster: a stock aMule 2.3.3
//! `0x22` and the `HELLO_REQ` that drew it, replayed byte-for-byte against
//! rmule's three-way. The bytes are evidence — never regenerated,
//! never hand-edited.

use std::net::Ipv4Addr;

use rmule_kad::{
    Kad2Message, KadEvent, KadId, KadNode, KadNodeEndpoint, KadObfuscation,
    MISC_OPTIONS_ACK_REQUEST, decode_exact, udp_verify_key,
};
use rmule_primitives::{ClientDecryptKeys, DatagramSenderAddress, decrypt_datagram_client};
use rmule_testkit::kad_node::{NODE_ID, T0, datagrams, drain_outputs, events, fixed_nonce, start};

/// The captured run's own facts (interop run `1785253158`, 2026-07-28). The
/// secret is rmule's private derivation seed for that run; it is what makes the
/// counterparty datagram — encrypted under the key rmule handed aMule —
/// decodable at all, so it is recorded rather than regenerated.
const CAPTURE_SECRET: u32 = 2_971_274_909;
const CAPTURE_RMULE_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 3);
const CAPTURE_AMULE_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 2);
const CAPTURE_AMULE_UDP_PORT: u16 = 4674;
/// aMule's pinned Kad ID in the flow-K topology; rmule's is its bitwise inverse
/// (`NODE_ID`, `0xAA…`), which is what this suite's `node()` already carries.
const CAPTURE_AMULE_ID: KadId = KadId::from_bytes([0x55; KadId::BYTE_LEN]);

fn capture_frame(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/verify_keys/captured/amule-233-hello-res-ack-20260728")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// The node as it ran on the bench: rmule's Kad ID, that run's verify-key state,
/// and send-obfuscation armed. Inbound decrypt is always on, so the captured
/// frames open against this node exactly as they did live.
fn capture_node() -> KadNode {
    KadNode::new(start().obfuscation(
        KadObfuscation::new(fixed_nonce).with_verify_keys(CAPTURE_SECRET, CAPTURE_RMULE_IP),
    ))
}

fn capture_peer() -> KadNodeEndpoint {
    KadNodeEndpoint::new(CAPTURE_AMULE_IP, CAPTURE_AMULE_UDP_PORT)
}

#[test]
fn the_captured_amule_hello_res_ack_decodes_as_self_id_and_no_tags() {
    let frame = capture_frame("hello_res_ack_0x22_crypt.bin");

    // MASKED, never an exact byte: aMule draws the marker's high bits at random
    // (`GetRandomUint8()`), so only the low two bits — the key-family index —
    // are a protocol fact. Family 2 is the receiver-key family: with no client
    // hash to key on, aMule encrypted the ACK under the key WE handed IT
    // (`EncryptSendClient`, `kadRecvKeyUsed`).
    assert_eq!(
        frame[0] & 0x03,
        2,
        "aMule keyed the ACK on our verify key, not on a Kad ID"
    );

    let our_key = udp_verify_key(CAPTURE_SECRET, CAPTURE_AMULE_IP);
    let decrypted = decrypt_datagram_client(
        &frame,
        &ClientDecryptKeys {
            kad_id: Some(NODE_ID.as_bytes()),
            receiver_verify_key: Some(our_key),
            sender: DatagramSenderAddress::V4(CAPTURE_AMULE_IP.octets()),
            ..Default::default()
        },
    )
    .expect("the ACK opens under the key rmule handed aMule");

    assert_eq!(
        decrypted.receiver_verify_key,
        Some(our_key),
        "aMule echoed our key back — this echo IS the IP proof (`validReceiverKey`)"
    );
    assert_ne!(
        decrypted.sender_verify_key,
        Some(0),
        "and handed us its own key for our address in the same trailer"
    );

    // `<selfID16><tagcnt1=0>` behind the `0xE4 0x22` envelope.
    let rmule_kad::KadDecoded::Plain(envelope) =
        decode_exact(&decrypted.payload).expect("the plaintext is a Kad envelope")
    else {
        panic!("a hello-res-ack is never packed");
    };
    assert_eq!(
        Kad2Message::decode(&envelope).expect("decodes"),
        Kad2Message::HelloResAck {
            id: CAPTURE_AMULE_ID
        },
        "aMule writes its own Kad ID and nothing else"
    );
    assert_eq!(
        decrypted.payload.len(),
        2 + KadId::BYTE_LEN + 1,
        "envelope + 16-byte ID + the single zero tag-count byte"
    );
    assert_eq!(
        *decrypted.payload.last().expect("non-empty"),
        0,
        "`WriteUInt8(0)` — no tags at this time"
    );
}

#[test]
fn a_flipped_byte_makes_the_captured_ack_undecodable() {
    // The vacuity guard: the decode above must not be something any 35 bytes
    // would satisfy. One flipped ciphertext byte desyncs the RC4 stream and the
    // datagram stops opening.
    let our_key = udp_verify_key(CAPTURE_SECRET, CAPTURE_AMULE_IP);
    let keys = |key: u32| ClientDecryptKeys {
        kad_id: Some(NODE_ID.as_bytes()),
        receiver_verify_key: Some(key),
        sender: DatagramSenderAddress::V4(CAPTURE_AMULE_IP.octets()),
        ..Default::default()
    };

    let mut flipped = capture_frame("hello_res_ack_0x22_crypt.bin");
    flipped[3] ^= 0x01;
    assert!(
        decrypt_datagram_client(&flipped, &keys(our_key)).is_none(),
        "a corrupted ACK fails the sync word instead of yielding a payload"
    );

    // And the key is load-bearing: the intact frame under a one-off secret opens
    // nothing, so the assertions above are about THIS run's handed-out key.
    assert!(
        decrypt_datagram_client(
            &capture_frame("hello_res_ack_0x22_crypt.bin"),
            &keys(udp_verify_key(
                CAPTURE_SECRET.wrapping_add(1),
                CAPTURE_AMULE_IP
            )),
        )
        .is_none(),
        "the ACK opens only under the key rmule actually handed this aMule"
    );
}

#[test]
fn the_captured_amule_hello_req_asks_nothing_and_hands_us_a_key() {
    // The datagram that opens the three-way. aMule sends it from its own routing
    // maintenance (`CRoutingZone::OnSmallTimer`) with `requestAckPacket = false`,
    // so the ACK request in this exchange is entirely rmule's — which is why the
    // capture needed rmule to be the RESPONDER.
    let frame = capture_frame("hello_req_0x11_crypt.bin");
    assert_eq!(
        frame[0] & 0x03,
        0,
        "keyed on our Kad ID: aMule knew the contact it was helloing"
    );

    let decrypted = decrypt_datagram_client(
        &frame,
        &ClientDecryptKeys {
            kad_id: Some(NODE_ID.as_bytes()),
            ..Default::default()
        },
    )
    .expect("the hello opens under our Kad ID");
    assert_eq!(
        decrypted.receiver_verify_key,
        Some(0),
        "aMule held no key for us — the `!validReceiverKey` half of the ACK-request gate"
    );
    assert_ne!(
        decrypted.sender_verify_key,
        Some(0),
        "but handed us one, which is what rmule must reply under"
    );

    let rmule_kad::KadDecoded::Plain(envelope) =
        decode_exact(&decrypted.payload).expect("a Kad envelope")
    else {
        panic!("a hello is never packed");
    };
    let Kad2Message::HelloReq(info) = Kad2Message::decode(&envelope).expect("decodes") else {
        panic!("expected a HELLO_REQ");
    };
    assert_eq!(info.id, CAPTURE_AMULE_ID);
    assert_eq!(info.version, 8, "KADEMLIA_VERSION 0x08 in aMule 2.3.3");
    assert_eq!(
        info.misc_options & MISC_OPTIONS_ACK_REQUEST,
        0,
        "a timer-driven hello never requests an ACK of its own"
    );
}

#[test]
fn replaying_the_capture_drives_rmules_whole_three_way() {
    // The live exchange, byte for byte: aMule's HELLO_REQ in, rmule's HELLO_RES
    // out (ACK-request bit + a sender key — the two things aMule demands before
    // it will answer), aMule's `0x22` in, contact verified.
    let mut node = capture_node();
    let peer = capture_peer();

    node.handle_datagram(T0, peer, &capture_frame("hello_req_0x11_crypt.bin"));
    let answered = drain_outputs(&mut node);

    let (to, reply) = datagrams(&answered)
        .into_iter()
        .next()
        .expect("rmule answers the hello");
    assert_eq!(to, peer);
    let reply = decrypt_datagram_client(
        &reply,
        &ClientDecryptKeys {
            kad_id: Some(CAPTURE_AMULE_ID.as_bytes()),
            ..Default::default()
        },
    )
    .expect("rmule answers under aMule's Kad ID, as aMule does");
    assert_eq!(
        reply.sender_verify_key,
        Some(udp_verify_key(CAPTURE_SECRET, CAPTURE_AMULE_IP)),
        "the sender key aMule needs; an empty one makes it log and drop"
    );
    let rmule_kad::KadDecoded::Plain(envelope) = decode_exact(&reply.payload).expect("envelope")
    else {
        panic!("never packed");
    };
    let Kad2Message::HelloRes(info) = Kad2Message::decode(&envelope).expect("decodes") else {
        panic!("expected a HELLO_RES");
    };
    assert_ne!(
        info.misc_options & MISC_OPTIONS_ACK_REQUEST,
        0,
        "rmule asks the fresh contact to prove its IP"
    );

    // 6 ms later on the wire — the captured ACK.
    node.handle_datagram(
        T0 + std::time::Duration::from_millis(6),
        peer,
        &capture_frame("hello_res_ack_0x22_crypt.bin"),
    );
    let verified = drain_outputs(&mut node);

    assert!(
        events(&verified).contains(&KadEvent::ContactVerified {
            id: CAPTURE_AMULE_ID
        }),
        "the counterparty's own ACK is what verifies it"
    );
}
