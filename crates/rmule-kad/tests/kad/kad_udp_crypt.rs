//! Kad-UDP per-datagram obfuscation integration (ADR-0046).
//!
//! The sans-I/O node's crypt surface, exercised end to end against the
//! datagram-crypt primitive (`rmule_primitives::datagram_obfuscation`):
//!
//! - **Dual-path receive** (always on, aMule `DecryptReceivedClient`): a crypt
//!   datagram keyed on this node's own Kad ID decrypts and dispatches exactly
//!   as its plaintext twin; a plaintext datagram still dispatches; garbage that
//!   neither decrypts nor decodes is rejected.
//! - **Send-encrypt** (capture-gated off by default): once
//!   enabled, an outbound datagram to a *known contact* of version ≥ 6 is
//!   RC4-encrypted keyed on that contact's Kad ID, and the recipient recovers
//!   the exact plaintext with its *own* Kad ID — aMule's symmetric key choice.
//!   Pre-crypt (v<6) contacts stay plaintext; handler replies that carry a
//!   dispatch key ride the receiver-key family instead (`verify_keys.rs`).
//!
//! These are the deterministic-tier integration KATs. The datagram byte scheme
//! itself is `[pending]` until an ADR-0046 Kad-crypt capture ratifies the wire
//! bytes (see docs/reference/notes/obfuscation.md, "Kad-UDP crypt capture
//! recipe"); a mesh-sim / FakeKadPeer vector is rmule-authored and can never
//! prove the gate, so no captured vector is fabricated here.

use rmule_kad::{
    Kad2Message, Kad2NodeInfo, KadEvent, KadId, KadNode, KadNodeConfig, KadNodeDiagnostic,
    KadNodeEndpoint, KadOutput, decode_exact,
};
use rmule_primitives::{
    ClientDecryptKeys, ClientEncryptKey, UserHash, decrypt_datagram_client,
    encrypt_datagram_client, is_udp_plaintext_marker,
};
use rmule_testkit::kad_node::{T0, datagrams, endpoint, fixed_nonce, id};

fn node_with_id(node_id: KadId) -> KadNode {
    KadNode::new(KadNodeConfig {
        id: node_id,
        tcp_port: 4662,
        udp_port: 4672,
        user_hash: UserHash::from_bytes([0xEE; 16]),
    })
}

/// Encrypt a plaintext Kad datagram for `recipient_id` under the KadNodeId
/// family — exactly what a peer holding our Kad ID would put on the wire.
fn crypt_to(recipient_id: KadId, plain: &[u8]) -> Vec<u8> {
    encrypt_datagram_client(
        plain,
        &ClientEncryptKey::KadNode {
            kad_id: recipient_id.as_bytes(),
            receiver_verify_key: 0,
            sender_verify_key: 0,
        },
        &fixed_nonce(),
    )
}

fn drain(node: &mut KadNode) -> Vec<KadOutput> {
    rmule_primitives::session::drain(|| node.poll_output())
}

fn sent_messages(outputs: &[KadOutput]) -> Vec<(KadNodeEndpoint, Kad2Message)> {
    outputs
        .iter()
        .filter_map(|output| match output {
            KadOutput::Datagram { to, bytes } => {
                let rmule_kad::KadDecoded::Plain(envelope) =
                    decode_exact(bytes).expect("plaintext emission decodes")
                else {
                    panic!("the node never packs outbound datagrams");
                };
                Some((*to, Kad2Message::decode(&envelope).expect("valid message")))
            }
            KadOutput::Event(_) => None,
        })
        .collect()
}

fn diagnostics(outputs: &[KadOutput]) -> Vec<KadNodeDiagnostic> {
    outputs
        .iter()
        .filter_map(|output| match output {
            KadOutput::Event(KadEvent::Diagnostic(diagnostic)) => Some(*diagnostic),
            _ => None,
        })
        .collect()
}

// --- dual-path receive -------------------------------------------------------

#[test]
fn crypt_ping_decrypts_and_dispatches_like_a_plaintext_ping() {
    let node_id = id(0xAA);
    let peer = endpoint(7, 5000);
    let plain_ping = Kad2Message::Ping.encode().encode();

    // Plaintext baseline: a ping draws a pong echoing the observed UDP port.
    let mut base = node_with_id(node_id);
    base.handle_datagram(T0, peer, &plain_ping);
    let baseline = sent_messages(&drain(&mut base));

    // Crypt path: the same ping, RC4-wrapped keyed on the node's own Kad ID.
    let wrapped = crypt_to(node_id, &plain_ping);
    assert!(
        !is_udp_plaintext_marker(wrapped[0]),
        "the wrapper is obfuscated"
    );
    let mut node = node_with_id(node_id);
    node.handle_datagram(T0, peer, &wrapped);
    let crypt = sent_messages(&drain(&mut node));

    assert_eq!(
        crypt, baseline,
        "a crypt ping drives the identical pong as its plaintext twin"
    );
    assert_eq!(
        crypt,
        vec![(
            peer,
            Kad2Message::Pong {
                udp_port: peer.udp_port()
            }
        )]
    );
}

#[test]
fn crypt_bootstrap_req_is_transparent_to_the_responder() {
    let node_id = id(0xAA);
    let peer = endpoint(9, 6000);
    let plain = Kad2Message::BootstrapReq.encode().encode();

    let mut base = node_with_id(node_id);
    base.handle_datagram(T0, peer, &plain);
    let baseline = sent_messages(&drain(&mut base));

    let mut node = node_with_id(node_id);
    node.handle_datagram(T0, peer, &crypt_to(node_id, &plain));
    let crypt = sent_messages(&drain(&mut node));

    assert_eq!(
        crypt, baseline,
        "crypt bootstrap draws the same bootstrap res"
    );
    assert!(
        matches!(crypt.as_slice(), [(to, Kad2Message::BootstrapRes { .. })] if *to == peer),
        "the responder answers a bootstrap res either way"
    );
}

#[test]
fn a_datagram_keyed_on_a_foreign_kad_id_is_not_for_us_and_is_rejected() {
    // Encrypted for someone else's Kad ID: our own-ID trial decrypt misses, the
    // bytes are not plaintext Kad, so the envelope decode rejects them and no
    // reply is drawn — aMule's "decrypt failed, not one of ours" drop.
    let mut node = node_with_id(id(0xAA));
    let for_someone_else = crypt_to(id(0x55), &Kad2Message::Ping.encode().encode());

    node.handle_datagram(T0, endpoint(7, 5000), &for_someone_else);
    let outputs = drain(&mut node);

    assert_eq!(datagrams(&outputs), Vec::new(), "not-for-us draws no reply");
    assert!(matches!(
        diagnostics(&outputs).as_slice(),
        [KadNodeDiagnostic::UndecodableEnvelope { .. }]
    ));
}

#[test]
fn garbage_that_neither_decrypts_nor_decodes_is_rejected() {
    let mut node = node_with_id(id(0xAA));
    // A non-plaintext-marker first byte whose body cannot validate the sync
    // word under our Kad ID key, and is not a Kad protocol byte either.
    let garbage: Vec<u8> = (0u8..40)
        .map(|i| i.wrapping_mul(37).wrapping_add(3))
        .collect();
    assert!(!is_udp_plaintext_marker(garbage[0]));

    node.handle_datagram(T0, endpoint(7, 5000), &garbage);
    let outputs = drain(&mut node);

    assert_eq!(datagrams(&outputs), Vec::new(), "garbage draws no reply");
    assert!(matches!(
        diagnostics(&outputs).as_slice(),
        [KadNodeDiagnostic::UndecodableEnvelope { .. }]
    ));
}

// --- send-encrypt ------------------------------------------------------------

#[test]
fn send_encrypt_keys_on_the_recipient_kad_id_and_round_trips_to_the_plaintext() {
    let node_id = id(0xAA);
    let recipient_id = id(0xC1);
    let peer = endpoint(7, 5000);
    let hello_req = Kad2Message::HelloReq(Kad2NodeInfo {
        id: recipient_id,
        tcp_port: 4662,
        version: 8,
        udp_port_tag: Some(peer.udp_port()),
        misc_options: 0,
    })
    .encode()
    .encode();

    // Plaintext baseline: the hello res the node emits with send-crypt off.
    let mut base = node_with_id(node_id);
    base.handle_datagram(T0, peer, &hello_req);
    let baseline = datagrams(&drain(&mut base));
    let [(base_to, plain_res)] = baseline.as_slice() else {
        panic!("exactly one hello res");
    };
    assert_eq!(*base_to, peer);
    assert_eq!(
        plain_res[0], 0xE4,
        "the baseline hello res is plaintext Kad"
    );

    // Send-crypt on: the node stores the requester (Responded) then replies; the
    // requester is now a known contact, so the res is encrypted keyed on its
    // Kad ID (aMule keys the send on the target's client ID).
    let mut node = node_with_id(node_id);
    node.enable_datagram_obfuscation(fixed_nonce);
    node.handle_datagram(T0, peer, &hello_req);
    let sent = datagrams(&drain(&mut node));
    let [(to, crypt_res)] = sent.as_slice() else {
        panic!("exactly one hello res");
    };
    assert_eq!(*to, peer);
    assert!(
        !matches!(crypt_res[0], 0xE4 | 0xE5),
        "the reply is obfuscated, not a plaintext Kad datagram"
    );

    // The recipient decrypts with its OWN Kad ID and recovers exactly the
    // plaintext hello res the baseline emitted.
    let recovered = decrypt_datagram_client(
        crypt_res,
        &ClientDecryptKeys {
            kad_id: Some(recipient_id.as_bytes()),
            ..Default::default()
        },
    )
    .expect("recipient decrypts with its own Kad ID");
    assert_eq!(
        &recovered.payload, plain_res,
        "the decrypted payload is byte-identical to the plaintext hello res"
    );

    // A different Kad ID key does not recover it: the family is keyed.
    assert!(
        decrypt_datagram_client(
            crypt_res,
            &ClientDecryptKeys {
                kad_id: Some(id(0x99).as_bytes()),
                ..Default::default()
            },
        )
        .is_none(),
        "the wrong Kad ID cannot decrypt the datagram"
    );
}

#[test]
fn send_encrypt_leaves_datagrams_to_strangers_plaintext() {
    // A ping from an unknown endpoint draws a pong, but the endpoint is not a
    // stored contact, so there is no key to obfuscate toward — plaintext, like
    // aMule, which only obfuscates toward a contact whose key it holds.
    let mut node = node_with_id(id(0xAA));
    node.enable_datagram_obfuscation(fixed_nonce);

    node.handle_datagram(T0, endpoint(7, 5000), &Kad2Message::Ping.encode().encode());
    let sent = drain(&mut node);

    // `sent_messages` decodes as plaintext; that it succeeds and yields the pong
    // is itself proof the reply was not obfuscated.
    assert_eq!(
        sent_messages(&sent),
        vec![(endpoint(7, 5000), Kad2Message::Pong { udp_port: 5000 })],
    );
    let out = datagrams(&sent);
    let [(_, pong)] = out.as_slice() else {
        panic!("exactly one pong");
    };
    assert_eq!(pong[0], 0xE4, "a reply to a stranger stays plaintext");
}

#[test]
fn send_encrypt_stays_plaintext_toward_a_pre_crypt_contact() {
    // aMule never encrypts toward a contact below Kad version 6 — obfuscation
    // shipped with v6 (eMule 0.49a), and `SendMyDetails` sends the sub-v6 leg
    // plaintext, asserting `targetKey.IsEmpty()`
    // (`KademliaUDPListener.cpp#L152`); `SendNullPacket` and `Bootstrap` gate
    // on the same `>= 6`. A v5 peer handed an RC4 datagram could never decrypt
    // it, so even with send-crypt armed the answer to a stored v5 contact must
    // stay plaintext.
    let peer = endpoint(7, 5000);
    let hello_req = Kad2Message::HelloReq(Kad2NodeInfo {
        id: id(0xC1),
        tcp_port: 4662,
        version: 5, // the newest pre-crypt version
        udp_port_tag: Some(peer.udp_port()),
        misc_options: 0,
    })
    .encode()
    .encode();

    let mut node = node_with_id(id(0xAA));
    node.enable_datagram_obfuscation(fixed_nonce);
    node.handle_datagram(T0, peer, &hello_req);
    let sent = datagrams(&drain(&mut node));
    let [(to, res)] = sent.as_slice() else {
        panic!("exactly one hello res");
    };
    assert_eq!(*to, peer);
    assert_eq!(
        res[0], 0xE4,
        "a v5 contact predates the crypt layer: the reply stays plaintext"
    );
}

#[test]
fn send_crypt_is_off_by_default_so_the_node_stays_byte_for_byte_plaintext() {
    // The default (capture-gated) posture: even a reply to a known contact is
    // plaintext until send-obfuscation is explicitly enabled.
    let node_id = id(0xAA);
    let peer = endpoint(7, 5000);
    let hello_req = Kad2Message::HelloReq(Kad2NodeInfo {
        id: id(0xC1),
        tcp_port: 4662,
        version: 8,
        udp_port_tag: Some(peer.udp_port()),
        misc_options: 0,
    })
    .encode()
    .encode();

    let mut node = node_with_id(node_id);
    node.handle_datagram(T0, peer, &hello_req);
    let sent = datagrams(&drain(&mut node));

    let [(_, res)] = sent.as_slice() else {
        panic!("exactly one hello res");
    };
    assert_eq!(
        res[0], 0xE4,
        "no obfuscation without enable_datagram_obfuscation"
    );
}

/// Genuine stock aMule 2.3.3 obfuscated Kad datagram (interop flow K
/// `kad-firewalled-buddy --kad-crypt`, run 1785065651). aMule armed Kad
/// obfuscation and sent this `KADEMLIA2_PING` encrypted to rmule's all-`0xAA`
/// Kad ID. It is the ratification vector for ADR-0046's `[pending]` byte
/// facts: rmule's dual-path receive must decrypt a REAL aMule crypt datagram,
/// not just its own encrypt. Regression guard for the crypt-sync endianness
/// (rmule framed it big-endian; aMule writes it little-endian).
#[test]
fn decrypts_a_genuine_amule_2_3_3_kad_crypt_datagram() {
    let frame = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "tests/fixtures/kad_crypt/captured/amule-233-kad-crypt-20260726/hello_req_0x60_crypt.bin",
    ))
    .expect("read captured aMule Kad crypt frame");

    let rmule_kad_id = [0xAAu8; 16];
    let decrypted = decrypt_datagram_client(
        &frame,
        &ClientDecryptKeys {
            kad_id: Some(&rmule_kad_id),
            ..Default::default()
        },
    )
    .expect("rmule must decrypt a genuine aMule KadID-keyed crypt datagram");

    // The recovered plaintext is a bare KADEMLIA2_PING: proto 0xE4, opcode 0x60.
    assert_eq!(
        decrypted.payload.as_slice(),
        &[0xE4, 0x60],
        "decrypted payload is the plaintext KADEMLIA2_PING"
    );
}
