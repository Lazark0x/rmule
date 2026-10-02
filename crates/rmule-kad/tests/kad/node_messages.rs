//! Typed Kad2 node-message codecs against genuine captured aMule datagrams,
//! and the datagram boundary underneath them: a packed datagram must behave
//! exactly like its plain twin, and an undecodable one must produce a
//! diagnostic and no state change.
//!
//! Every `captured_*` test decodes a real aMule 2.3.3 emission from
//! `fixtures/node/captured/private-amule-kad-node-messages-20260707/` (see its
//! `metadata.toml` for provenance) or from the routing-distance fixture, so the
//! codec is aMule-compatible by construction, not just round-trip-consistent.

use std::net::Ipv4Addr;

use rmule_kad::{
    Kad2Message, Kad2MessageDecodeError, Kad2NodeInfo, KadContact, KadDecoded, KadEnvelope, KadId,
    KadNodeDiagnostic, KadNodeEndpoint, MISC_OPTIONS_ACK_REQUEST, MISC_OPTIONS_TCP_FIREWALLED,
    decode_exact,
};
use rmule_primitives::session::drain;
use rmule_testkit::kad_node::{T0, diagnostics, endpoint, node, sent_messages};

macro_rules! node_fixture {
    ($name:literal) => {
        include_bytes!(concat!(
            "../fixtures/node/captured/private-amule-kad-node-messages-20260707/",
            $name
        ))
    };
}

const BOOTSTRAP_REQ: &[u8] = node_fixture!("bootstrap_req_0x01.bin");
const BOOTSTRAP_RES: &[u8] = node_fixture!("bootstrap_res_0x09.bin");
const BOOTSTRAP_RES_EMPTY: &[u8] = node_fixture!("bootstrap_res_empty_0x09.bin");
const HELLO_REQ: &[u8] = node_fixture!("hello_req_0x11.bin");
const HELLO_RES: &[u8] = node_fixture!("hello_res_0x19.bin");
const HELLO_RES_MIN: &[u8] = node_fixture!("hello_res_min_0x19.bin");
const PING: &[u8] = node_fixture!("ping_0x60.bin");
const PONG: &[u8] = node_fixture!("pong_0x61.bin");

const LOOKUP_REQ: &[u8] = include_bytes!(
    "../fixtures/routing/captured/private-amule-kad-distance-20260707/request_0x21.bin"
);
const LOOKUP_RES: &[u8] = include_bytes!(
    "../fixtures/routing/captured/private-amule-kad-distance-20260707/result_0x29.bin"
);

fn decode(datagram: &[u8]) -> Result<Kad2Message, Kad2MessageDecodeError> {
    let KadDecoded::Plain(envelope) = decode_exact(datagram).expect("fixture envelope") else {
        panic!("all node-message fixtures are plain 0xE4");
    };
    Kad2Message::decode(&envelope)
}

fn id(hex_bytes: [u8; 16]) -> KadId {
    KadId::from_bytes(hex_bytes)
}

#[test]
fn captured_bootstrap_req_is_an_empty_payload() {
    assert_eq!(decode(BOOTSTRAP_REQ), Ok(Kad2Message::BootstrapReq));
}

#[test]
fn captured_bootstrap_res_decodes_sender_and_contact_rows() {
    let Ok(Kad2Message::BootstrapRes { sender, contacts }) = decode(BOOTSTRAP_RES) else {
        panic!("expected a bootstrap response");
    };

    assert_eq!(
        sender,
        Kad2NodeInfo {
            id: id([
                0xb5, 0x2d, 0x30, 0x8e, 0x5c, 0xa2, 0x06, 0xb8, 0x23, 0xfc, 0x85, 0x93, 0xd2, 0x62,
                0x10, 0xf2
            ]),
            tcp_port: 4662,
            version: 8,
            udp_port_tag: None,
            // A bootstrap-response header carries no tag list.
            misc_options: 0,
        }
    );

    let rows: Vec<(KadId, Ipv4Addr, u16, u16, u8)> = contacts
        .iter()
        .map(|c| {
            (
                c.id(),
                c.endpoint().ip(),
                c.endpoint().udp_port(),
                c.tcp_port(),
                c.version(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        vec![
            (
                id([
                    0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad,
                    0xae, 0xaf, 0xb0
                ]),
                Ipv4Addr::new(172, 30, 0, 2),
                4672,
                4662,
                8
            ),
            (
                id([
                    0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
                    0xce, 0xcf, 0xd0
                ]),
                Ipv4Addr::new(172, 30, 0, 3),
                4673,
                4662,
                8
            ),
        ]
    );
}

#[test]
fn captured_bootstrap_res_with_zero_contacts_decodes() {
    let Ok(Kad2Message::BootstrapRes { contacts, .. }) = decode(BOOTSTRAP_RES_EMPTY) else {
        panic!("expected a bootstrap response");
    };
    assert!(contacts.is_empty());
}

#[test]
fn captured_hello_req_decodes_sender_info_udp_port_and_misc_options() {
    // The captured HELLO_REQ carries misc-options 0x02 — the capturing aMule node
    // was TCP-firewalled (bit 1). A request never sets the ack-request bit.
    assert_eq!(
        decode(HELLO_REQ),
        Ok(Kad2Message::HelloReq(Kad2NodeInfo {
            id: id([
                0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce,
                0xcf, 0xd0
            ]),
            tcp_port: 4662,
            version: 8,
            udp_port_tag: Some(4673),
            misc_options: MISC_OPTIONS_TCP_FIREWALLED,
        }))
    );
}

#[test]
fn captured_hello_res_decodes_misc_options_ack_request() {
    // The captured HELLO_RES carries misc-options 0x04 — the ack-request bit
    // (bit 2), aMule asking the peer to prove its IP via a 0x22 (ADR-0064).
    assert_eq!(
        decode(HELLO_RES),
        Ok(Kad2Message::HelloRes(Kad2NodeInfo {
            id: id([
                0x31, 0xd2, 0x15, 0x51, 0xc6, 0x13, 0x0e, 0xc7, 0xc2, 0xa0, 0xa7, 0x7b, 0x73, 0x21,
                0xd5, 0x8b
            ]),
            tcp_port: 4662,
            version: 8,
            udp_port_tag: Some(4674),
            misc_options: MISC_OPTIONS_ACK_REQUEST,
        }))
    );
}

#[test]
fn captured_hello_res_without_udp_port_tag_decodes_misc_options() {
    // No 0xFC tag, but a 0x06 misc-options byte: TCP-firewalled + ack-request.
    assert_eq!(
        decode(HELLO_RES_MIN),
        Ok(Kad2Message::HelloRes(Kad2NodeInfo {
            id: id([0xaa; 16]),
            tcp_port: 4662,
            version: 8,
            udp_port_tag: None,
            misc_options: MISC_OPTIONS_TCP_FIREWALLED | MISC_OPTIONS_ACK_REQUEST,
        }))
    );
}

#[test]
fn encode_reproduces_captured_hello_bytes_including_misc_options() {
    // Byte-exact re-encode of all three captured hellos — proves the 0xF2
    // misc-options tag layout and the SOURCEUPORT-then-KADMISCOPTIONS order
    // against genuine aMule 2.3.3 bytes (upgrades the bit meanings from
    // documentation-backed to capture-observed for these values).
    let Ok(Kad2Message::HelloReq(req)) = decode(HELLO_REQ) else {
        panic!("hello req");
    };
    assert_eq!(Kad2Message::HelloReq(req).encode().encode(), HELLO_REQ);
    let Ok(Kad2Message::HelloRes(res)) = decode(HELLO_RES) else {
        panic!("hello res");
    };
    assert_eq!(Kad2Message::HelloRes(res).encode().encode(), HELLO_RES);
    let Ok(Kad2Message::HelloRes(min)) = decode(HELLO_RES_MIN) else {
        panic!("hello res min");
    };
    assert_eq!(Kad2Message::HelloRes(min).encode().encode(), HELLO_RES_MIN);
}

#[test]
fn captured_ping_and_pong_decode() {
    assert_eq!(decode(PING), Ok(Kad2Message::Ping));
    assert_eq!(decode(PONG), Ok(Kad2Message::Pong { udp_port: 4674 }));
}

#[test]
fn committed_lookup_req_fixture_decodes_with_masked_count() {
    // 0x0B = KADEMLIA_FIND_NODE; the low five bits are the requested contact
    // count, the top three are masked away.
    assert_eq!(
        decode(LOOKUP_REQ),
        Ok(Kad2Message::LookupReq {
            count: 0x0B,
            target: id([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]),
            check: id([0xaa; 16]),
        })
    );
}

#[test]
fn committed_lookup_res_fixture_decodes_four_ranked_contacts() {
    let Ok(Kad2Message::LookupRes { target, contacts }) = decode(LOOKUP_RES) else {
        panic!("expected a lookup response");
    };
    assert_eq!(
        target,
        id([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff
        ])
    );
    // aMule's closest-first ranking: byte-flip positions 12, 15, 0, 3.
    let first = contacts.first().expect("four contacts");
    assert_eq!(
        first.endpoint(),
        KadNodeEndpoint::new(Ipv4Addr::new(172, 30, 0, 7), 4677)
    );
    assert_eq!(first.tcp_port(), 4662);
    assert_eq!(first.version(), 8);
    assert_eq!(contacts.len(), 4);
}

#[test]
fn lookup_req_count_mask_strips_the_top_three_bits() {
    // Same fixture bytes with the raw count's top bits set: the decoded count
    // must still be 0x0B (aMule masks with 0x1F).
    let mut raw = LOOKUP_REQ.to_vec();
    raw[2] = 0x0B | 0xE0;
    assert_eq!(
        decode(&raw),
        Ok(Kad2Message::LookupReq {
            count: 0x0B,
            target: id([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]),
            check: id([0xaa; 16]),
        })
    );
}

#[test]
fn every_message_encode_round_trips_through_decode() {
    let info = Kad2NodeInfo {
        id: KadId::from_bytes([0x42; 16]),
        tcp_port: 4662,
        version: 8,
        udp_port_tag: Some(4700),
        misc_options: 0,
    };
    let contact = KadContact::new(
        KadId::from_bytes([0x24; 16]),
        KadNodeEndpoint::new(Ipv4Addr::new(203, 0, 113, 9), 4710),
        4711,
        8,
    );
    let messages = vec![
        Kad2Message::BootstrapReq,
        Kad2Message::BootstrapRes {
            sender: Kad2NodeInfo {
                udp_port_tag: None,
                ..info
            },
            contacts: vec![contact],
        },
        Kad2Message::HelloReq(info),
        Kad2Message::HelloRes(Kad2NodeInfo {
            udp_port_tag: None,
            ..info
        }),
        // A hello with the misc-options tag present (both a firewalled bit and
        // the ack-request bit) must round-trip the byte, not just drop it.
        Kad2Message::HelloRes(Kad2NodeInfo {
            misc_options: MISC_OPTIONS_TCP_FIREWALLED | MISC_OPTIONS_ACK_REQUEST,
            ..info
        }),
        Kad2Message::HelloResAck {
            id: KadId::from_bytes([0x77; 16]),
        },
        Kad2Message::Ping,
        Kad2Message::Pong { udp_port: 4674 },
        Kad2Message::LookupReq {
            count: 2,
            target: KadId::from_bytes([0x10; 16]),
            check: KadId::from_bytes([0x20; 16]),
        },
        Kad2Message::LookupRes {
            target: KadId::from_bytes([0x10; 16]),
            contacts: vec![contact],
        },
    ];

    for message in messages {
        let envelope = message.encode();
        assert_eq!(
            Kad2Message::decode(&envelope),
            Ok(message),
            "encode -> decode must be the identity"
        );
    }
}

#[test]
fn encode_reproduces_captured_bytes_for_fixed_layout_messages() {
    // Byte-exact against genuine aMule emissions (and, for the lookup request,
    // against the stimulus bytes aMule demonstrably accepted and answered).
    assert_eq!(Kad2Message::BootstrapReq.encode().encode(), BOOTSTRAP_REQ);
    assert_eq!(Kad2Message::Ping.encode().encode(), PING);
    assert_eq!(Kad2Message::Pong { udp_port: 4674 }.encode().encode(), PONG);
    assert_eq!(
        Kad2Message::LookupReq {
            count: 0x0B,
            target: id([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]),
            check: id([0xaa; 16]),
        }
        .encode()
        .encode(),
        LOOKUP_REQ
    );
}

#[test]
fn unknown_opcode_is_a_typed_error() {
    let envelope = KadEnvelope::plain(0x99, vec![]);
    assert_eq!(
        Kad2Message::decode(&envelope),
        Err(Kad2MessageDecodeError::UnknownOpcode { opcode: 0x99 })
    );
}

#[test]
fn malformed_payloads_are_typed_errors_never_panics() {
    let cases: Vec<(u8, Vec<u8>)> = vec![
        // Hello truncated mid-ID.
        (0x11, vec![0x42; 7]),
        // Hello with a tag list that overruns the payload.
        (0x11, {
            let mut p = vec![0x42; 16];
            p.extend_from_slice(&4662u16.to_le_bytes());
            p.push(8);
            p.push(2); // claims two tags
            p.extend_from_slice(&[0x08, 0x01, 0x00]); // truncated tag
            p
        }),
        // Ping with trailing bytes (eMule requires exact size).
        (0x60, vec![0x00]),
        // Pong with only one port byte.
        (0x61, vec![0x12]),
        // Bootstrap res whose count overstates the rows present.
        (0x09, {
            let mut p = vec![0x42; 16];
            p.extend_from_slice(&4662u16.to_le_bytes());
            p.push(8);
            p.extend_from_slice(&5u16.to_le_bytes()); // five rows claimed
            p.extend_from_slice(&[0u8; 25]); // one row present
            p
        }),
        // Bootstrap res with trailing bytes after the declared rows.
        (0x09, {
            let mut p = vec![0x42; 16];
            p.extend_from_slice(&4662u16.to_le_bytes());
            p.push(8);
            p.extend_from_slice(&0u16.to_le_bytes());
            p.push(0xFF);
            p
        }),
        // Lookup req with a zero contact count after masking (aMule drops it).
        (0x21, {
            let mut p = vec![0xE0];
            p.extend_from_slice(&[0x10; 16]);
            p.extend_from_slice(&[0x20; 16]);
            p
        }),
        // Lookup req truncated mid-check.
        (0x21, {
            let mut p = vec![0x02];
            p.extend_from_slice(&[0x10; 16]);
            p.extend_from_slice(&[0x20; 8]);
            p
        }),
        // Lookup res whose contact count overstates the rows present.
        (0x29, {
            let mut p = vec![0x10; 16];
            p.push(3);
            p.extend_from_slice(&[0u8; 25]);
            p
        }),
        // Absurd count with almost no bytes: must error, not allocate.
        (0x29, {
            let mut p = vec![0x10; 16];
            p.push(0xFF);
            p
        }),
    ];

    for (opcode, payload) in cases {
        let envelope = KadEnvelope::plain(opcode, payload);
        assert!(
            matches!(
                Kad2Message::decode(&envelope),
                Err(Kad2MessageDecodeError::Malformed { .. })
            ),
            "opcode 0x{opcode:02x} case must be a typed Malformed error"
        );
    }
}

// --- the datagram boundary underneath the codecs -----------------------------

#[test]
fn packed_datagrams_are_dispatched_like_their_plain_twins() {
    use std::io::Write;
    let mut node = node();

    let plain = Kad2Message::Ping.encode();
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(plain.payload())
        .expect("in-memory deflate");
    let mut packed = vec![0xE5, plain.opcode()];
    packed.extend_from_slice(&encoder.finish().expect("in-memory deflate"));

    node.handle_datagram(T0, endpoint(6, 4906), &packed);
    assert_eq!(
        sent_messages(&drain(|| node.poll_output())),
        vec![(endpoint(6, 4906), Kad2Message::Pong { udp_port: 4906 })]
    );
}

#[test]
fn undecodable_datagrams_produce_diagnostics_and_change_nothing() {
    let mut node = node();

    // Not a Kad protocol byte.
    node.handle_datagram(T0, endpoint(1, 4701), &[0xD4, 0x11, 0x00]);
    // Valid envelope, malformed hello payload.
    node.handle_datagram(T0, endpoint(1, 4701), &[0xE4, 0x11, 0x42, 0x42]);
    // Valid envelope, opcode outside every implemented role.
    node.handle_datagram(T0, endpoint(1, 4701), &[0xE4, 0x99]);

    let outputs = drain(|| node.poll_output());
    // One diagnostic per datagram, plus the silent→heard edge the
    // first *well-formed envelope* fires — the raw-garbage first datagram
    // never reaches the entry gate's stamp.
    assert_eq!(
        outputs.len(),
        4,
        "three diagnostics + one edge: {outputs:?}"
    );
    assert!(matches!(
        diagnostics(&outputs).as_slice(),
        [
            KadNodeDiagnostic::UndecodableEnvelope { .. },
            KadNodeDiagnostic::UndecodableMessage { .. },
            KadNodeDiagnostic::UndecodableMessage { .. },
        ]
    ));
    assert!(node.routing_table().is_empty());
    assert!(node.next_wake().is_none());
}
