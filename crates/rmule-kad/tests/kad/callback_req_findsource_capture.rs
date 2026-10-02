//! aMule's `FINDSOURCE` road to a buddy named by ID alone, read off the
//! bench (interop flow M `kad-core-buddy --amule-requester --omit-buddy-endpoint`, run
//! `1790190646`).
//!
//! The rmule storer served a type-3 row carrying `TAG_BUDDYHASH` and no
//! `TAG_SERVERIP`/`TAG_SERVERPORT` (an rmule publisher's: no stock aMule writes
//! one). A stock aMule requester read it, walked toward the buddy ID with a
//! `KADEMLIA2_REQ`, and sent its `0x52` to the contact that answered — the rmule
//! buddy at distance 0. The row is rmule's; the walk and the `0x52` are
//! aMule's. Provenance in `meta.toml`.
//!
//! The keyed twin (run `1790206695`): the same requester
//! with aMule's crypt layer on sent the same `0x52` inside a Kad crypt envelope
//! keyed on the buddy's Kad ID, and the rmule buddy relayed it.

use std::net::Ipv4Addr;

use rmule_kad::opcode::KADEMLIA2_SEARCH_RES;
use rmule_kad::{
    FileHash, Kad2Message, KadDecoded, KadEvent, KadNode, KadNodeConfig, KadOutput,
    KadSourceRowFacts, UserHash, decode_exact, decode_source_result,
};
use rmule_primitives::{
    ClientDecryptKeys, DatagramKeyFamily, Ipv4Endpoint, decrypt_datagram_client,
};
use rmule_testkit::kad_node::endpoint;

use crate::fixture::{KAD_PROTO, captured};

const FIXTURE_DIR: &str = "fixtures/buddy/captured/amule-233-callback-req-findsource-20260923/";
const KEYED_DIR: &str = "fixtures/buddy/captured/amule-233-callback-req-findsource-keyed-20260923/";
const ENDPOINT_BRANCH_DIR: &str = "fixtures/buddy/captured/amule-233-callback-req-20260923/";

/// `KADEMLIA_CALLBACK_REQ`.
const OP_CALLBACK_REQ: u8 = 0x52;

/// The one row the storer served, as rmule's reader projects it.
fn row() -> KadSourceRowFacts {
    let frame = captured(FIXTURE_DIR, "storer_search_res_0x3b.bin");
    let KadDecoded::Plain(envelope) = decode_exact(&frame).expect("a plain 0xE4 datagram") else {
        panic!("the storer answered in the clear");
    };
    assert_eq!(envelope.opcode(), KADEMLIA2_SEARCH_RES);
    let rows = decode_source_result(&envelope).expect("the row decodes");
    let [row] = rows.as_slice() else {
        panic!("one row, got {}", rows.len());
    };
    row.facts().expect("a decoded row carries its facts")
}

/// The row names a buddy and no endpoint: the reader has only the ID to go on,
/// which is what sent aMule down `BaseClient.cpp:2159-2175` (kno `ab483654`).
#[test]
fn the_row_amule_walked_from_named_its_buddy_by_id_alone() {
    let row = row();
    assert_eq!(row.source_type, 3, "firewalled behind a buddy");
    let buddy = row.buddy.expect("a type-3 row names its buddy");
    assert_eq!(buddy.buddy_udp, None, "no TAG_SERVERIP/TAG_SERVERPORT");
}

/// The walk's request targets the row's buddy ID in the order the `0x52`
/// then carries it, and asks the buddy itself (`check` is the receiver's ID).
#[test]
fn amules_walk_asked_the_buddy_for_its_own_id() {
    let frame = captured(FIXTURE_DIR, "findsource_walk_req_0x21.bin");
    let KadDecoded::Plain(envelope) = decode_exact(&frame).expect("a plain 0xE4 datagram") else {
        panic!("the walk left in the clear");
    };
    let buddy_id = row().buddy.expect("a type-3 row names its buddy").buddy_id;
    assert_eq!(
        Kad2Message::decode(&envelope),
        Ok(Kad2Message::LookupReq {
            count: 2,
            target: buddy_id,
            check: buddy_id,
        }),
        "KADEMLIA_FIND_VALUE toward the buddy ID, sent to the buddy"
    );
}

/// The `FINDSOURCE` `0x52` (`Search.cpp:1092-1100`) names the row's buddy and
/// is byte for byte the endpoint branch's: aMule's two writers agree.
#[test]
fn amules_findsource_callback_is_its_endpoint_branch_callback() {
    let frame = captured(FIXTURE_DIR, "callback_req_0x52.bin");
    assert_eq!(frame.len(), 36);
    assert_eq!((frame[0], frame[1]), (KAD_PROTO, OP_CALLBACK_REQ));
    let buddy = row().buddy.expect("a type-3 row names its buddy");
    assert_eq!(&frame[2..18], buddy.buddy_id.as_bytes());
    assert_eq!(
        frame,
        captured(ENDPOINT_BRANCH_DIR, "callback_req_0x52.bin")
    );
}

/// The keyed `0x52` opens under the buddy's own Kad ID — the `KadNodeId`
/// family, aMule's `SendPacket(…, &clientID)` (`Search.cpp:1103-1110`, kno
/// `ab483654`) — to exactly the plaintext capture, with no receiver verify key
/// (the buddy never handed the requester one).
#[test]
fn amules_keyed_findsource_callback_opens_under_the_buddys_kad_id() {
    let envelope = captured(KEYED_DIR, "callback_req_0x52_envelope.bin");
    let buddy_id = row().buddy.expect("a type-3 row names its buddy").buddy_id;
    let opened = decrypt_datagram_client(
        &envelope,
        &ClientDecryptKeys {
            kad_id: Some(buddy_id.as_bytes()),
            ..Default::default()
        },
    )
    .expect("keyed on the buddy's Kad ID");
    assert_eq!(opened.family, DatagramKeyFamily::KadNodeId);
    assert_eq!(
        opened.payload,
        captured(FIXTURE_DIR, "callback_req_0x52.bin")
    );
    assert_eq!(opened.receiver_verify_key, Some(0));
    assert_eq!(opened.sender_verify_key, Some(0xB849_FF6C));
}

/// A node holding the buddy's Kad ID takes the envelope off the wire as the
/// requester's relay request — what the bench's buddy did live before its
/// `0x99`.
#[test]
fn a_buddy_node_asks_to_relay_amules_keyed_findsource_callback() {
    let buddy_id = row().buddy.expect("a type-3 row names its buddy").buddy_id;
    let mut node = KadNode::new(KadNodeConfig {
        id: buddy_id,
        tcp_port: 4663,
        udp_port: 4679,
        user_hash: UserHash::from_bytes([0xEE; 16]),
    });
    let requester = endpoint(7, 4704);
    node.handle_datagram(
        rmule_testkit::kad_node::T0,
        requester,
        &captured(KEYED_DIR, "callback_req_0x52_envelope.bin"),
    );
    let relay: Vec<KadEvent> = rmule_primitives::session::drain(|| node.poll_output())
        .into_iter()
        .filter_map(|output| match output {
            KadOutput::Event(event @ KadEvent::CallbackRelayRequested { .. }) => Some(event),
            _ => None,
        })
        .collect();
    assert_eq!(
        relay,
        vec![KadEvent::CallbackRelayRequested {
            requester: Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 7), 4704),
            buddy_id,
            file_hash: FileHash::from_hex("009D91607B0D86D64FAFF631E02ED864").unwrap(),
            requester_tcp_port: 4662,
        }]
    );
}
