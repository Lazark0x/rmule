//! aMule's own `KADEMLIA_CALLBACK_REQ` (`0x52`), read against the row that
//! drew it (interop flow M `kad-core-buddy --amule-requester`, run `1790185890`).
//!
//! A stock aMule requester, handed only the ed2k link, took the firewalled
//! aMule's type-3 row from the rmule storer placed at the file key and wrote
//! this `0x52` to the buddy the row named. The `0x3B` is the context (rmule's
//! storer re-serializing the firewalled aMule's publish); the `0x52` is the
//! evidence. The question it settles: does the requester's
//! `buddyID` field reach the buddy in the order the buddy holds its own ID?
//! The file and port fields, and rmule's decode of all three, are the codec's
//! KAT (`rmule_kad::buddy`, pinned to the same bytes). Provenance in
//! `meta.toml`.
//!
//! And kno's own `0x52` (run `1790234064`): the same writer
//! at kno's Fork Pin, drawn by a row rmule's storer re-served with `bi6`.

use std::net::{Ipv4Addr, Ipv6Addr};

use rmule_kad::opcode::KADEMLIA2_SEARCH_RES;
use rmule_kad::{KadDecoded, KadSourceRowFacts, decode_exact, decode_source_result};
use rmule_primitives::{Ipv4Endpoint, kad_wire_id};

use crate::fixture::{KAD_PROTO, captured, le_u16};

const FIXTURE_DIR: &str = "fixtures/buddy/captured/amule-233-callback-req-20260923/";
const KNO_FIXTURE_DIR: &str = "fixtures/buddy/captured/amule-kno-ab483654-callback-req-20260924/";

/// `KADEMLIA_CALLBACK_REQ`.
const OP_CALLBACK_REQ: u8 = 0x52;

/// Where the requester sent the `0x52`: the rmule buddy's Kad UDP endpoint.
const BUDDY_UDP: Ipv4Endpoint = Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 3), 4679);

fn callback_req() -> Vec<u8> {
    captured(FIXTURE_DIR, "callback_req_0x52.bin")
}

/// The one row a storer served, as rmule's reader projects it.
fn row_in(dir: &str, name: &str) -> KadSourceRowFacts {
    let frame = captured(dir, name);
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

fn row() -> KadSourceRowFacts {
    row_in(FIXTURE_DIR, "storer_search_res_0x3b.bin")
}

/// The row the requester read is a type-3 row naming the buddy it wrote to.
#[test]
fn the_row_amule_read_named_the_buddy_it_called() {
    let row = row();
    assert_eq!(row.source_type, 3, "firewalled behind a buddy");
    let buddy = row.buddy.expect("a type-3 row names its buddy");
    assert_eq!(
        buddy.buddy_udp,
        Some(BUDDY_UDP),
        "TAG_SERVERIP/TAG_SERVERPORT are where the 0x52 went"
    );
}

/// `buddyID` is `WriteUInt128(CUInt128(GetBuddyID()))`, `GetBuddyID()` the
/// row's `TAG_BUDDYHASH` loaded `SetValueBE` (`Search.cpp:1194-1202`,
/// `BaseClient.cpp:2133-2141`, kno `ab483654`): one word swap from the tag,
/// which lands on the ID the reader already holds in wire order.
#[test]
fn amules_callback_carries_the_rows_buddy_id_in_wire_order() {
    let frame = callback_req();
    assert_eq!(frame.len(), 36);
    assert_eq!((frame[0], frame[1]), (KAD_PROTO, OP_CALLBACK_REQ));
    let buddy = row().buddy.expect("a type-3 row names its buddy");
    assert_eq!(&frame[2..18], buddy.buddy_id.as_bytes());
    assert_eq!(
        kad_wire_id(frame[2..18].try_into().unwrap()),
        *b"\xCC\xDD\xEE\xFF\x88\x99\xAA\xBB\x44\x55\x66\x77\x00\x11\x22\x33",
        "and one swap back is TAG_BUDDYHASH's big-endian bytes"
    );
}

/// kno's `0x52` answers the row rmule's storer re-served with `bi6`: kno
/// dropped the tag (`Search.cpp:1205-1224`) and called back through the IPv4
/// trio alone — the buddy ID and the file key rmule's own reader takes from
/// the same row and search, stock 2.3.3's layout field for field.
#[test]
fn amule_knos_callback_answers_a_bi6_row_through_its_ipv4_trio() {
    let row = row_in(KNO_FIXTURE_DIR, "storer_search_res_bi6_0x3b.bin");
    assert_eq!(row.source_type, 3, "firewalled behind a buddy");
    let buddy = row.buddy.expect("a type-3 row names its buddy");
    assert_eq!(
        buddy.buddy_udp,
        Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 8), 4672)),
        "TAG_SERVERIP/TAG_SERVERPORT, where kno's 0x52 went"
    );
    assert_eq!(
        buddy.buddy_ipv6,
        Some(Ipv6Addr::new(0x3fff, 0x0ed2, 1, 0, 0, 0, 0, 8)),
        "the bi6 kno read beside the trio, and never dialled"
    );

    let answer = captured(KNO_FIXTURE_DIR, "storer_search_res_bi6_0x3b.bin");
    let frame = captured(KNO_FIXTURE_DIR, "callback_req_0x52.bin");
    assert_eq!(frame.len(), 36);
    assert_eq!((frame[0], frame[1]), (KAD_PROTO, OP_CALLBACK_REQ));
    assert_eq!(&frame[2..18], buddy.buddy_id.as_bytes());
    assert_eq!(frame[18..34], answer[18..34], "the key the answer served");
    assert_eq!(le_u16(&frame[34..]), 4662);
}
