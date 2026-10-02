//! The Kad2 opcodes rmule models: each modelled byte maps to its cited wire
//! value and round-trips, and a byte outside the set maps to nothing.

use rmule_kad::opcode::{
    KADEMLIA2_BOOTSTRAP_REQ, KADEMLIA2_BOOTSTRAP_RES, KADEMLIA2_HELLO_REQ, KADEMLIA2_HELLO_RES,
    KADEMLIA2_PING, KADEMLIA2_PONG, KADEMLIA2_REQ, KADEMLIA2_RES, KADEMLIA2_SEARCH_RES,
    KADEMLIA2_SEARCH_SOURCE_REQ, Kad2Opcode,
};

#[test]
fn modelled_kad2_opcodes_match_cited_wire_bytes() {
    assert_eq!(KADEMLIA2_BOOTSTRAP_REQ, 0x01);
    assert_eq!(KADEMLIA2_BOOTSTRAP_RES, 0x09);
    assert_eq!(KADEMLIA2_HELLO_REQ, 0x11);
    assert_eq!(KADEMLIA2_HELLO_RES, 0x19);
    assert_eq!(KADEMLIA2_REQ, 0x21);
    assert_eq!(KADEMLIA2_RES, 0x29);
    assert_eq!(KADEMLIA2_SEARCH_SOURCE_REQ, 0x34);
    assert_eq!(KADEMLIA2_SEARCH_RES, 0x3B);
    assert_eq!(KADEMLIA2_PING, 0x60);
    assert_eq!(KADEMLIA2_PONG, 0x61);
}

#[test]
fn kad2_opcode_round_trips_through_its_wire_byte() {
    for byte in [0x01, 0x09, 0x11, 0x19, 0x21, 0x29, 0x34, 0x3B, 0x60, 0x61] {
        let opcode = Kad2Opcode::try_from_u8(byte).expect("modelled opcode must map");
        assert_eq!(opcode.as_u8(), byte);
    }
}

#[test]
fn unmodelled_opcodes_do_not_map() {
    // 0x38 is the Kad1 source-result opcode; rmule models Kad2 only.
    assert_eq!(Kad2Opcode::try_from_u8(0x38), None);
    assert_eq!(Kad2Opcode::try_from_u8(0x00), None);
    assert_eq!(Kad2Opcode::try_from_u8(0xFF), None);
}
