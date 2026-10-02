//! Kad distance is word-LE, most-significant-word first: flipping the top bit
//! of each word in turn orders the distances, and the distance to self is the
//! minimum.

use rmule_kad::KadId;

// The Kad ID byte order and distance ordering are capture-proven (ADR-0043):
// a private aMule 0x29 routing response ranked four discrimination
// contacts and confirmed `word_le_msw_first` — four 32-bit words, most-significant
// word first, each little-endian on the wire. This file pins that the gate is
// lifted and that `KadId::distance` encodes exactly that ordering.

fn id_with_top_bit_flipped(base: &[u8; 16], position: usize) -> KadId {
    let mut bytes = *base;
    bytes[position] ^= 0x80;
    KadId::from_bytes(bytes)
}

#[test]
fn distance_ordering_evidence_is_no_longer_blocked() {
    assert!(
        KadId::DISTANCE_ORDER_BLOCKED_BY.is_empty(),
        "distance ordering is capture-proven; nothing gates it anymore"
    );
}

#[test]
fn distance_follows_word_le_msw_first_byte_significance() {
    // Under word_le_msw_first the wire-byte significance order (most significant
    // first) is 3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12. So a single-top-bit
    // difference at byte 12 (the least significant position) is the smallest
    // distance, and one at byte 3 (the most significant) is the largest.
    let target = KadId::from_bytes([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ]);
    let base = *target.as_bytes();

    let at12 = id_with_top_bit_flipped(&base, 12).distance(&target);
    let at15 = id_with_top_bit_flipped(&base, 15).distance(&target);
    let at0 = id_with_top_bit_flipped(&base, 0).distance(&target);
    let at3 = id_with_top_bit_flipped(&base, 3).distance(&target);

    // Exactly the closest-first order aMule returned in the captured 0x29.
    assert!(at12 < at15, "byte 12 is less significant than byte 15");
    assert!(at15 < at0, "byte 15 is less significant than byte 0");
    assert!(at0 < at3, "byte 0 is less significant than byte 3");
}

#[test]
fn distance_to_self_is_the_minimum() {
    let id = KadId::from_bytes([7u8; 16]);
    let other = KadId::from_bytes([8u8; 16]);
    assert!(id.distance(&id) < other.distance(&id));
}
