//! rmule's Kad distance ordering reproduces a genuine aMule routing response.
//!
//! `result_0x29.bin` is a captured aMule 2.3.3 `KADEMLIA2_RES` (ADR-0043):
//! the responder ranked four seeded contacts by its own XOR distance to a
//! target and returned them closest-first. This test parses that response and
//! asserts that sorting the same contacts by [`KadId::distance`] reproduces the
//! exact wire order — i.e. rmule's distance ordering is aMule-compatible, not just
//! self-consistent. See the fixture's `metadata.toml` for provenance.

use rmule_kad::KadId;

const RESULT: &[u8] = include_bytes!(
    "../fixtures/routing/captured/private-amule-kad-distance-20260707/result_0x29.bin"
);
const REQUEST: &[u8] = include_bytes!(
    "../fixtures/routing/captured/private-amule-kad-distance-20260707/request_0x21.bin"
);

/// Parse `[E4 29][target 16][count 1][contact 25]*` into (target, contact ids in
/// wire order).
fn parse_result(bytes: &[u8]) -> (KadId, Vec<KadId>) {
    assert_eq!(&bytes[0..2], &[0xE4, 0x29], "KADEMLIA2_RES envelope");
    let mut target = [0u8; 16];
    target.copy_from_slice(&bytes[2..18]);
    let count = bytes[18] as usize;
    let mut ids = Vec::with_capacity(count);
    let mut off = 19;
    for _ in 0..count {
        let mut id = [0u8; 16];
        id.copy_from_slice(&bytes[off..off + 16]);
        ids.push(KadId::from_bytes(id));
        off += 25;
    }
    (KadId::from_bytes(target), ids)
}

#[test]
fn rmule_distance_reproduces_amules_captured_ranking() {
    let (target, wire_order) = parse_result(RESULT);
    assert_eq!(wire_order.len(), 4, "the capture returned four contacts");

    let mut rmule_order = wire_order.clone();
    rmule_order.sort_by_key(|id| id.distance(&target));

    assert_eq!(
        rmule_order, wire_order,
        "rmule's XOR-distance sort must match aMule's closest-first wire order"
    );
}

#[test]
fn closest_contact_confirms_word_le_msw_first() {
    let (target, wire_order) = parse_result(RESULT);

    // The four contacts differ from the target in exactly one top bit, at wire
    // positions {0, 3, 12, 15}. word_le_msw_first predicts position 12 is closest;
    // big-endian would predict 15, little-endian 0. aMule returned position 12.
    let closest = wire_order[0];
    let mut expected = *target.as_bytes();
    expected[12] ^= 0x80;
    assert_eq!(
        closest.as_bytes(),
        &expected,
        "closest contact is the byte-12 flip — word_le_msw_first"
    );
}

#[test]
fn stimulus_request_targets_match_the_response() {
    // The request is context, not evidence, but it must be the well-formed REQ
    // that provoked this response: same target, KADEMLIA2_REQ opcode.
    assert_eq!(&REQUEST[0..2], &[0xE4, 0x21], "KADEMLIA2_REQ envelope");
    let (target, _) = parse_result(RESULT);
    assert_eq!(
        &REQUEST[3..19],
        target.as_bytes(),
        "the stimulus asked for the same target the response echoes"
    );
}
