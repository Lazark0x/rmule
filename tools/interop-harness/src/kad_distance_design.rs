//! Adversarial contact/target design for the Kad distance-ordering capture
//! (ADR-0043).
//!
//! `KadId::DISTANCE_ORDER_BLOCKED_BY` gates every nearest-contact API on proof of
//! how aMule turns the 16 on-wire Kad bytes into a comparable 128-bit magnitude
//! for XOR distance. The word-swap byte order is already capture-proven (the
//! `0x34` target equalled the file hash with each 32-bit word byte-reversed), but
//! that fixes only how bytes sit *inside* a word — not which word is most
//! significant, nor the overall compare direction.
//!
//! This module is a **design artifact, not production Kad semantics**. It enumerates
//! the surviving hypotheses as pure byte-significance permutations, builds a contact
//! set whose XOR-closest-to-target ordering differs under each, and proves (in tests)
//! that the design actually discriminates. The harness seeds these contacts into one
//! aMule responder's routing table and reads the winning hypothesis off the `0x29`
//! answer. Nothing here decides the answer — aMule does, on the wire.
//!
//! Clean-room note (ADR-0004/0013): the hypotheses are candidate *protocol facts to
//! be verified by capture*, derived from the observable word-swap plus first
//! principles — not transcribed from aMule's GPLv2 `CUInt128`.

use crate::kad_seed::KadContact;

/// A byte-significance hypothesis: the 16 wire-byte indices listed
/// most-significant first. Assembling the XOR-distance bytes in this order into a
/// big-endian `u128` yields the magnitude aMule would compare.
#[derive(Clone, Copy, Debug)]
pub struct Hypothesis {
    /// The hypothesis name recorded in the verdict.
    pub name: &'static str,
    /// Wire-byte indices, most-significant first.
    pub significance: [usize; 16],
}

/// Naive big-endian over all 16 wire bytes: `b[0]` most significant. Equivalent to
/// reading four 32-bit words most-significant-word-first with each word *big-endian*
/// internally.
pub const H_BIG_ENDIAN: Hypothesis = Hypothesis {
    name: "big_endian_16",
    significance: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
};

/// Naive little-endian over all 16 wire bytes: `b[15]` most significant. Equivalent
/// to least-significant-word-first with each word little-endian internally, so it
/// also stands in for the "word order reversed" reading.
pub const H_LITTLE_ENDIAN: Hypothesis = Hypothesis {
    name: "little_endian_16",
    significance: [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
};

/// eMule-believed reading: four 32-bit words, most-significant-word first, each word
/// **little-endian** on the wire (the proven word-swap). Within word 0 the most
/// significant byte is `b[3]`, so the byte-significance order is
/// `3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12`.
pub const H_WORD_LE: Hypothesis = Hypothesis {
    name: "word_le_msw_first",
    significance: [3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12],
};

/// The three surviving, pairwise-distinct hypotheses the capture must discriminate.
pub const HYPOTHESES: [Hypothesis; 3] = [H_BIG_ENDIAN, H_LITTLE_ENDIAN, H_WORD_LE];

/// Fixed, arbitrary lookup target used for the capture. Byte-position markers so the
/// seed and the decoded answer are easy to read by eye.
pub const TARGET: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
];

/// Wire-byte positions each seeded contact flips (top bit, `0x80`) relative to
/// [`TARGET`]. Chosen so the closest contact under each hypothesis is a *different*
/// position: big-endian → 15, little-endian → 0, word-LE → 12. The full 4-contact
/// ordering also differs pairwise, giving redundant confirmation beyond the single
/// closest.
pub const FLIP_POSITIONS: [usize; 4] = [0, 3, 12, 15];

/// The bit flipped at each position. `0x80` is the most significant bit of the byte,
/// so the single differing byte alone decides the comparison at that position —
/// no lower-bit interaction to reason about.
const FLIP_MASK: u8 = 0x80;

/// The seeded contact IDs (on-wire bytes): [`TARGET`] with one [`FLIP_POSITIONS`]
/// byte flipped by `FLIP_MASK`. Index `i` corresponds to `FLIP_POSITIONS[i]`.
#[must_use]
pub fn contact_ids() -> Vec<[u8; 16]> {
    FLIP_POSITIONS
        .iter()
        .map(|&pos| {
            let mut id = TARGET;
            id[pos] ^= FLIP_MASK;
            id
        })
        .collect()
}

/// The seeded contacts as bootstrap `nodes.dat` records: distinct private endpoints,
/// current Kad2 version. IPs are `172.30.0.10 + i` purely to keep them routable and
/// distinct; only the IDs carry the discrimination.
#[must_use]
pub fn seed_contacts() -> Vec<KadContact> {
    contact_ids()
        .into_iter()
        .enumerate()
        .map(|(i, kad_id)| KadContact {
            kad_id,
            ipv4: [172, 30, 0, 10 + i as u8],
            udp_port: 4672,
            tcp_port: 4662,
            version: 8,
        })
        .collect()
}

/// XOR distance between an on-wire id and the target.
fn xor_distance(id: [u8; 16], target: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = id[i] ^ target[i];
    }
    out
}

/// The comparable 128-bit magnitude of a distance under a hypothesis.
fn magnitude(distance: [u8; 16], hypothesis: &Hypothesis) -> u128 {
    let mut m = 0u128;
    for &idx in &hypothesis.significance {
        m = (m << 8) | u128::from(distance[idx]);
    }
    m
}

/// The closest-first ordering of the seeded contacts under a hypothesis, returned as
/// indices into [`FLIP_POSITIONS`] / [`contact_ids`]. Element 0 is the contact aMule
/// would return first when asked for the single closest to [`TARGET`].
#[must_use]
pub fn expected_ranking(hypothesis: &Hypothesis) -> Vec<usize> {
    let ids = contact_ids();
    let mut order: Vec<usize> = (0..ids.len()).collect();
    order.sort_by_key(|&i| magnitude(xor_distance(ids[i], TARGET), hypothesis));
    order
}

/// The wire-byte flip position of the contact each hypothesis ranks closest — the
/// single value the `count = 1` capture reads out.
#[must_use]
pub fn expected_closest_position(hypothesis: &Hypothesis) -> usize {
    FLIP_POSITIONS[expected_ranking(hypothesis)[0]]
}

/// The responder's seeded 16-byte Kad ID (verbatim in `preferencesKad.dat`, so it
/// is also the on-wire identity). Far from [`TARGET`] and every contact so the
/// discrimination contacts sit together in one bucket and stay retained. Also the
/// `check` field the stimulus REQ must carry, or aMule drops it as misrouted.
pub const RESPONDER_KAD_ID: [u8; 16] = [0xAA; 16];

/// Kad2 REQ contact-type byte. `0x0B` = `KADEMLIA_FIND_NODE` — asks the responder
/// for up to eleven contacts closest to the target, enough to read the full
/// ordering of the four seeded contacts back.
pub const REQ_FIND_NODE: u8 = 0x0B;

/// Build a `KADEMLIA2_REQ` (`0x21`) datagram: `E4 21 | type(1) | target(16) |
/// check(16)`. The `check` is the receiver's own Kad ID (anti-misroute); `target`
/// is the key whose closest contacts the responder should return.
#[must_use]
pub fn kademlia2_req(contact_type: u8, target: [u8; 16], check: [u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(35);
    out.push(0xE4);
    out.push(0x21);
    out.push(contact_type);
    out.extend_from_slice(&target);
    out.extend_from_slice(&check);
    out
}

/// The concrete stimulus datagram this capture sends the responder: ask for the
/// contacts closest to [`TARGET`], carrying the responder's own ID as `check`.
#[must_use]
pub fn stimulus_req() -> Vec<u8> {
    kademlia2_req(REQ_FIND_NODE, TARGET, RESPONDER_KAD_ID)
}

/// One contact row inside a decoded `KADEMLIA2_RES`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResContact {
    /// The contact's on-wire Kad ID.
    pub kad_id: [u8; 16],
    /// The contact's IPv4 as dotted octets.
    pub ipv4: [u8; 4],
    /// The contact's Kad UDP port.
    pub udp_port: u16,
}

/// A decoded `KADEMLIA2_RES` (`0x29`): the echoed target and the returned contacts
/// in wire order (aMule emits them closest-first).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedRes {
    /// The echoed lookup target.
    pub target: [u8; 16],
    /// The returned contacts, closest first as aMule ranks them.
    pub contacts: Vec<ResContact>,
}

/// Decode a `KADEMLIA2_RES` from a raw Kad UDP payload (`E4 29 | target(16) |
/// count(1) | contact(25)×count`). Returns `None` if the payload is not a `0x29`
/// or is truncated.
#[must_use]
pub fn decode_kademlia2_res(payload: &[u8]) -> Option<DecodedRes> {
    if payload.len() < 19 || payload[0] != 0xE4 || payload[1] != 0x29 {
        return None;
    }
    let mut target = [0u8; 16];
    target.copy_from_slice(&payload[2..18]);
    let count = payload[18] as usize;
    let mut contacts = Vec::with_capacity(count);
    let mut off = 19;
    for _ in 0..count {
        let row = payload.get(off..off + 25)?;
        let mut kad_id = [0u8; 16];
        kad_id.copy_from_slice(&row[0..16]);
        let ipv4 = [row[16], row[17], row[18], row[19]];
        let udp_port = u16::from_le_bytes([row[20], row[21]]);
        contacts.push(ResContact {
            kad_id,
            ipv4,
            udp_port,
        });
        off += 25;
    }
    Some(DecodedRes { target, contacts })
}

/// Which hypothesis a returned closest contact's Kad ID matches, if it is one of
/// the seeded discrimination contacts. Returns the hypothesis name.
#[must_use]
pub fn identify_hypothesis(closest_kad_id: &[u8; 16]) -> Option<&'static str> {
    let ids = contact_ids();
    let position = ids.iter().position(|id| id == closest_kad_id)?;
    let flip = FLIP_POSITIONS[position];
    HYPOTHESES
        .iter()
        .find(|h| expected_closest_position(h) == flip)
        .map(|h| h.name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn each_hypothesis_is_a_permutation_of_all_16_positions() {
        for h in HYPOTHESES {
            let seen: HashSet<usize> = h.significance.into_iter().collect();
            assert_eq!(seen.len(), 16, "{} repeats or omits a byte index", h.name);
            assert!(
                seen.into_iter().all(|i| i < 16),
                "{} indexes out of range",
                h.name
            );
        }
    }

    #[test]
    fn design_discriminates_on_the_single_closest_contact() {
        // The whole point of the capture: `count = 1` names the hypothesis.
        let closest: Vec<usize> = HYPOTHESES.iter().map(expected_closest_position).collect();
        let unique: HashSet<usize> = closest.iter().copied().collect();
        assert_eq!(
            unique.len(),
            HYPOTHESES.len(),
            "closest-contact positions must be pairwise distinct, got {closest:?}"
        );
        // Pin the concrete expectation so a regression in the permutations is loud.
        assert_eq!(expected_closest_position(&H_BIG_ENDIAN), 15);
        assert_eq!(expected_closest_position(&H_LITTLE_ENDIAN), 0);
        assert_eq!(expected_closest_position(&H_WORD_LE), 12);
    }

    #[test]
    fn design_discriminates_on_the_full_ordering_too() {
        let rankings: Vec<Vec<usize>> = HYPOTHESES.iter().map(expected_ranking).collect();
        for (a, ha) in HYPOTHESES.iter().enumerate() {
            for (b, hb) in HYPOTHESES.iter().enumerate() {
                if a < b {
                    assert_ne!(
                        rankings[a], rankings[b],
                        "{} and {} share a full ordering",
                        ha.name, hb.name
                    );
                }
            }
        }
    }

    #[test]
    fn stimulus_req_has_the_captured_kademlia2_req_layout() {
        let req = stimulus_req();
        assert_eq!(req.len(), 35, "E4 21 + type + 16 target + 16 check");
        assert_eq!(&req[0..3], &[0xE4, 0x21, REQ_FIND_NODE]);
        assert_eq!(&req[3..19], &TARGET, "target key");
        assert_eq!(&req[19..35], &RESPONDER_KAD_ID, "check = receiver id");
    }

    #[test]
    fn responder_id_is_distinct_from_target_and_every_contact() {
        assert_ne!(RESPONDER_KAD_ID, TARGET);
        for id in contact_ids() {
            assert_ne!(RESPONDER_KAD_ID, id);
        }
    }

    #[test]
    fn round_trips_a_res_and_identifies_each_hypothesis() {
        for hypothesis in HYPOTHESES {
            // Synthesize a 0x29 whose single closest contact is the one this
            // hypothesis predicts, and confirm the decoder + identifier agree.
            let closest_pos = expected_closest_position(&hypothesis);
            let mut closest_id = TARGET;
            closest_id[closest_pos] ^= 0x80;

            let mut payload = vec![0xE4, 0x29];
            payload.extend_from_slice(&TARGET);
            payload.push(1); // count
            payload.extend_from_slice(&closest_id);
            payload.extend_from_slice(&[10, 0, 0, 1]); // ip
            payload.extend_from_slice(&4672u16.to_le_bytes()); // udp
            payload.extend_from_slice(&4662u16.to_le_bytes()); // tcp
            payload.push(8); // version

            let decoded = decode_kademlia2_res(&payload).expect("decodes");
            assert_eq!(decoded.target, TARGET);
            assert_eq!(decoded.contacts.len(), 1);
            assert_eq!(decoded.contacts[0].kad_id, closest_id);
            assert_eq!(
                identify_hypothesis(&decoded.contacts[0].kad_id),
                Some(hypothesis.name)
            );
        }
    }

    #[test]
    fn decoder_rejects_non_0x29_and_empty_responses() {
        assert!(decode_kademlia2_res(&[0xE4, 0x21, 0x00]).is_none());
        // A well-formed empty (count=0) response decodes to zero contacts.
        let mut empty = vec![0xE4, 0x29];
        empty.extend_from_slice(&TARGET);
        empty.push(0);
        let decoded = decode_kademlia2_res(&empty).expect("count=0 still decodes");
        assert!(decoded.contacts.is_empty());
        assert!(identify_hypothesis(&[0x00; 16]).is_none());
    }

    #[test]
    fn seed_contacts_differ_from_target_in_exactly_one_top_bit() {
        for (contact, &pos) in seed_contacts().iter().zip(&FLIP_POSITIONS) {
            let diff: Vec<usize> = (0..16)
                .filter(|&i| contact.kad_id[i] != TARGET[i])
                .collect();
            assert_eq!(
                diff,
                vec![pos],
                "contact must differ only at its flip position"
            );
            assert_eq!(contact.kad_id[pos] ^ TARGET[pos], FLIP_MASK, "top-bit flip");
        }
    }
}
