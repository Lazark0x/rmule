//! The tap reader's decoders: both status forms, multipacket entries and request ranges.

use std::collections::BTreeSet;

use rmule_primitives::ED2K_PART_SIZE;

use super::{StatusForm, decode_status, requested_parts, status_entries};
use crate::flow::pcap::Ed2kFrame;

const HASH: [u8; 16] = [0x5A; 16];
const P: u64 = ED2K_PART_SIZE;

fn frame(protocol: u8, opcode: u8, payload: &[u8]) -> Ed2kFrame {
    let mut bytes = vec![protocol];
    bytes.extend_from_slice(&(payload.len() as u32 + 1).to_le_bytes());
    bytes.push(opcode);
    bytes.extend_from_slice(payload);
    Ed2kFrame {
        at: 1.0,
        source: "10.0.0.2:4662".parse().unwrap(),
        destination: "10.0.0.9:40000".parse().unwrap(),
        protocol,
        opcode,
        bytes,
    }
}

fn set(parts: &[u32]) -> BTreeSet<u32> {
    parts.iter().copied().collect()
}

/// aMule's two forms: `0` for a complete file; `size / PARTSIZE + 1`
/// otherwise, whose last bit at an exact multiple is a phantom part never
/// read; anything else is refused.
#[test]
fn both_status_forms_decode_and_the_phantom_bit_is_never_read() {
    assert_eq!(
        decode_status(0, &[], 3 * P),
        (StatusForm::Complete, set(&[0, 1, 2]))
    );
    // 2.5 parts: three real parts, count three, bits 0 and 2.
    assert_eq!(
        decode_status(3, &[0b101], 2 * P + P / 2),
        (StatusForm::Counted { phantom: false }, set(&[0, 2]))
    );
    // Exactly two parts: count three, and the phantom bit set stays unread.
    assert_eq!(
        decode_status(3, &[0b110], 2 * P),
        (StatusForm::Counted { phantom: true }, set(&[1]))
    );
    assert_eq!(
        decode_status(2, &[0b11], 2 * P),
        (StatusForm::Refused, BTreeSet::new())
    );
}

/// The status entry of a multipacket answer is found past the name and AICH
/// entries aMule writes before it.
#[test]
fn a_multipacket_answer_yields_its_status_entry() {
    let mut payload = HASH.to_vec();
    payload.push(0x59);
    payload.extend_from_slice(&10_u16.to_le_bytes());
    payload.extend_from_slice(b"stream.mkv");
    payload.push(0x9D);
    payload.extend_from_slice(&[7; 20]);
    payload.push(0x50);
    payload.extend_from_slice(&13_u16.to_le_bytes());
    payload.extend_from_slice(&[0xFF, 0x01]);
    let answer = frame(0xC5, 0x93, &payload);
    assert_eq!(
        status_entries(&answer, &HASH),
        vec![(13, [0xFF_u8, 0x01].as_slice())]
    );
    assert!(status_entries(&answer, &[0; 16]).is_empty());

    let mut standalone = HASH.to_vec();
    standalone.extend_from_slice(&0_u16.to_le_bytes());
    assert_eq!(
        status_entries(&frame(0xE3, 0x50, &standalone), &HASH),
        vec![(0, [].as_slice())]
    );
}

/// A request's empty ranges name nothing, and an end is exclusive: a range
/// ending on a part boundary does not reach the next part.
#[test]
fn a_request_names_the_parts_its_ranges_fall_in() {
    let mut narrow = HASH.to_vec();
    for start in [P, P + 10, 0] {
        narrow.extend_from_slice(&(start as u32).to_le_bytes());
    }
    for end in [P + 10, 2 * P, 0] {
        narrow.extend_from_slice(&(end as u32).to_le_bytes());
    }
    assert_eq!(
        requested_parts(&frame(0xE3, 0x47, &narrow), &HASH),
        Some(set(&[1]))
    );

    let mut wide = HASH.to_vec();
    for start in [5 * P, 0, 0] {
        wide.extend_from_slice(&start.to_le_bytes());
    }
    for end in [5 * P + 1, 0, 0] {
        wide.extend_from_slice(&end.to_le_bytes());
    }
    assert_eq!(
        requested_parts(&frame(0xC5, 0xA3, &wide), &HASH),
        Some(set(&[5]))
    );
    assert_eq!(requested_parts(&frame(0xE3, 0x50, &wide), &HASH), None);
}
