//! The tap reader against frames laid out as aMule and rmule write them.

use std::io::Write as _;

use super::{Fragments, Said, Status, Udp, decode, decode_udp};

const HASH: [u8; 16] = [0xAB; 16];

fn decoded(protocol: u8, opcode: u8, body: &[u8], from_rmule: bool) -> Vec<Said> {
    decode(
        protocol,
        opcode,
        body,
        from_rmule,
        &mut Fragments::default(),
    )
}

/// rmule's bundled answer names the file and writes its status: six parts,
/// parts 0 and 3 held.
#[test]
fn a_bundled_answer_reads_as_its_name_and_its_status() {
    let mut body = HASH.to_vec();
    body.push(0x59);
    body.extend_from_slice(&10u16.to_le_bytes());
    body.extend_from_slice(b"stream.mkv");
    body.push(0x50);
    body.extend_from_slice(&6u16.to_le_bytes());
    body.push(0b0000_1001);
    let said = decoded(0xC5, 0x93, &body, true);
    assert_eq!(
        said,
        vec![
            Said::Name {
                hash: HASH,
                name: "stream.mkv".to_owned()
            },
            Said::Status {
                hash: HASH,
                status: Status {
                    count: 6,
                    held: [0, 3].into()
                }
            },
        ]
    );
}

/// A 64-bit request keeps its asked ranges and drops the empty slot.
#[test]
fn a_wide_request_keeps_only_its_asked_ranges() {
    let mut body = HASH.to_vec();
    for start in [9_723_904u64, 0, 0] {
        body.extend_from_slice(&start.to_le_bytes());
    }
    for end in [9_732_096u64, 4_096, 0] {
        body.extend_from_slice(&end.to_le_bytes());
    }
    assert_eq!(
        decoded(0xC5, 0xA3, &body, false),
        vec![Said::Request {
            hash: HASH,
            ranges: vec![(9_723_904, 9_732_096), (0, 4_096)]
        }]
    );
}

/// A compressed block is one zlib stream cut into fragments: nothing reads
/// until the last fragment, then the block inflates whole.
#[test]
fn a_compressed_block_reads_once_its_fragments_are_all_in() {
    let plain: Vec<u8> = (0..50_000u32).map(|n| (n % 7) as u8).collect();
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&plain).unwrap();
    let packed = encoder.finish().unwrap();
    let (first, second) = packed.split_at(packed.len() / 2);
    let frame = |fragment: &[u8]| {
        let mut body = HASH.to_vec();
        body.extend_from_slice(&9_728_000u32.to_le_bytes());
        body.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        body.extend_from_slice(fragment);
        body
    };
    let mut fragments = Fragments::default();
    assert!(decode(0xC5, 0x40, &frame(first), true, &mut fragments).is_empty());
    assert_eq!(
        decode(0xC5, 0x40, &frame(second), true, &mut fragments),
        vec![Said::Block {
            hash: HASH,
            start: 9_728_000,
            bytes: plain
        }]
    );
}

/// A v4 source answer strides 29 bytes a record; the ID leads each.
#[test]
fn a_v4_source_answer_reads_each_records_id() {
    let mut body = vec![4u8];
    body.extend_from_slice(&HASH);
    body.extend_from_slice(&2u16.to_le_bytes());
    for id in [0x0300_13ACu32, 0x0400_13AC] {
        body.extend_from_slice(&id.to_le_bytes());
        body.extend_from_slice(&[0u8; 25]);
    }
    assert_eq!(
        decoded(0xC5, 0x84, &body, true),
        vec![Said::Sources {
            hash: HASH,
            ids: vec![0x0300_13AC, 0x0400_13AC]
        }]
    );
}

/// aMule's bundle carries its own status after the name ask; the source
/// ask after it is still found.
#[test]
fn a_bundle_with_the_askers_status_still_shows_its_source_ask() {
    let mut body = HASH.to_vec();
    body.extend_from_slice(&52_640_000u64.to_le_bytes());
    body.push(0x58);
    body.extend_from_slice(&6u16.to_le_bytes());
    body.push(0);
    body.push(0x4F);
    body.extend_from_slice(&[0x83, 4, 0, 0]);
    assert_eq!(
        decoded(0xC5, 0xA4, &body, false),
        vec![Said::NameAsk {
            hash: HASH,
            sources_asked: true
        }]
    );
}

/// A reask answer carries the status when the asker's UDP version asks for
/// it, else the rank alone; count `0` is the complete-file form.
#[test]
fn a_reask_answer_reads_with_or_without_its_status() {
    let mut with_status = vec![0xC5, 0x91];
    with_status.extend_from_slice(&6u16.to_le_bytes());
    with_status.push(0b0000_1001);
    with_status.extend_from_slice(&1u16.to_le_bytes());
    assert_eq!(
        decode_udp(&with_status, true),
        Some(Udp::Ack {
            status: Some(Status {
                count: 6,
                held: [0, 3].into()
            }),
            rank: 1
        })
    );
    assert_eq!(
        decode_udp(&[0xC5, 0x91, 0, 0, 2, 0], true),
        Some(Udp::Ack {
            status: Some(Status {
                count: 0,
                held: [].into()
            }),
            rank: 2
        })
    );
    assert_eq!(
        decode_udp(&[0xC5, 0x91, 3, 0], true),
        Some(Udp::Ack {
            status: None,
            rank: 3
        })
    );
}
