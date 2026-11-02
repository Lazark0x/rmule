//! Stock aMule 2.3.3's large-file frames, captured live over a file past
//! 4 GiB (`fixtures/large_file/captured/*/meta.toml`): rmule reads each and
//! writes the same bytes back, and it reads stock's hello as claiming them.

use crate::fixture::load;
use rmule_peer::{MiscOptions2, PartOffsetWidth, PeerPacket};
use rmule_primitives::Packet;

const FIXTURE_DIR: &str = "fixtures/large_file/captured/amule-233-large-file-20261101/";

const FOUR_GIB: u64 = 1 << 32;

fn decode_single(name: &str) -> (Vec<u8>, Packet, PeerPacket) {
    let bytes = load(FIXTURE_DIR, name);
    let (packet, consumed) = Packet::decode(&bytes).expect("fixture frame decodes");
    assert_eq!(consumed, bytes.len(), "{name} is exactly one frame");
    let decoded = PeerPacket::decode(&packet).expect("peer packet decodes");
    (bytes, packet, decoded)
}

#[test]
fn stock_claims_large_files_in_its_hello() {
    let (_, _, decoded) = decode_single("hello_answer_0x4c.bin");
    let PeerPacket::HelloAnswer(answer) = decoded else {
        panic!("expected HelloAnswer, got {decoded:?}");
    };
    let misc2 = MiscOptions2::from_tags(&answer.body().tags).expect("stock sends MiscOptions2");
    assert!(misc2.supports_large_files());
}

/// A block past 4 GiB takes the request to `_I64`: the rule
/// [`rmule_peer::PartRanges::width`] writes by.
#[test]
fn stocks_request_past_four_gib_reads_and_reencodes_byte_for_byte() {
    let (bytes, _, decoded) = decode_single("request_parts_i64_0xa3.bin");
    let PeerPacket::RequestParts(request) = decoded else {
        panic!("expected RequestParts, got {decoded:?}");
    };
    assert!(request.ranges.live().all(|(start, _)| start > FOUR_GIB));
    assert_eq!(request.ranges.width(), PartOffsetWidth::U64);
    let written = request.encode_packet(request.ranges.width()).unwrap();
    assert_eq!(written.encode(), bytes);
}

#[test]
fn stocks_plain_block_past_four_gib_reads_and_reencodes_byte_for_byte() {
    let (bytes, packet, decoded) = decode_single("sending_part_i64_0xa2.bin");
    let PeerPacket::SendingPart(part) = decoded else {
        panic!("expected SendingPart, got {decoded:?}");
    };
    assert!(part.start > FOUR_GIB);
    assert_eq!(part.end - part.start, part.data.len() as u64);
    assert_eq!(packet.opcode(), 0xA2);
    let written = part.encode_packet(PartOffsetWidth::U64).unwrap();
    assert_eq!(written.encode(), bytes);
}

/// The block across the 4 GiB offset: its start fits a `u32` and the frame is
/// still `_I64`, since stock judges the whole block (`UploadClient.cpp:361`).
#[test]
fn stocks_compressed_block_across_four_gib_reads_and_reencodes_byte_for_byte() {
    let (bytes, _, decoded) = decode_single("compressed_part_i64_0xa1.bin");
    let PeerPacket::CompressedPart(part) = decoded else {
        panic!("expected CompressedPart, got {decoded:?}");
    };
    assert!(part.start < FOUR_GIB && part.start + rmule_peer::EMBLOCKSIZE > FOUR_GIB);
    assert_eq!(
        part.compressed_block_len as usize,
        part.compressed_chunk.len()
    );
    let written = part.encode_packet(PartOffsetWidth::U64).unwrap();
    assert_eq!(written.encode(), bytes);
}
