//! Cites at amule 377ec8d9:
//!   OP_REQUESTPARTS     = 0x47 (OP_EDONKEYPROT) <HASH 16><start[3] u32×3><end[3] u32×3>
//!   OP_REQUESTPARTS_I64 = 0xA3 (OP_EMULEPROT)   <HASH 16><start[3] u64×3><end[3] u64×3>
//!   OP_SENDINGPART      = 0x46 (OP_EDONKEYPROT) <HASH 16><start u32><end u32><data>
//!   OP_SENDINGPART_I64  = 0xA2 (OP_EMULEPROT)   <HASH 16><start u64><end u64><data>
//!
//! `DownloadClient.cpp::SendBlockRequests` always writes exactly 3
//! (start, end) pairs; unused slots are zero-padded with `(0, 0)`
//! sentinels. The receiver `UploadClient.cpp::ProcessRequestPartsPacket`
//! unconditionally reads 3 pairs — fewer pairs corrupts the wire.

use rmule_peer::{
    CompressedPart, PartOffsetWidth, PartRanges, PeerPacket, RequestParts, SendingPart,
};
use rmule_primitives::{FileHash, Packet, PacketProtocol};

fn hash() -> FileHash {
    FileHash::from_bytes([0x77; 16])
}

#[test]
fn part_offset_width_picks_u32_below_or_equal_4gb_minus_one() {
    assert_eq!(PartOffsetWidth::for_file_size(0), PartOffsetWidth::U32);
    assert_eq!(PartOffsetWidth::for_file_size(1), PartOffsetWidth::U32);
    assert_eq!(
        PartOffsetWidth::for_file_size(u32::MAX as u64),
        PartOffsetWidth::U32
    );
    assert_eq!(
        PartOffsetWidth::for_file_size(u32::MAX as u64 + 1),
        PartOffsetWidth::U64
    );
    assert_eq!(
        PartOffsetWidth::for_file_size(u64::MAX),
        PartOffsetWidth::U64
    );
}

#[test]
fn requestparts_u32_encode_matches_handwritten_bytes() {
    let ranges = PartRanges::new([
        (100, 200),
        (1_000_000, 2_000_000),
        (u32::MAX as u64, u32::MAX as u64),
    ])
    .unwrap();
    let req = RequestParts {
        file_hash: hash(),
        ranges,
    };

    let mut expected = hash().as_bytes().to_vec();
    expected.extend_from_slice(&100u32.to_le_bytes());
    expected.extend_from_slice(&1_000_000u32.to_le_bytes());
    expected.extend_from_slice(&(u32::MAX).to_le_bytes());
    expected.extend_from_slice(&200u32.to_le_bytes());
    expected.extend_from_slice(&2_000_000u32.to_le_bytes());
    expected.extend_from_slice(&(u32::MAX).to_le_bytes());

    let packet = req.encode_packet(PartOffsetWidth::U32).unwrap();
    assert_eq!(packet.protocol(), PacketProtocol::Edonkey);
    assert_eq!(packet.opcode(), 0x47);
    assert_eq!(packet.payload(), expected.as_slice());
}

#[test]
fn requestparts_u64_encode_matches_handwritten_bytes_for_i64_variant() {
    let big = 5_000_000_000u64;
    let ranges = PartRanges::new([(big, big + 100), (0, 0), (0, 0)]).unwrap();
    let req = RequestParts {
        file_hash: hash(),
        ranges,
    };

    let mut expected = hash().as_bytes().to_vec();
    expected.extend_from_slice(&big.to_le_bytes());
    expected.extend_from_slice(&0u64.to_le_bytes());
    expected.extend_from_slice(&0u64.to_le_bytes());
    expected.extend_from_slice(&(big + 100).to_le_bytes());
    expected.extend_from_slice(&0u64.to_le_bytes());
    expected.extend_from_slice(&0u64.to_le_bytes());

    let packet = req.encode_packet(PartOffsetWidth::U64).unwrap();
    assert_eq!(packet.protocol(), PacketProtocol::Emule);
    assert_eq!(packet.opcode(), 0xA3);
    assert_eq!(packet.payload(), expected.as_slice());
}

#[test]
fn requestparts_u32_encode_rejects_ranges_overflowing_u32() {
    let ranges = PartRanges::new([(0, u32::MAX as u64 + 1), (0, 0), (0, 0)]).unwrap();
    let req = RequestParts {
        file_hash: hash(),
        ranges,
    };
    assert!(req.encode_packet(PartOffsetWidth::U32).is_err());
}

#[test]
fn requestparts_u64_encode_accepts_ranges_within_u32() {
    let ranges = PartRanges::new([(100, 200), (0, 0), (0, 0)]).unwrap();
    let req = RequestParts {
        file_hash: hash(),
        ranges,
    };
    // Encoding a small-file range with U64 width is fine — payload
    // just zero-extends each value to 8 bytes.
    let packet = req.encode_packet(PartOffsetWidth::U64).unwrap();
    assert_eq!(packet.protocol(), PacketProtocol::Emule);
    assert_eq!(packet.opcode(), 0xA3);
}

#[test]
fn sendingpart_u32_decodes() {
    let data: Vec<u8> = (0..16u8).collect();
    let mut payload = hash().as_bytes().to_vec();
    payload.extend_from_slice(&100u32.to_le_bytes());
    payload.extend_from_slice(&(100u32 + data.len() as u32).to_le_bytes());
    payload.extend_from_slice(&data);

    let packet = Packet::new(PacketProtocol::Edonkey, 0x46, payload.clone());
    match PeerPacket::decode(&packet).expect("sendingpart") {
        PeerPacket::SendingPart(sp) => {
            assert_eq!(sp.file_hash, hash());
            assert_eq!(sp.start, 100);
            assert_eq!(sp.end, 100 + data.len() as u64);
            assert_eq!(sp.data, data);
            let re = sp.encode_packet(PartOffsetWidth::U32).unwrap();
            assert_eq!(re.opcode(), 0x46);
            assert_eq!(re.payload(), payload.as_slice());
        }
        other => panic!("expected SendingPart, got {other:?}"),
    }
}

#[test]
fn sendingpart_i64_decodes() {
    let big = 5_000_000_000u64;
    let data: Vec<u8> = (0..16u8).collect();
    let mut payload = hash().as_bytes().to_vec();
    payload.extend_from_slice(&big.to_le_bytes());
    payload.extend_from_slice(&(big + data.len() as u64).to_le_bytes());
    payload.extend_from_slice(&data);

    let packet = Packet::new(PacketProtocol::Emule, 0xA2, payload.clone());
    match PeerPacket::decode(&packet).expect("sendingpart_i64") {
        PeerPacket::SendingPart(sp) => {
            assert_eq!(sp.start, big);
            assert_eq!(sp.end, big + data.len() as u64);
            assert_eq!(sp.data, data);
            let re = sp.encode_packet(PartOffsetWidth::U64).unwrap();
            assert_eq!(re.protocol(), PacketProtocol::Emule);
            assert_eq!(re.opcode(), 0xA2);
            assert_eq!(re.payload(), payload.as_slice());
        }
        other => panic!("expected SendingPart, got {other:?}"),
    }
}

#[test]
fn sendingpart_round_trips_with_decoder_choosing_variant_by_opcode() {
    // Decoder picks u32 vs u64 by opcode; encoder picks by caller-supplied width.
    let u32_packet = Packet::new(PacketProtocol::Edonkey, 0x46, {
        let mut p = hash().as_bytes().to_vec();
        p.extend_from_slice(&0u32.to_le_bytes());
        p.extend_from_slice(&3u32.to_le_bytes());
        p.extend_from_slice(b"abc");
        p
    });
    let sp = match PeerPacket::decode(&u32_packet).unwrap() {
        PeerPacket::SendingPart(sp) => sp,
        _ => panic!(),
    };
    // Width mismatch: encoding u32 wire opcode but caller declared U64
    // would re-emit OP_SENDINGPART_I64 — that's the caller's choice;
    // tested separately. Same SendingPart value supports both.
    assert!(sp.encode_packet(PartOffsetWidth::U32).is_ok());
    assert!(sp.encode_packet(PartOffsetWidth::U64).is_ok());
}

#[test]
fn sendingpart_u32_encode_rejects_offsets_above_u32_max() {
    let sp = SendingPart {
        file_hash: hash(),
        start: u32::MAX as u64 + 1,
        end: u32::MAX as u64 + 100,
        data: vec![0u8; 99],
    };
    assert!(sp.encode_packet(PartOffsetWidth::U32).is_err());
}

#[test]
fn compressedpart_u32_decodes_header_and_chunk() {
    // [HASH 16][start u32][nBlockSize u32][compressed chunk to end].
    let chunk = vec![0x78, 0x9c, 0xDE, 0xAD, 0xBE, 0xEF];
    let mut payload = hash().as_bytes().to_vec();
    payload.extend_from_slice(&184_320u32.to_le_bytes()); // start
    payload.extend_from_slice(&4242u32.to_le_bytes()); // nBlockSize (total)
    payload.extend_from_slice(&chunk);

    let packet = Packet::new(PacketProtocol::Emule, 0x40, payload);
    let cp = CompressedPart::decode_packet(&packet).expect("compressedpart");
    assert_eq!(cp.file_hash, hash());
    assert_eq!(cp.start, 184_320);
    assert_eq!(cp.compressed_block_len, 4242);
    assert_eq!(cp.compressed_chunk, chunk);
}

#[test]
fn compressedpart_i64_uses_u64_start_but_keeps_u32_block_len() {
    // The I64 variant widens only `start`; `nBlockSize` stays u32.
    let big = 5_000_000_000u64;
    let chunk = vec![1u8, 2, 3];
    let mut payload = hash().as_bytes().to_vec();
    payload.extend_from_slice(&big.to_le_bytes()); // start u64
    payload.extend_from_slice(&77u32.to_le_bytes()); // nBlockSize u32 (not widened)
    payload.extend_from_slice(&chunk);

    let packet = Packet::new(PacketProtocol::Emule, 0xA1, payload);
    let cp = CompressedPart::decode_packet(&packet).expect("compressedpart_i64");
    assert_eq!(cp.start, big);
    assert_eq!(cp.compressed_block_len, 77);
    assert_eq!(cp.compressed_chunk, chunk);
}

#[test]
fn partranges_rejects_start_after_end() {
    // Defensive constructor check — the wire allows it but the meaning
    // is undefined; aMule treats start > end as malformed.
    let r = PartRanges::new([(10, 5), (0, 0), (0, 0)]);
    assert!(r.is_err());
}

#[test]
fn sendingpart_decode_rejects_payload_short_for_declared_range() {
    // declared end - start = 1000 but only 4 bytes of data supplied
    let mut payload = hash().as_bytes().to_vec();
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&1000u32.to_le_bytes());
    payload.extend_from_slice(&[0xFFu8; 4]);
    let packet = Packet::new(PacketProtocol::Edonkey, 0x46, payload);
    assert!(PeerPacket::decode(&packet).is_err());
}
