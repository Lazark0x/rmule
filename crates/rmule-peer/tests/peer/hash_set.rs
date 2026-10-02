//! Cites at amule 377ec8d9:
//!   OP_HASHSETREQUEST = 0x51 — payload `<HASH 16>`
//!   OP_HASHSETANSWER  = 0x52 — actual wire is `<HASH 16><u16 part_count><PartHash[count]>`.
//!     TCP.h comment lies (`<count 2><HASH[count] 16*count>`); the handler
//!     `DownloadClient.cpp::ProcessHashSet` reads the leading file_hash via
//!     `md4cmp(packet, ...)` before the part-hash array.
//!
//! rmule reuses `PartHash` (the 16-byte MD4 newtype already in
//! `rmule-primitives::hash`); there is no separate `Md4` primitive.

use rmule_peer::PeerPacket;
use rmule_primitives::{FileHash, Packet, PacketProtocol, PartHash};

fn hash() -> FileHash {
    FileHash::from_bytes([0x01; 16])
}

fn part_hash(seed: u8) -> PartHash {
    PartHash::from_bytes([seed; 16])
}

#[test]
fn op_hashsetrequest_round_trips() {
    let payload = hash().as_bytes().to_vec();
    let packet = Packet::new(PacketProtocol::Edonkey, 0x51, payload.clone());
    match PeerPacket::decode(&packet).expect("request") {
        PeerPacket::HashSetRequest(r) => {
            assert_eq!(r.file_hash, hash());
            assert_eq!(r.encode_packet().payload(), payload.as_slice());
        }
        other => panic!("expected HashSetRequest, got {other:?}"),
    }
}

#[test]
fn op_hashsetanswer_round_trips_with_three_part_hashes() {
    let parts = vec![part_hash(0xAA), part_hash(0xBB), part_hash(0xCC)];
    let mut payload = hash().as_bytes().to_vec();
    payload.extend_from_slice(&(parts.len() as u16).to_le_bytes());
    for p in &parts {
        payload.extend_from_slice(p.as_bytes());
    }

    let packet = Packet::new(PacketProtocol::Edonkey, 0x52, payload.clone());
    match PeerPacket::decode(&packet).expect("answer") {
        PeerPacket::HashSetAnswer(a) => {
            assert_eq!(a.file_hash, hash());
            assert_eq!(a.part_hashes, parts);
            assert_eq!(a.encode_packet().payload(), payload.as_slice());
        }
        other => panic!("expected HashSetAnswer, got {other:?}"),
    }
}

#[test]
fn op_hashsetanswer_round_trips_with_single_part_hash() {
    let parts = [part_hash(0x55)];
    let mut payload = hash().as_bytes().to_vec();
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.extend_from_slice(parts[0].as_bytes());

    let packet = Packet::new(PacketProtocol::Edonkey, 0x52, payload.clone());
    match PeerPacket::decode(&packet).expect("answer") {
        PeerPacket::HashSetAnswer(a) => {
            assert_eq!(a.part_hashes.len(), 1);
            assert_eq!(a.encode_packet().payload(), payload.as_slice());
        }
        other => panic!("expected HashSetAnswer, got {other:?}"),
    }
}

#[test]
fn op_hashsetanswer_rejects_count_payload_disagreement() {
    // Declare 3 hashes but only supply 2 (32 bytes after the count).
    let mut payload = hash().as_bytes().to_vec();
    payload.extend_from_slice(&3u16.to_le_bytes());
    payload.extend_from_slice(part_hash(0).as_bytes());
    payload.extend_from_slice(part_hash(1).as_bytes());
    let packet = Packet::new(PacketProtocol::Edonkey, 0x52, payload);
    assert!(PeerPacket::decode(&packet).is_err());
}

#[test]
fn op_hashsetanswer_accepts_zero_part_count_for_single_chunk_file() {
    // A single-chunk file (size <= ED2K_PART_SIZE) has its whole-file
    // MD4 as the only part hash, so real eMule peers answer
    // OP_HASHSETANSWER with part_count = 0 and no hash array. Captured
    // live from the official emule-project.net client (client_id
    // 848213584) answering for the 3.4 MB
    // "Rick Astley - Never Gonna Give You Up.mp3" during the core-peer
    // CLI audit. Per ADR-0018 this well-formed packet is preserved, not
    // rejected; core then verifies the lone part via the whole-file hash.
    let file_hash = FileHash::from_bytes([
        0x45, 0x64, 0x91, 0x2F, 0xC0, 0x2A, 0x89, 0x1A, 0x92, 0x01, 0x65, 0x80, 0x30, 0x91, 0x48,
        0x29,
    ]);
    let mut payload = file_hash.as_bytes().to_vec();
    payload.extend_from_slice(&0u16.to_le_bytes());
    let packet = Packet::new(PacketProtocol::Edonkey, 0x52, payload.clone());
    match PeerPacket::decode(&packet).expect("zero-part answer decodes") {
        PeerPacket::HashSetAnswer(a) => {
            assert_eq!(a.file_hash, file_hash);
            assert!(a.part_hashes.is_empty());
            assert_eq!(a.encode_packet().payload(), payload.as_slice());
        }
        other => panic!("expected HashSetAnswer, got {other:?}"),
    }
}

#[test]
fn op_hashsetanswer_rejects_trailing_bytes() {
    let mut payload = hash().as_bytes().to_vec();
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.extend_from_slice(part_hash(0).as_bytes());
    payload.push(0xFF); // trailing byte not covered by declared hash count
    let packet = Packet::new(PacketProtocol::Edonkey, 0x52, payload);
    assert!(PeerPacket::decode(&packet).is_err());
}
