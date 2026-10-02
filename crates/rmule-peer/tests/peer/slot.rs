//! Cites at amule 377ec8d9:
//!   OP_STARTUPLOADREQ  = 0x54 (OP_EDONKEYPROT) — <HASH 16>
//!   OP_ACCEPTUPLOADREQ = 0x55 (OP_EDONKEYPROT) — empty
//!   OP_CANCELTRANSFER  = 0x56 (OP_EDONKEYPROT) — empty; symmetric cancel (ADR-0056)
//!   OP_OUTOFPARTREQS   = 0x57 (OP_EDONKEYPROT) — empty; TCP "no slot now"
//!   OP_QUEUERANKING    = 0x60 (OP_EMULEPROT)   — exactly 12 bytes:
//!                        u16 rank + u32 + u32 + u16 zero pad
//!
//! aMule receiver `ClientTCPSocket.cpp:1331-1349` requires `size == 12`
//! and reads only `PeekUInt16(buffer)` — trailing 10 bytes are ignored.
//! eMule spec §6.5.4 documents the 10 trailing zeros as "purpose unknown".

use rmule_peer::PeerPacket;
use rmule_primitives::{FileHash, Packet, PacketProtocol};

fn hash() -> FileHash {
    FileHash::from_bytes([0x42; 16])
}

#[test]
fn op_startuploadreq_round_trips() {
    let payload = hash().as_bytes().to_vec();
    let packet = Packet::new(PacketProtocol::Edonkey, 0x54, payload.clone());
    match PeerPacket::decode(&packet).expect("startuploadreq") {
        PeerPacket::StartUploadReq(s) => {
            assert_eq!(s.file_hash, hash());
            assert_eq!(s.encode_packet().payload(), payload.as_slice());
            assert_eq!(s.encode_packet().protocol(), PacketProtocol::Edonkey);
        }
        other => panic!("expected StartUploadReq, got {other:?}"),
    }
}

#[test]
fn op_acceptuploadreq_round_trips_empty_payload() {
    let packet = Packet::new(PacketProtocol::Edonkey, 0x55, Vec::new());
    match PeerPacket::decode(&packet).expect("accept") {
        PeerPacket::AcceptUploadReq(a) => {
            assert_eq!(a.encode_packet().payload(), &[] as &[u8]);
            assert_eq!(a.encode_packet().opcode(), 0x55);
        }
        other => panic!("expected AcceptUploadReq, got {other:?}"),
    }
}

#[test]
fn op_canceltransfer_round_trips_empty_payload() {
    let packet = Packet::new(PacketProtocol::Edonkey, 0x56, Vec::new());
    match PeerPacket::decode(&packet).expect("canceltransfer") {
        PeerPacket::CancelTransfer(c) => {
            assert_eq!(c.encode_packet().payload(), &[] as &[u8]);
            assert_eq!(c.encode_packet().opcode(), 0x56);
            assert_eq!(c.encode_packet().protocol(), PacketProtocol::Edonkey);
        }
        other => panic!("expected CancelTransfer, got {other:?}"),
    }
}

#[test]
fn op_outofpartreqs_round_trips_empty_payload() {
    let packet = Packet::new(PacketProtocol::Edonkey, 0x57, Vec::new());
    match PeerPacket::decode(&packet).expect("outofpartreqs") {
        PeerPacket::OutOfPartReqs(o) => {
            assert_eq!(o.encode_packet().payload(), &[] as &[u8]);
            assert_eq!(o.encode_packet().opcode(), 0x57);
        }
        other => panic!("expected OutOfPartReqs, got {other:?}"),
    }
}

#[test]
fn op_acceptuploadreq_rejects_nonempty_payload() {
    let packet = Packet::new(PacketProtocol::Edonkey, 0x55, vec![0xFF]);
    assert!(PeerPacket::decode(&packet).is_err());
}

#[test]
fn op_outofpartreqs_rejects_nonempty_payload() {
    let packet = Packet::new(PacketProtocol::Edonkey, 0x57, vec![0xFF]);
    assert!(PeerPacket::decode(&packet).is_err());
}

fn build_ranking_payload(rank: u16) -> Vec<u8> {
    let mut payload = Vec::with_capacity(12);
    payload.extend_from_slice(&rank.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload
}

#[test]
fn op_queueranking_decodes_rank_samples_over_emule_protocol() {
    for &rank in &[0u16, 1, u16::MAX] {
        let payload = build_ranking_payload(rank);
        let packet = Packet::new(PacketProtocol::Emule, 0x60, payload.clone());
        match PeerPacket::decode(&packet).expect("queueranking") {
            PeerPacket::QueueRanking(q) => {
                assert_eq!(q.rank, rank);
                let re = q.encode_packet();
                assert_eq!(re.payload(), payload.as_slice());
                assert_eq!(re.protocol(), PacketProtocol::Emule);
                assert_eq!(re.opcode(), 0x60);
            }
            other => panic!("expected QueueRanking, got {other:?}"),
        }
    }
}

#[test]
fn op_queueranking_rejects_wrong_payload_size() {
    for &len in &[0usize, 2, 4, 11, 13, 16] {
        let packet = Packet::new(PacketProtocol::Emule, 0x60, vec![0u8; len]);
        let result = PeerPacket::decode(&packet);
        assert!(
            result.is_err(),
            "expected error for len {len}, got {result:?}"
        );
    }
}

#[test]
fn op_queueranking_tolerates_nonzero_trailing_pad_on_decode() {
    // aMule reads first 2 bytes only (PeekUInt16) — trailing 10 bytes
    // are ignored regardless of content.
    let mut payload = 7u16.to_le_bytes().to_vec();
    payload.extend_from_slice(&[0xFFu8; 10]);
    let packet = Packet::new(PacketProtocol::Emule, 0x60, payload);
    match PeerPacket::decode(&packet).expect("queueranking with dirty pad") {
        PeerPacket::QueueRanking(q) => {
            assert_eq!(q.rank, 7);
            // Re-encode always writes zero pad.
            let re = q.encode_packet();
            assert_eq!(&re.payload()[2..], &[0u8; 10]);
        }
        other => panic!("expected QueueRanking, got {other:?}"),
    }
}

#[test]
fn opcode_0x60_dispatches_by_protocol_byte() {
    let payload = build_ranking_payload(42);
    // Same opcode, eDonkey protocol: not QueueRanking — `OP_ASKSHAREDFILESDIRANS`
    // (ADR-0068 human-layer catalog), an unsolicited browse answer rmule
    // parses, counts, and drops; its payload is not inspected.
    let edonkey = Packet::new(PacketProtocol::Edonkey, 0x60, payload);
    assert_eq!(
        PeerPacket::decode(&edonkey).expect("edonkey 0x60"),
        PeerPacket::AskSharedFilesDirAns
    );
}
