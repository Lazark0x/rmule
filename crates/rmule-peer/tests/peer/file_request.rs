//! Opcode + payload citations: `src/include/protocol/ed2k/Client2Client/TCP.h`
//! at amule `377ec8d9`:
//!   OP_REQUESTFILENAME   = 0x58  (client → peer)  <HASH 16>[<u16 part_count><bitmap>]
//!   OP_REQFILENAMEANSWER = 0x59  (peer → client)  <HASH 16><u16 len><name>
//!   OP_FILEREQANSNOFIL   = 0x48  (peer → client)  <HASH 16>
//!   OP_SETREQFILEID      = 0x4F  (client → peer)  <HASH 16>
//!   OP_FILESTATUS        = 0x50  (peer → client)  <HASH 16><u16 part_count><bitmap>
//!
//! The TCP.h comment for OP_REQFILENAMEANSWER says `<len 4>` but the
//! actual handler (DownloadClient.cpp::ProcessFileInfo) calls
//! `data->ReadString(...)` whose default `lenBytes = 2`
//! (SafeFile.h:155). u16 is the truth.

use rmule_peer::file::PartBitmap;
use rmule_peer::{PeerPacket, RequestFileName};
use rmule_primitives::{FileHash, Packet, PacketProtocol};

fn hash() -> FileHash {
    FileHash::from_bytes([
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99,
    ])
}

fn assert_round_trip(opcode: u8, payload: Vec<u8>, expected_kind: &str) {
    let packet = Packet::new(PacketProtocol::Edonkey, opcode, payload.clone());
    let decoded = PeerPacket::decode(&packet).expect(expected_kind);
    let reencoded = decoded.encode();
    assert_eq!(reencoded.protocol(), PacketProtocol::Edonkey);
    assert_eq!(reencoded.opcode(), opcode);
    assert_eq!(reencoded.payload(), payload.as_slice());
}

#[test]
fn op_request_filename_round_trips() {
    assert_round_trip(0x58, hash().as_bytes().to_vec(), "request filename");
    // Confirm typed projection.
    let packet = Packet::new(PacketProtocol::Edonkey, 0x58, hash().as_bytes().to_vec());
    match PeerPacket::decode(&packet).unwrap() {
        PeerPacket::RequestFileName(r) => assert_eq!(r.file_hash, hash()),
        other => panic!("expected RequestFileName, got {other:?}"),
    }
}

#[test]
fn op_reqfilenameanswer_round_trips_with_u16_length_prefix() {
    let name = b"shared-file.bin";
    let mut payload = Vec::new();
    payload.extend_from_slice(hash().as_bytes());
    payload.extend_from_slice(&(name.len() as u16).to_le_bytes());
    payload.extend_from_slice(name);

    let packet = Packet::new(PacketProtocol::Edonkey, 0x59, payload.clone());
    match PeerPacket::decode(&packet).expect("answer") {
        PeerPacket::ReqFileNameAnswer(r) => {
            assert_eq!(r.file_hash, hash());
            assert_eq!(r.file_name.as_bytes(), name);
            assert_eq!(r.encode_packet().payload(), payload.as_slice());
        }
        other => panic!("expected ReqFileNameAnswer, got {other:?}"),
    }
}

#[test]
fn op_reqfilenameanswer_rejects_truncated_length_prefix() {
    let mut payload = hash().as_bytes().to_vec();
    payload.push(0x00); // only one length byte
    let packet = Packet::new(PacketProtocol::Edonkey, 0x59, payload);
    assert!(PeerPacket::decode(&packet).is_err());
}

#[test]
fn op_reqfilenameanswer_rejects_name_length_overrun() {
    let mut payload = hash().as_bytes().to_vec();
    payload.extend_from_slice(&100u16.to_le_bytes());
    payload.extend_from_slice(b"only-3"); // declared 100, given 6
    let packet = Packet::new(PacketProtocol::Edonkey, 0x59, payload);
    assert!(PeerPacket::decode(&packet).is_err());
}

#[test]
fn op_filereqansnofil_round_trips() {
    assert_round_trip(0x48, hash().as_bytes().to_vec(), "no file answer");
    let packet = Packet::new(PacketProtocol::Edonkey, 0x48, hash().as_bytes().to_vec());
    match PeerPacket::decode(&packet).unwrap() {
        PeerPacket::FileReqAnsNoFil(r) => assert_eq!(r.file_hash, hash()),
        other => panic!("expected FileReqAnsNoFil, got {other:?}"),
    }
}

#[test]
fn op_setreqfileid_round_trips() {
    assert_round_trip(0x4F, hash().as_bytes().to_vec(), "set req file id");
    let packet = Packet::new(PacketProtocol::Edonkey, 0x4F, hash().as_bytes().to_vec());
    match PeerPacket::decode(&packet).unwrap() {
        PeerPacket::SetReqFileId(r) => assert_eq!(r.file_hash, hash()),
        other => panic!("expected SetReqFileId, got {other:?}"),
    }
}

#[test]
fn op_filestatus_round_trips_with_bitmap() {
    let part_count: u16 = 10;
    let bitmap_bytes = [0b1010_1010u8, 0b0000_0011];
    let mut payload = Vec::new();
    payload.extend_from_slice(hash().as_bytes());
    payload.extend_from_slice(&part_count.to_le_bytes());
    payload.extend_from_slice(&bitmap_bytes);

    let packet = Packet::new(PacketProtocol::Edonkey, 0x50, payload.clone());
    match PeerPacket::decode(&packet).expect("file status") {
        PeerPacket::FileStatus(fs) => {
            assert_eq!(fs.file_hash, hash());
            assert_eq!(fs.bitmap.part_count(), part_count as u32);
            assert_eq!(fs.bitmap.encode(), bitmap_bytes.to_vec());
            assert_eq!(fs.encode_packet().payload(), payload.as_slice());
        }
        other => panic!("expected FileStatus, got {other:?}"),
    }
}

#[test]
fn op_filestatus_complete_file_signal_is_zero_part_count_no_bitmap() {
    // aMule's wire convention: part_count = 0 means "peer has complete file".
    // PartBitmap decodes literally (empty bitmap); session layer interprets.
    let mut payload = hash().as_bytes().to_vec();
    payload.extend_from_slice(&0u16.to_le_bytes());

    let packet = Packet::new(PacketProtocol::Edonkey, 0x50, payload.clone());
    match PeerPacket::decode(&packet).expect("file status complete") {
        PeerPacket::FileStatus(fs) => {
            assert_eq!(fs.bitmap.part_count(), 0);
            assert_eq!(fs.bitmap.iter_present().count(), 0);
            assert_eq!(fs.encode_packet().payload(), payload.as_slice());
        }
        other => panic!("expected FileStatus, got {other:?}"),
    }
}

#[test]
fn op_filestatus_rejects_bitmap_length_mismatch() {
    let mut payload = hash().as_bytes().to_vec();
    payload.extend_from_slice(&10u16.to_le_bytes());
    payload.push(0xFF); // declared 10 parts → expects 2 bytes, given 1
    let packet = Packet::new(PacketProtocol::Edonkey, 0x50, payload);
    assert!(PeerPacket::decode(&packet).is_err());
}

#[test]
fn unknown_opcode_in_family_preserves_bytes_with_protocol_attribution() {
    let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
    // 0x53 is unused in the file-request family at the pin.
    let packet = Packet::new(PacketProtocol::Edonkey, 0x53, payload.clone());
    match PeerPacket::decode(&packet).unwrap() {
        PeerPacket::Unknown {
            protocol,
            opcode,
            payload: bytes,
        } => {
            assert_eq!(protocol, PacketProtocol::Edonkey);
            assert_eq!(opcode, 0x53);
            assert_eq!(bytes, payload);
        }
        other => panic!("expected Unknown, got {other:?}"),
    }
}

/// `OP_REQUESTFILENAME`'s two shapes: the bare hash at
/// extended-requests level 0, and the hash then `WritePartStatus`'s
/// `<u16 count><bitmap>` at level 1. The decoder keeps every byte after the
/// hash unread — a level-2 writer's trailing complete-source count included —
/// for the serving side to read against the asked file.
#[test]
fn a_name_ask_carries_the_askers_part_status_when_the_level_asks_for_it() {
    let bare = RequestFileName::new(hash(), None);
    assert_eq!(bare.encode_packet().payload(), hash().as_bytes());
    assert_eq!(
        RequestFileName::decode_packet(&bare.encode_packet()),
        Ok(bare)
    );

    let status = PartBitmap::decode(10, &[0b1010_0101, 0b10]).unwrap();
    let with_status = RequestFileName::new(hash(), Some(&status));
    let mut wire = hash().as_bytes().to_vec();
    wire.extend_from_slice(&[0x0A, 0x00, 0b1010_0101, 0b10]);
    assert_eq!(with_status.encode_packet().payload(), wire.as_slice());

    wire.extend_from_slice(&7u16.to_le_bytes());
    let level_two = Packet::new(PacketProtocol::Edonkey, 0x58, wire.clone());
    assert_eq!(
        RequestFileName::decode_packet(&level_two)
            .unwrap()
            .status
            .as_bytes(),
        &wire[FileHash::BYTE_LEN..],
    );
}
