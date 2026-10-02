//! ADR-0054 KATs: opcode registration + the composition property (bundle
//! items decode to the same typed values the standalone codecs produce for
//! logically-equivalent data).

use rmule_peer::multipacket::{AnswerItem, MultiPacketAnswer, MultiPacketRequest, RequestItem};
use rmule_peer::{AichFileHashAns, FileStatus, PeerOpcode, PeerPacket, ReqFileNameAnswer};
use rmule_primitives::{AichRootHash, Ed2kText, FileHash, Packet, PacketProtocol};

fn hash() -> FileHash {
    FileHash::from_bytes([0x9A; FileHash::BYTE_LEN])
}

#[test]
fn multipacket_opcodes_are_registered_under_emule_protocol() {
    assert_eq!(PeerOpcode::MultiPacket.as_u8(), 0x92);
    assert_eq!(PeerOpcode::MultiPacketExt.as_u8(), 0xA4);
    assert_eq!(PeerOpcode::MultiPacketAnswer.as_u8(), 0x93);
    assert_eq!(PeerOpcode::MultiPacket.protocol(), PacketProtocol::Emule);
    assert_eq!(PeerOpcode::MultiPacketExt.protocol(), PacketProtocol::Emule);
    assert_eq!(
        PeerOpcode::MultiPacketAnswer.protocol(),
        PacketProtocol::Emule
    );
}

#[test]
fn umbrella_dispatches_multipacket_request_and_answer_opcodes() {
    // The umbrella does not preserve these opcodes as Unknown bytes — each
    // decodes into its own PeerPacket
    // variant via the `multipacket` module's own walkers (ADR-0054), the same
    // pattern `RequestParts`/`RequestPartsI64` already use.
    let fh = hash();

    let base_request = MultiPacketRequest {
        file_hash: fh,
        file_size: None,
        items: vec![
            RequestItem::Name { part_status: None },
            RequestItem::SetReqId,
        ],
        unknown_sub: None,
        cut: None,
    };
    match PeerPacket::decode(&base_request.encode_packet()).expect("0x92 decodes") {
        PeerPacket::MultiPacketRequest(r) => assert_eq!(r, base_request),
        other => panic!("expected MultiPacketRequest, got {other:?}"),
    }

    let ext_request = MultiPacketRequest {
        file_hash: fh,
        file_size: Some(1_000),
        items: vec![RequestItem::AichRoot],
        unknown_sub: None,
        cut: None,
    };
    match PeerPacket::decode(&ext_request.encode_packet()).expect("0xA4 decodes") {
        PeerPacket::MultiPacketRequest(r) => assert_eq!(r, ext_request),
        other => panic!("expected MultiPacketRequest, got {other:?}"),
    }

    let answer = MultiPacketAnswer {
        file_hash: fh,
        items: vec![AnswerItem::Name(Ed2kText::from_utf8("clip.mkv"))],
        unknown_sub: None,
    };
    match PeerPacket::decode(&answer.encode_packet()).expect("0x93 decodes") {
        PeerPacket::MultiPacketAnswer(a) => assert_eq!(a, answer),
        other => panic!("expected MultiPacketAnswer, got {other:?}"),
    }
}

#[test]
fn umbrella_multipacket_decode_error_maps_to_the_multipacket_variant() {
    // A malformed frame's decode error surfaces through the umbrella's own
    // error type rather than being swallowed into Unknown — matching how
    // every other well-known-but-malformed opcode behaves.
    let packet = Packet::new(
        PacketProtocol::Emule,
        PeerOpcode::MultiPacket.as_u8(),
        vec![0xAA],
    );
    assert!(matches!(
        PeerPacket::decode(&packet),
        Err(rmule_peer::PeerPacketDecodeError::MultiPacket { .. })
    ));
}

#[test]
fn answer_items_equal_what_the_standalone_codecs_decode_for_the_same_data() {
    let fh = hash();
    let name = b"clip.mkv";
    let bitmap_bytes = [0b1010_1010u8];
    let root = AichRootHash::from_bytes([0x5A; AichRootHash::BYTE_LEN]);

    // The bundle's unframed sub-stream: 0x59 (name), 0x50 (status), 0x9D
    // (AICH root) — each item's payload is the standalone payload minus the
    // leading file_hash (ADR-0054).
    let mut payload = fh.as_bytes().to_vec();
    payload.push(0x59);
    payload.extend_from_slice(&(name.len() as u16).to_le_bytes());
    payload.extend_from_slice(name);
    payload.push(0x50);
    payload.extend_from_slice(&8u16.to_le_bytes());
    payload.extend_from_slice(&bitmap_bytes);
    payload.push(0x9D);
    payload.extend_from_slice(root.as_bytes());

    let bundle =
        MultiPacketAnswer::decode_packet(&Packet::new(PacketProtocol::Emule, 0x93, payload))
            .expect("bundle decodes");

    // Same logical data, decoded through the pre-existing standalone
    // codecs (hash carried once per standalone packet instead of once for
    // the whole bundle).
    let mut standalone_name_payload = fh.as_bytes().to_vec();
    standalone_name_payload.extend_from_slice(&(name.len() as u16).to_le_bytes());
    standalone_name_payload.extend_from_slice(name);
    let standalone_name = ReqFileNameAnswer::decode_packet(&Packet::new(
        PacketProtocol::Edonkey,
        0x59,
        standalone_name_payload,
    ))
    .expect("standalone name decodes");

    let mut standalone_status_payload = fh.as_bytes().to_vec();
    standalone_status_payload.extend_from_slice(&8u16.to_le_bytes());
    standalone_status_payload.extend_from_slice(&bitmap_bytes);
    let standalone_status = FileStatus::decode_packet(&Packet::new(
        PacketProtocol::Edonkey,
        0x50,
        standalone_status_payload,
    ))
    .expect("standalone status decodes");
    let mut standalone_aich_payload = fh.as_bytes().to_vec();
    standalone_aich_payload.extend_from_slice(root.as_bytes());
    let standalone_aich = AichFileHashAns::decode_packet(&Packet::new(
        PacketProtocol::Emule,
        0x9D,
        standalone_aich_payload,
    ))
    .expect("standalone aich decodes");

    assert_eq!(bundle.file_hash, fh);
    assert_eq!(
        bundle.items,
        vec![
            AnswerItem::Name(standalone_name.file_name),
            AnswerItem::Status(standalone_status.bitmap),
            AnswerItem::AichRoot(standalone_aich.root),
        ]
    );
    assert!(bundle.unknown_sub.is_none());
}
