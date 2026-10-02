//! Sans-I/O Server Capability flow: the test plays the role of core,
//! feeding inbound serve packets and answer commands, asserting the
//! session emits the right serve events and frames the right wire
//! replies. (ADR-0031; design §6.)

use crate::fixture::plain_hello_body;
use rmule_peer::{
    CancelTransfer, HashSetRequest, Hello, HelloAnswer, MiscOptions1, PartOffsetWidth, PartRanges,
    PeerCommand, PeerError, PeerEvent, PeerOpcode, PeerOutput, PeerPacket, PeerSession,
    RequestFileName, RequestParts, SetReqFileId, StartUploadReq,
};
use rmule_primitives::session::drain;
use rmule_primitives::{Ed2kText, FileHash, Packet, PartHash, UserHash};
use rmule_testkit::peer_session::{peer_at, serverless_ctx};

/// An inbound session driven through the hello exchange — ready to serve.
fn inbound_session() -> PeerSession {
    let mut s = PeerSession::new_inbound(peer_at(9), serverless_ctx());
    let hello = Hello::new(plain_hello_body(UserHash::from_bytes(
        [0x42; UserHash::BYTE_LEN],
    )))
    .encode_packet()
    .encode();
    s.handle_bytes(&hello);
    let _ = drain(|| s.poll_output());
    s
}

/// An inbound session whose peer advertised data-compression support.
fn inbound_session_with_compression() -> PeerSession {
    let mut s = PeerSession::new_inbound(peer_at(9), serverless_ctx());
    let mut body = plain_hello_body(UserHash::from_bytes([0x42; UserHash::BYTE_LEN]));
    body.tags.push(MiscOptions1::rmule_advertised().to_tag());
    s.handle_bytes(&Hello::new(body).encode_packet().encode());
    let _ = drain(|| s.poll_output());
    s
}

fn decode_last_write(outputs: &[PeerOutput]) -> PeerPacket {
    let bytes = outputs
        .iter()
        .rev()
        .find_map(|o| match o {
            PeerOutput::Write(b) => Some(b.clone()),
            _ => None,
        })
        .expect("a Write output");
    let (packet, _) = Packet::decode(&bytes).expect("frame decodes");
    PeerPacket::decode(&packet).expect("packet decodes")
}

#[test]
fn inbound_file_request_emits_file_requested() {
    let mut s = inbound_session();
    let fh = FileHash::from_bytes([0xA1; FileHash::BYTE_LEN]);
    s.handle_bytes(&RequestFileName::new(fh, None).encode_packet().encode());
    let outputs = drain(|| s.poll_output());
    assert!(
        outputs.iter().any(|o| matches!(o,
            PeerOutput::Event(PeerEvent::FileRequested { file_hash, .. }) if *file_hash == fh)),
        "expected FileRequested, got {outputs:?}"
    );
}

#[test]
fn inbound_set_req_file_id_emits_file_id_set() {
    let mut s = inbound_session();
    let fh = FileHash::from_bytes([0xA2; FileHash::BYTE_LEN]);
    s.handle_bytes(&SetReqFileId { file_hash: fh }.encode_packet().encode());
    let outputs = drain(|| s.poll_output());
    assert!(outputs.iter().any(|o| matches!(o,
        PeerOutput::Event(PeerEvent::FileIdSet { file_hash }) if *file_hash == fh)));
}

#[test]
fn answer_file_name_frames_req_file_name_answer() {
    let mut s = inbound_session();
    let fh = FileHash::from_bytes([0xA1; FileHash::BYTE_LEN]);
    let name = Ed2kText::from_utf8("movie.avi");
    s.handle_command(PeerCommand::AnswerFileName {
        file_hash: fh,
        file_name: name.clone(),
    });
    match decode_last_write(&drain(|| s.poll_output())) {
        PeerPacket::ReqFileNameAnswer(a) => {
            assert_eq!(a.file_hash, fh);
            assert_eq!(a.file_name, name);
        }
        other => panic!("expected ReqFileNameAnswer, got {other:?}"),
    }
}

#[test]
fn answer_file_not_found_frames_file_req_ans_no_fil() {
    let mut s = inbound_session();
    let fh = FileHash::from_bytes([0xA3; FileHash::BYTE_LEN]);
    s.handle_command(PeerCommand::AnswerFileNotFound { file_hash: fh });
    match decode_last_write(&drain(|| s.poll_output())) {
        PeerPacket::FileReqAnsNoFil(a) => assert_eq!(a.file_hash, fh),
        other => panic!("expected FileReqAnsNoFil, got {other:?}"),
    }
}

#[test]
fn serve_dispatch_is_symmetric_on_dialed_sessions() {
    // ADR-0031: one bidirectional session. A serve request on a session
    // WE dialed (outbound) must project to a serve event, not Unknown — a
    // future `new_inbound`-only gate would break this and is a regression.
    let remote = UserHash::from_bytes([0x77; UserHash::BYTE_LEN]);
    let mut s = PeerSession::new_outbound(peer_at(9), serverless_ctx());
    s.start();
    let _ = drain(|| s.poll_output());
    s.handle_bytes(
        &HelloAnswer::new(plain_hello_body(remote))
            .encode_packet()
            .encode(),
    );
    let _ = drain(|| s.poll_output());

    let fh = FileHash::from_bytes([0xB2; FileHash::BYTE_LEN]);
    s.handle_bytes(&RequestFileName::new(fh, None).encode_packet().encode());
    let outputs = drain(|| s.poll_output());
    assert!(
        outputs.iter().any(|o| matches!(o,
            PeerOutput::Event(PeerEvent::FileRequested { file_hash, .. }) if *file_hash == fh)),
        "serve request on a dialed session must emit FileRequested, not Unknown"
    );
}

#[test]
fn serve_request_before_hello_stays_unknown() {
    let mut s = PeerSession::new_inbound(peer_at(9), serverless_ctx());
    let fh = FileHash::from_bytes([0xC3; FileHash::BYTE_LEN]);
    s.handle_bytes(&RequestFileName::new(fh, None).encode_packet().encode());
    let outputs = drain(|| s.poll_output());
    assert!(
        outputs
            .iter()
            .any(|o| matches!(o, PeerOutput::Event(PeerEvent::UnknownPeerPacket { .. })))
    );
    assert!(
        !outputs
            .iter()
            .any(|o| matches!(o, PeerOutput::Event(PeerEvent::FileRequested { .. })))
    );
    assert!(!outputs.iter().any(|o| matches!(o, PeerOutput::Close(_))));
}

#[test]
fn answer_before_identify_is_command_rejected() {
    let mut s = PeerSession::new_inbound(peer_at(9), serverless_ctx());
    let fh = FileHash::from_bytes([0xD4; FileHash::BYTE_LEN]);
    s.handle_command(PeerCommand::AnswerFileNotFound { file_hash: fh });
    let outputs = drain(|| s.poll_output());
    assert!(
        outputs
            .iter()
            .any(|o| matches!(o, PeerOutput::Event(PeerEvent::CommandRejected { .. })))
    );
    assert!(
        !outputs.iter().any(|o| matches!(o, PeerOutput::Write(_))),
        "no wire bytes may be framed before the hello exchange"
    );
}

#[test]
fn inbound_start_upload_req_emits_slot_requested() {
    let mut s = inbound_session();
    let fh = FileHash::from_bytes([0xA1; FileHash::BYTE_LEN]);
    s.handle_bytes(&StartUploadReq { file_hash: fh }.encode_packet().encode());
    let outputs = drain(|| s.poll_output());
    assert!(outputs.iter().any(|o| matches!(o,
        PeerOutput::Event(PeerEvent::SlotRequested { file_hash }) if *file_hash == fh)));
}

#[test]
fn grant_slot_frames_accept_upload_req() {
    let mut s = inbound_session();
    let fh = FileHash::from_bytes([0xA1; FileHash::BYTE_LEN]);
    s.handle_command(PeerCommand::GrantSlot { file_hash: fh });
    assert!(matches!(
        decode_last_write(&drain(|| s.poll_output())),
        PeerPacket::AcceptUploadReq(_)
    ));
}

/// A mule's hello: the queue rank rides the extended protocol.
#[test]
fn set_queue_rank_frames_queue_ranking() {
    let mut s = PeerSession::new_inbound(peer_at(9), serverless_ctx());
    let mut body = plain_hello_body(UserHash::from_bytes([0x42; UserHash::BYTE_LEN]));
    body.tags
        .push(rmule_testkit::peer_session::mule_version_tag());
    s.handle_bytes(&Hello::new(body).encode_packet().encode());
    let _ = drain(|| s.poll_output());
    s.handle_command(PeerCommand::SetQueueRank { rank: 7 });
    match decode_last_write(&drain(|| s.poll_output())) {
        PeerPacket::QueueRanking(q) => assert_eq!(q.rank, 7),
        other => panic!("expected QueueRanking, got {other:?}"),
    }
}

#[test]
fn refuse_slot_frames_out_of_part_reqs() {
    let mut s = inbound_session();
    let fh = FileHash::from_bytes([0xA1; FileHash::BYTE_LEN]);
    s.handle_command(PeerCommand::RefuseSlot { file_hash: fh });
    assert!(matches!(
        decode_last_write(&drain(|| s.poll_output())),
        PeerPacket::OutOfPartReqs(_)
    ));
}

#[test]
fn inbound_cancel_transfer_after_grant_emits_transfer_cancelled_and_clears_served_slot() {
    let mut s = inbound_session();
    let fh = FileHash::from_bytes([0xA1; FileHash::BYTE_LEN]);
    s.handle_command(PeerCommand::GrantSlot { file_hash: fh });
    let _ = drain(|| s.poll_output());

    s.handle_bytes(&CancelTransfer.encode_packet().encode());
    let outputs = drain(|| s.poll_output());
    assert!(
        outputs.iter().any(|o| matches!(o,
            PeerOutput::Event(PeerEvent::TransferCancelled { file_hash }) if *file_hash == fh)),
        "expected TransferCancelled, got {outputs:?}"
    );
    assert!(
        !outputs.iter().any(|o| matches!(o, PeerOutput::Close(_))),
        "a cancel keeps the connection open"
    );

    // served_slot is cleared: a stray late SendBlock for the cancelled file
    // is rejected rather than framed (ADR-0056 "pending unsent blocks dropped").
    s.handle_command(PeerCommand::SendBlock {
        file_hash: fh,
        start: 0,
        end: 4,
        bytes: vec![1, 2, 3, 4],
    });
    let after = drain(|| s.poll_output());
    assert!(after.iter().any(|o| matches!(
        o,
        PeerOutput::Event(PeerEvent::CommandRejected {
            reason: PeerError::ServeSlotNotGranted
        })
    )));
    assert!(!after.iter().any(|o| matches!(o, PeerOutput::Write(_))));
}

#[test]
fn inbound_cancel_transfer_without_a_granted_slot_is_a_silent_noop() {
    // aMule's `RemoveFromUploadQueue` silently returns false for a peer
    // holding no slot: no event, no write, no close.
    let mut s = inbound_session();
    s.handle_bytes(&CancelTransfer.encode_packet().encode());
    let outputs = drain(|| s.poll_output());
    assert!(
        outputs.is_empty(),
        "a slotless cancel must be a silent no-op, got {outputs:?}"
    );
}

#[test]
fn parts_request_after_grant_emits_parts_requested() {
    let mut s = inbound_session();
    let fh = FileHash::from_bytes([0xA1; FileHash::BYTE_LEN]);
    s.handle_command(PeerCommand::GrantSlot { file_hash: fh });
    let _ = drain(|| s.poll_output());

    let ranges = PartRanges::new([(0, 10), (0, 0), (0, 0)]).unwrap();
    s.handle_bytes(
        &RequestParts {
            file_hash: fh,
            ranges,
        }
        .encode_packet(PartOffsetWidth::U32)
        .unwrap()
        .encode(),
    );
    let outputs = drain(|| s.poll_output());
    assert!(outputs.iter().any(|o| matches!(o,
        PeerOutput::Event(PeerEvent::PartsRequested { file_hash, ranges: r })
            if *file_hash == fh && *r == ranges)));
}

#[test]
fn parts_request_without_slot_reports_serve_parts_without_slot() {
    let mut s = inbound_session();
    let fh = FileHash::from_bytes([0xEE; FileHash::BYTE_LEN]);
    let ranges = PartRanges::new([(0, 10), (0, 0), (0, 0)]).unwrap();
    s.handle_bytes(
        &RequestParts {
            file_hash: fh,
            ranges,
        }
        .encode_packet(PartOffsetWidth::U32)
        .unwrap()
        .encode(),
    );
    let outputs = drain(|| s.poll_output());
    assert!(outputs.iter().any(|o| matches!(o,
        PeerOutput::Event(PeerEvent::ServePartsWithoutSlot { file_hash }) if *file_hash == fh)));
    assert!(
        !outputs.iter().any(|o| matches!(o, PeerOutput::Close(_))),
        "an unslotted parts request closes the flow, not the session"
    );
}

#[test]
fn send_block_after_grant_frames_sending_part() {
    let mut s = inbound_session();
    let fh = FileHash::from_bytes([0xA1; FileHash::BYTE_LEN]);
    s.handle_command(PeerCommand::GrantSlot { file_hash: fh });
    let _ = drain(|| s.poll_output());

    s.handle_command(PeerCommand::SendBlock {
        file_hash: fh,
        start: 0,
        end: 4,
        bytes: vec![1, 2, 3, 4],
    });
    match decode_last_write(&drain(|| s.poll_output())) {
        PeerPacket::SendingPart(sp) => {
            assert_eq!(sp.file_hash, fh);
            assert_eq!((sp.start, sp.end), (0, 4));
            assert_eq!(sp.data, vec![1, 2, 3, 4]);
        }
        other => panic!("expected SendingPart, got {other:?}"),
    }
}

#[test]
fn serve_compresses_block_for_a_compression_capable_peer() {
    let mut s = inbound_session_with_compression();
    let fh = FileHash::from_bytes([0xA1; FileHash::BYTE_LEN]);
    s.handle_command(PeerCommand::GrantSlot { file_hash: fh });
    let _ = drain(|| s.poll_output());

    let plain: Vec<u8> = b"compressible block ".repeat(40);
    s.handle_command(PeerCommand::SendBlock {
        file_hash: fh,
        start: 0,
        end: plain.len() as u64,
        bytes: plain.clone(),
    });
    match decode_last_write(&drain(|| s.poll_output())) {
        PeerPacket::CompressedPart(cp) => {
            assert_eq!(cp.start, 0);
            assert!(
                (cp.compressed_block_len as usize) < plain.len(),
                "compressed block must be smaller than raw"
            );
            // The served compressed payload inflates back to the block.
            use flate2::read::ZlibDecoder;
            use std::io::Read;
            let mut got = Vec::new();
            ZlibDecoder::new(&cp.compressed_chunk[..])
                .read_to_end(&mut got)
                .unwrap();
            assert_eq!(got, plain);
        }
        other => panic!("expected CompressedPart, got {other:?}"),
    }
}

#[test]
fn serve_sends_raw_when_compression_does_not_shrink() {
    // A 4-byte block: zlib overhead makes the compressed form larger, so the
    // raw OP_SENDINGPART wins (compress-only-if-smaller).
    let mut s = inbound_session_with_compression();
    let fh = FileHash::from_bytes([0xA1; FileHash::BYTE_LEN]);
    s.handle_command(PeerCommand::GrantSlot { file_hash: fh });
    let _ = drain(|| s.poll_output());

    s.handle_command(PeerCommand::SendBlock {
        file_hash: fh,
        start: 0,
        end: 4,
        bytes: vec![1, 2, 3, 4],
    });
    assert!(matches!(
        decode_last_write(&drain(|| s.poll_output())),
        PeerPacket::SendingPart(_)
    ));
}

#[test]
fn send_block_without_grant_is_command_rejected() {
    let mut s = inbound_session();
    let fh = FileHash::from_bytes([0xA1; FileHash::BYTE_LEN]);
    s.handle_command(PeerCommand::SendBlock {
        file_hash: fh,
        start: 0,
        end: 4,
        bytes: vec![1, 2, 3, 4],
    });
    let outputs = drain(|| s.poll_output());
    assert!(outputs.iter().any(|o| matches!(
        o,
        PeerOutput::Event(PeerEvent::CommandRejected {
            reason: PeerError::ServeSlotNotGranted
        })
    )));
    assert!(
        !outputs.iter().any(|o| matches!(o, PeerOutput::Write(_))),
        "no OP_SENDINGPART may be framed for an ungranted slot"
    );
}

#[test]
fn full_inbound_serve_flow_hello_to_part_bytes() {
    use rmule_peer::PartBitmap;

    let remote = UserHash::from_bytes([0x99; UserHash::BYTE_LEN]);
    let fh = FileHash::from_bytes([0xA1; FileHash::BYTE_LEN]);
    let mut s = PeerSession::new_inbound(peer_at(9), serverless_ctx());

    // 1. Peer hello → identify + OP_HELLOANSWER.
    s.handle_bytes(
        &Hello::new(plain_hello_body(remote))
            .encode_packet()
            .encode(),
    );
    let out = drain(|| s.poll_output());
    assert!(
        out.iter()
            .any(|o| matches!(o, PeerOutput::Event(PeerEvent::PeerIdentified { .. })))
    );
    assert!(matches!(
        decode_last_write(&out),
        PeerPacket::HelloAnswer(_)
    ));

    // 2. RequestFileName → FileRequested; answer the name.
    s.handle_bytes(&RequestFileName::new(fh, None).encode_packet().encode());
    assert!(
        drain(|| s.poll_output())
            .iter()
            .any(|o| matches!(o, PeerOutput::Event(PeerEvent::FileRequested { .. })))
    );
    s.handle_command(PeerCommand::AnswerFileName {
        file_hash: fh,
        file_name: Ed2kText::from_utf8("f.bin"),
    });
    assert!(matches!(
        decode_last_write(&drain(|| s.poll_output())),
        PeerPacket::ReqFileNameAnswer(_)
    ));

    // 3. SetReqFileId → FileIdSet; answer the bitmap.
    s.handle_bytes(&SetReqFileId { file_hash: fh }.encode_packet().encode());
    assert!(
        drain(|| s.poll_output())
            .iter()
            .any(|o| matches!(o, PeerOutput::Event(PeerEvent::FileIdSet { .. })))
    );
    s.handle_command(PeerCommand::AnswerFileStatus {
        file_hash: fh,
        bitmap: PartBitmap::decode(1, &[0b1]).unwrap(),
    });
    assert!(matches!(
        decode_last_write(&drain(|| s.poll_output())),
        PeerPacket::FileStatus(_)
    ));

    // 4. HashSetRequest → HashSetRequested; answer the hashes.
    s.handle_bytes(&HashSetRequest { file_hash: fh }.encode_packet().encode());
    assert!(
        drain(|| s.poll_output())
            .iter()
            .any(|o| matches!(o, PeerOutput::Event(PeerEvent::HashSetRequested { .. })))
    );
    s.handle_command(PeerCommand::AnswerHashSet {
        file_hash: fh,
        part_hashes: vec![PartHash::from_bytes([0x01; PartHash::BYTE_LEN])],
    });
    assert!(matches!(
        decode_last_write(&drain(|| s.poll_output())),
        PeerPacket::HashSetAnswer(_)
    ));

    // 5. StartUploadReq → SlotRequested; grant the slot.
    s.handle_bytes(&StartUploadReq { file_hash: fh }.encode_packet().encode());
    assert!(
        drain(|| s.poll_output())
            .iter()
            .any(|o| matches!(o, PeerOutput::Event(PeerEvent::SlotRequested { .. })))
    );
    s.handle_command(PeerCommand::GrantSlot { file_hash: fh });
    assert!(matches!(
        decode_last_write(&drain(|| s.poll_output())),
        PeerPacket::AcceptUploadReq(_)
    ));

    // 6. RequestParts → PartsRequested; stream the block.
    let ranges = PartRanges::new([(0, 4), (0, 0), (0, 0)]).unwrap();
    s.handle_bytes(
        &RequestParts {
            file_hash: fh,
            ranges,
        }
        .encode_packet(PartOffsetWidth::U32)
        .unwrap()
        .encode(),
    );
    assert!(
        drain(|| s.poll_output())
            .iter()
            .any(|o| matches!(o, PeerOutput::Event(PeerEvent::PartsRequested { .. })))
    );
    s.handle_command(PeerCommand::SendBlock {
        file_hash: fh,
        start: 0,
        end: 4,
        bytes: vec![9, 9, 9, 9],
    });
    match decode_last_write(&drain(|| s.poll_output())) {
        PeerPacket::SendingPart(sp) => {
            assert_eq!((sp.start, sp.end), (0, 4));
            assert_eq!(sp.data, vec![9, 9, 9, 9]);
        }
        other => panic!("expected SendingPart, got {other:?}"),
    }
}

#[test]
fn answer_file_status_for_a_complete_file_writes_amules_zero_part_count_sentinel() {
    // aMule's own writer (`ClientTCPSocket.cpp` `OP_SETREQFILEID`, kno
    // `ab483654`): `IsPartFile() ? WritePartStatus() : data.WriteUInt16(0)`
    // — a fully-owned shared file writes a literal zero part count and no
    // bitmap bytes, never a real bitmap with every bit set.
    use rmule_peer::PartBitmap;

    let fh = FileHash::from_bytes([0x7A; FileHash::BYTE_LEN]);
    let mut s = inbound_session();
    s.handle_command(PeerCommand::AnswerFileStatus {
        file_hash: fh,
        bitmap: PartBitmap::all_present(4),
    });
    match decode_last_write(&drain(|| s.poll_output())) {
        PeerPacket::FileStatus(status) => {
            assert_eq!(status.bitmap, PartBitmap::complete_source_sentinel());
        }
        other => panic!("expected FileStatus, got {other:?}"),
    }
}

#[test]
fn answer_file_status_for_a_partial_file_writes_the_bitmap_literally() {
    use rmule_peer::PartBitmap;

    let fh = FileHash::from_bytes([0x7B; FileHash::BYTE_LEN]);
    let mut s = inbound_session();
    let partial = PartBitmap::decode(4, &[0b0111]).unwrap();
    s.handle_command(PeerCommand::AnswerFileStatus {
        file_hash: fh,
        bitmap: partial.clone(),
    });
    match decode_last_write(&drain(|| s.poll_output())) {
        PeerPacket::FileStatus(status) => {
            assert_eq!(status.bitmap, partial);
        }
        other => panic!("expected FileStatus, got {other:?}"),
    }
}

/// aMule never closes on a slot ask or a cancel for their length: a
/// `OP_STARTUPLOADREQ` that is not exactly a hash is let pass, connection
/// kept, and `OP_CANCELTRANSFER` acts whatever rides after it (stock 2.3.3
/// `4e8f2b3c` `ClientTCPSocket.cpp:606-618`, `:673-678`).
#[test]
fn a_slot_ask_of_the_wrong_length_and_a_cancel_with_a_body_keep_the_connection() {
    let mut s = inbound_session();
    let fh = FileHash::from_bytes([0xA1; FileHash::BYTE_LEN]);
    let long_ask = Packet::new(
        PeerOpcode::StartUploadReq.protocol(),
        PeerOpcode::StartUploadReq.as_u8(),
        [fh.as_bytes().as_slice(), &[0]].concat(),
    );
    s.handle_bytes(&long_ask.encode());
    let outputs = drain(|| s.poll_output());
    assert!(
        !outputs.iter().any(|o| matches!(
            o,
            PeerOutput::Close(_) | PeerOutput::Event(PeerEvent::SlotRequested { .. })
        )),
        "{outputs:?}"
    );

    s.handle_command(PeerCommand::GrantSlot { file_hash: fh });
    let _ = drain(|| s.poll_output());
    let cancel = Packet::new(
        PeerOpcode::CancelTransfer.protocol(),
        PeerOpcode::CancelTransfer.as_u8(),
        vec![0],
    );
    s.handle_bytes(&cancel.encode());
    let outputs = drain(|| s.poll_output());
    assert!(
        outputs.iter().any(|o| matches!(o,
            PeerOutput::Event(PeerEvent::TransferCancelled { file_hash }) if *file_hash == fh)),
        "{outputs:?}"
    );
    assert!(!outputs.iter().any(|o| matches!(o, PeerOutput::Close(_))));
}
