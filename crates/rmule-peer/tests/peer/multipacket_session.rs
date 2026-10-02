//! ADR-0054 session-level fan-in + `0x93` composition.
//!
//! The load-bearing evidence is fan-in EQUIVALENCE: a bundled request/answer
//! must produce exactly the outputs the equivalent standalone packet
//! sequence produces, modulo the single `0x93` composition — see
//! `bundled_serve_request_fans_in_identically_to_the_standalone_sequence` and
//! `bundled_answer_fans_in_identically_to_the_standalone_sequence`. The
//! codec-only KATs for the same opcodes live in `multipacket.rs`; this leg
//! covers only what the session wiring adds on top of them.

use std::net::Ipv4Addr;

use rmule_peer::multipacket::{AnswerItem, MultiPacketAnswer, MultiPacketRequest, RequestItem};
use rmule_peer::{
    BundledAsk, FileProbeStatus, FileStatus, Hello, HelloAnswer, MiscOptions1, PartBitmap,
    PeerCommand, PeerEvent, PeerHelloBody, PeerOpcode, PeerOutput, PeerPacket, PeerSession,
    ReqFileNameAnswer, RequestFileName, SetReqFileId,
};
use rmule_primitives::session::drain;
use rmule_primitives::{
    AichRootHash, ClientId, Ed2kText, FileHash, Ipv4Endpoint, Packet, PacketProtocol, UserHash,
};
use rmule_testkit::peer_session::{events, peer_at, serverless_ctx, writes};

/// The asks of the one bundle `outputs` handed core about `fh`.
fn bundle_asks(outputs: &[PeerOutput], fh: FileHash) -> Vec<BundledAsk> {
    events(outputs)
        .into_iter()
        .find_map(|e| match e {
            PeerEvent::FileBundleRequested {
                file_hash, asks, ..
            } if *file_hash == fh => Some(asks.clone()),
            _ => None,
        })
        .expect("the bundle reaches core as one event")
}

fn remote_hello_body(user_hash: UserHash) -> PeerHelloBody {
    PeerHelloBody {
        user_hash,
        client_id: ClientId::from_u32(0x2000_0002),
        tcp_port: 4662,
        tags: Vec::new(),
        connected_server: Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0),
    }
}

/// An inbound session driven through the hello exchange — ready to serve.
fn identified_inbound_session() -> PeerSession {
    let mut s = PeerSession::new_inbound(peer_at(40), serverless_ctx());
    let hello = Hello::new(remote_hello_body(UserHash::from_bytes(
        [0x42; UserHash::BYTE_LEN],
    )))
    .encode_packet()
    .encode();
    s.handle_bytes(&hello);
    let _ = drain(|| s.poll_output());
    s
}

/// An outbound session driven through the hello exchange — ready to request.
fn identified_outbound_session() -> PeerSession {
    let mut s = PeerSession::new_outbound(peer_at(40), serverless_ctx());
    s.start();
    let _ = drain(|| s.poll_output());
    let answer = HelloAnswer::new(remote_hello_body(UserHash::from_bytes(
        [0x99; UserHash::BYTE_LEN],
    )))
    .encode_packet()
    .encode();
    s.handle_bytes(&answer);
    let _ = drain(|| s.poll_output());
    s
}

#[test]
fn bundled_serve_request_fans_in_identically_to_the_standalone_sequence() {
    let fh = FileHash::from_bytes([0xB1; FileHash::BYTE_LEN]);
    let name = Ed2kText::from_utf8("movie.avi");
    let bitmap = PartBitmap::decode(1, &[0b1]).unwrap();

    // Standalone: two separate requests, two separate events, two separate
    // answer packets.
    let mut standalone = identified_inbound_session();
    standalone.handle_bytes(&RequestFileName::new(fh, None).encode_packet().encode());
    standalone.handle_bytes(&SetReqFileId { file_hash: fh }.encode_packet().encode());
    let standalone_request_out = drain(|| standalone.poll_output());
    assert!(
        events(&standalone_request_out)
            .iter()
            .any(|e| matches!(e, PeerEvent::FileRequested { file_hash, .. } if *file_hash == fh))
    );
    assert!(
        events(&standalone_request_out)
            .iter()
            .any(|e| matches!(e, PeerEvent::FileIdSet { file_hash } if *file_hash == fh))
    );

    standalone.handle_command(PeerCommand::AnswerFileName {
        file_hash: fh,
        file_name: name.clone(),
    });
    standalone.handle_command(PeerCommand::AnswerFileStatus {
        file_hash: fh,
        bitmap: bitmap.clone(),
    });
    let standalone_answer_out = drain(|| standalone.poll_output());
    let standalone_writes = writes(&standalone_answer_out);
    assert_eq!(
        standalone_writes.len(),
        2,
        "standalone answers frame two separate packets"
    );
    assert_eq!(standalone_writes[0].opcode(), 0x59);
    assert_eq!(standalone_writes[1].opcode(), 0x50);

    // Bundled: one MultiPacket request — the SAME two events — then one
    // composed 0x93 instead of two packets.
    let mut bundled = identified_inbound_session();
    let request = MultiPacketRequest {
        file_hash: fh,
        file_size: None,
        items: vec![
            RequestItem::Name { part_status: None },
            RequestItem::SetReqId,
        ],
        unknown_sub: None,
        cut: None,
    };
    bundled.handle_bytes(&request.encode_packet().encode());
    let bundled_request_out = drain(|| bundled.poll_output());
    assert_eq!(
        bundle_asks(&bundled_request_out, fh),
        vec![BundledAsk::Name { part_status: None }, BundledAsk::SetReqId],
    );
    assert!(
        writes(&bundled_request_out).is_empty(),
        "consuming a bundled request writes nothing by itself"
    );

    bundled.handle_command(PeerCommand::AnswerFileName {
        file_hash: fh,
        file_name: name.clone(),
    });
    let after_name = drain(|| bundled.poll_output());
    assert!(
        writes(&after_name).is_empty(),
        "the bundle waits for SetReqId's answer too before composing"
    );

    bundled.handle_command(PeerCommand::AnswerFileStatus {
        file_hash: fh,
        bitmap: bitmap.clone(),
    });
    let bundled_answer_out = drain(|| bundled.poll_output());
    let bundled_writes = writes(&bundled_answer_out);
    assert_eq!(
        bundled_writes.len(),
        1,
        "the bundle composes one 0x93 instead of two packets"
    );
    match PeerPacket::decode(&bundled_writes[0]).expect("0x93 decodes") {
        PeerPacket::MultiPacketAnswer(ans) => {
            assert_eq!(ans.file_hash, fh);
            assert_eq!(
                ans.items,
                // A complete bitmap collapses to aMule's part-count-0
                // sentinel at the writer — same for both shapes.
                vec![
                    AnswerItem::Name(name),
                    AnswerItem::Status(PartBitmap::complete_source_sentinel())
                ]
            );
        }
        other => panic!("expected MultiPacketAnswer, got {other:?}"),
    }
}

#[test]
fn bundled_answer_fans_in_identically_to_the_standalone_sequence() {
    let fh = FileHash::from_bytes([0xB2; FileHash::BYTE_LEN]);
    let name = Ed2kText::from_utf8("clip.mkv");
    let bitmap = PartBitmap::decode(2, &[0b11]).unwrap();

    // Both shapes solicit the probe first: an answer for a
    // never-solicited file is dropped — identically in both shapes, which is
    // ADR-0054's fan-in equivalence.
    // Standalone: two separate answer packets.
    let mut standalone = identified_outbound_session();
    standalone.handle_command(PeerCommand::ProbeFile {
        file_hash: fh,
        file_size: 20_000_000,
        own_status: PartBitmap::downloader_empty(20_000_000),
    });
    let _ = drain(|| standalone.poll_output());
    standalone.handle_bytes(
        &ReqFileNameAnswer {
            file_hash: fh,
            file_name: name.clone(),
        }
        .encode_packet()
        .encode(),
    );
    standalone.handle_bytes(
        &FileStatus {
            file_hash: fh,
            bitmap: bitmap.clone(),
        }
        .encode_packet()
        .encode(),
    );
    let standalone_out = drain(|| standalone.poll_output());
    let standalone_probed = events(&standalone_out)
        .into_iter()
        .find_map(|e| match e {
            PeerEvent::FileProbed { file_hash, status } if *file_hash == fh => Some(status.clone()),
            _ => None,
        })
        .expect("standalone sequence probes the file available");

    // Bundled: one MultiPacketAnswer carrying both sub-items, upgrading the
    // solicited probe state exactly as the standalone pair does.
    let mut bundled = identified_outbound_session();
    bundled.handle_command(PeerCommand::ProbeFile {
        file_hash: fh,
        file_size: 20_000_000,
        own_status: PartBitmap::downloader_empty(20_000_000),
    });
    let _ = drain(|| bundled.poll_output());
    let answer = MultiPacketAnswer {
        file_hash: fh,
        items: vec![AnswerItem::Name(name), AnswerItem::Status(bitmap)],
        unknown_sub: None,
    };
    bundled.handle_bytes(&answer.encode_packet().encode());
    let bundled_out = drain(|| bundled.poll_output());
    let bundled_probed = events(&bundled_out)
        .into_iter()
        .find_map(|e| match e {
            PeerEvent::FileProbed { file_hash, status } if *file_hash == fh => Some(status.clone()),
            _ => None,
        })
        .expect("bundled answer probes the file available identically");

    assert_eq!(standalone_probed, bundled_probed);
    assert!(matches!(
        standalone_probed,
        FileProbeStatus::Available { .. }
    ));
}

#[test]
fn not_shared_answers_plain_file_req_ans_no_fil_and_sends_no_bundle() {
    let fh = FileHash::from_bytes([0xB3; FileHash::BYTE_LEN]);
    let mut session = identified_inbound_session();
    let request = MultiPacketRequest {
        file_hash: fh,
        file_size: None,
        items: vec![
            RequestItem::Name { part_status: None },
            RequestItem::SetReqId,
            RequestItem::AichRoot,
        ],
        unknown_sub: None,
        cut: None,
    };
    session.handle_bytes(&request.encode_packet().encode());
    let _ = drain(|| session.poll_output());

    session.handle_command(PeerCommand::AnswerFileNotFound { file_hash: fh });
    let out = drain(|| session.poll_output());
    let sent = writes(&out);
    assert_eq!(
        sent.len(),
        1,
        "not-shared answers with exactly one packet, never a bundle"
    );
    assert_eq!(sent[0].opcode(), 0x48);
}

#[test]
fn aich_omitted_from_the_composed_answer_when_it_has_not_arrived_by_flush() {
    let fh = FileHash::from_bytes([0xB4; FileHash::BYTE_LEN]);
    let name = Ed2kText::from_utf8("f.bin");
    let bitmap = PartBitmap::decode(1, &[0b1]).unwrap();
    let mut session = identified_inbound_session();
    let request = MultiPacketRequest {
        file_hash: fh,
        file_size: None,
        items: vec![
            RequestItem::Name { part_status: None },
            RequestItem::SetReqId,
            RequestItem::AichRoot,
        ],
        unknown_sub: None,
        cut: None,
    };
    session.handle_bytes(&request.encode_packet().encode());
    let _ = drain(|| session.poll_output());

    session.handle_command(PeerCommand::AnswerFileName {
        file_hash: fh,
        file_name: name.clone(),
    });
    session.handle_command(PeerCommand::AnswerFileStatus {
        file_hash: fh,
        bitmap: bitmap.clone(),
    });
    let out = drain(|| session.poll_output());
    let sent = writes(&out);
    assert_eq!(
        sent.len(),
        1,
        "flushes on name+status alone, never blocking on the AICH answer"
    );
    match PeerPacket::decode(&sent[0]).unwrap() {
        PeerPacket::MultiPacketAnswer(ans) => {
            assert_eq!(
                ans.items,
                // A complete bitmap collapses to aMule's part-count-0
                // sentinel at the writer.
                vec![
                    AnswerItem::Name(name),
                    AnswerItem::Status(PartBitmap::complete_source_sentinel())
                ],
                "AICH is silently omitted, per ADR-0054"
            );
        }
        other => panic!("expected MultiPacketAnswer, got {other:?}"),
    }

    // A late AICH answer (core replies after the bundle already flushed) is
    // sent standalone rather than dropped outright — the pending bundle is
    // already gone by then. The standalone `OP_AICHFILEHASHANS` (0x9D) must
    // carry `[file_hash 16][root 20]`: aMule's non-bundled reader
    // (`ProcessAICHFileHash` with a null file) reads the file-hash prefix
    // before the root, so a root-only frame under-runs its parse and drops the
    // source. The bundled sub-item omits the hash; the standalone
    // packet does not.
    let root = AichRootHash::from_bytes([0x77; AichRootHash::BYTE_LEN]);
    session.handle_command(PeerCommand::AnswerAichFileHash { root });
    let late = drain(|| session.poll_output());
    let late_writes = writes(&late);
    assert_eq!(late_writes.len(), 1);
    assert_eq!(late_writes[0].opcode(), 0x9D);
    let payload = late_writes[0].payload();
    assert_eq!(
        payload.len(),
        FileHash::BYTE_LEN + AichRootHash::BYTE_LEN,
        "standalone OP_AICHFILEHASHANS carries the file hash then the root"
    );
    assert_eq!(&payload[..FileHash::BYTE_LEN], fh.as_bytes());
    assert_eq!(&payload[FileHash::BYTE_LEN..], root.as_bytes());
}

#[test]
fn aich_only_bundle_flushes_once_its_answer_arrives() {
    let fh = FileHash::from_bytes([0xB5; FileHash::BYTE_LEN]);
    let root = AichRootHash::from_bytes([0x88; AichRootHash::BYTE_LEN]);
    let mut session = identified_inbound_session();
    let request = MultiPacketRequest {
        file_hash: fh,
        file_size: None,
        items: vec![RequestItem::AichRoot],
        unknown_sub: None,
        cut: None,
    };
    session.handle_bytes(&request.encode_packet().encode());
    let request_out = drain(|| session.poll_output());
    assert_eq!(bundle_asks(&request_out, fh), vec![BundledAsk::AichRoot]);
    assert!(writes(&request_out).is_empty());

    session.handle_command(PeerCommand::AnswerAichFileHash { root });
    let out = drain(|| session.poll_output());
    let sent = writes(&out);
    assert_eq!(
        sent.len(),
        1,
        "AICH alone is a valid, self-contained trigger"
    );
    match PeerPacket::decode(&sent[0]).unwrap() {
        PeerPacket::MultiPacketAnswer(ans) => {
            assert_eq!(ans.file_hash, fh);
            assert_eq!(ans.items, vec![AnswerItem::AichRoot(root)]);
        }
        other => panic!("expected MultiPacketAnswer, got {other:?}"),
    }
}

#[test]
fn bundle_with_only_source_items_never_sends_an_answer() {
    let fh = FileHash::from_bytes([0xB6; FileHash::BYTE_LEN]);
    let mut session = identified_inbound_session();
    let request = MultiPacketRequest {
        file_hash: fh,
        file_size: None,
        items: vec![
            RequestItem::Sources,
            RequestItem::Sources2 {
                version: 4,
                options: 0,
            },
        ],
        unknown_sub: None,
        cut: None,
    };
    session.handle_bytes(&request.encode_packet().encode());
    let out = drain(|| session.poll_output());
    assert!(
        writes(&out).is_empty(),
        "aMule's '>16 bytes' rule: nothing but the hash sends no 0x93 at all"
    );
    assert!(
        !events(&out).iter().any(|e| matches!(
            e,
            PeerEvent::FileRequested { .. }
                | PeerEvent::FileIdSet { .. }
                | PeerEvent::AichFileHashRequested { .. }
        )),
        "source subs alone fan into no served-file event either — ADR-0055 owns serving them"
    );
}

#[test]
fn unknown_sub_in_a_bundled_request_keeps_the_valid_prefix_and_stays_open() {
    let fh = FileHash::from_bytes([0xB7; FileHash::BYTE_LEN]);
    let mut payload = fh.as_bytes().to_vec();
    payload.push(0x58); // Name
    payload.push(0x4F); // SetReqId
    payload.push(0xFF); // unknown
    payload.extend_from_slice(&[0xAA, 0xBB]);
    let bytes = Packet::new(
        PacketProtocol::Emule,
        PeerOpcode::MultiPacket.as_u8(),
        payload,
    )
    .encode();

    let mut session = identified_inbound_session();
    session.handle_bytes(&bytes);
    let out = drain(|| session.poll_output());

    assert_eq!(
        bundle_asks(&out, fh),
        vec![BundledAsk::Name { part_status: None }, BundledAsk::SetReqId],
    );
    assert!(events(&out).iter().any(|e| matches!(
        e,
        PeerEvent::MultiPacketUnknownSub { file_hash, opcode, remaining }
            if *file_hash == fh && *opcode == 0xFF && *remaining == 2
    )));
    assert!(!out.iter().any(|o| matches!(o, PeerOutput::Close(_))));
}

#[test]
fn unknown_sub_in_a_bundled_answer_keeps_the_valid_prefix_and_stays_open() {
    let fh = FileHash::from_bytes([0xB8; FileHash::BYTE_LEN]);
    let name = b"ok.bin";
    let mut payload = fh.as_bytes().to_vec();
    payload.push(0x59);
    payload.extend_from_slice(&(name.len() as u16).to_le_bytes());
    payload.extend_from_slice(name);
    payload.push(0xEE); // unknown
    payload.push(0xCC);
    let bytes = Packet::new(
        PacketProtocol::Emule,
        PeerOpcode::MultiPacketAnswer.as_u8(),
        payload,
    )
    .encode();

    let mut session = identified_outbound_session();
    session.handle_bytes(&bytes);
    let out = drain(|| session.poll_output());

    assert!(events(&out).iter().any(|e| matches!(
        e,
        PeerEvent::MultiPacketUnknownSub { file_hash, opcode, remaining }
            if *file_hash == fh && *opcode == 0xEE && *remaining == 1
    )));
    assert!(!out.iter().any(|o| matches!(o, PeerOutput::Close(_))));
}

#[test]
fn bundled_request_before_hello_is_unknown_preserved_and_stays_open() {
    let fh = FileHash::from_bytes([0xB9; FileHash::BYTE_LEN]);
    let mut session = PeerSession::new_inbound(peer_at(40), serverless_ctx());
    let request = MultiPacketRequest {
        file_hash: fh,
        file_size: None,
        items: vec![RequestItem::Name { part_status: None }],
        unknown_sub: None,
        cut: None,
    };
    session.handle_bytes(&request.encode_packet().encode());
    let out = drain(|| session.poll_output());

    assert!(
        events(&out)
            .iter()
            .any(|e| matches!(e, PeerEvent::UnknownPeerPacket { .. }))
    );
    assert!(
        !events(&out)
            .iter()
            .any(|e| matches!(e, PeerEvent::FileRequested { .. }))
    );
    assert!(!out.iter().any(|o| matches!(o, PeerOutput::Close(_))));
}

#[test]
fn outbound_hello_advertises_multipacket_support() {
    // Advert-flip gating (ADR-0047 registry): consume+serve ship together
    // with the MiscOptions1 bit-1 flip, so a fresh session's
    // own hello carries it — never aspirational.
    let mut session = PeerSession::new_outbound(peer_at(40), serverless_ctx());
    session.start();
    let out = drain(|| session.poll_output());
    let hello_bytes = out
        .iter()
        .find_map(|o| match o {
            PeerOutput::Write(b) => Some(b.clone()),
            _ => None,
        })
        .expect("start() writes the hello");
    let (packet, _) = Packet::decode(&hello_bytes).expect("hello frame decodes");
    let hello = Hello::decode_packet(&packet).expect("hello decodes");
    let misc1 = MiscOptions1::from_tags(&hello.body().tags).expect("MiscOptions1 tag present");
    assert!(
        misc1.supports_multipacket(),
        "consume+serve are live — the registry bit flips truthful (ADR-0054)"
    );
}
