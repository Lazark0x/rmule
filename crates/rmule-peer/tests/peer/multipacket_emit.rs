//! ADR-0054 bundle **emit**.
//!
//! rmule as the downloader collapses the standalone file-negotiation quintet
//! (`OP_REQUESTFILENAME` + `OP_SETREQFILEID` + `OP_REQUESTSOURCES` +
//! `OP_AICHFILEHASHREQ`) into one `OP_MULTIPACKET` (`0x92`) /
//! `OP_MULTIPACKET_EXT` (`0xA4`) bundle **iff** the peer advertised the
//! MultiPacket capability — the mirror of the consume/serve side. The
//! load-bearing evidence is the gate: a peer without the bit gets the separate
//! packets, a peer with it gets exactly one bundle, and the `0xA4`-vs-`0x92`
//! choice rides the ExtMultiPacket bit alone (aMule always writes `size8` in
//! the EXT form). The round-trip drives a real emit → serve-consume →
//! answer-consume through two sessions, proving the composed request the
//! downloader put on the wire upgrades its own probe state once answered.

use std::net::Ipv4Addr;

use rmule_peer::multipacket::RequestItem;
use rmule_peer::{
    AnswerItem, FileProbeStatus, HashSetAnswer, HelloAnswer, MiscOptions1, MiscOptions2,
    MultiPacketAnswer, PartRanges, PeerCommand, PeerError, PeerEvent, PeerHelloBody, PeerOutput,
    PeerPacket, PeerSession,
};
use rmule_primitives::session::drain;
use rmule_primitives::{
    ClientId, ED2K_PART_SIZE, Ed2kText, FileHash, Ipv4Endpoint, Packet, PacketProtocol, PartHash,
    Tag, UserHash,
};
use rmule_testkit::peer_session::{events, peer_at, serverless_ctx, writes};

/// A mule's hello body carrying `tags` (the capability advertisement under
/// test) beside its `CT_EMULE_VERSION`, which source exchange rides on.
fn peer_body(tags: Vec<Tag>) -> PeerHelloBody {
    let mut tags = tags;
    tags.insert(0, rmule_testkit::peer_session::mule_version_tag());
    PeerHelloBody {
        user_hash: UserHash::from_bytes([0x99; UserHash::BYTE_LEN]),
        client_id: ClientId::from_u32(0x2000_0002),
        tcp_port: 4662,
        tags,
        connected_server: Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0),
    }
}

/// An identified outbound session whose peer advertised `tags` — ready to
/// emit a file request against that capability set.
fn identified_against(tags: Vec<Tag>) -> PeerSession {
    let mut session = PeerSession::new_outbound(peer_at(50), serverless_ctx());
    session.start();
    let _ = drain(|| session.poll_output());
    let answer = HelloAnswer::new(peer_body(tags)).encode_packet().encode();
    session.handle_bytes(&answer);
    let _ = drain(|| session.poll_output());
    session
}

/// `CT_EMULE_MISCOPTIONS1` with bit 1 (`SupportMultiPacket`) lit and the SX1
/// nibble at 3 — a peer aMule would ask for sources (stock 2.3.3 `DownloadClient.cpp:191`).
fn misc1_multipacket() -> Tag {
    MiscOptions1::from_bits(1 << 1 | 3 << 12).to_tag()
}

/// `CT_EMULE_MISCOPTIONS1` with no MultiPacket bit and the SX1 nibble at 3.
fn misc1_plain() -> Tag {
    MiscOptions1::from_bits(3 << 12).to_tag()
}

/// `CT_EMULE_MISCOPTIONS2` with only bit 5 (`SupportExtMultiPacket`) lit.
fn misc2_ext() -> Tag {
    MiscOptions2::from_bits(1 << 5).to_tag()
}

fn hash() -> FileHash {
    FileHash::from_bytes([0x11; FileHash::BYTE_LEN])
}

#[test]
fn peer_without_multipacket_gets_the_standalone_quintet() {
    // A mule without the MultiPacket bit. The negotiation goes out as the
    // separate standalone packets, byte-for-byte the path rmule has always
    // taken, in aMule's request order.
    let mut session = identified_against(vec![misc1_plain()]);
    session.handle_command(PeerCommand::RequestFile {
        file_hash: hash(),
        file_size: ED2K_PART_SIZE + 1,
        own_status: rmule_peer::PartBitmap::downloader_empty(ED2K_PART_SIZE + 1), // multi-part → SetReqId included
        want_sources: true,
        want_aich_root: true,
    });
    let out = drain(|| session.poll_output());
    let opcodes: Vec<u8> = writes(&out).iter().map(Packet::opcode).collect();
    assert_eq!(
        opcodes,
        vec![0x58, 0x4F, 0x81, 0x9E],
        "the quintet is four separate packets against a non-multipacket peer"
    );
    // Every one carries the file hash as its (leading) payload — no bundle framing.
    for p in writes(&out) {
        assert_eq!(&p.payload()[..FileHash::BYTE_LEN], hash().as_bytes());
    }
}

#[test]
fn peer_with_multipacket_but_not_ext_gets_one_base_0x92_bundle() {
    // MiscOptions1 bit 1 set, no MiscOptions2: the base `0x92` form — one
    // bundle, no `size8`.
    let mut session = identified_against(vec![misc1_multipacket()]);
    session.handle_command(PeerCommand::RequestFile {
        file_hash: hash(),
        file_size: ED2K_PART_SIZE + 1,
        own_status: rmule_peer::PartBitmap::downloader_empty(ED2K_PART_SIZE + 1),
        want_sources: true,
        want_aich_root: true,
    });
    let out = drain(|| session.poll_output());
    let sent = writes(&out);
    assert_eq!(sent.len(), 1, "the whole quintet collapses to one packet");
    assert_eq!(sent[0].opcode(), 0x92);
    assert_eq!(sent[0].protocol(), PacketProtocol::Emule);
    match PeerPacket::decode(&sent[0]).expect("bundle decodes") {
        PeerPacket::MultiPacketRequest(req) => {
            assert_eq!(req.file_hash, hash());
            assert_eq!(req.file_size, None, "base 0x92 carries no size8");
            assert_eq!(
                req.items,
                vec![
                    RequestItem::Name { part_status: None },
                    RequestItem::SetReqId,
                    RequestItem::Sources,
                    RequestItem::AichRoot,
                ]
            );
        }
        other => panic!("expected MultiPacketRequest, got {other:?}"),
    }
}

#[test]
fn ext_peer_gets_a_0xa4_bundle_carrying_the_file_size() {
    // MiscOptions1 bit 1 AND MiscOptions2 bit 5: aMule selects `0xA4` on the
    // ext bit alone and always writes the file size — the large-file form.
    let big: u64 = 5_000_000_000; // > 4 GiB, the reason size8 exists
    let mut session = identified_against(vec![misc1_multipacket(), misc2_ext()]);
    session.handle_command(PeerCommand::RequestFile {
        file_hash: hash(),
        file_size: big,
        own_status: rmule_peer::PartBitmap::downloader_empty(big),
        want_sources: true,
        want_aich_root: true,
    });
    let out = drain(|| session.poll_output());
    let sent = writes(&out);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].opcode(), 0xA4);

    // Golden vector (request direction): the exact payload bytes on the wire —
    // hash, little-endian size8, then the unframed sub-opcode stream.
    let mut expected = hash().as_bytes().to_vec();
    expected.extend_from_slice(&big.to_le_bytes());
    expected.extend_from_slice(&[0x58, 0x4F, 0x81, 0x9E]);
    assert_eq!(sent[0].payload(), expected.as_slice());

    match PeerPacket::decode(&sent[0]).expect("bundle decodes") {
        PeerPacket::MultiPacketRequest(req) => {
            assert_eq!(req.file_size, Some(big));
            assert_eq!(
                req.items,
                vec![
                    RequestItem::Name { part_status: None },
                    RequestItem::SetReqId,
                    RequestItem::Sources,
                    RequestItem::AichRoot,
                ]
            );
        }
        other => panic!("expected MultiPacketRequest, got {other:?}"),
    }
}

#[test]
fn sub_part_file_omits_setreqid_and_optional_items_are_gated() {
    // ADR-0054 item composition: 0x58 always, 0x4F only when multi-part, the
    // SX and AICH subs only when the caller asks. A single-part download with
    // neither optional item bundles to a lone Name.
    let mut session = identified_against(vec![misc1_multipacket(), misc2_ext()]);
    session.handle_command(PeerCommand::RequestFile {
        file_hash: hash(),
        file_size: ED2K_PART_SIZE - 1,
        own_status: rmule_peer::PartBitmap::downloader_empty(ED2K_PART_SIZE - 1), // sub-part → no part-status ask
        want_sources: false,
        want_aich_root: false,
    });
    let out = drain(|| session.poll_output());
    let sent = writes(&out);
    assert_eq!(sent.len(), 1);
    match PeerPacket::decode(&sent[0]).expect("bundle decodes") {
        PeerPacket::MultiPacketRequest(req) => {
            assert_eq!(
                req.items,
                vec![RequestItem::Name { part_status: None }],
                "sub-part, sources/aich off: Name is the only sub-item"
            );
        }
        other => panic!("expected MultiPacketRequest, got {other:?}"),
    }
}

#[test]
fn exact_one_part_size_file_omits_setreqid_one_byte_over_includes_it() {
    // The `0x4F` boundary is aMule's `GetPartCount() > 1`
    // (`DownloadClient.cpp:232`), and `GetPartCount()` folds the phantom
    // last part out of an exact multiple of the part size
    // (`KnownFile.cpp` `SetFileSize`) — so a file of exactly one part size
    // has `GetPartCount() == 1` and gets no `OP_SETREQFILEID`, while one
    // byte over does.
    let mut session = identified_against(vec![]);
    session.handle_command(PeerCommand::RequestFile {
        file_hash: hash(),
        file_size: ED2K_PART_SIZE,
        own_status: rmule_peer::PartBitmap::downloader_empty(ED2K_PART_SIZE),
        want_sources: false,
        want_aich_root: false,
    });
    let out = drain(|| session.poll_output());
    let opcodes: Vec<u8> = writes(&out).iter().map(Packet::opcode).collect();
    assert_eq!(
        opcodes,
        vec![0x58],
        "exactly one part size: RequestFileName only, no SetReqFileId"
    );

    let mut session = identified_against(vec![]);
    session.handle_command(PeerCommand::RequestFile {
        file_hash: hash(),
        file_size: ED2K_PART_SIZE + 1,
        own_status: rmule_peer::PartBitmap::downloader_empty(ED2K_PART_SIZE + 1),
        want_sources: false,
        want_aich_root: false,
    });
    let out = drain(|| session.poll_output());
    let opcodes: Vec<u8> = writes(&out).iter().map(Packet::opcode).collect();
    assert_eq!(
        opcodes,
        vec![0x58, 0x4F],
        "one byte over: RequestFileName then SetReqFileId"
    );
}

#[test]
fn the_decision_core_gates_setreqid_identically_in_both_wire_shapes() {
    // "Both shapes share one decision core": the sub-part SetReqId omission is
    // the same choice whether the peer bundles or not — a non-multipacket peer
    // sees Name alone as a single standalone packet, no SetReqId.
    let mut session = identified_against(vec![]);
    session.handle_command(PeerCommand::RequestFile {
        file_hash: hash(),
        file_size: ED2K_PART_SIZE - 1,
        own_status: rmule_peer::PartBitmap::downloader_empty(ED2K_PART_SIZE - 1),
        want_sources: false,
        want_aich_root: false,
    });
    let out = drain(|| session.poll_output());
    let opcodes: Vec<u8> = writes(&out).iter().map(Packet::opcode).collect();
    assert_eq!(
        opcodes,
        vec![0x58],
        "sub-part standalone: RequestFileName only, no SetReqFileId"
    );
}

#[test]
fn request_file_before_identify_puts_no_bytes_on_the_wire() {
    // Wire-safety invariant: a bundle must never precede the hello exchange
    // (the consume side lands a pre-handshake bundle in Unknown-preserve).
    let mut session = PeerSession::new_outbound(peer_at(50), serverless_ctx());
    session.start();
    let _ = drain(|| session.poll_output()); // our own hello
    session.handle_command(PeerCommand::RequestFile {
        file_hash: hash(),
        file_size: ED2K_PART_SIZE + 1,
        own_status: rmule_peer::PartBitmap::downloader_empty(ED2K_PART_SIZE + 1),
        want_sources: true,
        want_aich_root: true,
    });
    let out = drain(|| session.poll_output());
    assert!(
        writes(&out).is_empty(),
        "no negotiation bytes before the peer is identified"
    );
    assert!(events(&out).iter().any(|e| matches!(
        e,
        PeerEvent::CommandRejected {
            reason: PeerError::CommandBeforeIdentified
        }
    )));
}

#[test]
fn emitted_bundle_round_trips_through_a_serving_session_into_file_probed() {
    // Emit → serve-consume + 0x93 composition → answer-consume, all through
    // real sessions: the downloader's own composed request
    // comes back as a bundled answer and upgrades its probe state to Available,
    // proving the wire bytes it emitted are the ones a compliant uploader
    // negotiates against. Two-session loopback per the existing precedent
    // (`aich_file_hash_request_and_answer_round_trip_between_two_sessions`).
    let fh = FileHash::from_bytes([0xC7; FileHash::BYTE_LEN]);
    let name = Ed2kText::from_utf8("bundle.bin");
    let bitmap = rmule_peer::PartBitmap::decode(2, &[0b11]).unwrap();

    // Downloader: peer advertises full multipacket + ext, so RequestFile emits 0xA4.
    let mut downloader = identified_against(vec![misc1_multipacket(), misc2_ext()]);
    downloader.handle_command(PeerCommand::RequestFile {
        file_hash: fh,
        file_size: ED2K_PART_SIZE + 1,
        own_status: rmule_peer::PartBitmap::downloader_empty(ED2K_PART_SIZE + 1),
        want_sources: false,
        want_aich_root: false,
    });
    let bundle_bytes = drain(|| downloader.poll_output())
        .iter()
        .find_map(|o| match o {
            PeerOutput::Write(b) => Some(b.to_vec()),
            _ => None,
        })
        .expect("RequestFile emits the bundle");

    // Uploader: an inbound serving session consumes the bundle (fan-in)
    // and, once core answers name + status, composes the single 0x93.
    let mut uploader = {
        let mut s = PeerSession::new_inbound(peer_at(50), serverless_ctx());
        let hello = rmule_peer::Hello::new(peer_body(vec![misc1_multipacket(), misc2_ext()]))
            .encode_packet()
            .encode();
        s.handle_bytes(&hello);
        let _ = drain(|| s.poll_output());
        s
    };
    uploader.handle_bytes(&bundle_bytes);
    let served = drain(|| uploader.poll_output());
    assert!(
        events(&served).iter().any(
            |e| matches!(e, PeerEvent::FileBundleRequested { file_hash, .. } if *file_hash == fh)
        ),
        "the uploader hands the bundle to core as one serve event"
    );
    uploader.handle_command(PeerCommand::AnswerFileName {
        file_hash: fh,
        file_name: name.clone(),
    });
    uploader.handle_command(PeerCommand::AnswerFileStatus {
        file_hash: fh,
        bitmap: bitmap.clone(),
    });
    let answer_bytes = drain(|| uploader.poll_output())
        .iter()
        .find_map(|o| match o {
            PeerOutput::Write(b) => Some(b.to_vec()),
            _ => None,
        })
        .expect("uploader composes one 0x93");
    assert_eq!(
        Packet::decode(&answer_bytes).unwrap().0.opcode(),
        0x93,
        "the uploader answers with a single bundled 0x93"
    );

    // Back to the downloader: consuming the 0x93 upgrades probe state.
    downloader.handle_bytes(&answer_bytes);
    let probed = drain(|| downloader.poll_output());
    let status = events(&probed)
        .into_iter()
        .find_map(|e| match e {
            PeerEvent::FileProbed { file_hash, status } if *file_hash == fh => Some(status.clone()),
            _ => None,
        })
        .expect("the emitted-then-answered bundle probes the file");
    match status {
        FileProbeStatus::Available { file_name, .. } => assert_eq!(file_name, name),
        other => panic!("expected Available, got {other:?}"),
    }
}

/// `CT_EMULE_MISCOPTIONS2` with ExtMultiPacket (bit 5) and SourceExchange2
/// (bit 10) lit — the pair a stock aMule 2.3.3 advertises together.
fn misc2_ext_sx2() -> Tag {
    MiscOptions2::from_bits((1 << 5) | (1 << 10)).to_tag()
}

#[test]
fn sx2_peer_gets_the_sources2_sub_per_the_source_ask_policy() {
    // ADR-0054: "the SX request sub per the existing source-ask policy" — a
    // peer that advertised SourceExchange2 (ADR-0055) is asked with the v4
    // `0x83` sub inside the bundle, the same variant the granular
    // `RequestSources` command selects for it.
    let size = ED2K_PART_SIZE + 1;
    let mut session = identified_against(vec![misc1_multipacket(), misc2_ext_sx2()]);
    session.handle_command(PeerCommand::RequestFile {
        file_hash: hash(),
        file_size: size,
        own_status: rmule_peer::PartBitmap::downloader_empty(size),
        want_sources: true,
        want_aich_root: true,
    });
    let out = drain(|| session.poll_output());
    let sent = writes(&out);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].opcode(), 0xA4);

    // Golden vector: the SX2 sub rides as `0x83 <ver1=4> <opts2=0 LE>`.
    let mut expected = hash().as_bytes().to_vec();
    expected.extend_from_slice(&size.to_le_bytes());
    expected.extend_from_slice(&[0x58, 0x4F, 0x83, 0x04, 0x00, 0x00, 0x9E]);
    assert_eq!(sent[0].payload(), expected.as_slice());

    match PeerPacket::decode(&sent[0]).expect("bundle decodes") {
        PeerPacket::MultiPacketRequest(req) => {
            assert_eq!(
                req.items,
                vec![
                    RequestItem::Name { part_status: None },
                    RequestItem::SetReqId,
                    RequestItem::Sources2 {
                        version: 4,
                        options: 0,
                    },
                    RequestItem::AichRoot,
                ]
            );
        }
        other => panic!("expected MultiPacketRequest, got {other:?}"),
    }
}

#[test]
fn the_bundles_probe_is_recorded_so_request_parts_does_not_reprobe() {
    // Live wiring: `RequestFile`'s multi-part item set carries the
    // name + status pair, so the session records the probe as in flight. A
    // `RequestParts` that follows must not re-issue the standalone
    // `0x58`+`0x4F` on top of the bundle — it only adds the hash-set ask —
    // and the slot flow still advances to `OP_STARTUPLOADREQ` once the
    // bundled answer and the hash set land.
    let fh = hash();
    let size = ED2K_PART_SIZE + 1;
    let mut session = identified_against(vec![misc1_multipacket(), misc2_ext()]);
    session.handle_command(PeerCommand::RequestFile {
        file_hash: fh,
        file_size: size,
        own_status: rmule_peer::PartBitmap::downloader_empty(size),
        want_sources: false,
        want_aich_root: false,
    });
    let out = drain(|| session.poll_output());
    assert_eq!(
        writes(&out).iter().map(Packet::opcode).collect::<Vec<_>>(),
        vec![0xA4]
    );

    let ranges = PartRanges::new([(0, 1024), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::RequestParts {
        file_hash: fh,
        file_size: size,
        ranges,
    });
    let out = drain(|| session.poll_output());
    assert_eq!(
        writes(&out).iter().map(Packet::opcode).collect::<Vec<_>>(),
        vec![0x51],
        "the probe rode the bundle: RequestParts adds only the hash-set ask"
    );

    let answer = MultiPacketAnswer {
        file_hash: fh,
        items: vec![
            AnswerItem::Name(Ed2kText::from_utf8("bundled.bin")),
            AnswerItem::Status(rmule_peer::PartBitmap::decode(2, &[0b11]).unwrap()),
        ],
        unknown_sub: None,
    };
    session.handle_bytes(&answer.encode_packet().encode());
    let hashes = HashSetAnswer {
        file_hash: fh,
        part_hashes: vec![
            PartHash::from_bytes([0xAA; 16]),
            PartHash::from_bytes([0xBB; 16]),
        ],
    };
    session.handle_bytes(&hashes.encode_packet().encode());
    let out = drain(|| session.poll_output());
    assert_eq!(
        writes(&out).iter().map(Packet::opcode).collect::<Vec<_>>(),
        vec![0x54],
        "probe (from the bundle) + hash set → the slot flow sends STARTUPLOADREQ"
    );
}
