//! Packet-level codec vectors for the human-layer catalog (ADR-0068,
//! Private-Citizen Parity): decode vectors per row (well-formed / truncated /
//! oversize), golden emit vectors, and the `0x61`/`0x60` collision pairs
//! under `0xE3` (Edonkey) vs `0xC5` (Emule) that the shared `PeerOpcode`
//! registry cannot resolve on its own (ADR-0025).

use std::net::Ipv4Addr;

use rmule_peer::{
    ChangeClientId, FileDesc, HumanLayerDecodeError, Message, PeerPacket, PeerPacketDecodeError,
    PublicIpAnswer, QueueRanking,
};
use rmule_primitives::{ClientId, Ed2kText, Packet, PacketProtocol};

// --- Browse requests: 0x4A / 0x5D / 0x5E — payload never inspected ---------

#[test]
fn browse_requests_decode_and_ignore_any_payload() {
    for (opcode, junk) in [
        (0x4Au8, vec![]),
        (0x5D, vec![0xAA; 3]),
        (0x5E, b"movies".to_vec()),
    ] {
        let packet = Packet::new(PacketProtocol::Edonkey, opcode, junk);
        let decoded = PeerPacket::decode(&packet).expect("browse request always decodes");
        match (opcode, decoded) {
            (0x4A, PeerPacket::AskSharedFiles) => {}
            (0x5D, PeerPacket::AskSharedDirs) => {}
            (0x5E, PeerPacket::AskSharedFilesDir) => {}
            (op, other) => {
                panic!("opcode 0x{op:02X}: expected the matching request, got {other:?}")
            }
        }
    }
}

// --- Golden emit: OP_ASKSHAREDDENIEDANS (0x61, Edonkey, empty) ------------

#[test]
fn ask_shared_denied_ans_encodes_as_empty_edonkey_0x61_and_round_trips() {
    let packet = PeerPacket::AskSharedDeniedAns.encode();
    assert_eq!(packet.protocol(), PacketProtocol::Edonkey);
    assert_eq!(packet.opcode(), 0x61);
    assert!(
        packet.payload().is_empty(),
        "aMule's denial carries no payload"
    );
    assert_eq!(
        PeerPacket::decode(&packet).expect("round-trips"),
        PeerPacket::AskSharedDeniedAns
    );
}

// --- The 0x61 collision pair: OP_ASKSHAREDDENIEDANS (Edonkey) vs ----------
// --- OP_FILEDESC (Emule) ---------------------------------------------------

#[test]
fn opcode_0x61_disambiguates_by_protocol_denied_ans_vs_filedesc() {
    let denied = Packet::new(PacketProtocol::Edonkey, 0x61, Vec::new());
    assert_eq!(
        PeerPacket::decode(&denied).expect("edonkey 0x61 decodes"),
        PeerPacket::AskSharedDeniedAns
    );

    let mut filedesc_payload = vec![3u8]; // rating
    filedesc_payload.extend_from_slice(&4u32.to_le_bytes()); // comment len
    filedesc_payload.extend_from_slice(b"gr8!");
    let filedesc = Packet::new(PacketProtocol::Emule, 0x61, filedesc_payload);
    match PeerPacket::decode(&filedesc).expect("emule 0x61 decodes") {
        PeerPacket::FileDesc(d) => {
            assert_eq!(d.rating, 3);
            assert_eq!(d.comment, Ed2kText::from_utf8("gr8!"));
        }
        other => panic!("expected FileDesc, got {other:?}"),
    }
}

#[test]
fn filedesc_encodes_under_emule_0x61_not_edonkey() {
    let packet = FileDesc {
        rating: 5,
        comment: Ed2kText::from_utf8("nice"),
    }
    .encode_packet();
    assert_eq!(packet.protocol(), PacketProtocol::Emule);
    assert_eq!(packet.opcode(), 0x61);
}

// --- The 0x60 collision pair: OP_ASKSHAREDFILESDIRANS (Edonkey) vs --------
// --- OP_QUEUERANKING (Emule) — a pre-existing opcode that must not regress -

#[test]
fn opcode_0x60_disambiguates_by_protocol_filesdirans_vs_queueranking() {
    // Edonkey: the new unsolicited-answer row (ADR-0068), payload ignored.
    let filesdirans = Packet::new(PacketProtocol::Edonkey, 0x60, vec![0xEE; 6]);
    assert_eq!(
        PeerPacket::decode(&filesdirans).expect("edonkey 0x60 decodes"),
        PeerPacket::AskSharedFilesDirAns
    );

    // Emule: the pre-existing QueueRanking — must still decode
    // exactly as it did before 0x60/0x61 were handled at all.
    let mut rank_payload = 7u16.to_le_bytes().to_vec();
    rank_payload.extend_from_slice(&[0u8; 10]);
    let queueranking = Packet::new(PacketProtocol::Emule, 0x60, rank_payload);
    match PeerPacket::decode(&queueranking).expect("emule 0x60 still decodes") {
        PeerPacket::QueueRanking(q) => assert_eq!(q.rank, 7),
        other => panic!("expected QueueRanking (regression), got {other:?}"),
    }
}

#[test]
fn queue_ranking_encode_is_unaffected_by_the_new_0x60_edonkey_row() {
    // Regression anchor: QueueRanking's own encode path is untouched.
    let packet = QueueRanking { rank: 42 }.encode_packet();
    assert_eq!(packet.protocol(), PacketProtocol::Emule);
    assert_eq!(packet.opcode(), 0x60);
}

// --- Unsolicited browse/publicip answers: payload ignored, never rejected -

#[test]
fn unsolicited_browse_answers_decode_and_ignore_any_payload() {
    let files_answer = Packet::new(PacketProtocol::Edonkey, 0x4B, vec![0x01; 20]);
    assert_eq!(
        PeerPacket::decode(&files_answer).expect("0x4B decodes"),
        PeerPacket::AskSharedFilesAnswer
    );
    let dirs_ans = Packet::new(PacketProtocol::Edonkey, 0x5F, vec![0x02; 8]);
    assert_eq!(
        PeerPacket::decode(&dirs_ans).expect("0x5F decodes"),
        PeerPacket::AskSharedDirsAns
    );
}

#[test]
fn public_ip_req_decodes_and_ignores_any_payload() {
    let packet = Packet::new(PacketProtocol::Emule, 0x97, vec![0xFF; 4]);
    assert_eq!(
        PeerPacket::decode(&packet).expect("0x97 decodes"),
        PeerPacket::PublicIpReq
    );
}

#[test]
fn chat_captcha_req_and_res_decode_and_ignore_any_payload() {
    let req = Packet::new(PacketProtocol::Emule, 0xA5, vec![0x10; 40]);
    assert_eq!(
        PeerPacket::decode(&req).expect("0xA5 decodes"),
        PeerPacket::ChatCaptchaReq
    );
    let res = Packet::new(PacketProtocol::Emule, 0xA6, vec![0x20; 10]);
    assert_eq!(
        PeerPacket::decode(&res).expect("0xA6 decodes"),
        PeerPacket::ChatCaptchaRes
    );
}

// --- OP_PUBLICIP_ANSWER (0x98): golden emit + decode + truncated ----------

#[test]
fn public_ip_answer_encodes_the_observed_ipv4_and_round_trips() {
    let answer = PublicIpAnswer {
        ip: Ipv4Addr::new(203, 0, 113, 42),
    };
    let packet = answer.encode_packet();
    assert_eq!(packet.protocol(), PacketProtocol::Emule);
    assert_eq!(packet.opcode(), 0x98);
    assert_eq!(packet.payload(), &[203, 0, 113, 42]);
    match PeerPacket::decode(&packet).expect("round-trips") {
        PeerPacket::PublicIpAnswer(a) => assert_eq!(a.ip, answer.ip),
        other => panic!("expected PublicIpAnswer, got {other:?}"),
    }
}

#[test]
fn public_ip_answer_truncated_is_rejected() {
    let packet = Packet::new(PacketProtocol::Emule, 0x98, vec![1, 2, 3]);
    let err = PeerPacket::decode(&packet).expect_err("3 bytes is not a full IPv4");
    assert_eq!(
        err,
        PeerPacketDecodeError::HumanLayer {
            source: HumanLayerDecodeError::WrongPayloadLen {
                expected: 4,
                actual: 3
            }
        }
    );
}

// --- OP_MESSAGE (0x4E): well-formed / truncated / oversize (450 cap) ------

#[test]
fn message_decodes_well_formed_and_round_trips() {
    let msg = Message {
        text: Ed2kText::from_utf8("hi there"),
    };
    let packet = msg.encode_packet();
    assert_eq!(packet.protocol(), PacketProtocol::Edonkey);
    assert_eq!(packet.opcode(), 0x4E);
    match PeerPacket::decode(&packet).expect("well-formed message decodes") {
        PeerPacket::Message(m) => assert_eq!(m.text, msg.text),
        other => panic!("expected Message, got {other:?}"),
    }
}

#[test]
fn message_missing_length_prefix_is_truncated() {
    let packet = Packet::new(PacketProtocol::Edonkey, 0x4E, vec![0x00]);
    let err = PeerPacket::decode(&packet).expect_err("1 byte has no full length prefix");
    assert_eq!(
        err,
        PeerPacketDecodeError::HumanLayer {
            source: HumanLayerDecodeError::Truncated {
                needed: 2,
                actual: 1
            }
        }
    );
}

#[test]
fn message_declared_length_must_exactly_match_the_frame() {
    // Declares 10 bytes of text but the frame only carries 3 — aMule's own
    // strict check (`length + 2u != size`), unlike OP_FILEDESC's safe read.
    let mut payload = 10u16.to_le_bytes().to_vec();
    payload.extend_from_slice(b"hi!");
    let packet = Packet::new(PacketProtocol::Edonkey, 0x4E, payload);
    let err = PeerPacket::decode(&packet).expect_err("declared/actual length mismatch");
    assert_eq!(
        err,
        PeerPacketDecodeError::HumanLayer {
            source: HumanLayerDecodeError::SizeMismatch {
                declared: 10,
                actual: 5
            }
        }
    );
}

#[test]
fn message_oversize_is_capped_to_450_bytes_not_rejected() {
    // A declared length of 500 whose frame actually carries 500 bytes passes
    // aMule's strict size check; only the *read* is capped at 450 — the
    // message is truncated, never rejected.
    let text = vec![b'x'; 500];
    let mut payload = 500u16.to_le_bytes().to_vec();
    payload.extend_from_slice(&text);
    let packet = Packet::new(PacketProtocol::Edonkey, 0x4E, payload);
    match PeerPacket::decode(&packet).expect("oversize message still decodes") {
        PeerPacket::Message(m) => assert_eq!(m.text.as_bytes().len(), 450),
        other => panic!("expected Message, got {other:?}"),
    }
}

// --- OP_FILEDESC (0x61, Emule): well-formed / truncated / len4 bloat ------

#[test]
fn filedesc_decodes_well_formed_and_round_trips() {
    let desc = FileDesc {
        rating: 4,
        comment: Ed2kText::from_utf8("great file"),
    };
    let packet = desc.encode_packet();
    match PeerPacket::decode(&packet).expect("well-formed filedesc decodes") {
        PeerPacket::FileDesc(d) => assert_eq!(d, desc),
        other => panic!("expected FileDesc, got {other:?}"),
    }
}

#[test]
fn filedesc_header_truncated_is_rejected() {
    // Only 4 bytes: rating + 3 of the 4 length bytes — the header itself
    // is a hard read, unlike the comment string after it.
    let packet = Packet::new(PacketProtocol::Emule, 0x61, vec![0u8; 4]);
    let err = PeerPacket::decode(&packet).expect_err("incomplete header");
    assert_eq!(
        err,
        PeerPacketDecodeError::HumanLayer {
            source: HumanLayerDecodeError::Truncated {
                needed: 5,
                actual: 4
            }
        }
    );
}

#[test]
fn filedesc_declared_len4_bloat_clamps_to_available_bytes_not_rejected() {
    // BaseClient.cpp's "safe read": a declared length past the actual
    // remaining bytes clamps to what's there instead of failing.
    let mut payload = vec![2u8]; // rating
    payload.extend_from_slice(&u32::MAX.to_le_bytes()); // len4 bloat
    payload.extend_from_slice(b"ok"); // only 2 bytes actually present
    let packet = Packet::new(PacketProtocol::Emule, 0x61, payload);
    match PeerPacket::decode(&packet).expect("len4 bloat still decodes") {
        PeerPacket::FileDesc(d) => {
            assert_eq!(d.rating, 2);
            assert_eq!(d.comment, Ed2kText::from_utf8("ok"));
        }
        other => panic!("expected FileDesc, got {other:?}"),
    }
}

#[test]
fn filedesc_comment_is_capped_to_50_bytes_and_tolerates_trailing_bytes() {
    let mut payload = vec![1u8];
    let text = vec![b'y'; 80];
    payload.extend_from_slice(&80u32.to_le_bytes());
    payload.extend_from_slice(&text);
    payload.extend_from_slice(b"trailing junk aMule never checks for");
    let packet = Packet::new(PacketProtocol::Emule, 0x61, payload);
    match PeerPacket::decode(&packet).expect("trailing bytes tolerated") {
        PeerPacket::FileDesc(d) => assert_eq!(d.comment.as_bytes().len(), 50),
        other => panic!("expected FileDesc, got {other:?}"),
    }
}

#[test]
fn filedesc_wrong_frame_is_rejected() {
    // Bypasses `packet.rs`'s (protocol, opcode) pre-dispatch — the decoder
    // must self-validate rather than trust an upstream match (ADR-0068).
    let wrong_protocol = Packet::new(PacketProtocol::Edonkey, 0x61, vec![0u8; 5]);
    assert_eq!(
        FileDesc::decode_packet(&wrong_protocol),
        Err(HumanLayerDecodeError::WrongFrame { opcode: 0x61 })
    );
    let wrong_opcode = Packet::new(PacketProtocol::Emule, 0x60, vec![0u8; 5]);
    assert_eq!(
        FileDesc::decode_packet(&wrong_opcode),
        Err(HumanLayerDecodeError::WrongFrame { opcode: 0x60 })
    );
}

// --- OP_CHANGE_CLIENT_ID (0x4D): well-formed / wrong length ---------------

#[test]
fn change_client_id_decodes_well_formed_and_round_trips() {
    let change = ChangeClientId {
        new_id: ClientId::from_u32(0x0203_0405),
        new_server_ip: Ipv4Addr::new(198, 51, 100, 7),
    };
    let packet = change.encode_packet();
    assert_eq!(packet.protocol(), PacketProtocol::Edonkey);
    assert_eq!(packet.opcode(), 0x4D);
    match PeerPacket::decode(&packet).expect("well-formed change-client-id decodes") {
        PeerPacket::ChangeClientId(c) => assert_eq!(c, change),
        other => panic!("expected ChangeClientId, got {other:?}"),
    }
}

#[test]
fn change_client_id_wrong_payload_len_is_rejected() {
    let packet = Packet::new(PacketProtocol::Edonkey, 0x4D, vec![0u8; 7]);
    let err = PeerPacket::decode(&packet).expect_err("7 bytes is not the 8-byte shape");
    assert_eq!(
        err,
        PeerPacketDecodeError::HumanLayer {
            source: HumanLayerDecodeError::WrongPayloadLen {
                expected: 8,
                actual: 7
            }
        }
    );
}

#[test]
fn umbrella_preserves_unrelated_opcodes_as_unknown_still() {
    // Regression anchor: an opcode the human layer does not handle stays Unknown.
    let packet = Packet::new(PacketProtocol::Edonkey, 0x62, vec![0xAB]);
    match PeerPacket::decode(&packet).expect("unrelated opcode still decodes to Unknown") {
        PeerPacket::Unknown {
            protocol, opcode, ..
        } => {
            assert_eq!(protocol, PacketProtocol::Edonkey);
            assert_eq!(opcode, 0x62);
        }
        other => panic!("expected Unknown, got {other:?}"),
    }
}
