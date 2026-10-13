//! Every wire decoder reads through the one bounds-checked reader, so a
//! datagram or payload cut at any byte must come back as an error — never a
//! panic, never a short read taken for a whole one. Each valid encoding is cut
//! at every offset below the length its shape requires; the bundles, whose
//! decoders keep the prefix they could read by design, are cut everywhere and
//! only required not to panic.

use rmule_peer::{
    AichAnswer, AichFileHashAns, AichFileHashReq, AichRequest, AnswerItem, AnswerSources,
    AnswerSources2, BundleCut, Callback, ChangeClientId, CompressedPart, DirectCallbackReq,
    EmuleInfo, ExtendedRequests, FileReqAnsNoFil, FileStatus, HashSetAnswer, HashSetRequest, Hello,
    Message, MultiPacketAnswer, MultiPacketRequest, PartBitmap, PartOffsetWidth, PartRanges,
    PeerPacket, PublicIpAnswer, PublicKeyPacket, QueueRanking, ReaskAck, ReaskCallbackTcp,
    ReaskFilePing, ReqFileNameAnswer, RequestFileName, RequestItem, RequestParts, RequestSources2,
    SecIdentStatePacket, SendingPart, SetReqFileId, SignaturePacket, SourceExchangeEntry,
    SourceExchangeVersion,
};
use rmule_primitives::{
    AichRootHash, ClientId, Ed2kText, FileHash, Ipv4Endpoint, Ipv6Endpoint, Packet, PacketProtocol,
    PartHash, PeerEndpoint, PeerSource, SourceClaim, UserHash,
};
use rmule_testkit::wire::cut_payload;
use std::net::{Ipv4Addr, Ipv6Addr};

fn hash() -> FileHash {
    FileHash::from_bytes([0x11; 16])
}

fn bitmap() -> PartBitmap {
    PartBitmap::all_present(19)
}

/// The packet decodes whole, and fails at every payload cut short of whole.
fn assert_cuts_fail(name: &str, packet: &Packet) {
    PeerPacket::decode(packet).unwrap_or_else(|e| panic!("{name}: the whole packet: {e}"));
    for cut in 0..packet.payload().len() {
        let cut_packet = cut_payload(packet, cut);
        assert!(
            PeerPacket::decode(&cut_packet).is_err(),
            "{name}: a payload cut to {cut} of {} bytes decoded",
            packet.payload().len()
        );
    }
}

#[test]
fn a_tcp_packet_cut_anywhere_inside_its_shape_is_an_error() {
    let root = AichRootHash::from_bytes([0x22; 20]);
    let ranges = PartRanges::new([(0, 10), (20, 30), (0, 0)]).unwrap();
    let sending = SendingPart {
        file_hash: hash(),
        start: 100,
        end: 104,
        data: vec![1, 2, 3, 4],
    };
    // A compressed part and an AICH answer take any tail after their header,
    // so the whole packet here is the bare header.
    let compressed = CompressedPart {
        file_hash: hash(),
        start: 100,
        compressed_block_len: 9,
        compressed_chunk: Vec::new(),
    };
    let requests = RequestParts {
        file_hash: hash(),
        ranges,
    };
    let cases = [
        (
            "hash-set request",
            HashSetRequest { file_hash: hash() }.encode_packet(),
        ),
        (
            "hash-set answer",
            HashSetAnswer {
                file_hash: hash(),
                part_hashes: vec![PartHash::from_bytes([3; 16]); 2],
            }
            .encode_packet(),
        ),
        (
            "aich request",
            AichRequest {
                file_hash: hash(),
                part: 4,
                root,
            }
            .encode_packet(),
        ),
        (
            "aich answer header",
            AichAnswer {
                file_hash: hash(),
                part: 4,
                root,
                recovery_data: Vec::new(),
            }
            .encode_packet(),
        ),
        (
            "aich file-hash request",
            AichFileHashReq { file_hash: hash() }.encode_packet(),
        ),
        (
            "aich file-hash answer",
            AichFileHashAns {
                file_hash: hash(),
                root,
            }
            .encode_packet(),
        ),
        (
            "request parts u32",
            requests.encode_packet(PartOffsetWidth::U32).unwrap(),
        ),
        (
            "request parts u64",
            requests.encode_packet(PartOffsetWidth::U64).unwrap(),
        ),
        (
            "sending part u32",
            sending.encode_packet(PartOffsetWidth::U32).unwrap(),
        ),
        (
            "sending part u64",
            sending.encode_packet(PartOffsetWidth::U64).unwrap(),
        ),
        (
            "compressed part header u32",
            compressed.encode_packet(PartOffsetWidth::U32).unwrap(),
        ),
        (
            "compressed part header u64",
            compressed.encode_packet(PartOffsetWidth::U64).unwrap(),
        ),
        (
            "file-name answer",
            ReqFileNameAnswer {
                file_hash: hash(),
                file_name: Ed2kText::from_bytes(b"a name".to_vec()),
            }
            .encode_packet(),
        ),
        (
            "no-file answer",
            FileReqAnsNoFil { file_hash: hash() }.encode_packet(),
        ),
        (
            "set request file id",
            SetReqFileId { file_hash: hash() }.encode_packet(),
        ),
        (
            "file status",
            FileStatus {
                file_hash: hash(),
                bitmap: bitmap(),
            }
            .encode_packet(),
        ),
        (
            "file-name ask, bare hash",
            RequestFileName::new(hash(), None).encode_packet(),
        ),
    ];
    for (name, packet) in &cases {
        assert_cuts_fail(name, packet);
    }
}

#[test]
fn a_client_udp_datagram_cut_anywhere_is_an_error() {
    let ping = ReaskFilePing {
        file_hash: hash(),
        part_status: Some(bitmap()),
        complete_sources: Some(7),
    }
    .encode_udp();
    let ack = ReaskAck {
        part_status: Some(bitmap()),
        rank: 12,
    }
    .encode_udp();
    let callback = DirectCallbackReq {
        our_tcp_port: 4662,
        our_user_hash: UserHash::from_bytes([0x33; 16]),
        connect_options: 0x83,
    }
    .encode_udp();

    ReaskFilePing::decode_udp(&ping, 4).unwrap();
    ReaskAck::decode_udp(&ack, 4).unwrap();
    DirectCallbackReq::decode_udp(&callback).unwrap();
    for cut in 0..ping.len() {
        assert!(
            ReaskFilePing::decode_udp(&ping[..cut], 4).is_err(),
            "ping cut to {cut}"
        );
    }
    for cut in 0..ack.len() {
        assert!(
            ReaskAck::decode_udp(&ack[..cut], 4).is_err(),
            "ack cut to {cut}"
        );
    }
    for cut in 0..callback.len() {
        assert!(
            DirectCallbackReq::decode_udp(&callback[..cut]).is_err(),
            "callback request cut to {cut}"
        );
    }
}

#[test]
fn a_bundle_cut_anywhere_never_panics() {
    let request = MultiPacketRequest {
        file_hash: hash(),
        file_size: Some(9_728_000),
        items: vec![
            RequestItem::Name {
                part_status: Some(PartBitmap::all_present(2)),
            },
            RequestItem::SetReqId,
            RequestItem::Sources2 {
                version: 4,
                options: 1,
            },
        ],
        unknown_sub: None,
        cut: None,
    }
    .encode_packet();
    let answer = MultiPacketAnswer {
        file_hash: hash(),
        items: vec![
            AnswerItem::Name(Ed2kText::from_bytes(b"a name".to_vec())),
            AnswerItem::Status(bitmap()),
            AnswerItem::AichRoot(AichRootHash::from_bytes([0x44; 20])),
        ],
        unknown_sub: None,
    }
    .encode_packet();

    let level = ExtendedRequests::negotiated(2, 2);
    for cut in 0..=request.payload().len() {
        let packet = cut_payload(&request, cut);
        let decoded = MultiPacketRequest::decode_packet(&packet, level);
        if cut < 16 + 8 {
            assert!(decoded.is_err(), "request cut to {cut}");
        }
    }
    for cut in 0..=answer.payload().len() {
        let packet = cut_payload(&answer, cut);
        let decoded = MultiPacketAnswer::decode_packet(&packet);
        if cut < 16 {
            assert!(decoded.is_err(), "answer cut to {cut}");
        }
    }
    // A request cut inside a trailer is reported as a cut, not failed.
    let sources2_cut = cut_payload(&request, request.payload().len() - 1);
    let walked = MultiPacketRequest::decode_packet(&sources2_cut, level).unwrap();
    assert_eq!(walked.cut, Some(BundleCut::Sources2));
}

/// A decode that takes only the packet: the whole one succeeds, every cut errs.
fn assert_decoder_cuts_fail<T, E>(
    name: &str,
    packet: &Packet,
    decode: impl Fn(&Packet) -> Result<T, E>,
) {
    assert!(decode(packet).is_ok(), "{name}: the whole packet");
    for cut in 0..packet.payload().len() {
        let cut_packet = cut_payload(packet, cut);
        assert!(
            decode(&cut_packet).is_err(),
            "{name}: a payload cut to {cut} of {} bytes decoded",
            packet.payload().len()
        );
    }
}

#[test]
fn buddy_relay_secure_ident_and_human_layer_packets_cut_anywhere_are_errors() {
    let v4 = Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 7), 4662);
    let v6 = Ipv6Endpoint::new("2001:db8::1".parse::<Ipv6Addr>().unwrap(), 4662);
    assert_decoder_cuts_fail(
        "0x9A relay, IPv4 requester",
        &ReaskCallbackTcp {
            requester: PeerEndpoint::V4(v4),
            forwarded: Vec::new(),
        }
        .encode_packet(),
        ReaskCallbackTcp::decode_packet,
    );
    assert_decoder_cuts_fail(
        "0x9A relay, IPv6 requester",
        &ReaskCallbackTcp {
            requester: PeerEndpoint::V6(v6),
            forwarded: Vec::new(),
        }
        .encode_packet(),
        ReaskCallbackTcp::decode_packet,
    );
    assert_decoder_cuts_fail(
        "0x99 callback",
        &Callback {
            buddy_id: [0x44; 16],
            file_hash: hash(),
            requester: v4,
        }
        .encode_packet(),
        Callback::decode_packet,
    );
    assert_decoder_cuts_fail(
        "secure-ident state",
        &SecIdentStatePacket {
            state: rmule_peer::SecIdentState::KeyAndSignNeeded,
            challenge: 7,
        }
        .encode_packet(),
        SecIdentStatePacket::decode_packet,
    );
    assert_decoder_cuts_fail(
        "public key",
        &PublicKeyPacket { der: vec![1; 9] }.encode_packet(),
        PublicKeyPacket::decode_packet,
    );
    assert_decoder_cuts_fail(
        "signature, v1",
        &SignaturePacket {
            signature: vec![2; 9],
            ip_kind: None,
        }
        .encode_packet(),
        SignaturePacket::decode_packet,
    );
    assert_decoder_cuts_fail(
        "chat message",
        &Message {
            text: Ed2kText::from_bytes(b"hello".to_vec()),
        }
        .encode_packet(),
        Message::decode_packet,
    );
    assert_decoder_cuts_fail(
        "change client id",
        &ChangeClientId {
            new_id: ClientId::from_u32(0x0102_0304),
            new_server_ip: Ipv4Addr::new(1, 2, 3, 4),
        }
        .encode_packet(),
        ChangeClientId::decode_packet,
    );
    assert_decoder_cuts_fail(
        "public ip answer",
        &PublicIpAnswer {
            ip: Ipv4Addr::new(1, 2, 3, 4),
        }
        .encode_packet(),
        PublicIpAnswer::decode_packet,
    );
    assert_decoder_cuts_fail(
        "queue ranking",
        &QueueRanking { rank: 12 }.encode_packet(),
        QueueRanking::decode_packet,
    );
}

#[test]
fn source_exchange_hello_and_emule_info_packets_cut_anywhere_are_errors() {
    let entry = SourceExchangeEntry::new(
        SourceClaim::new(
            PeerSource::new(ClientId::from_u32(0x0A0B_0C0D), 4662),
            None,
            None,
        ),
        None,
    );
    assert_decoder_cuts_fail(
        "request sources 2",
        &RequestSources2 {
            version: 4,
            options: 1,
            file_hash: hash(),
        }
        .encode_packet(),
        RequestSources2::decode_packet,
    );
    assert_decoder_cuts_fail(
        "answer sources",
        &AnswerSources {
            file_hash: hash(),
            sources: vec![entry],
        }
        .encode_packet(SourceExchangeVersion::V1),
        |packet| AnswerSources::decode_packet(packet, 1),
    );
    assert_decoder_cuts_fail(
        "answer sources 2",
        &AnswerSources2 {
            version: SourceExchangeVersion::V1,
            file_hash: hash(),
            sources: vec![entry],
        }
        .encode_packet(),
        AnswerSources2::decode_packet,
    );

    // A hello with no tags: user hash, id, port, tag count 0, connected server.
    let mut hello = vec![16];
    hello.extend_from_slice(&[0x55; 16]);
    hello.extend_from_slice(&0x0102_0304_u32.to_le_bytes());
    hello.extend_from_slice(&4662_u16.to_le_bytes());
    hello.extend_from_slice(&0_u32.to_le_bytes());
    hello.extend_from_slice(&[0; 6]);
    assert_decoder_cuts_fail(
        "hello",
        &Packet::new(PacketProtocol::Edonkey, 0x01, hello),
        Hello::decode_packet,
    );
    // OP_EMULEINFO: version, protocol, tag count 0.
    assert_decoder_cuts_fail(
        "emule info",
        &Packet::new(PacketProtocol::Emule, 0x01, vec![0x43, 0x01, 0, 0, 0, 0]),
        EmuleInfo::decode_packet,
    );
}

#[test]
fn nat_traversal_frames_cut_anywhere_are_errors() {
    use rmule_peer::natt::{
        CapsFrame, EndpointHint, NattConnectOptions, NattFrame, QuicProof, RendezvousBody,
    };

    let sender = UserHash::from_bytes([0xA1; 16]);
    let recipient = UserHash::from_bytes([0xB2; 16]);
    let caps = CapsFrame {
        connect_options: NattConnectOptions::from_byte(0x83),
        sender,
        expected_recipient: recipient,
        file_hash: hash(),
    };
    let frame = NattFrame::Caps(caps).encode();
    assert!(NattFrame::decode(&frame).is_ok());
    for cut in 0..frame.len() {
        assert!(
            NattFrame::decode(&frame[..cut]).is_err(),
            "caps frame cut to {cut}"
        );
    }

    let proof = QuicProof {
        sender,
        expected_recipient: recipient,
    }
    .encode();
    assert!(QuicProof::decode(&proof).is_ok());
    for cut in 0..proof.len() {
        assert!(
            QuicProof::decode(&proof[..cut]).is_err(),
            "quic proof cut to {cut}"
        );
    }

    let hint = EndpointHint {
        target: sender,
        buddy_id: [0xC3; 16],
        file_hash: Some(hash()),
        target_endpoint: Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 7), 4672),
        options: NattConnectOptions::from_byte(0x83),
    }
    .encode_udp();
    assert!(EndpointHint::decode_udp(&hint).is_ok());
    for cut in 0..hint.len() {
        assert!(
            EndpointHint::decode_udp(&hint[..cut]).is_err(),
            "hint cut to {cut}"
        );
    }

    // The rendezvous body reads by bytes remaining, so only its fixed head
    // (header, requester hash, options byte) is mandatory.
    let rendezvous = RendezvousBody {
        requester: sender,
        options: NattConnectOptions::from_byte(0x83),
        file_hash: Some(hash()),
        claimed_endpoint: Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 7), 4672)),
        transport_hint: None,
    }
    .encode_standalone();
    assert!(RendezvousBody::decode_standalone(&rendezvous).is_ok());
    for cut in 0..2 + 16 + 1 {
        assert!(
            RendezvousBody::decode_standalone(&rendezvous[..cut]).is_err(),
            "rendezvous cut to {cut}"
        );
    }
}
