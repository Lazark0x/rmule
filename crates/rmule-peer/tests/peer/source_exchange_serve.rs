//! Session-level source-exchange **serve** side (ADR-0055). A
//! peer's `OP_REQUESTSOURCES` / `OP_REQUESTSOURCES2` (standalone
//! or a multipacket `Sources`/`Sources2` sub) surfaces as
//! [`PeerEvent::SourcesRequested`] carrying the aMule-exact serve wire form,
//! and core's `AnswerSources` command frames `OP_ANSWERSOURCES` (`0x82`) or
//! `OP_ANSWERSOURCES2` (`0x84`) — pack-attempted above `PEER_PACK_THRESHOLD`
//! (354 bytes, ADR-0053). The pool / filter / per-peer throttle brain is
//! core-side (`rmule-core` `serve::source_exchange`); this file pins the wire.

use std::net::Ipv4Addr;

use rmule_peer::{
    AnswerSources, AnswerSources2, HelloAnswer, MiscOptions1, MiscOptions2, MultiPacketRequest,
    PeerCommand, PeerEvent, PeerHelloBody, PeerOutput, PeerSession, RequestItem, RequestSources2,
    RequestSourcesPacket, ServedSourcesVersion, SourceExchangeVersion,
};
use rmule_primitives::session::drain;
use rmule_primitives::{
    ClientId, Ed2kText, ExchangedSource, FileHash, Ipv4Endpoint, Packet, PacketProtocol,
    PeerSource, Tag, TagName, TagValue, UserHash,
};
use rmule_testkit::peer_session::{ctx, file_hash, last_write_bytes, peer_at};

/// A framed `OP_HELLOANSWER` from a peer advertising SX1 `sx1_nibble` and,
/// when `supports_sx2`, `SupportsSourceEx2` (`MiscOptions2` bit 10) — the two
/// inputs the serve-version pick reads off the *requester's* hello.
fn peer_hello_answer(sx1_nibble: u8, supports_sx2: bool) -> Vec<u8> {
    let mut tags = vec![
        Tag::new(
            TagName::length_prefixed_id(0x01),
            TagValue::String(Ed2kText::from_utf8("remote")),
        ),
        MiscOptions1::from_bits(u32::from(sx1_nibble) << 12).to_tag(),
    ];
    if supports_sx2 {
        tags.push(MiscOptions2::from_bits(1 << 10).to_tag());
    }
    let body = PeerHelloBody {
        user_hash: UserHash::from_bytes([0x99; UserHash::BYTE_LEN]),
        client_id: ClientId::from_u32(0x2000_0002),
        tcp_port: 4662,
        tags,
        connected_server: Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0),
    };
    HelloAnswer::new(body).encode_packet().encode()
}

/// An identified session against a peer with the given advertised SX capability.
fn identified(sx1_nibble: u8, supports_sx2: bool) -> PeerSession {
    let mut session = PeerSession::new_outbound(peer_at(9), ctx());
    session.start();
    drain(|| session.poll_output());
    session.handle_bytes(&peer_hello_answer(sx1_nibble, supports_sx2));
    drain(|| session.poll_output());
    session
}

fn sources_requested(outputs: &[PeerOutput]) -> Option<(FileHash, ServedSourcesVersion)> {
    outputs.iter().find_map(|o| match o {
        PeerOutput::Event(PeerEvent::SourcesRequested { file_hash, version }) => {
            Some((*file_hash, *version))
        }
        PeerOutput::Event(PeerEvent::FileBundleRequested {
            file_hash, asks, ..
        }) => asks.iter().find_map(|ask| match ask {
            rmule_peer::BundledAsk::Sources(version) => Some((*file_hash, *version)),
            _ => None,
        }),
        _ => None,
    })
}

fn high_id_source(id: u32, port: u16) -> ExchangedSource {
    ExchangedSource::plain(PeerSource::new(ClientId::from_u32(id), port))
}

#[test]
fn a_standalone_request_sources_surfaces_an_sx1_serve_request_at_the_peer_nibble() {
    let mut session = identified(3, false);
    let fh = file_hash(0x42);
    session.handle_bytes(
        &RequestSourcesPacket { file_hash: fh }
            .encode_packet()
            .encode(),
    );
    let out = drain(|| session.poll_output());
    assert_eq!(
        sources_requested(&out),
        Some((fh, ServedSourcesVersion::Sx1(SourceExchangeVersion::V3))),
        "a plain 0x81 serves SX1 at the requester's own advertised nibble",
    );
}

#[test]
fn a_request_sources2_from_an_sx2_peer_surfaces_an_sx2_serve_request() {
    let mut session = identified(3, true);
    let fh = file_hash(0x43);
    session.handle_bytes(
        &RequestSources2 {
            version: 4,
            options: 0,
            file_hash: fh,
        }
        .encode_packet()
        .encode(),
    );
    let out = drain(|| session.poll_output());
    assert_eq!(
        sources_requested(&out),
        Some((fh, ServedSourcesVersion::Sx2(SourceExchangeVersion::V4))),
        "an SX2-advertising peer naming version 4 earns a 0x84 answer",
    );
}

#[test]
fn a_request_sources2_from_a_non_sx2_peer_falls_to_the_sx1_path() {
    // aMule serves SX2 only when the requester *advertised* SupportsSourceEx2;
    // without it, even a 0x83 falls to 0x82 at the requester's SX1 nibble.
    let mut session = identified(2, false);
    let fh = file_hash(0x44);
    session.handle_bytes(
        &RequestSources2 {
            version: 4,
            options: 0,
            file_hash: fh,
        }
        .encode_packet()
        .encode(),
    );
    let out = drain(|| session.poll_output());
    assert_eq!(
        sources_requested(&out),
        Some((fh, ServedSourcesVersion::Sx1(SourceExchangeVersion::V2))),
    );
}

#[test]
fn a_bundled_sources_sub_reaches_the_same_serve_callback() {
    // ADR-0055: a multipacket Sources sub shares the standalone ask's serve
    // path (and, core-side, its per-peer throttle).
    let mut session = identified(3, false);
    let fh = file_hash(0x46);
    let bundle = MultiPacketRequest {
        file_hash: fh,
        file_size: None,
        items: vec![RequestItem::Sources],
        unknown_sub: None,
        cut: None,
    };
    session.handle_bytes(&bundle.encode_packet().encode());
    let out = drain(|| session.poll_output());
    assert_eq!(
        sources_requested(&out),
        Some((fh, ServedSourcesVersion::Sx1(SourceExchangeVersion::V3))),
    );
}

#[test]
fn answer_sources_command_frames_op_answersources_and_round_trips_the_sources() {
    let mut session = identified(3, false);
    let fh = file_hash(0x45);
    let sources = vec![
        high_id_source(0x0203_0405, 4662),
        high_id_source(0x0607_0809, 5000),
    ];
    session.handle_command(PeerCommand::AnswerSources {
        file_hash: fh,
        sources,
        version: ServedSourcesVersion::Sx1(SourceExchangeVersion::V3),
    });
    let out = drain(|| session.poll_output());
    let (packet, _) = Packet::decode(&last_write_bytes(&out)).expect("answer frames");
    assert_eq!(packet.protocol(), PacketProtocol::Emule);
    assert_eq!(packet.opcode(), 0x82, "SX1 answer is OP_ANSWERSOURCES");
    // Decode back at the peer's own nibble (3 → v3, hybrid ids): the sources
    // round-trip through the serve encoder's byte-swap.
    let decoded = AnswerSources::decode_packet(&packet, 3).expect("v3 answer decodes");
    assert_eq!(decoded.file_hash, fh);
    let ids: Vec<u32> = decoded
        .sources
        .iter()
        .map(|e| e.source().peer_source().wire_id())
        .collect();
    assert_eq!(ids, vec![0x0203_0405, 0x0607_0809]);
}

#[test]
fn answer_sources_command_frames_op_answersources2_for_an_sx2_answer() {
    let mut session = identified(3, true);
    let fh = file_hash(0x4A);
    session.handle_command(PeerCommand::AnswerSources {
        file_hash: fh,
        sources: vec![high_id_source(0x0203_0405, 4662)],
        version: ServedSourcesVersion::Sx2(SourceExchangeVersion::V4),
    });
    let out = drain(|| session.poll_output());
    let (packet, _) = Packet::decode(&last_write_bytes(&out)).expect("answer frames");
    assert_eq!(packet.protocol(), PacketProtocol::Emule);
    assert_eq!(packet.opcode(), 0x84, "SX2 answer is OP_ANSWERSOURCES2");
    let decoded = AnswerSources2::decode_packet(&packet).expect("0x84 decodes");
    assert_eq!(decoded.version, SourceExchangeVersion::V4);
    assert_eq!(decoded.file_hash, fh);
    assert_eq!(decoded.sources.len(), 1);
}

#[test]
fn the_pack_threshold_gates_the_answersources_emit() {
    // v1 payload = 16 (hash) + 2 (count) + count*12. 28 sources → 354 bytes
    // (at the threshold, stays plain); 29 → 366 (over it, packed 0xD4).
    let answer = |count: u32| {
        let mut session = identified(1, false);
        let sources: Vec<_> = (0..count)
            .map(|i| high_id_source(0x0A00_0000 + i, 4662))
            .collect();
        session.handle_command(PeerCommand::AnswerSources {
            file_hash: file_hash(0x77),
            sources,
            version: ServedSourcesVersion::Sx1(SourceExchangeVersion::V1),
        });
        let out = drain(|| session.poll_output());
        Packet::decode(&last_write_bytes(&out))
            .expect("answer frames")
            .0
    };

    let at_threshold = answer(28);
    assert_eq!(
        at_threshold.protocol(),
        PacketProtocol::Emule,
        "a 354-byte answer is at the threshold and stays a plain 0x82",
    );
    assert_eq!(at_threshold.opcode(), 0x82);

    let over_threshold = answer(29);
    assert_eq!(
        over_threshold.protocol(),
        PacketProtocol::PackedEd2k,
        "a 366-byte answer crosses PEER_PACK_THRESHOLD and ships packed (0xD4)",
    );
    assert_eq!(
        over_threshold.opcode(),
        0x82,
        "the answersources opcode rides through the 0xD4 pack",
    );
}

#[test]
fn a_serve_request_before_identify_is_preserved_as_unknown_not_answered() {
    // The serve callback never fires on an out-of-order request: an inbound
    // 0x81 before the hello exchange is preserved as Unknown, session open.
    let mut session = PeerSession::new_inbound(peer_at(9), ctx());
    session.handle_bytes(
        &RequestSourcesPacket {
            file_hash: file_hash(0x42),
        }
        .encode_packet()
        .encode(),
    );
    let out = drain(|| session.poll_output());
    assert!(
        sources_requested(&out).is_none(),
        "no serve callback before the peer has identified",
    );
    assert!(
        out.iter().any(|o| matches!(
            o,
            PeerOutput::Event(PeerEvent::UnknownPeerPacket { opcode: 0x81, .. })
        )),
        "the premature request is preserved as Unknown (ADR-0018)",
    );
}

/// `HasEd2kWireForm` (ADR-0087): a classic answer has one 32-bit id field per
/// entry and no address block, so a native-IPv6 source is **omitted** rather
/// than written as its sentinel or as a zero. Either would name a source the
/// reader cannot resolve, and a zero would send it down a callback nobody can
/// broker. The IPv4 sources around it still go out.
#[test]
fn a_native_ipv6_source_is_omitted_from_a_classic_answer_never_zeroed() {
    let mut session = identified(1, false);
    let fh = file_hash(0x5C);
    let ipv6 = ExchangedSource::plain(PeerSource::Ipv6(rmule_primitives::Ipv6Endpoint::new(
        "2a01:4f8::7".parse().unwrap(),
        4662,
    )));
    session.handle_command(PeerCommand::AnswerSources {
        file_hash: fh,
        sources: vec![high_id_source(0x0203_0405, 4662), ipv6],
        version: ServedSourcesVersion::Sx1(SourceExchangeVersion::V1),
    });
    let out = drain(|| session.poll_output());
    let (packet, _) = Packet::decode(&last_write_bytes(&out)).expect("answer frames");
    let decoded = AnswerSources::decode_packet(&packet, 1).expect("v1 answer decodes");

    let ids: Vec<u32> = decoded
        .sources
        .iter()
        .map(|e| e.source().peer_source().wire_id())
        .collect();
    assert_eq!(
        ids,
        vec![0x0203_0405],
        "the IPv4 source stands, the IPv6 one is absent — not 0, not 0xFFFFFFFF"
    );
}

/// The ExtSX arm is the one shape that *can* carry it: the same source list,
/// answered to a peer that claimed `MODMISC_EXTXS`, keeps both.
#[test]
fn the_ext_sx_answer_carries_the_ipv6_source_the_classic_one_omits() {
    let mut session = identified(1, false);
    let fh = file_hash(0x5D);
    let endpoint = rmule_primitives::Ipv6Endpoint::new("2a01:4f8::7".parse().unwrap(), 4662);
    session.handle_command(PeerCommand::AnswerSources {
        file_hash: fh,
        sources: vec![
            high_id_source(0x0203_0405, 4662),
            ExchangedSource::plain(PeerSource::Ipv6(endpoint)),
        ],
        version: ServedSourcesVersion::Ext {
            sx2: false,
            emission: rmule_peer::ExtSxEmission::default(),
        },
    });
    let out = drain(|| session.poll_output());
    let (packet, _) = Packet::decode(&last_write_bytes(&out)).expect("answer frames");
    let decoded = AnswerSources::decode_ext_packet(&packet).expect("ExtSX answer decodes");

    assert_eq!(decoded.sources.len(), 2);
    assert_eq!(decoded.sources[1].ipv6(), Some(endpoint));
    assert_eq!(
        decoded.sources[1].source().peer_source(),
        PeerSource::Ipv6(endpoint)
    );
}

/// A dual-stack High-ID source — a queued client whose hello named its IPv6
/// beside a routable id — goes out in an ExtSX answer with `CT_MOD_IP_V6`
/// beside the IPv4 id, emule-qt's own writer's record (`KnownFile.cpp:937`:
/// the tag is written for any source with an open public IPv6, High ID or
/// not). A classic answer of the same source is byte-identical to one of the
/// source without its IPv6 half: the fixed stride has nowhere to put it.
#[test]
fn a_dual_stack_source_carries_its_ipv6_beside_the_ipv4_in_an_ext_answer_only() {
    let fh = file_hash(0x5E);
    let v4 = PeerSource::new(
        ClientId::from_u32(u32::from_le_bytes([198, 51, 100, 7])),
        4662,
    );
    let v6 = rmule_primitives::Ipv6Endpoint::new("3fff:ed2:1::7".parse().unwrap(), 4662);
    let hash = UserHash::from_bytes([0x51; UserHash::BYTE_LEN]);
    let single = ExchangedSource::new(v4, Some(hash), None);
    let dual = single.with_ipv6_half(Some(v6));

    let answer = |source: ExchangedSource, version: ServedSourcesVersion| {
        let mut session = identified(4, true);
        session.handle_command(PeerCommand::AnswerSources {
            file_hash: fh,
            sources: vec![source],
            version,
        });
        let out = drain(|| session.poll_output());
        let (packet, _) = Packet::decode(&last_write_bytes(&out)).expect("answer frames");
        packet
    };

    let ext = answer(
        dual,
        ServedSourcesVersion::Ext {
            sx2: true,
            emission: rmule_peer::ExtSxEmission { skip_tags: true },
        },
    );
    assert_eq!(ext.opcode(), 0x84);
    let mut expected = vec![0x01]; // ExtSX pins the version at 1
    expected.extend_from_slice(fh.as_bytes());
    expected.extend_from_slice(&[0x01, 0x00]); // one record
    expected.extend_from_slice(&[198, 51, 100, 7, 0x36, 0x12]); // the IPv4 id, port 4662
    expected.push(0x02); // two tags
    expected.extend_from_slice(&[0x81, 0xae]); // CT_MOD_IP_V6, HASH16
    expected.extend_from_slice(&v6.ip.octets());
    expected.extend_from_slice(&[0x81, 0xbc]); // CT_EMULE_USERHASH, HASH16
    expected.extend_from_slice(hash.as_bytes());
    assert_eq!(ext.payload(), expected.as_slice());

    let classic = ServedSourcesVersion::Sx2(SourceExchangeVersion::V4);
    assert_eq!(
        answer(dual, classic).payload(),
        answer(single, classic).payload(),
        "the classic writer is unchanged by the IPv6 half"
    );
}
