//! Session-level source-exchange **serve** side (ADR-0055). A
//! peer's `OP_REQUESTSOURCES` / `OP_REQUESTSOURCES2` (standalone
//! or a multipacket `Sources`/`Sources2` sub) surfaces as
//! [`ServerEvent::SourcesRequested`]; the session keeps the aMule-exact serve
//! wire form it picked from the asker's advert, and core's `AnswerSources`
//! command frames `OP_ANSWERSOURCES` (`0x82`) or `OP_ANSWERSOURCES2` (`0x84`)
//! in it — pack-attempted above `PEER_PACK_THRESHOLD` (354 bytes, ADR-0053).
//! The pool / filter / per-peer throttle brain is core-side (`rmule-core`
//! `serve::source_exchange`); this file pins the wire.

use std::net::Ipv4Addr;

use rmule_peer::{
    AnswerSources, AnswerSources2, BundledAsk, HelloAnswer, MiscOptions1, MiscOptions2,
    ModMiscOptions, MultiPacketRequest, NoticeEvent, PeerCommand, PeerError, PeerEvent,
    PeerHelloBody, PeerOutput, PeerSession, RequestItem, RequestSources2, RequestSourcesPacket,
    ServerCommand, ServerEvent, SourceExchangeVersion,
};
use rmule_primitives::session::drain;
use rmule_primitives::{
    ClientId, Ed2kText, FileHash, Informant, Ipv4Endpoint, Packet, PacketProtocol, PeerSource,
    SourceSighting, Tag, TagName, TagValue, UserHash,
};
use rmule_testkit::peer_session::{ctx, file_hash, last_write_bytes, peer_at};

/// What a requester's hello says about source exchange: the three inputs the
/// serve-form pick reads off it.
#[derive(Clone, Copy)]
struct Advert {
    /// Its SX1 nibble (`MiscOptions1`).
    sx1_nibble: u8,
    /// Whether it advertised `SupportsSourceEx2` (`MiscOptions2` bit 10).
    supports_sx2: bool,
    /// Its `CT_MOD_MISCOPTIONS` claim, when it sent one (ADR-0087).
    mod_misc: Option<ModMiscOptions>,
}

const fn classic(sx1_nibble: u8, supports_sx2: bool) -> Advert {
    Advert {
        sx1_nibble,
        supports_sx2,
        mod_misc: None,
    }
}

/// A requester claiming ExtSX (`MODMISC_EXTXS`), and the skip-tags bit when
/// `skip_tags`.
const fn ext_sx(sx1_nibble: u8, supports_sx2: bool, skip_tags: bool) -> Advert {
    let bits = if skip_tags { 1 | (1 << 5) } else { 1 };
    Advert {
        sx1_nibble,
        supports_sx2,
        mod_misc: Some(ModMiscOptions::from_bits(bits)),
    }
}

/// A framed `OP_HELLOANSWER` from a peer making `advert`.
fn peer_hello_answer(advert: Advert) -> Vec<u8> {
    let mut tags = vec![
        Tag::new(
            TagName::length_prefixed_id(0x01),
            TagValue::String(Ed2kText::from_utf8("remote")),
        ),
        MiscOptions1::from_bits(u32::from(advert.sx1_nibble) << 12).to_tag(),
    ];
    if advert.supports_sx2 {
        tags.push(MiscOptions2::from_bits(1 << 10).to_tag());
    }
    if let Some(claim) = advert.mod_misc {
        tags.push(claim.to_tag());
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

/// An identified session against a peer making `advert`.
fn identified(advert: Advert) -> PeerSession {
    let mut session = PeerSession::new_outbound(peer_at(9), ctx());
    session.start();
    drain(|| session.poll_output());
    session.handle_bytes(&peer_hello_answer(advert));
    drain(|| session.poll_output());
    session
}

/// A standalone `OP_REQUESTSOURCES` (`0x81`).
fn plain_ask(file_hash: FileHash) -> Vec<u8> {
    RequestSourcesPacket { file_hash }.encode_packet().encode()
}

/// A standalone `OP_REQUESTSOURCES2` (`0x83`) naming `version`.
fn sx2_ask(file_hash: FileHash, version: u8) -> Vec<u8> {
    RequestSources2 {
        version,
        options: 0,
        file_hash,
    }
    .encode_packet()
    .encode()
}

/// The file a standalone or bundled source ask in `outputs` named.
fn sources_requested(outputs: &[PeerOutput]) -> Option<FileHash> {
    outputs.iter().find_map(|o| match o {
        PeerOutput::Event(PeerEvent::Server(ServerEvent::SourcesRequested { file_hash })) => {
            Some(*file_hash)
        }
        PeerOutput::Event(PeerEvent::Server(ServerEvent::FileBundleRequested {
            file_hash,
            asks,
            ..
        })) => asks
            .iter()
            .any(|ask| matches!(ask, BundledAsk::Sources))
            .then_some(*file_hash),
        _ => None,
    })
}

/// The source count the session reported for the answer in `outputs`.
fn sources_answered(outputs: &[PeerOutput]) -> Option<usize> {
    outputs.iter().find_map(|o| match o {
        PeerOutput::Event(PeerEvent::Server(ServerEvent::SourcesAnswered { count, .. })) => {
            Some(*count)
        }
        _ => None,
    })
}

/// Feed `ask` to `session`, check it surfaced as a source ask for
/// `file_hash`, answer it with `sources`, and return what went out.
fn ask_then_answer(
    session: &mut PeerSession,
    ask: &[u8],
    file_hash: FileHash,
    sources: Vec<SourceSighting>,
) -> Vec<PeerOutput> {
    session.handle_bytes(ask);
    let asked = drain(|| session.poll_output());
    assert_eq!(
        sources_requested(&asked),
        Some(file_hash),
        "the ask surfaced"
    );
    session.handle_command(PeerCommand::Server(ServerCommand::AnswerSources {
        file_hash,
        sources,
    }));
    drain(|| session.poll_output())
}

fn answer_packet(outputs: &[PeerOutput]) -> Packet {
    Packet::decode(&last_write_bytes(outputs))
        .expect("answer frames")
        .0
}

fn high_id_source(id: u32, port: u16) -> SourceSighting {
    SourceSighting::plain(
        PeerSource::new(ClientId::from_u32(id), port),
        Informant::Own,
    )
}

fn ids(sources: &[rmule_peer::SourceExchangeEntry]) -> Vec<u32> {
    sources
        .iter()
        .filter_map(|e| e.source().peer_source())
        .map(PeerSource::wire_id)
        .collect()
}

fn ipv6_source() -> SourceSighting {
    SourceSighting::plain(
        PeerSource::Ipv6(rmule_primitives::Ipv6Endpoint::new(
            "2a01:4f8::7".parse().unwrap(),
            4662,
        )),
        Informant::Own,
    )
}

#[test]
fn a_standalone_request_sources_is_answered_in_sx1_at_the_peer_nibble() {
    let mut session = identified(classic(3, false));
    let fh = file_hash(0x42);
    let sources = vec![
        high_id_source(0x0203_0405, 4662),
        high_id_source(0x0607_0809, 5000),
    ];
    let out = ask_then_answer(&mut session, &plain_ask(fh), fh, sources);
    let packet = answer_packet(&out);
    assert_eq!(packet.protocol(), PacketProtocol::Emule);
    assert_eq!(packet.opcode(), 0x82, "SX1 answer is OP_ANSWERSOURCES");
    // Decode back at the peer's own nibble (3 → v3, hybrid ids): the sources
    // round-trip through the serve encoder's byte-swap.
    let decoded = AnswerSources::decode_packet(&packet, 3).expect("v3 answer decodes");
    assert_eq!(decoded.file_hash, fh);
    assert_eq!(ids(&decoded.sources), vec![0x0203_0405, 0x0607_0809]);
}

#[test]
fn a_request_sources2_from_an_sx2_peer_is_answered_in_sx2() {
    let mut session = identified(classic(3, true));
    let fh = file_hash(0x43);
    let out = ask_then_answer(
        &mut session,
        &sx2_ask(fh, 4),
        fh,
        vec![high_id_source(0x0203_0405, 4662)],
    );
    let packet = answer_packet(&out);
    assert_eq!(packet.protocol(), PacketProtocol::Emule);
    assert_eq!(packet.opcode(), 0x84, "SX2 answer is OP_ANSWERSOURCES2");
    let decoded = AnswerSources2::decode_packet(&packet).expect("0x84 decodes");
    assert_eq!(decoded.version, SourceExchangeVersion::V4);
    assert_eq!(decoded.file_hash, fh);
    assert_eq!(decoded.sources.len(), 1);
}

#[test]
fn a_request_sources2_from_a_non_sx2_peer_falls_to_the_sx1_path() {
    // aMule serves SX2 only when the requester *advertised* SupportsSourceEx2;
    // without it, even a 0x83 falls to 0x82 at the requester's SX1 nibble.
    let mut session = identified(classic(2, false));
    let fh = file_hash(0x44);
    let out = ask_then_answer(
        &mut session,
        &sx2_ask(fh, 4),
        fh,
        vec![high_id_source(0x0203_0405, 4662)],
    );
    let packet = answer_packet(&out);
    assert_eq!(packet.opcode(), 0x82);
    let decoded = AnswerSources::decode_packet(&packet, 2).expect("v2 answer decodes");
    assert_eq!(ids(&decoded.sources), vec![0x0203_0405]);
}

#[test]
fn a_bundled_sources_sub_is_answered_like_the_standalone_ask() {
    // ADR-0055: a multipacket Sources sub shares the standalone ask's serve
    // path (and, core-side, its per-peer throttle).
    let mut session = identified(classic(3, false));
    let fh = file_hash(0x46);
    let bundle = MultiPacketRequest {
        file_hash: fh,
        file_size: None,
        items: vec![RequestItem::Sources],
        unknown_sub: None,
        cut: None,
    };
    let out = ask_then_answer(
        &mut session,
        &bundle.encode_packet().encode(),
        fh,
        vec![high_id_source(0x0203_0405, 4662)],
    );
    let packet = answer_packet(&out);
    assert_eq!(packet.opcode(), 0x82);
    let decoded = AnswerSources::decode_packet(&packet, 3).expect("v3 answer decodes");
    assert_eq!(ids(&decoded.sources), vec![0x0203_0405]);
}

#[test]
fn an_answer_to_a_file_never_asked_about_is_rejected_and_sends_nothing() {
    let mut session = identified(classic(3, false));
    session.handle_command(PeerCommand::Server(ServerCommand::AnswerSources {
        file_hash: file_hash(0x47),
        sources: vec![high_id_source(0x0203_0405, 4662)],
    }));
    let out = drain(|| session.poll_output());
    assert!(
        !out.iter().any(|o| matches!(o, PeerOutput::Write(_))),
        "no wire form was negotiated, so nothing is framed"
    );
    assert!(out.iter().any(|o| matches!(
        o,
        PeerOutput::Event(PeerEvent::Notice(NoticeEvent::CommandRejected {
            reason: PeerError::SourcesNotAsked
        }))
    )));
}

#[test]
fn the_pack_threshold_gates_the_answersources_emit() {
    // v1 payload = 16 (hash) + 2 (count) + count*12. 28 sources → 354 bytes
    // (at the threshold, stays plain); 29 → 366 (over it, packed 0xD4).
    let answer = |count: u32| {
        let mut session = identified(classic(1, false));
        let sources: Vec<_> = (0..count)
            .map(|i| high_id_source(0x0A00_0000 + i, 4662))
            .collect();
        let fh = file_hash(0x77);
        answer_packet(&ask_then_answer(&mut session, &plain_ask(fh), fh, sources))
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
    session.handle_bytes(&plain_ask(file_hash(0x42)));
    let out = drain(|| session.poll_output());
    assert!(
        sources_requested(&out).is_none(),
        "no serve callback before the peer has identified",
    );
    assert!(
        out.iter().any(|o| matches!(
            o,
            PeerOutput::Event(PeerEvent::Notice(NoticeEvent::UnknownPacket {
                opcode: 0x81,
                ..
            }))
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
    let mut session = identified(classic(1, false));
    let fh = file_hash(0x5C);
    let out = ask_then_answer(
        &mut session,
        &plain_ask(fh),
        fh,
        vec![high_id_source(0x0203_0405, 4662), ipv6_source()],
    );
    let decoded = AnswerSources::decode_packet(&answer_packet(&out), 1).expect("v1 answer decodes");
    assert_eq!(
        ids(&decoded.sources),
        vec![0x0203_0405],
        "the IPv4 source stands, the IPv6 one is absent — not 0, not 0xFFFFFFFF"
    );
    assert_eq!(
        sources_answered(&out),
        Some(1),
        "the report counts what went out, not what core handed over"
    );
}

/// One ask is owed one answer: the negotiated form is spent when the answer
/// goes out, so a link that asks about many files over its life does not keep
/// a form per file, and a repeat answer is refused as unasked.
#[test]
fn an_answered_ask_is_forgotten_and_a_second_answer_is_refused() {
    let mut session = identified(classic(1, false));
    let fh = file_hash(0x5D);
    let first = ask_then_answer(
        &mut session,
        &plain_ask(fh),
        fh,
        vec![high_id_source(0x0203_0405, 4662)],
    );
    assert_eq!(sources_answered(&first), Some(1));
    session.handle_command(PeerCommand::Server(ServerCommand::AnswerSources {
        file_hash: fh,
        sources: vec![high_id_source(0x0203_0405, 4662)],
    }));
    let second = drain(|| session.poll_output());
    assert!(
        second.iter().any(|o| matches!(
            o,
            PeerOutput::Event(PeerEvent::Notice(NoticeEvent::CommandRejected {
                reason: PeerError::SourcesNotAsked
            }))
        )),
        "the repeat answer is refused: {second:?}"
    );
    assert!(!second.iter().any(|o| matches!(o, PeerOutput::Write(_))));
}

/// A classic answer the framing limit leaves empty is aMule's `NULL` reply:
/// nothing goes out, not an empty list.
#[test]
fn a_classic_answer_of_only_ipv6_sources_sends_nothing() {
    let mut session = identified(classic(1, false));
    let fh = file_hash(0x5F);
    let out = ask_then_answer(&mut session, &plain_ask(fh), fh, vec![ipv6_source()]);
    assert!(
        !out.iter().any(|o| matches!(o, PeerOutput::Write(_))),
        "an answer with no framable entry is not framed: {out:?}"
    );
    assert_eq!(
        sources_answered(&out),
        None,
        "nothing sent, nothing reported"
    );
}

/// The ExtSX arm is the one shape that *can* carry it: the same source list,
/// answered to a peer that claimed `MODMISC_EXTXS`, keeps both.
#[test]
fn the_ext_sx_answer_carries_the_ipv6_source_the_classic_one_omits() {
    let mut session = identified(ext_sx(1, false, false));
    let fh = file_hash(0x5D);
    let endpoint = rmule_primitives::Ipv6Endpoint::new("2a01:4f8::7".parse().unwrap(), 4662);
    let out = ask_then_answer(
        &mut session,
        &plain_ask(fh),
        fh,
        vec![high_id_source(0x0203_0405, 4662), ipv6_source()],
    );
    let decoded =
        AnswerSources::decode_ext_packet(&answer_packet(&out)).expect("ExtSX answer decodes");

    assert_eq!(decoded.sources.len(), 2);
    assert_eq!(decoded.sources[1].ipv6(), Some(endpoint));
    assert_eq!(
        decoded.sources[1].source().peer_source(),
        Some(PeerSource::Ipv6(endpoint))
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
    let single = SourceSighting::new(v4, Some(hash), None, Informant::Own);
    let dual = single.with_ipv6_half(Some(v6));

    let answer = |source: SourceSighting, advert: Advert| {
        let mut session = identified(advert);
        answer_packet(&ask_then_answer(
            &mut session,
            &sx2_ask(fh, 4),
            fh,
            vec![source],
        ))
    };

    let ext = answer(dual, ext_sx(4, true, true));
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

    let sx2 = classic(4, true);
    assert_eq!(
        answer(dual, sx2).payload(),
        answer(single, sx2).payload(),
        "the classic writer is unchanged by the IPv6 half"
    );
}
