//! Packed source-exchange capture replay (genuine stock aMule 2.3.3, run
//! `w6-0xD4`, 2026-07-28) — the `0xD4` leg, which also covers the inbound
//! inflate and the `0x84` v4 consume: aMule has exactly two peer-TCP
//! `PackPacket()` call sites and both are `CreateSrcInfoPacket`, so a packed
//! peer frame is only ever an over-threshold source answer.
//!
//! rmule dialed a downloading aMule that held 15 established High-ID sources
//! and asked for sources inside one `OP_MULTIPACKET_EXT` (`0xA4`) bundle. The
//! answer's plain body would have been 454 bytes — over aMule's 354-byte
//! `PEER_PACK_THRESHOLD` — so aMule zlib-packed it and re-framed it as `0xD4`.
//! The fixture is the counterparty's own frame (ADR-0045); provenance is in
//! the fixture dir's `meta.toml`.

use std::net::Ipv4Addr;

use crate::fixture::load;
use rmule_peer::{
    AnswerSources2, HelloAnswer, MiscOptions1, MiscOptions2, PEER_COMPRESSED_FRAME_LIMIT,
    PEER_PACK_THRESHOLD, PeerCommand, PeerEvent, PeerHandshakeContext, PeerHelloBody, PeerOutput,
    PeerSession, SourceExchangeVersion,
};
use rmule_primitives::session::drain;
use rmule_primitives::{
    ClientId, ClientIdentity, Ed2kText, FileHash, Ipv4Endpoint, Packet, PacketProtocol,
    PeerEndpoint, UserHash,
};

const FIXTURE_DIR: &str = "fixtures/source_exchange/captured/amule-233-packed-answer-20260728/";
const FIXTURE: &str = "answer_sources2_packed_0xD4.bin";

/// The synthetic 200 MiB file the registrants served and aMule was downloading.
const FILE_HASH: [u8; 16] = [
    0xC7, 0x31, 0xE1, 0x0A, 0x25, 0xF8, 0x69, 0x49, 0x50, 0xD4, 0xF3, 0xDD, 0xAF, 0x81, 0x09, 0x40,
];
const FILE_SIZE: u64 = 209_715_200;

/// Every registrant container advertised this one TCP port; the distinct
/// container IPs are what earned them distinct High IDs.
const REGISTRANT_PORT: u16 = 14662;
/// The 15 registrant containers occupied `172.31.0.11 ..= 172.31.0.25`.
const REGISTRANT_COUNT: usize = 15;
const REGISTRANT_FIRST_OCTET4: u8 = 11;

/// Inflate the captured frame the way the session's consume path does.
fn inflated() -> Packet {
    let bytes = load(FIXTURE_DIR, FIXTURE);
    let (packet, consumed) = Packet::decode(&bytes).expect("fixture frame decodes");
    assert_eq!(consumed, bytes.len(), "fixture is exactly one frame");
    assert_eq!(
        packet.protocol(),
        PacketProtocol::PackedEd2k,
        "aMule re-framed the over-threshold answer as 0xD4",
    );
    rmule_primitives::inflate(&packet, PEER_COMPRESSED_FRAME_LIMIT, PacketProtocol::Emule)
        .expect("aMule's zlib body inflates")
}

/// The framing facts the `0xD4` row is about: aMule packed *because* the plain
/// body crossed its 354-byte threshold, and the opcode byte survives the pack
/// uncompressed right after the length word.
#[test]
fn amule_packs_the_over_threshold_source_answer_as_0xd4() {
    let bytes = load(FIXTURE_DIR, FIXTURE);
    let (packet, _) = Packet::decode(&bytes).expect("fixture frame decodes");
    assert_eq!(
        packet.opcode(),
        0x84,
        "the packed frame keeps OP_ANSWERSOURCES2 in the clear",
    );

    let inflated = inflated();
    assert_eq!(
        inflated.protocol(),
        PacketProtocol::Emule,
        "aMule re-attributes an unpacked frame to OP_EMULEPROT",
    );
    // 1 version + 16 hash + 2 count + 15 * 29 (v4 stride) = 454.
    assert_eq!(inflated.payload().len(), 454);
    assert!(
        inflated.payload().len() > PEER_PACK_THRESHOLD,
        "the plain body crossed aMule's pack threshold — that is why it packed",
    );
    assert!(
        bytes.len() < inflated.encode().len(),
        "aMule only keeps the packed form when it actually shrinks the frame",
    );
}

/// The v4 geometry and the exact source rows: the 15 distinct-IP High-ID
/// registrants aMule had established, each on its advertised TCP port.
#[test]
fn the_packed_answer_carries_all_fifteen_v4_source_rows() {
    let answer = AnswerSources2::decode_packet(&inflated()).expect("0x84 decodes");

    assert_eq!(answer.version, SourceExchangeVersion::V4);
    assert_eq!(answer.file_hash, FileHash::from_bytes(FILE_HASH));
    assert_eq!(answer.sources.len(), REGISTRANT_COUNT);

    let mut observed: Vec<PeerEndpoint> = answer
        .sources
        .iter()
        .map(|entry| {
            entry
                .source()
                .peer_source()
                .as_peer_endpoint()
                .expect("aMule only exchanges High-ID sources")
        })
        .collect();
    observed.sort();
    let expected: Vec<PeerEndpoint> = (0..REGISTRANT_COUNT)
        .map(|i| {
            let octet = REGISTRANT_FIRST_OCTET4 + u8::try_from(i).expect("registrant index fits");
            PeerEndpoint::V4(Ipv4Endpoint::new(
                Ipv4Addr::new(172, 31, 0, octet),
                REGISTRANT_PORT,
            ))
        })
        .collect();
    assert_eq!(
        observed, expected,
        "every established High-ID registrant appears exactly once",
    );
}

/// End-to-end consume: a session that solicited sources the way the capture
/// dial did takes aMule's genuine packed frame off the wire, inflates it, and
/// reports all 15 candidates — the inbound-inflate leg.
#[test]
fn a_soliciting_session_inflates_the_packed_answer_into_sources_received() {
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(172, 31, 0, 3), 4662));
    let ctx = PeerHandshakeContext {
        identity: ClientIdentity::new(
            UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
            Ed2kText::from_utf8("rmule"),
            4662,
            0x3C,
        ),
        client_id: ClientId::from_u32(0x1000_0001),
        connected_server: None,
    };
    let mut session = PeerSession::new_outbound(peer, ctx);
    session.start();
    let _ = drain(|| session.poll_output());

    // aMule's real advert trio: MultiPacket, ExtMultiPacket, SourceExchange2.
    let answer = HelloAnswer::new(PeerHelloBody {
        user_hash: UserHash::from_bytes([0x99; UserHash::BYTE_LEN]),
        client_id: ClientId::from_u32(0x0300_1FAC),
        tcp_port: 4662,
        tags: vec![
            MiscOptions1::from_bits(1 << 1).to_tag(),
            MiscOptions2::from_bits((1 << 5) | (1 << 10)).to_tag(),
        ],
        connected_server: Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0),
    })
    .encode_packet()
    .encode();
    session.handle_bytes(&answer);
    let _ = drain(|| session.poll_output());

    let file_hash = FileHash::from_bytes(FILE_HASH);
    session.handle_command(PeerCommand::RequestFile {
        file_hash,
        file_size: FILE_SIZE,
        own_status: rmule_peer::PartBitmap::downloader_empty(FILE_SIZE),
        want_sources: true,
        want_aich_root: false,
    });
    let _ = drain(|| session.poll_output());

    session.handle_bytes(&load(FIXTURE_DIR, FIXTURE));
    let sources = drain(|| session.poll_output())
        .iter()
        .find_map(|o| match o {
            PeerOutput::Event(PeerEvent::SourcesReceived {
                file_hash: fh,
                sources,
            }) if *fh == file_hash => Some(sources.clone()),
            _ => None,
        })
        .expect("the packed 0xD4 answer reaches the consume core");
    assert_eq!(
        sources.len(),
        REGISTRANT_COUNT,
        "all 15 rows survive the sanity filter as actionable candidates",
    );
}
