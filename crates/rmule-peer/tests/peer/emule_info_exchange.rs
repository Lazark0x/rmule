//! `OP_EMULEINFO` / `OP_EMULEINFOANSWER`: read as aMule and eMule read
//! them, folded into the Client Software before or after the hello, answered,
//! and sent to an accepted pre-0.42 mule — the only version such a mule sends
//! rides here.
//!
//! One vector is **captured**: stock aMule 2.3.3's OS-info block (run
//! `1790208592`, `fixtures/emule_info/captured/`). Every legacy block is **derived** from the
//! two readers' source — no bench client predates eMule 0.42.

use std::sync::Arc;

use rmule_peer::{
    ClientFamily, ClientMod, EmuleInfo, Hello, HelloAnswer, LegacyMuleInfo, MiscOptions1,
    PeerEvent, PeerHelloBody, PeerOutput, PeerPacket, PeerSession, SecIdentState,
    SecureIdentConfig,
};
use rmule_primitives::session::drain;
use rmule_primitives::{
    Ed2kText, Packet, PacketProtocol, SecureIdentKey, Tag, TagName, TagValue, UserHash,
};
use rmule_testkit::peer_session::{peer_at, serverless_ctx};

use crate::fixture::{client_version as v, hello_body, load};

/// A user hash with eMule's mark (`[5] = 14`, `[14] = 111`).
fn emule_hash() -> UserHash {
    let mut bytes = [0x77; 16];
    bytes[5] = 14;
    bytes[14] = 111;
    UserHash::from_bytes(bytes)
}

/// A pre-0.42 eMule's hello: its name and `CT_VERSION`, no mule tag.
fn old_emule_hello() -> PeerHelloBody {
    hello_body(
        emule_hash(),
        0x0200_0002,
        vec![
            Tag::new(
                TagName::length_prefixed_id(0x01),
                TagValue::String(Ed2kText::from_utf8("old mule")),
            ),
            Tag::new(TagName::length_prefixed_id(0x11), TagValue::U32(0x3C)),
        ],
    )
}

/// A legacy block as eMule's `SendMuleInfoPacket` writes one (`BaseClient.cpp:695-732`):
/// `mule_version`, protocol 1, then old-format integer tags.
fn legacy_block(opcode: u8, mule_version: u8, tags: &[(u8, u32)]) -> Vec<u8> {
    let mut payload = vec![mule_version, 0x01];
    payload.extend_from_slice(&u32::try_from(tags.len()).unwrap().to_le_bytes());
    for &(id, value) in tags {
        payload.extend_from_slice(
            &Tag::new(TagName::length_prefixed_id(id), TagValue::U32(value)).encode(),
        );
    }
    Packet::new(PacketProtocol::Emule, opcode, payload).encode()
}

/// eMule 0.30's block: compression 1, UDP 4 on port 4672, SX 2, comments 1,
/// ext-requests 1, SUI v1+v2.
fn emule_030_block(opcode: u8) -> Vec<u8> {
    legacy_block(
        opcode,
        0x30,
        &[
            (0x20, 1),
            (0x22, 4),
            (0x21, 4672),
            (0x23, 2),
            (0x24, 1),
            (0x25, 1),
            (0x27, 3),
        ],
    )
}

fn outputs(session: &mut PeerSession) -> (Vec<PeerPacket>, Vec<PeerEvent>, bool) {
    let mut packets = Vec::new();
    let mut events = Vec::new();
    let mut closed = false;
    for output in drain(|| session.poll_output()) {
        match output {
            PeerOutput::Write(bytes) => {
                let (packet, _) = Packet::decode(&bytes).expect("a frame");
                packets.push(PeerPacket::decode(&packet).expect("rmule's own write decodes"));
            }
            PeerOutput::Event(event) => events.push(event),
            PeerOutput::Close(_) => closed = true,
        }
    }
    (packets, events, closed)
}

fn identified_software(events: &[PeerEvent]) -> rmule_peer::ClientSoftware {
    events
        .iter()
        .find_map(|e| match e {
            PeerEvent::PeerIdentified { identity } => Some(identity.software().clone()),
            _ => None,
        })
        .expect("PeerIdentified")
}

#[test]
fn captured_amule_os_info_block_reads_as_os_info_and_leaves_identity_alone() {
    let frame = load(
        "fixtures/emule_info/captured/amule-233-osinfo-20260924",
        "amule_op_emuleinfo_osinfo.bin",
    );
    let packet = Packet::decode_exact(&frame).expect("a whole frame");
    assert_eq!(
        EmuleInfo::decode_packet(&packet).expect("aMule's own block decodes"),
        EmuleInfo::OsInfo {
            os: Some(Ed2kText::from_utf8("Linux"))
        }
    );

    let mut session = crate::fixture::identified_session();
    session.handle_bytes(&frame);
    let (packets, events, closed) = outputs(&mut session);
    assert!(!closed);
    assert!(
        packets.is_empty(),
        "aMule answers an OS-info block only with its own, which rmule has none of"
    );
    assert!(
        events
            .iter()
            .all(|e| !matches!(e, PeerEvent::PeerSoftwareRevised { .. }))
    );
}

#[test]
fn a_dialed_old_mule_sends_its_block_before_its_answer_and_gets_its_version() {
    let mut session = PeerSession::new_outbound(peer_at(7), serverless_ctx());
    session.start();
    let _ = outputs(&mut session);

    // What a pre-0.42 eMule does with rmule's hello, which it cannot read as a
    // mule hello: its block, then its answer (eMule `ListenSocket.cpp:274-276`).
    session.handle_bytes(&emule_030_block(0x01));
    let (packets, _, closed) = outputs(&mut session);
    assert!(!closed);
    assert!(
        matches!(
            packets.as_slice(),
            [PeerPacket::EmuleInfo { answer: true, .. }]
        ),
        "every legacy block is answered: {packets:?}"
    );
    session.handle_bytes(&HelloAnswer::new(old_emule_hello()).encode_packet().encode());
    let (_, events, _) = outputs(&mut session);
    let software = identified_software(&events);
    assert_eq!(software.family(), ClientFamily::Emule);
    assert_eq!(software.version(), v(0, 30, 0));
}

#[test]
fn an_accepted_old_mule_is_sent_our_block_and_its_answer_revises_its_software() {
    let mut session = PeerSession::new_inbound(peer_at(8), serverless_ctx());
    session.handle_bytes(&Hello::new(old_emule_hello()).encode_packet().encode());
    let (packets, events, _) = outputs(&mut session);
    assert!(
        matches!(
            packets.as_slice(),
            [
                PeerPacket::EmuleInfo { answer: false, .. },
                PeerPacket::HelloAnswer(_)
            ]
        ),
        "our block goes first, as both references send it: {packets:?}"
    );
    let software = identified_software(&events);
    assert_eq!(
        (software.family(), software.version()),
        (ClientFamily::Emule, None)
    );

    // eMule 0.22b's `0x2B` is read as `0x22` by both references.
    session.handle_bytes(&legacy_block(0x02, 0x2B, &[(0x20, 1), (0x26, 0)]));
    let (packets, events, closed) = outputs(&mut session);
    assert!(!closed);
    assert!(packets.is_empty(), "an answer is not answered");
    let revised = events
        .iter()
        .find_map(|e| match e {
            PeerEvent::PeerSoftwareRevised { software } => Some(software.clone()),
            _ => None,
        })
        .expect("the block names its version after identification");
    assert_eq!(revised.family(), ClientFamily::Emule);
    assert_eq!(revised.version(), v(0, 22, 0));
}

#[test]
fn a_block_naming_a_compatible_client_and_mod_names_that_family() {
    let mut session = PeerSession::new_outbound(peer_at(7), serverless_ctx());
    session.start();
    let _ = outputs(&mut session);
    let mut block = legacy_block(0x01, 0x42, &[(0x20, 1), (0x26, 2)]);
    // Append an `ET_MOD_VERSION` string and bump the count.
    let mod_tag = Tag::new(
        TagName::length_prefixed_id(0x55),
        TagValue::String(Ed2kText::from_utf8("lMule")),
    )
    .encode();
    block[8] += 1;
    block.extend_from_slice(&mod_tag);
    let len = u32::try_from(block.len() - 5).unwrap();
    block[1..5].copy_from_slice(&len.to_le_bytes());
    session.handle_bytes(&block);
    session.handle_bytes(&HelloAnswer::new(old_emule_hello()).encode_packet().encode());
    let (_, events, _) = outputs(&mut session);
    let software = identified_software(&events);
    assert_eq!(software.family(), ClientFamily::Xmule);
    assert_eq!(software.version(), v(0, 42, 0));
    assert_eq!(
        software.client_mod(),
        Some(&ClientMod::Named(Ed2kText::from_utf8("lMule")))
    );
}

#[test]
fn a_modern_hello_behind_the_mark_is_sent_no_block() {
    let mut hello = old_emule_hello();
    hello.tags.push(Tag::new(
        TagName::length_prefixed_id(0xFB),
        TagValue::U32(0x0001_1880),
    ));
    let mut session = PeerSession::new_inbound(peer_at(8), serverless_ctx());
    session.handle_bytes(&Hello::new(hello).encode_packet().encode());
    let (packets, _, _) = outputs(&mut session);
    assert!(matches!(packets.as_slice(), [PeerPacket::HelloAnswer(_)]));
}

#[test]
fn a_block_before_an_accepted_peers_hello_is_dropped_not_answered() {
    let mut session = PeerSession::new_inbound(peer_at(8), serverless_ctx());
    session.handle_bytes(&emule_030_block(0x01));
    let (packets, _, closed) = outputs(&mut session);
    assert!(packets.is_empty());
    assert!(
        !closed,
        "kept open (ADR-0018); both references would hang up"
    );
}

#[test]
fn the_implied_capabilities_of_an_old_version_and_a_zero_compression() {
    let decode =
        |frame: Vec<u8>| match EmuleInfo::decode_packet(&Packet::decode_exact(&frame).unwrap()) {
            Ok(EmuleInfo::Legacy(block)) => block,
            other => panic!("{other:?}"),
        };
    // 0x24 implies UDP v1, SX v1 and comments v1 (eMule `BaseClient.cpp:746-749`)…
    let with_compression = decode(legacy_block(0x01, 0x24, &[(0x20, 1), (0x21, 4672)]));
    let caps = with_compression.capabilities();
    assert_eq!(
        (
            caps.udp_version(),
            caps.source_exchange_version(),
            caps.data_compression_version()
        ),
        (1, 1, 1)
    );
    assert_eq!(with_compression.udp_port(), 4672);
    // …but a block without compression knew no extended protocol (`:872-877`).
    let without = decode(legacy_block(0x01, 0x24, &[(0x21, 4672), (0x25, 2)]));
    let caps = without.capabilities();
    assert_eq!(
        (
            caps.source_exchange_version(),
            caps.extended_requests_version()
        ),
        (0, 0)
    );
    assert_eq!(without.udp_port(), 0);
}

#[test]
fn an_old_mules_block_lights_secure_identification_as_its_hello_cannot() {
    let key = Arc::new(SecureIdentKey::generate().expect("a key"));
    let mut session = PeerSession::new_outbound(peer_at(7), serverless_ctx()).with_secure_ident(
        SecureIdentConfig {
            key,
            challenge: 0x1234_5678,
        },
    );
    session.start();
    let _ = outputs(&mut session);
    session.handle_bytes(&emule_030_block(0x01));
    let _ = outputs(&mut session);
    session.handle_bytes(&HelloAnswer::new(old_emule_hello()).encode_packet().encode());
    let (packets, _, _) = outputs(&mut session);
    assert!(
        packets.iter().any(|p| matches!(
            p,
            PeerPacket::SecIdentState(s) if s.state == SecIdentState::KeyAndSignNeeded
        )),
        "ET_FEATURES 3 claims SUI; the hello alone claims nothing: {packets:?}"
    );
}

#[test]
fn rmules_own_block_is_its_hello_advert_in_the_legacy_form() {
    let mut session = PeerSession::new_outbound(peer_at(7), serverless_ctx());
    session.start();
    let (packets, _, _) = outputs(&mut session);
    let Some(PeerPacket::Hello(ours)) = packets.first() else {
        panic!("our hello first");
    };
    let advert = MiscOptions1::from_tags(&ours.body().tags).expect("our hello claims MiscOptions1");

    session.handle_bytes(&emule_030_block(0x01));
    let (packets, _, _) = outputs(&mut session);
    let Some(PeerPacket::EmuleInfo {
        info: EmuleInfo::Legacy(block),
        ..
    }) = packets.first()
    else {
        panic!("a legacy answer: {packets:?}");
    };
    let caps = block.capabilities();
    assert_eq!(
        (
            caps.data_compression_version(),
            caps.source_exchange_version(),
            caps.extended_requests_version(),
            caps.udp_version(),
            caps.secure_identification_version(),
        ),
        (
            advert.data_compression_version(),
            advert.source_exchange_version(),
            advert.extended_requests_version(),
            advert.udp_version(),
            advert.secure_identification_version() & 0x03,
        ),
        "one registry, two encodings (ADR-0047)"
    );
    assert_eq!(
        block.compatible_client(),
        3,
        "aMule's code, as the hello's word"
    );
    assert_eq!(
        block.mule_version(),
        0x47,
        "aMule's CURRENT_VERSION_SHORT, captured"
    );
    assert_eq!(
        block.client_mod(),
        LegacyMuleInfo::advertised(ours.body()).client_mod()
    );
}

fn identified_reask(events: &[PeerEvent]) -> Option<(u16, u8)> {
    events.iter().find_map(|e| match e {
        PeerEvent::PeerIdentified { identity } => identity.client_udp_reask(),
        _ => None,
    })
}

#[test]
fn a_dialed_old_mules_block_names_the_port_it_is_reasked_at() {
    let mut session = PeerSession::new_outbound(peer_at(7), serverless_ctx());
    session.start();
    let _ = outputs(&mut session);
    session.handle_bytes(&emule_030_block(0x01));
    let _ = outputs(&mut session);
    session.handle_bytes(&HelloAnswer::new(old_emule_hello()).encode_packet().encode());
    let (_, events, _) = outputs(&mut session);
    assert_eq!(
        identified_reask(&events),
        Some((4672, 4)),
        "ET_UDPPORT and ET_UDPVER stand in for the CT_EMULE_UDPPORTS the hello lacks"
    );
}

#[test]
fn an_accepted_old_mules_answer_revises_the_reask_contact_once() {
    let mut session = PeerSession::new_inbound(peer_at(8), serverless_ctx());
    session.handle_bytes(&Hello::new(old_emule_hello()).encode_packet().encode());
    let (_, events, _) = outputs(&mut session);
    assert_eq!(identified_reask(&events), None);

    session.handle_bytes(&emule_030_block(0x02));
    let (_, events, _) = outputs(&mut session);
    assert!(
        events.contains(&PeerEvent::PeerReaskContactRevised {
            udp_port: 4672,
            udp_version: 4
        }),
        "{events:?}"
    );
}

#[test]
fn a_hello_that_named_its_port_keeps_it() {
    let mut hello = old_emule_hello();
    hello
        .tags
        .push(rmule_peer::UdpPortsAdvert::new(5000, 0).to_tag());
    let mut session = PeerSession::new_inbound(peer_at(8), serverless_ctx());
    session.handle_bytes(&Hello::new(hello).encode_packet().encode());
    let _ = outputs(&mut session);
    session.handle_bytes(&emule_030_block(0x02));
    let (_, events, _) = outputs(&mut session);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, PeerEvent::PeerReaskContactRevised { .. })),
        "{events:?}"
    );
}

/// Made frames, not captures. Stock aMule 2.3.3 reads the version, the
/// protocol byte and the tag count (`BaseClient.cpp:855-857`) and, under a
/// protocol byte that is neither `0xFF` nor `0x01`, returns before the first
/// tag (`:893-895`): a tag it could not read never ends the link. A block too
/// short for its count throws there, and aMule disconnects
/// (`ClientTCPSocket.cpp:2018-2047`).
#[test]
fn a_made_block_under_an_unknown_protocol_byte_is_not_read_past_its_count() {
    let unreadable_tag = [0x30, 0x02, 0x01, 0x00, 0x00, 0x00, 0xEE];
    let packet = Packet::new(PacketProtocol::Emule, 0x01, unreadable_tag.to_vec());
    assert_eq!(
        EmuleInfo::decode_packet(&packet).expect("the header alone decides"),
        EmuleInfo::Other {
            protocol: 0x02,
            mule_version: 0x30
        }
    );
    let mut session = crate::fixture::identified_session();
    session.handle_bytes(&packet.encode());
    assert!(!outputs(&mut session).2, "aMule keeps the link");

    let no_count = Packet::new(PacketProtocol::Emule, 0x01, vec![0x30, 0x02]);
    let mut session = crate::fixture::identified_session();
    session.handle_bytes(&no_count.encode());
    assert!(
        outputs(&mut session).2,
        "aMule disconnects on the short read"
    );
}

/// Made frames, not captures. Stock aMule 2.3.3 answers an `OP_EMULEINFO` whose
/// `ProcessMuleInfoPacket` returns false — every block but OS info, an unknown
/// protocol byte included (`BaseClient.cpp:893-895`, `:1006`) — with its own
/// block, to the sender, each time (`ClientTCPSocket.cpp:1262-1273`); an
/// `OP_EMULEINFOANSWER` is never answered (`:1280-1292`).
#[test]
fn a_made_block_under_an_unknown_protocol_byte_is_answered_each_time() {
    let block = |opcode| Packet::new(PacketProtocol::Emule, opcode, vec![0x30, 0x02, 0, 0, 0, 0]);
    let mut session = crate::fixture::identified_session();
    for _ in 0..2 {
        session.handle_bytes(&block(0x01).encode());
        let (packets, _, closed) = outputs(&mut session);
        assert!(!closed);
        assert!(
            matches!(
                packets.as_slice(),
                [PeerPacket::EmuleInfo {
                    answer: true,
                    info: EmuleInfo::Legacy(_),
                    ..
                }]
            ),
            "{packets:?}"
        );
    }
    session.handle_bytes(&block(0x02).encode());
    assert!(
        outputs(&mut session).0.is_empty(),
        "an answer is not answered"
    );
}

/// Made frames, not captures. Under a protocol byte that is neither `0x01`
/// nor `0xFF`, stock aMule 2.3.3 still records the block's version (`0x2B`
/// read as `0x22`), clears the compatible client and clears the mule flag
/// before it returns (`BaseClient.cpp:884-895`); the hello answer that follows
/// names the peer from that (`:705`). An xMule block came first, so its
/// family and version are what the unknown block must overwrite.
#[test]
fn a_made_block_under_an_unknown_protocol_byte_records_its_version_and_clears_the_client() {
    let identified_after = |answer: PeerHelloBody| {
        let mut session = PeerSession::new_outbound(peer_at(7), serverless_ctx());
        session.start();
        let _ = outputs(&mut session);
        session.handle_bytes(&legacy_block(0x01, 0x42, &[(0x20, 1), (0x26, 2)]));
        let unknown = Packet::new(PacketProtocol::Emule, 0x01, vec![0x2B, 0x02, 0, 0, 0, 0]);
        session.handle_bytes(&unknown.encode());
        session.handle_bytes(&HelloAnswer::new(answer).encode_packet().encode());
        identified_software(&outputs(&mut session).1)
    };

    let marked = identified_after(old_emule_hello());
    assert_eq!(marked.family(), ClientFamily::Emule, "compatible client 0");
    assert_eq!(marked.version(), v(0, 22, 0));

    let mut unmarked_hello = old_emule_hello();
    unmarked_hello.user_hash = UserHash::from_bytes([0x33; 16]);
    let unmarked = identified_after(unmarked_hello);
    assert_eq!(
        unmarked.family(),
        ClientFamily::Edonkey,
        "the mule flag is cleared, so only the hash mark could name a mule"
    );
}

/// A request for a file only a pre-0.42 mule holds, asking for sources.
fn request_with_sources() -> rmule_peer::PeerCommand {
    rmule_peer::PeerCommand::RequestFile {
        file_hash: rmule_primitives::FileHash::from_bytes([
            0x3C, 0x71, 0x0A, 0xE4, 0x92, 0x15, 0x6B, 0xD8, 0x07, 0x4F, 0xA1, 0x2E, 0x5D, 0xC9,
            0x86, 0x33,
        ]),
        file_size: 700_001,
        own_status: rmule_peer::PartBitmap::downloader_empty(700_001),
        want_sources: true,
        want_aich_root: false,
    }
}

/// The file request a session reports: its source-exchange facts and
/// whether it asked.
fn request_sent(events: &[PeerEvent]) -> (rmule_peer::SourceExchangeSupport, bool) {
    events
        .iter()
        .find_map(|e| match e {
            PeerEvent::FileRequestSent {
                support,
                sources_asked,
                ..
            } => Some((*support, *sources_asked)),
            _ => None,
        })
        .expect("FileRequestSent")
}

fn asks_sources(packets: &[PeerPacket]) -> bool {
    packets
        .iter()
        .any(|p| matches!(p, PeerPacket::RequestSources(_)))
}

/// A pre-0.42 mule states its SX version only in its block (aMule 2.3.3
/// `BaseClient.cpp:918-921`). A block that arrives after the file request:
/// the request asked nothing and says so, and the block's revision makes the
/// peer askable — what a later connection's gate reads.
#[test]
fn an_old_mules_block_after_the_request_revises_its_source_exchange() {
    let mut session = PeerSession::new_inbound(peer_at(8), serverless_ctx());
    session.handle_bytes(&Hello::new(old_emule_hello()).encode_packet().encode());
    let (_, events, _) = outputs(&mut session);
    let PeerEvent::PeerIdentified { identity } = &events[0] else {
        panic!("identified first: {events:?}");
    };
    assert!(!identity.source_exchange().askable());

    session.handle_command(request_with_sources());
    let (packets, events, _) = outputs(&mut session);
    assert!(!asks_sources(&packets));
    assert!(!request_sent(&events).1);

    session.handle_bytes(&emule_030_block(0x02));
    let (_, events, _) = outputs(&mut session);
    let revised = events
        .iter()
        .find_map(|e| match e {
            PeerEvent::PeerSourceExchangeRevised { support } => Some(*support),
            _ => None,
        })
        .expect("the block revises the source-exchange facts");
    assert!(revised.askable());
    assert_eq!(revised.sx1_version(), 2);

    // The same block again changes nothing and says nothing.
    session.handle_bytes(&emule_030_block(0x02));
    let (_, events, _) = outputs(&mut session);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, PeerEvent::PeerSourceExchangeRevised { .. })),
        "{events:?}"
    );
}

/// The block before the request: the session asks, and its report says it
/// asked under the block's facts — so the download stamps the ask it sent.
#[test]
fn an_old_mules_block_before_the_request_is_asked_and_reported_asked() {
    let mut session = PeerSession::new_inbound(peer_at(8), serverless_ctx());
    session.handle_bytes(&Hello::new(old_emule_hello()).encode_packet().encode());
    session.handle_bytes(&emule_030_block(0x02));
    let _ = outputs(&mut session);

    session.handle_command(request_with_sources());
    let (packets, events, _) = outputs(&mut session);
    assert!(asks_sources(&packets), "{packets:?}");
    let (support, asked) = request_sent(&events);
    assert!(asked);
    assert!(support.askable());
}

/// A block naming no compression zeroes its SX version (aMule 2.3.3
/// `BaseClient.cpp:973-975`): the peer stays unaskable and nothing is revised
/// for the gate.
#[test]
fn an_old_mules_block_without_compression_is_never_asked() {
    let mut session = PeerSession::new_inbound(peer_at(8), serverless_ctx());
    session.handle_bytes(&Hello::new(old_emule_hello()).encode_packet().encode());
    session.handle_bytes(&legacy_block(0x02, 0x30, &[(0x23, 3)]));
    let _ = outputs(&mut session);

    session.handle_command(request_with_sources());
    let (packets, events, _) = outputs(&mut session);
    assert!(!asks_sources(&packets));
    assert!(!request_sent(&events).1);
}
