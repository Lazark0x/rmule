//! The source ask rmule puts on the wire toward a genuine aMule 2.3.3 hello
//! AMule's standalone `OP_REQUESTSOURCES2` arm rejects every
//! payload that is not 16 bytes (`ClientTCPSocket.cpp:1534-1535` at kno
//! `ab483654`, "Invalid size (OP_QUEUERANKING)") and drops the link, so the
//! eMule-form standalone ask — `<ver 1><opts 2><hash 16>`, 19 bytes — never
//! works against it, not even when aMule itself sends it. aMule's own
//! `SendFileRequest` avoids that arm by bundling: every file, one part or
//! many, is asked in an `OP_MULTIPACKET(_EXT)` whose SX2 sub is
//! `0x83 <ver 1><opts 2>` (the hash rides the bundle header). The hello and
//! the bundle pinned here are aMule-authored, from the reverse-serve capture
//! run `1785029762` (`fixtures/reverse_serve/.../meta.toml`); aMule's answer
//! to rmule's one-part bundle is from run `1790161721`.

use crate::fixture::load;
use rmule_peer::{
    BundledAsk, Hello, HelloAnswer, MiscOptions1, PartBitmap, PartRanges, PeerCommand, PeerEvent,
    PeerHelloBody, PeerSession,
};
use rmule_primitives::session::drain;
use rmule_primitives::{ED2K_PART_SIZE, FileHash, Packet, PacketProtocol, Tag, TagValue};
use rmule_testkit::peer_session::{events, peer_at, serverless_ctx, writes};

const FIXTURE_DIR: &str = "fixtures/reverse_serve/captured/amule-233-serve-consume-20260726/";

/// The 64 KiB file aMule asked for in that run — one part.
const FILE_HASH: [u8; 16] = [
    0x8E, 0x30, 0x2D, 0xB5, 0xB8, 0x06, 0xA2, 0x5C, 0x93, 0x85, 0xFC, 0x23, 0xF2, 0x10, 0x62, 0xD2,
];
const FILE_SIZE: u64 = 65_536;

/// `OP_REQUESTSOURCES2` (`0xC5` protocol).
const OP_REQUESTSOURCES2: u8 = 0x83;
/// `OP_REQUESTSOURCES` (`0xC5` protocol).
const OP_REQUESTSOURCES: u8 = 0x81;
/// `CT_EMULE_MISCOPTIONS1`.
const CT_EMULE_MISCOPTIONS1: u8 = 0xFA;

/// aMule's own hello body, as it sent it.
fn amule_hello() -> PeerHelloBody {
    let bytes = load(FIXTURE_DIR, "hello_0x10.bin");
    let (packet, _) = Packet::decode(&bytes).expect("captured hello frames");
    Hello::decode_packet(&packet)
        .expect("captured hello decodes")
        .into_body()
}

/// The same hello with the `SupportMultiPacket` bit cleared — the one peer
/// shape that makes rmule ask with standalone packets.
fn amule_hello_without_multipacket() -> PeerHelloBody {
    let mut body = amule_hello();
    for tag in &mut body.tags {
        if tag.name().id() == Some(CT_EMULE_MISCOPTIONS1)
            && let TagValue::U32(bits) = tag.value()
        {
            *tag = MiscOptions1::from_bits(bits & !(1 << 1)).to_tag();
        }
    }
    assert!(
        MiscOptions1::from_tags(&body.tags).is_some_and(|m| !m.supports_multipacket()),
        "the multipacket bit is off"
    );
    assert!(
        body.tags.iter().any(|t: &Tag| t.name().id() == Some(0xFE)),
        "the SX2 advert (MiscOptions2) is kept"
    );
    body
}

fn identified_against(body: PeerHelloBody) -> PeerSession {
    let mut session = PeerSession::new_outbound(peer_at(2), serverless_ctx());
    session.start();
    let _ = drain(|| session.poll_output());
    session.handle_bytes(&HelloAnswer::new(body).encode_packet().encode());
    let _ = drain(|| session.poll_output());
    session
}

fn hash() -> FileHash {
    FileHash::from_bytes(FILE_HASH)
}

/// aMule's hello with its extended-requests nibble (bits [8..12)) cleared —
/// the claim rmule itself made when aMule sent the captured bundle.
fn amule_hello_claiming_no_extended_requests() -> PeerHelloBody {
    let mut body = amule_hello();
    for tag in &mut body.tags {
        if tag.name().id() == Some(CT_EMULE_MISCOPTIONS1)
            && let TagValue::U32(bits) = tag.value()
        {
            *tag = MiscOptions1::from_bits(bits & !(0x0f << 8)).to_tag();
        }
    }
    body
}

fn one_part_ask() -> PeerCommand {
    PeerCommand::RequestFile {
        file_hash: hash(),
        file_size: FILE_SIZE,
        want_sources: true,
        want_aich_root: true,
        own_status: PartBitmap::downloader_empty(FILE_SIZE),
    }
}

/// KAT: aMule wrote the captured bundle to an rmule that claimed
/// extended-requests v0, so its `0x58` carries nothing. Asking a peer that
/// claims v0, rmule's bundle is those bytes exactly — `0xA4 <hash><size8>`
/// then `58 | 83 04 0000 | 9E`, no `OP_SETREQFILEID` for a single part.
#[test]
fn a_one_part_ask_to_a_v0_claimant_is_amules_own_bundle_byte_for_byte() {
    let mut session = identified_against(amule_hello_claiming_no_extended_requests());
    session.handle_command(one_part_ask());
    let sent = writes(&drain(|| session.poll_output()));
    assert_eq!(sent.len(), 1, "one bundle, nothing standalone beside it");
    assert_eq!(
        sent[0].encode(),
        load(FIXTURE_DIR, "request_multipacket_ext_0xa4.bin"),
        "rmule's bundle is aMule's captured 0xA4"
    );
}

/// The capture override puts rmule back where it stood when aMule sent the
/// captured bundle: claiming v0, it writes nothing after the `0x58` sub even
/// to aMule's real hello, and its hello says so.
#[test]
fn claiming_v0_by_override_asks_amule_with_its_own_bundle_byte_for_byte() {
    let mut session = PeerSession::new_outbound(peer_at(2), serverless_ctx())
        .with_extended_requests_capture_override(0);
    session.start();
    let hello = writes(&drain(|| session.poll_output()));
    let body = Hello::decode_packet(&hello[0])
        .expect("our hello decodes")
        .into_body();
    assert_eq!(
        MiscOptions1::from_tags(&body.tags).map(MiscOptions1::extended_requests_version),
        Some(0)
    );
    session.handle_bytes(&HelloAnswer::new(amule_hello()).encode_packet().encode());
    let _ = drain(|| session.poll_output());
    session.handle_command(one_part_ask());
    let sent = writes(&drain(|| session.poll_output()));
    assert_eq!(
        sent.iter().map(Packet::encode).collect::<Vec<_>>(),
        vec![load(FIXTURE_DIR, "request_multipacket_ext_0xa4.bin")]
    );
}

/// The complete-file ask: aMule's real hello claims
/// extended-requests v2, so the session speaks rmule's v1 and the `0x58` sub
/// carries rmule's part status — for a one-part file it holds nothing of,
/// `WritePartStatus`'s `01 00` count and one empty byte. Without it aMule
/// clears the asker's status and `CreateSrcInfoPacket` refuses a complete
/// file's source answer. Everything else is the captured bundle.
#[test]
fn a_one_part_ask_to_amule_carries_rmules_part_status_in_the_name_sub() {
    let mut session = identified_against(amule_hello());
    session.handle_command(one_part_ask());
    let sent = writes(&drain(|| session.poll_output()));
    let (captured, _) = Packet::decode(&load(FIXTURE_DIR, "request_multipacket_ext_0xa4.bin"))
        .expect("captured bundle frames");
    let name_sub = FileHash::BYTE_LEN + 8;
    assert_eq!(captured.payload()[name_sub], 0x58);
    let mut expected = captured.payload().to_vec();
    expected.splice(name_sub + 1..name_sub + 1, [0x01, 0x00, 0x00]);
    assert_eq!(
        sent,
        vec![Packet::new(
            captured.protocol(),
            captured.opcode(),
            expected
        )]
    );
}

/// The partfile ask: two and a half parts, the middle one held.
/// aMule's reader takes `size / PARTSIZE + 1` parts and one bit each, so the
/// sub is `58 03 00 02`, then `OP_SETREQFILEID` (multi-part) and the SX2 ask.
#[test]
fn a_partfile_ask_to_amule_carries_the_parts_rmule_holds() {
    let size = ED2K_PART_SIZE * 5 / 2;
    let mut session = identified_against(amule_hello());
    session.handle_command(PeerCommand::RequestFile {
        file_hash: hash(),
        file_size: size,
        want_sources: true,
        want_aich_root: false,
        own_status: PartBitmap::downloader(size, |part| part.value() == 1),
    });
    let sent = writes(&drain(|| session.poll_output()));
    let mut payload = hash().as_bytes().to_vec();
    payload.extend_from_slice(&size.to_le_bytes());
    payload.extend_from_slice(&[0x58, 0x03, 0x00, 0b010, 0x4F, 0x83, 0x04, 0x00, 0x00]);
    assert_eq!(
        sent,
        vec![Packet::new(PacketProtocol::Emule, 0xA4, payload)]
    );
}

/// A standalone name ask to a claimant carries the status too: aMule's
/// standalone reader throws "Wrong size on extended info packet" on a bare
/// 16-byte `0x58` from a peer that claimed extended requests, and drops it.
#[test]
fn a_standalone_name_ask_to_amule_is_never_the_bare_hash() {
    let mut session = identified_against(amule_hello_without_multipacket());
    session.handle_command(one_part_ask());
    let sent = writes(&drain(|| session.poll_output()));
    let name = sent
        .iter()
        .find(|p| p.protocol() == PacketProtocol::Edonkey && p.opcode() == 0x58)
        .expect("a standalone OP_REQUESTFILENAME");
    let mut expected = hash().as_bytes().to_vec();
    expected.extend_from_slice(&[0x01, 0x00, 0x00]);
    assert_eq!(name.payload(), expected.as_slice());
}

/// The `RequestParts` fallback (no prior `RequestFile`): a
/// one-part file's probe is the name ask alone, matching aMule's own
/// `SendFileRequest`, which adds `OP_SETREQFILEID` only when
/// `GetPartCount() > 1`.
#[test]
fn a_requestparts_fallback_ask_for_a_one_part_file_is_the_name_request_alone() {
    let mut session = identified_against(amule_hello());
    session.handle_command(PeerCommand::RequestParts {
        file_hash: hash(),
        file_size: FILE_SIZE,
        ranges: PartRanges::new([(0, 4), (0, 0), (0, 0)]).unwrap(),
    });
    let sent = writes(&drain(|| session.poll_output()));
    let opcodes: Vec<u8> = sent.iter().map(Packet::opcode).collect();
    assert_eq!(
        opcodes,
        vec![0x58],
        "no OP_SETREQFILEID for a one-part file: {sent:?}"
    );
}

/// The same fallback for a multi-part file keeps `OP_SETREQFILEID`
/// (aMule bundles it whenever `GetPartCount() > 1`) — unchanged by the one-part rule.
#[test]
fn a_requestparts_fallback_ask_for_a_multi_part_file_still_bundles_setreqfileid() {
    let mut session = identified_against(amule_hello());
    session.handle_command(PeerCommand::RequestParts {
        file_hash: hash(),
        file_size: 2 * ED2K_PART_SIZE,
        ranges: PartRanges::new([(0, 4), (0, 0), (0, 0)]).unwrap(),
    });
    let sent = writes(&drain(|| session.poll_output()));
    let opcodes: Vec<u8> = sent.iter().map(Packet::opcode).collect();
    assert_eq!(
        &opcodes[..2],
        [0x58, 0x4F],
        "OP_REQUESTFILENAME then OP_SETREQFILEID for a multi-part file: {sent:?}"
    );
}

/// Every road a source ask leaves by — the connect-time bundle for a one-part
/// or a two-part file, and the granular `RequestSources` — toward an aMule
/// hello with and without the multipacket bit: none of them is the 19-byte
/// standalone `0x83` aMule disconnects on; the standalone ask is the 16-byte
/// SX1 `0x81`, which that arm accepts.
#[test]
fn no_source_ask_to_an_amule_hello_is_the_standalone_19_byte_0x83() {
    let commands = [
        PeerCommand::RequestSources { file_hash: hash() },
        PeerCommand::RequestFile {
            file_hash: hash(),
            file_size: FILE_SIZE,
            own_status: PartBitmap::downloader_empty(FILE_SIZE),
            want_sources: true,
            want_aich_root: false,
        },
        PeerCommand::RequestFile {
            file_hash: hash(),
            file_size: 2 * ED2K_PART_SIZE,
            own_status: PartBitmap::downloader_empty(2 * ED2K_PART_SIZE),
            want_sources: true,
            want_aich_root: false,
        },
    ];
    for (label, hello) in [
        ("captured", amule_hello as fn() -> PeerHelloBody),
        ("no multipacket", amule_hello_without_multipacket),
    ] {
        for command in commands.clone() {
            let mut session = identified_against(hello());
            session.handle_command(command.clone());
            let sent = writes(&drain(|| session.poll_output()));
            let emule: Vec<&Packet> = sent
                .iter()
                .filter(|p| p.protocol() == PacketProtocol::Emule)
                .collect();
            assert!(
                emule.iter().all(|p| p.opcode() != OP_REQUESTSOURCES2),
                "{label}, {command:?}: a standalone 0x83 went out: {sent:?}"
            );
            if label == "no multipacket" {
                let ask: Vec<&&Packet> = emule
                    .iter()
                    .filter(|p| p.opcode() == OP_REQUESTSOURCES)
                    .collect();
                assert_eq!(ask.len(), 1, "{label}, {command:?}: one SX1 ask");
                assert_eq!(ask[0].payload(), hash().as_bytes(), "16 bytes: the hash");
            }
        }
    }
}

/// Run `1790161721`: aMule's answer to rmule's one-part bundle, cut
/// from the downloader's tap — a `0x93` carrying the name alone.
const ONE_PART_ANSWER_DIR: &str =
    "fixtures/multipacket/captured/amule-233-one-part-answer-20260923/";
/// That run's 4 MiB file.
const ONE_PART_HASH: [u8; 16] = [
    0x00, 0x9D, 0x91, 0x60, 0x7B, 0x0D, 0x86, 0xD6, 0x4F, 0xAF, 0xF6, 0x31, 0xE0, 0x2E, 0xD8, 0x64,
];
const ONE_PART_SIZE: u64 = 4_194_304;

/// aMule's `ProcessFileInfo` rule for a one-part file: a name answer means a
/// complete source, and aMule's answer to a one-part bundle carries no part
/// status. The bundle is the probe, so `RequestParts` adds nothing, and
/// aMule's captured name-only `0x93` alone opens the slot
/// (`OP_STARTUPLOADREQ`), as it did on the wire in that run.
#[test]
fn amules_name_only_answer_to_a_one_part_bundle_opens_the_slot() {
    let file_hash = FileHash::from_bytes(ONE_PART_HASH);
    let mut session = identified_against(amule_hello());
    session.handle_command(PeerCommand::RequestFile {
        file_hash,
        file_size: ONE_PART_SIZE,
        own_status: PartBitmap::downloader_empty(ONE_PART_SIZE),
        want_sources: true,
        want_aich_root: false,
    });
    let _ = drain(|| session.poll_output());
    session.handle_command(PeerCommand::RequestParts {
        file_hash,
        file_size: ONE_PART_SIZE,
        ranges: PartRanges::new([(0, 184_320), (0, 0), (0, 0)]).unwrap(),
    });
    let sent = writes(&drain(|| session.poll_output()));
    assert!(sent.is_empty(), "the bundle already asked: {sent:?}");

    session.handle_bytes(&load(ONE_PART_ANSWER_DIR, "answer_multipacket_0x93.bin"));
    let sent = writes(&drain(|| session.poll_output()));
    let opcodes: Vec<u8> = sent.iter().map(Packet::opcode).collect();
    assert_eq!(opcodes, vec![0x54], "OP_STARTUPLOADREQ on the name alone");
}

/// The other direction: once rmule claims extended-requests v1,
/// aMule's asker writes its part status after the `0x58` sub
/// (`SendFileRequest`, at the uploader's claim). Nothing frames it, so the
/// walker must read it at the session's level or take the count bytes for
/// sub-opcodes — here the SX2 ask behind it still reaches the serve side, and
/// the status itself reaches it with the name ask (the source answer's
/// needed-part filter reads it).
#[test]
fn an_amule_bundle_with_its_part_status_still_routes_the_source_ask() {
    let mut session = PeerSession::new_inbound(peer_at(3), serverless_ctx());
    session.handle_bytes(&Hello::new(amule_hello()).encode_packet().encode());
    let _ = drain(|| session.poll_output());
    let mut payload = hash().as_bytes().to_vec();
    payload.extend_from_slice(&FILE_SIZE.to_le_bytes());
    payload.extend_from_slice(&[0x58, 0x01, 0x00, 0x00, 0x83, 0x04, 0x00, 0x00]);
    session.handle_bytes(&Packet::new(PacketProtocol::Emule, 0xA4, payload).encode());
    let out = drain(|| session.poll_output());
    let seen = events(&out);
    assert!(
        seen.iter().any(|e| matches!(
            e,
            PeerEvent::FileBundleRequested { file_hash, asks, .. }
                if *file_hash == hash()
                    && matches!(
                        asks.as_slice(),
                        [BundledAsk::Name { part_status: Some(status) }, BundledAsk::Sources(_)]
                            if *status == PartBitmap::decode(1, &[0]).unwrap()
                    )
        )),
        "{seen:?}"
    );
}
