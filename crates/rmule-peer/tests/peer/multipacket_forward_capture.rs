//! Forward-direction multipacket capture replay (genuine stock aMule 2.3.3,
//! run `w18-0x93`, 2026-07-28) — the forward leg, unblocked by the download
//! runner's live wiring. rmule opened negotiation with the live download runner's
//! connect shape (one `0xA4` bundle: name + status + SX2 asks, `size8`), and
//! aMule answered this single composed `OP_MULTIPACKETANSWER` (`0x93`) — no
//! standalone `0x59`/`0x50` pair. The fixture is the counterparty's own frame
//! (ADR-0045); the tests re-decode it through the public API and replay it
//! into a session that solicited exactly as the live runner does. Provenance
//! in the fixture dir's `meta.toml`.

use std::net::Ipv4Addr;

use crate::fixture::load;
use rmule_peer::{
    FileProbeStatus, HelloAnswer, MiscOptions1, MiscOptions2, MultiPacketAnswer, PartBitmap,
    PeerCommand, PeerEvent, PeerHandshakeContext, PeerHelloBody, PeerOutput, PeerSession,
    multipacket::AnswerItem,
};
use rmule_primitives::session::drain;
use rmule_primitives::{
    ClientId, ClientIdentity, Ed2kText, FileHash, Ipv4Endpoint, Packet, PeerEndpoint, UserHash,
};

const FIXTURE_DIR: &str = "fixtures/multipacket/captured/amule-233-forward-answer-20260728/";

/// The synthetic 20 MiB file the direct-peer aMule shared this run.
const FILE_HASH: [u8; 16] = [
    0xB4, 0xC0, 0x26, 0xE3, 0xD7, 0x03, 0x47, 0xE0, 0x42, 0x4D, 0x1A, 0xFF, 0xA3, 0xFB, 0x8E, 0x6C,
];
const FILE_SIZE: u64 = 20_971_520;

/// aMule's `0x93` walks to exactly [Name, Status] — and the Status sub is the
/// `part_count = 0` empty-bitmap shorthand aMule sends for a source that has
/// the whole file, not a per-part enumeration.
#[test]
fn amule_forward_answer_0x93_walks_to_name_and_complete_status() {
    let bytes = load(FIXTURE_DIR, "answer_multipacket_0x93.bin");
    let (packet, consumed) = Packet::decode(&bytes).expect("fixture frame decodes");
    assert_eq!(consumed, bytes.len(), "fixture is exactly one frame");
    let answer = MultiPacketAnswer::decode_packet(&packet).expect("0x93 decodes");

    assert_eq!(answer.file_hash, FileHash::from_bytes(FILE_HASH));
    assert_eq!(
        answer.items,
        vec![
            AnswerItem::Name(Ed2kText::from_utf8("shared.bin")),
            AnswerItem::Status(PartBitmap::decode(0, &[]).expect("empty bitmap")),
        ],
        "one composed answer: the name plus the complete-source empty status"
    );
    assert!(answer.unknown_sub.is_none());

    // Byte-exact re-encode: our encoder reproduces aMule's own 0x93 frame.
    assert_eq!(
        answer.encode_packet().encode(),
        bytes,
        "re-encoded 0x93 must match aMule's captured bytes",
    );
}

/// Live-shape replay: a session that solicited exactly as the live download
/// runner does (`RequestFile` with the SX ask, against a peer
/// advertising MultiPacket + Ext + SX2, aMule's real trio) emits the same
/// `0xA4` bundle observed on the wire this run, and consuming aMule's genuine
/// `0x93` upgrades its probe to `Available` with the captured name and the
/// wire-level complete-source sentinel expanded to a full 3-part bitmap
/// (the fold knows this file's size from the `RequestFile` that
/// opened the probe).
#[test]
fn live_shaped_request_consumes_the_genuine_answer_into_file_probed() {
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 51), 4662));
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
    let answer = HelloAnswer::new(PeerHelloBody {
        user_hash: UserHash::from_bytes([0x99; UserHash::BYTE_LEN]),
        client_id: ClientId::from_u32(0x2000_0002),
        tcp_port: 4662,
        tags: vec![
            rmule_testkit::peer_session::mule_version_tag(),
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
        own_status: PartBitmap::downloader_empty(FILE_SIZE),
        want_sources: true,
        want_aich_root: false,
    });
    let out = drain(|| session.poll_output());
    let sent: Vec<Vec<u8>> = out
        .iter()
        .filter_map(|o| match o {
            PeerOutput::Write(b) => Some(b.to_vec()),
            _ => None,
        })
        .collect();
    // The exact frame rmule put on the wire this run (own bytes, asserted
    // deterministically rather than checked in as a fixture): 0xA4, hash,
    // size8 = 20971520 LE, subs [0x58, 0x4F, 0x83 v4 opts 0].
    let mut expected = vec![0xC5, 0x1F, 0x00, 0x00, 0x00, 0xA4];
    expected.extend_from_slice(&FILE_HASH);
    expected.extend_from_slice(&FILE_SIZE.to_le_bytes());
    expected.extend_from_slice(&[0x58, 0x4F, 0x83, 0x04, 0x00, 0x00]);
    assert_eq!(
        sent,
        vec![expected],
        "the live connect shape is the one 0xA4 bundle captured on the wire"
    );

    session.handle_bytes(&load(FIXTURE_DIR, "answer_multipacket_0x93.bin"));
    let probed = drain(|| session.poll_output())
        .iter()
        .find_map(|o| match o {
            PeerOutput::Event(PeerEvent::FileProbed {
                file_hash: fh,
                status,
            }) if *fh == file_hash => Some(status.clone()),
            _ => None,
        })
        .expect("aMule's genuine 0x93 upgrades the live-shaped probe");
    match probed {
        FileProbeStatus::Available {
            file_name,
            bitmap,
            complete,
        } => {
            assert_eq!(file_name, Ed2kText::from_utf8("shared.bin"));
            assert!(complete, "aMule's sentinel names a complete source");
            // The fold expands aMule's wire-level part-count-0 sentinel to a
            // full bitmap of the file's own 3-part count — the
            // probe state, unlike the wire bytes, never carries a fictional
            // 0-part file.
            assert_eq!(
                bitmap,
                PartBitmap::all_present(3),
                "the complete-source sentinel expands to every part of this 3-part file"
            );
        }
        other => panic!("expected Available, got {other:?}"),
    }
}
