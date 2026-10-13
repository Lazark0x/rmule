//! Peer-surface packed (`0xD4`) frame inflate at the session dispatch layer
//! (ADR-0053). Mirrors `rmule-ed2k`'s `session_compressed_frames.rs`:
//! invalid zlib and over-cap payloads are non-terminal skips; a valid packed
//! `OP_ANSWERSOURCES` inflates straight through to `SourcesReceived`.

use std::io::Write;
use std::net::Ipv4Addr;

use flate2::{Compression, write::ZlibEncoder};

use rmule_peer::{
    AnswerSources, CompressedFrameSkipReason, HelloAnswer, MiscOptions1, NoticeEvent,
    PEER_COMPRESSED_FRAME_LIMIT, PeerCommand, PeerEvent, PeerHelloBody, PeerOutput, PeerSession,
    RequesterCommand, RequesterEvent, SourceExchangeEntry, SourceExchangeVersion,
};
use rmule_primitives::session::drain;
use rmule_primitives::{
    ClientId, FileHash, Ipv4Endpoint, Packet, PacketProtocol, PeerSource, SourceClaim, UserHash,
};
use rmule_testkit::peer_session::{ctx, peer};

/// An identified outbound session: `start()` plus a `HelloAnswer` that
/// advertises source-exchange v1 — a real eMule/aMule peer always sends
/// `CT_EMULE_MISCOPTIONS1`, and `OP_ANSWERSOURCES`'s geometry cross-check
/// resolves against *this peer's* claimed nibble (ADR-0055), not
/// rmule's own.
fn session() -> PeerSession {
    let mut session = PeerSession::new_outbound(peer(), ctx());
    session.start();
    drain(|| session.poll_output());
    let answer = HelloAnswer::new(PeerHelloBody {
        user_hash: UserHash::from_bytes([0x99; UserHash::BYTE_LEN]),
        client_id: ClientId::from_u32(0x2000_0002),
        tcp_port: 4662,
        tags: vec![
            rmule_testkit::peer_session::mule_version_tag(),
            MiscOptions1::from_bits(1 << 12).to_tag(),
        ],
        connected_server: Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0),
    })
    .encode_packet()
    .encode();
    session.handle_bytes(&answer);
    drain(|| session.poll_output());
    session
}

fn zlib_bytes(input: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input).unwrap();
    encoder.finish().unwrap()
}

/// Frame a raw packed (`0xD4`) packet the way the wire does.
fn packed_frame_bytes(opcode: u8, compressed: &[u8]) -> Vec<u8> {
    Packet::new(PacketProtocol::PackedEd2k, opcode, compressed.to_vec()).encode()
}

#[test]
fn invalid_compressed_frame_is_skipped_without_closing_session() {
    let mut session = session();

    session.handle_bytes(&packed_frame_bytes(0x82, &[0, 1, 2]));

    let outputs = drain(|| session.poll_output());
    let (opcode, compressed_len, reason) = outputs
        .iter()
        .find_map(|o| match o {
            PeerOutput::Event(PeerEvent::Notice(NoticeEvent::CompressedFrameSkipped {
                opcode,
                compressed_len,
                reason,
            })) => Some((*opcode, *compressed_len, *reason)),
            _ => None,
        })
        .expect("CompressedFrameSkipped emitted");

    assert_eq!(opcode, 0x82);
    assert_eq!(compressed_len, 3);
    assert_eq!(reason, CompressedFrameSkipReason::InflateFailed);
    assert!(!outputs.iter().any(|o| matches!(o, PeerOutput::Close(_))));
}

#[test]
fn oversized_compressed_frame_is_skipped_without_closing_session() {
    let too_large = vec![b'x'; PEER_COMPRESSED_FRAME_LIMIT + 1];
    let compressed = zlib_bytes(&too_large);

    let mut session = session();

    session.handle_bytes(&packed_frame_bytes(0x82, &compressed));

    let outputs = drain(|| session.poll_output());
    let reason = outputs
        .iter()
        .find_map(|o| match o {
            PeerOutput::Event(PeerEvent::Notice(NoticeEvent::CompressedFrameSkipped {
                reason,
                ..
            })) => Some(*reason),
            _ => None,
        })
        .expect("CompressedFrameSkipped emitted");

    assert_eq!(
        reason,
        CompressedFrameSkipReason::DecompressedSizeLimitExceeded {
            limit: PEER_COMPRESSED_FRAME_LIMIT
        }
    );
    assert!(!outputs.iter().any(|o| matches!(o, PeerOutput::Close(_))));
}

#[test]
fn packed_answer_sources_inflates_to_sources_received() {
    let file_hash = FileHash::from_bytes([0x21; 16]);
    let source = SourceClaim::plain(PeerSource::new(ClientId::from_u32(0x0100_00A8), 4662));
    let plain = AnswerSources {
        file_hash,
        sources: vec![SourceExchangeEntry::plain(source)],
    }
    // V1: the shape rmule's live decode accepts at its advertised nibble.
    .encode_packet(SourceExchangeVersion::V1);
    assert_eq!(plain.protocol(), PacketProtocol::Emule);
    assert_eq!(plain.opcode(), 0x82);
    let compressed = zlib_bytes(plain.payload());

    let mut session = session();

    // Open the file's flow first — sources for a
    // never-requested file are dropped; this test's subject is the
    // packed-frame codec, not that gate. The name ask opens it: a nibble-1
    // peer is never asked for sources (ADR-0108).
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestFile {
        file_hash,
        file_size: 4096,
        own_status: rmule_peer::PartBitmap::downloader_empty(4096),
        want_sources: false,
        want_aich_root: false,
    }));
    let _ = drain(|| session.poll_output());

    session.handle_bytes(&packed_frame_bytes(0x82, &compressed));

    let outputs = drain(|| session.poll_output());
    let (fh, sources) = outputs
        .iter()
        .find_map(|o| match o {
            PeerOutput::Event(PeerEvent::Requester(RequesterEvent::SourcesReceived {
                file_hash,
                sources,
            })) => Some((*file_hash, sources.clone())),
            _ => None,
        })
        .expect("SourcesReceived emitted");

    assert_eq!(fh, file_hash);
    let peer = rmule_primitives::Informant::Party(session.peer_endpoint().ip());
    assert_eq!(
        sources,
        vec![source.stated_by(peer)],
        "the answering peer's word"
    );
    assert!(!outputs.iter().any(|o| matches!(o, PeerOutput::Close(_))));
}
