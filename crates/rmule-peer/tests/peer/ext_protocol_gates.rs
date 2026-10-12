//! What stock aMule 2.3.3 gates on the mule flag, `ExtProtocolAvailable()`
//! (`m_bEmuleProtocol`): asking a peer for sources (`IsSourceRequestAllowed`,
//! `DownloadClient.cpp:191`) and telling it its queue rank (`SendRankingInfo`,
//! `UploadClient.cpp:724`). The flag is the only conjunct asserted here. A mule hello sets the flag (`BaseClient.cpp:711`);
//! an `OP_EMULEINFO` under an unknown protocol byte clears it (`:893`).
//!
//! Made frames, not captures: every hello and block here is written from the
//! reader's source.

use rmule_peer::{
    ConnectionEvent, HelloAnswer, MiscOptions1, PeerCommand, PeerEvent, PeerIdentity, PeerOutput,
    PeerSession, RequesterCommand, ServerCommand,
};
use rmule_primitives::session::drain;
use rmule_primitives::{FileHash, Packet, PacketProtocol, UserHash};
use rmule_testkit::peer_session::{mule_version_tag, peer_at, serverless_ctx, writes};

use crate::fixture::hello_body;

/// An identified outbound session whose peer answered a mule hello
/// advertising source exchange version 4.
fn identified_mule() -> PeerSession {
    let mut session = PeerSession::new_outbound(peer_at(61), serverless_ctx());
    session.start();
    let _ = drain(|| session.poll_output());
    let answer = hello_body(
        UserHash::from_bytes([0x5C; 16]),
        0x2000_0002,
        vec![
            mule_version_tag(),
            MiscOptions1::from_bits(4 << 12).to_tag(),
        ],
    );
    session.handle_bytes(&HelloAnswer::new(answer).encode_packet().encode());
    let _ = drain(|| session.poll_output());
    session
}

/// An `OP_EMULEINFO` under protocol byte `0x02`: aMule records its version
/// and clears the mule flag.
fn clear_the_flag(session: &mut PeerSession) {
    let block = Packet::new(PacketProtocol::Emule, 0x01, vec![0x30, 0x02, 0, 0, 0, 0]);
    session.handle_bytes(&block.encode());
    let _ = drain(|| session.poll_output());
}

/// The opcodes a one-part file request, a standalone source ask and a queue
/// rank put on the wire.
fn asks(session: &mut PeerSession) -> Vec<u8> {
    let file_hash = FileHash::from_bytes([0x3A; FileHash::BYTE_LEN]);
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestFile {
        file_hash,
        file_size: 700_001,
        own_status: rmule_peer::PartBitmap::downloader_empty(700_001),
        want_sources: true,
        want_aich_root: false,
    }));
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestSources {
        file_hash,
    }));
    session.handle_command(PeerCommand::Server(ServerCommand::SetQueueRank {
        rank: 17,
    }));
    let out = drain(|| session.poll_output());
    writes(&out).iter().map(Packet::opcode).collect()
}

#[test]
fn a_mule_is_asked_for_sources_and_told_its_rank() {
    assert_eq!(
        asks(&mut identified_mule()),
        vec![0x58, 0x81, 0x81, 0x60],
        "name ask with its source ask, a standalone source ask, the rank"
    );
}

#[test]
fn a_peer_whose_mule_flag_was_cleared_is_asked_its_file_name_only() {
    let mut session = identified_mule();
    clear_the_flag(&mut session);
    assert_eq!(
        asks(&mut session),
        vec![0x58],
        "no source ask and no rank without the extended protocol"
    );
}

/// The identity a session hands up for a mule whose hello advertised the SX1
/// nibble `sx1`.
fn identity_of_mule_with_sx1(sx1: u32) -> PeerIdentity {
    let mut session = PeerSession::new_outbound(peer_at(62), serverless_ctx());
    session.start();
    let _ = drain(|| session.poll_output());
    let answer = hello_body(
        UserHash::from_bytes([
            0x91, 0x0E, 0x27, 0xB4, 0x5D, 0x63, 0xF8, 0x1A, 0xC2, 0x3B, 0x70, 0x0E, 0x84, 0xD9,
            0x16, 0xA5,
        ]),
        0x2000_0003,
        vec![
            mule_version_tag(),
            MiscOptions1::from_bits(sx1 << 12).to_tag(),
        ],
    );
    session.handle_bytes(&HelloAnswer::new(answer).encode_packet().encode());
    drain(|| session.poll_output())
        .into_iter()
        .find_map(|output| match output {
            PeerOutput::Event(PeerEvent::Connection(ConnectionEvent::Identified { identity })) => {
                Some(identity)
            }
            _ => None,
        })
        .expect("the hello identifies the peer")
}

/// The download needs the peer-side half of the source-ask gate after the
/// connection is gone (ADR-0108), so the identity carries the very facts the
/// session's own gate reads: a v4 mule is askable, a v1 mule is not.
#[test]
fn the_identity_carries_the_source_exchange_facts_the_session_gates_on() {
    let v4 = identity_of_mule_with_sx1(4).source_exchange();
    assert_eq!(v4.sx1_version(), 4);
    assert!(v4.askable());
    let v1 = identity_of_mule_with_sx1(1).source_exchange();
    assert_eq!(v1.sx1_version(), 1);
    assert!(!v1.askable(), "aMule never asks an SX1 nibble of 1");
}
