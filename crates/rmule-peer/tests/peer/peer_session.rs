//! The outbound session's spine: hello out, answer in, `Identified`. Plus the
//! ways a link ends — a malformed answer, a local disconnect, an elapsed hello
//! deadline — and the frames that must not end it: an unknown opcode, a second
//! `start`, a frame split across two reads, a peer's own late `OP_HELLO`.

use crate::fixture::{identified_session, plain_hello_body};
use rmule_peer::{
    ConnectionCommand, ConnectionEvent, Hello, HelloAnswer, NoticeEvent, PeerCloseReason,
    PeerCommand, PeerEvent, PeerOpcode, PeerOutput, PeerSession,
};
use rmule_primitives::session::drain;
use rmule_primitives::{Ed2kText, Packet, PacketProtocol, UserHash};
use rmule_testkit::peer_session::{ctx, peer};

#[test]
fn start_emits_hello_event_then_write() {
    let mut session = PeerSession::new_outbound(peer(), ctx());
    session.start();
    let outputs = drain(|| session.poll_output());
    assert!(matches!(
        outputs[0],
        PeerOutput::Event(PeerEvent::Connection(ConnectionEvent::HelloSent))
    ));
    match &outputs[1] {
        PeerOutput::Write(bytes) => {
            let (packet, _) = Packet::decode(bytes).expect("decodes");
            assert_eq!(packet.opcode(), 0x01);
            assert_eq!(packet.payload()[0], UserHash::BYTE_LEN as u8);
        }
        other => panic!("expected Write, got {other:?}"),
    }
    assert_eq!(outputs.len(), 2);
}

#[test]
fn hello_answer_identifies_peer() {
    let user_hash = UserHash::from_bytes([0x99; UserHash::BYTE_LEN]);
    let answer_bytes = HelloAnswer::new(plain_hello_body(user_hash))
        .encode_packet()
        .encode();

    let mut session = PeerSession::new_outbound(peer(), ctx());
    session.start();
    let _ = drain(|| session.poll_output());

    session.handle_bytes(&answer_bytes);
    let outputs = drain(|| session.poll_output());
    let identified = outputs
        .iter()
        .find_map(|o| match o {
            PeerOutput::Event(PeerEvent::Connection(ConnectionEvent::Identified { identity })) => {
                Some(identity)
            }
            _ => None,
        })
        .expect("Identified emitted");
    assert_eq!(identified.user_hash(), user_hash);
    assert_eq!(
        identified.nickname().map(Ed2kText::to_display_string),
        Some("remote".to_owned())
    );
    assert!(!outputs.iter().any(|o| matches!(o, PeerOutput::Close(_))));
}

#[test]
fn unknown_opcode_emits_event_without_closing() {
    let unknown_bytes = Packet::new(PacketProtocol::Edonkey, 0x77, vec![1, 2, 3]).encode();

    let mut session = PeerSession::new_outbound(peer(), ctx());
    session.start();
    let _ = drain(|| session.poll_output());
    session.handle_bytes(&unknown_bytes);

    let outputs = drain(|| session.poll_output());
    let unknown = outputs
        .iter()
        .find_map(|o| match o {
            PeerOutput::Event(PeerEvent::Notice(NoticeEvent::UnknownPacket {
                protocol: _,
                opcode,
                payload_len,
            })) => Some((*opcode, *payload_len)),
            _ => None,
        })
        .expect("UnknownPacket emitted");
    assert_eq!(unknown, (0x77, 3));
    assert!(!outputs.iter().any(|o| matches!(o, PeerOutput::Close(_))));
}

#[test]
fn malformed_hello_answer_closes_with_protocol_violation() {
    // Truncated answer: hash + client_id + port + zero tag count, but
    // missing the trailing 6-byte connected_server endpoint.
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0x55; UserHash::BYTE_LEN]);
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    let bad = Packet::new(PacketProtocol::Edonkey, 0x4C, payload).encode();

    let mut session = PeerSession::new_outbound(peer(), ctx());
    session.start();
    let _ = drain(|| session.poll_output());
    session.handle_bytes(&bad);
    let outputs = drain(|| session.poll_output());
    // Every close path — not just Local — emits the paired Disconnected
    // immediately before Close, so the terminal pair is the last two outputs.
    assert!(matches!(
        outputs.iter().rev().nth(1),
        Some(PeerOutput::Event(PeerEvent::Connection(
            ConnectionEvent::Disconnected {
                reason: PeerCloseReason::ProtocolViolation,
            }
        )))
    ));
    assert!(matches!(
        outputs.last(),
        Some(PeerOutput::Close(PeerCloseReason::ProtocolViolation))
    ));
}

/// A malformed frame ends the link on every leg with no rule of its own, on an
/// identified link where the frame could otherwise have been acted on.
#[test]
fn a_malformed_frame_on_a_plain_leg_closes_the_link() {
    use PeerOpcode as Op;
    let short = [0u8; 3];
    let frames = [
        (PacketProtocol::Emule, 0x01, &[][..]),
        (PacketProtocol::Emule, 0x02, &[][..]),
        (PacketProtocol::Emule, 0x61, &[][..]),
        // Sixteen bytes or fewer would be an `OP_AICHANSWER`'s refusal form.
        (PacketProtocol::Emule, 0x9C, &[0u8; 20][..]),
    ]
    .into_iter()
    .map(|(protocol, opcode, body)| Packet::new(protocol, opcode, body.to_vec()))
    .chain(
        [
            Op::RequestFileName,
            Op::ReqFileNameAnswer,
            Op::FileReqAnsNoFil,
            Op::SetReqFileId,
            Op::FileStatus,
            Op::HashSetRequest,
            Op::HashSetAnswer,
            Op::AcceptUploadReq,
            Op::OutOfPartReqs,
            Op::QueueRanking,
            Op::RequestParts,
            Op::RequestPartsI64,
            Op::SendingPart,
            Op::SendingPartI64,
            Op::CompressedPart,
            Op::CompressedPartI64,
            Op::RequestSources,
            Op::RequestSources2,
            Op::AichRequest,
            Op::AichFileHashReq,
            Op::AichFileHashAns,
            Op::SecIdentState,
            Op::PublicKey,
            Op::Signature,
            Op::MultiPacket,
            Op::MultiPacketExt,
            Op::MultiPacketAnswer,
            Op::PublicIpAnswer,
            Op::Message,
            Op::ChangeClientId,
            Op::ChangeClientIpV6,
        ]
        .into_iter()
        .map(|op| Packet::new(op.protocol(), op.as_u8(), short.to_vec())),
    );
    for frame in frames {
        let mut session = identified_session();
        session.handle_bytes(&frame.encode());
        let outputs = drain(|| session.poll_output());
        assert!(
            matches!(
                outputs.last(),
                Some(PeerOutput::Close(PeerCloseReason::ProtocolViolation))
            ),
            "{:?} 0x{:02X}: {outputs:?}",
            frame.protocol(),
            frame.opcode(),
        );
    }
}

/// aMule lets a slot ask of the wrong size pass, connection kept, so this one
/// plain frame is preserved rather than closed on.
#[test]
fn a_malformed_slot_ask_stays_open_as_unknown() {
    let op = PeerOpcode::StartUploadReq;
    let mut session = identified_session();
    session.handle_bytes(&Packet::new(op.protocol(), op.as_u8(), vec![0u8; 3]).encode());
    let outputs = drain(|| session.poll_output());
    assert!(matches!(
        outputs.as_slice(),
        [PeerOutput::Event(PeerEvent::Notice(
            NoticeEvent::UnknownPacket { .. }
        ))]
    ));
}

#[test]
fn disconnect_command_closes_locally() {
    let mut session = PeerSession::new_outbound(peer(), ctx());
    session.start();
    let _ = drain(|| session.poll_output());
    session.handle_command(PeerCommand::Connection(ConnectionCommand::Disconnect));

    let outputs = drain(|| session.poll_output());
    assert!(outputs.iter().any(|o| matches!(
        o,
        PeerOutput::Event(PeerEvent::Connection(ConnectionEvent::Disconnected {
            reason: PeerCloseReason::Local,
        }))
    )));
    assert!(matches!(
        outputs.last(),
        Some(PeerOutput::Close(PeerCloseReason::Local))
    ));
}

#[test]
fn hello_deadline_elapsed_closes_with_hello_timeout() {
    let mut session = PeerSession::new_outbound(peer(), ctx());
    session.start();
    let _ = drain(|| session.poll_output());

    session.hello_deadline_elapsed();
    let outputs = drain(|| session.poll_output());
    assert!(matches!(
        outputs.last(),
        Some(PeerOutput::Close(PeerCloseReason::HelloTimeout))
    ));
}

#[test]
fn hello_deadline_after_identified_is_noop() {
    let user_hash = UserHash::from_bytes([0x99; UserHash::BYTE_LEN]);
    let answer_bytes = HelloAnswer::new(plain_hello_body(user_hash))
        .encode_packet()
        .encode();
    let mut session = PeerSession::new_outbound(peer(), ctx());
    session.start();
    let _ = drain(|| session.poll_output());
    session.handle_bytes(&answer_bytes);
    let _ = drain(|| session.poll_output());

    session.hello_deadline_elapsed();
    let outputs = drain(|| session.poll_output());
    assert!(outputs.is_empty());
}

#[test]
fn ignore_start_called_after_we_already_sent_hello() {
    // Documented session contract: start is idempotent. Calling it twice
    // must not enqueue a second hello write.
    let mut session = PeerSession::new_outbound(peer(), ctx());
    session.start();
    let _ = drain(|| session.poll_output());
    session.start();
    assert!(drain(|| session.poll_output()).is_empty());
}

#[test]
fn truncated_bytes_buffer_across_calls_until_complete() {
    // The session accumulates partial frames in its in-buffer and only
    // dispatches once `Packet::decode` returns a full frame. Splitting
    // an OP_HELLOANSWER across two `handle_bytes` calls must yield a
    // single Identified, not a protocol violation or duplicate
    // event.
    let user_hash = UserHash::from_bytes([0x88; UserHash::BYTE_LEN]);
    let answer = HelloAnswer::new(plain_hello_body(user_hash))
        .encode_packet()
        .encode();
    let split_at = answer.len() / 2;

    let mut session = PeerSession::new_outbound(peer(), ctx());
    session.start();
    let _ = drain(|| session.poll_output());

    session.handle_bytes(&answer[..split_at]);
    let mid = drain(|| session.poll_output());
    assert!(
        mid.iter().all(|o| !matches!(
            o,
            PeerOutput::Event(PeerEvent::Connection(ConnectionEvent::Identified { .. }))
        )) && mid.iter().all(|o| !matches!(o, PeerOutput::Close(_))),
        "no premature identify or close on partial frame"
    );

    session.handle_bytes(&answer[split_at..]);
    let outputs = drain(|| session.poll_output());
    let identified_count = outputs
        .iter()
        .filter(|o| {
            matches!(
                o,
                PeerOutput::Event(PeerEvent::Connection(ConnectionEvent::Identified { .. }))
            )
        })
        .count();
    assert_eq!(identified_count, 1, "Identified emitted exactly once");
    assert!(!outputs.iter().any(|o| matches!(o, PeerOutput::Close(_))));
}

#[test]
fn unexpected_op_hello_after_we_dialed_is_logged_as_unknown() {
    // We are the dialer; a well-formed OP_HELLO from the
    // remote (instead of OP_HELLOANSWER) is unexpected but not a
    // protocol violation. It is logged as Unknown so the session
    // stays open and the operator can see what happened.
    let body = plain_hello_body(UserHash::from_bytes([0x44; UserHash::BYTE_LEN]));
    let hello_bytes = Hello::new(body).encode_packet().encode();

    let mut session = PeerSession::new_outbound(peer(), ctx());
    session.start();
    let _ = drain(|| session.poll_output());

    session.handle_bytes(&hello_bytes);
    let outputs = drain(|| session.poll_output());
    assert!(outputs.iter().any(|o| matches!(
        o,
        PeerOutput::Event(PeerEvent::Notice(NoticeEvent::UnknownPacket {
            opcode: 0x01,
            ..
        }))
    )));
    assert!(!outputs.iter().any(|o| matches!(o, PeerOutput::Close(_))));
}

#[test]
fn second_hello_answer_after_identified_is_logged_as_unknown() {
    // After Identified, a second OP_HELLOANSWER is no longer a state
    // transition; the session must not re-emit Identified and must
    // not close. Logging as Unknown matches the "preserve well-formed
    // unknown packets" discipline (ADR-0018) and keeps the session
    // available for whatever the peer wants to send next.
    let user_hash = UserHash::from_bytes([0x66; UserHash::BYTE_LEN]);
    let answer = HelloAnswer::new(plain_hello_body(user_hash))
        .encode_packet()
        .encode();

    let mut session = PeerSession::new_outbound(peer(), ctx());
    session.start();
    let _ = drain(|| session.poll_output());
    session.handle_bytes(&answer);
    let _ = drain(|| session.poll_output());

    session.handle_bytes(&answer);
    let outputs = drain(|| session.poll_output());
    assert!(outputs.iter().any(|o| matches!(
        o,
        PeerOutput::Event(PeerEvent::Notice(NoticeEvent::UnknownPacket {
            opcode: 0x4C,
            ..
        }))
    )));
    assert!(!outputs.iter().any(|o| matches!(
        o,
        PeerOutput::Event(PeerEvent::Connection(ConnectionEvent::Identified { .. }))
    )));
    assert!(!outputs.iter().any(|o| matches!(o, PeerOutput::Close(_))));
}
