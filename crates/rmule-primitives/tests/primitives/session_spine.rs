//! Behavioural tests for the shared session spine (ADR-0044): truncation
//! buffering across feeds, multi-packet dispatch, the paired-close
//! discipline, and post-close no-ops. Exercised through a minimal
//! embedding session shaped like the real protocol sessions: protocol
//! state next to the core, every close routed through one wrapper.

use rmule_primitives::{Packet, PacketProtocol, SessionCore, SessionOutput, session};

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Packet { opcode: u8 },
    Disconnected(Close),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Close {
    Frame,
    Local,
}

struct TestSession {
    core: SessionCore<Event, Close>,
    close_on_opcode: Option<u8>,
}

impl TestSession {
    fn new() -> Self {
        Self {
            core: SessionCore::new(),
            close_on_opcode: None,
        }
    }

    fn handle_bytes(&mut self, bytes: &[u8]) {
        SessionCore::feed(
            self,
            |session| &mut session.core,
            bytes,
            Self::dispatch,
            |session, _error| session.close(Close::Frame),
        );
    }

    fn dispatch(&mut self, packet: Packet) {
        self.core.push_event(Event::Packet {
            opcode: packet.opcode(),
        });
        if self.close_on_opcode == Some(packet.opcode()) {
            self.close(Close::Local);
        }
    }

    fn close(&mut self, reason: Close) {
        self.core.close(Event::Disconnected(reason), reason);
    }

    fn outputs(&mut self) -> Vec<SessionOutput<Event, Close>> {
        session::drain(|| self.core.poll_output())
    }
}

fn frame(opcode: u8) -> Vec<u8> {
    Packet::new(PacketProtocol::Edonkey, opcode, vec![0xAA, 0xBB]).encode()
}

#[test]
fn truncated_frame_buffers_across_feeds_until_complete() {
    let mut session = TestSession::new();
    let bytes = frame(0x01);
    let (head, tail) = bytes.split_at(bytes.len() - 1);
    for byte in head {
        session.handle_bytes(&[*byte]);
        assert!(
            session.core.poll_output().is_none(),
            "no dispatch before the frame completes"
        );
    }
    session.handle_bytes(tail);
    let outputs = session.outputs();
    assert!(matches!(
        outputs[..],
        [SessionOutput::Event(Event::Packet { opcode: 0x01 })]
    ));
}

#[test]
fn multi_packet_feed_dispatches_each_frame_in_order() {
    let mut session = TestSession::new();
    let mut bytes = frame(0x01);
    bytes.extend_from_slice(&frame(0x02));
    session.handle_bytes(&bytes);
    let outputs = session.outputs();
    assert!(matches!(
        outputs[..],
        [
            SessionOutput::Event(Event::Packet { opcode: 0x01 }),
            SessionOutput::Event(Event::Packet { opcode: 0x02 }),
        ]
    ));
}

#[test]
fn close_pairs_disconnected_before_close_exactly_once() {
    let mut session = TestSession::new();
    session.close(Close::Local);
    let outputs = session.outputs();
    assert!(matches!(
        outputs[..],
        [
            SessionOutput::Event(Event::Disconnected(Close::Local)),
            SessionOutput::Close(Close::Local),
        ]
    ));
    // The latch: a second close on any path emits nothing further.
    session.close(Close::Frame);
    assert!(session.outputs().is_empty());
    assert!(session.core.is_closed());
}

#[test]
fn feed_after_close_is_a_no_op() {
    let mut session = TestSession::new();
    session.close(Close::Local);
    session.outputs();
    session.handle_bytes(&frame(0x01));
    assert!(session.outputs().is_empty());
}

#[test]
fn dispatch_close_stops_the_loop_before_later_frames() {
    let mut session = TestSession::new();
    session.close_on_opcode = Some(0x01);
    let mut bytes = frame(0x01);
    bytes.extend_from_slice(&frame(0x02));
    session.handle_bytes(&bytes);
    let outputs = session.outputs();
    assert!(matches!(
        outputs[..],
        [
            SessionOutput::Event(Event::Packet { opcode: 0x01 }),
            SessionOutput::Event(Event::Disconnected(Close::Local)),
            SessionOutput::Close(Close::Local),
        ]
    ));
}

#[test]
fn frame_error_closes_through_the_session_mapping() {
    let mut session = TestSession::new();
    let mut bytes = frame(0x01);
    // A full header whose protocol byte 0x00 is no eD2k protocol:
    // frame error right after one good packet.
    bytes.extend_from_slice(&[0x00; 5]);
    session.handle_bytes(&bytes);
    let outputs = session.outputs();
    assert!(matches!(
        outputs[..],
        [
            SessionOutput::Event(Event::Packet { opcode: 0x01 }),
            SessionOutput::Event(Event::Disconnected(Close::Frame)),
            SessionOutput::Close(Close::Frame),
        ]
    ));
}
