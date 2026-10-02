//! The server punch through a live session (ADR-0091): the command becomes
//! the `0x60` on the wire, and the server's answers become events a caller
//! can attribute.

use std::net::Ipv4Addr;

use rmule_ed2k::{
    CommandRejectReason, Ed2kCommand, Ed2kCommandKind, Ed2kEvent, HolepunchFail,
    HolepunchFailReason, HolepunchInfo, HolepunchRole, Output,
};
use rmule_primitives::{ClientId, Ipv4Endpoint, UserHash};

use crate::fixture;

fn ask(target: u32) -> Ed2kCommand {
    Ed2kCommand::RequestHolepunch {
        target: ClientId::from_u32(target),
        our_udp_port: 4665,
    }
}

/// Logged in, the command is exactly the six-byte `0x60` frame. Before login
/// it is refused locally and nothing reaches the wire — a `0x60` ahead of the
/// login would be the first frame a server parses, and no server reads it as
/// one.
#[test]
fn a_holepunch_request_goes_out_only_once_logged_in() {
    let mut early = fixture::started_session(7);
    early.handle_command(ask(1337));
    assert!(matches!(
        early.poll_output(),
        Some(Output::Event(Ed2kEvent::CommandRejected {
            command: Ed2kCommandKind::RequestHolepunch,
            reason: CommandRejectReason::NotLoggedIn,
        }))
    ));
    assert!(early.poll_output().is_none(), "nothing was written");

    let mut session = fixture::logged_in_session(7);
    session.handle_command(ask(1337));
    let Some(Output::Write(bytes)) = session.poll_output() else {
        panic!("the request is a write");
    };
    assert_eq!(
        &bytes[..],
        [
            0xE3, 0x07, 0x00, 0x00, 0x00, 0x60, 0x39, 0x05, 0x00, 0x00, 0x39, 0x12
        ]
    );
}

/// An introduction arrives whether we asked or the peer did, and a refusal
/// names its target — unlike `OP_CALLBACK_FAIL`, whose empty body cannot be
/// matched to an attempt. A repeat of the same INFO is delivered again, not
/// swallowed: the session holds no attempt state to dedupe against, so that
/// is the consumer's job and the event says so.
#[test]
fn the_servers_answers_surface_as_attributable_events() {
    let mut session = fixture::logged_in_session(7);
    let info = HolepunchInfo {
        peer_udp: Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 7), 31999),
        peer_tcp_port: 4662,
        peer_hash: UserHash::from_bytes([0x44; 16]),
        role: HolepunchRole::Initiator,
    };
    let wire = info.encode_packet().encode();
    for _ in 0..2 {
        session.handle_bytes(&wire);
        let Some(Output::Event(Ed2kEvent::HolepunchIntroduced { info: got })) =
            session.poll_output()
        else {
            panic!("an introduction is an event");
        };
        assert_eq!(got, info);
    }

    let fail = HolepunchFail {
        target: ClientId::from_u32(1337),
        reason: HolepunchFailReason::TargetNoUdp,
    };
    session.handle_bytes(&fail.encode_packet().encode());
    let Some(Output::Event(Ed2kEvent::HolepunchRefused { fail: got })) = session.poll_output()
    else {
        panic!("a refusal is an event");
    };
    assert_eq!(got, fail);
}
