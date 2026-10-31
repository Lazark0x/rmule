//! Shutting a session down: a local disconnect emits the event before the
//! close, and a second `OP_IDCHANGE`, an `OP_REJECT` or a malformed source
//! answer leaves the session up.

use rmule_ed2k::{CloseReason, Ed2kCommand, Ed2kEvent, Opcode, Output};
use rmule_primitives::session::drain;
use rmule_primitives::{Packet, PacketProtocol};

fn frame(opcode: Opcode, payload: Vec<u8>) -> Vec<u8> {
    Packet::new(PacketProtocol::Edonkey, opcode.as_u8(), payload).encode()
}

/// A disconnect still runs its ordered pair: the session was live.
fn assert_still_live(session: &mut rmule_ed2k::Ed2kSession) {
    session.handle_command(Ed2kCommand::Disconnect);
    assert!(matches!(
        drain(|| session.poll_output()).as_slice(),
        [
            Output::Event(Ed2kEvent::Disconnected {
                reason: CloseReason::Local,
            }),
            Output::Close(CloseReason::Local),
        ]
    ));
}

/// `OP_REJECT` after the login discards one command, not the link (stock
/// 2.3.3 `ServerSocket.cpp:599-603`): closing would re-login and send every
/// offer and source ask again.
#[test]
fn a_reject_after_login_says_so_and_keeps_the_session() {
    let mut session = crate::fixture::logged_in_session(0);

    session.handle_bytes(&frame(Opcode::Reject, Vec::new()));

    let outputs = drain(|| session.poll_output());
    assert!(
        matches!(
            outputs.as_slice(),
            [Output::Event(Ed2kEvent::ServerRejectedCommand)]
        ),
        "{outputs:?}"
    );
    assert_still_live(&mut session);
}

/// Before the id there is no session to keep: the refusal stays typed.
#[test]
fn a_reject_before_the_id_ends_the_login() {
    let mut session = crate::fixture::started_session(0);

    session.handle_bytes(&frame(Opcode::Reject, Vec::new()));

    let outputs = drain(|| session.poll_output());
    assert!(
        matches!(
            outputs.as_slice(),
            [
                Output::Event(Ed2kEvent::LoginRejected),
                ..,
                Output::Close(CloseReason::LoginRejected)
            ]
        ),
        "{outputs:?}"
    );
}

/// "Don't disconnect because of wrong sources" (stock 2.3.3
/// `ServerSocket.cpp:617-619`), under either source opcode.
#[test]
fn a_malformed_source_answer_is_skipped_and_keeps_the_session() {
    for opcode in [Opcode::FoundSources, Opcode::FoundSourcesObfu] {
        let mut session = crate::fixture::logged_in_session(0);

        session.handle_bytes(&frame(opcode, vec![0xAB; 3]));

        let outputs = drain(|| session.poll_output());
        assert!(
            matches!(
                outputs.as_slice(),
                [Output::Event(Ed2kEvent::FoundSourcesSkipped { .. })]
            ),
            "{outputs:?}"
        );
        assert_still_live(&mut session);
    }
}

#[test]
fn local_disconnect_emits_disconnected_event_then_close() {
    let mut session = crate::fixture::logged_in_session(0);

    session.handle_command(Ed2kCommand::Disconnect);

    // Order matters: consumers see Disconnected on the event channel before
    // the driver observes Close and tears the socket down — the drained
    // sequence is exactly that terminal pair, nothing after.
    assert!(matches!(
        drain(|| session.poll_output()).as_slice(),
        [
            Output::Event(Ed2kEvent::Disconnected {
                reason: CloseReason::Local,
            }),
            Output::Close(CloseReason::Local),
        ]
    ));
}

#[test]
fn second_id_change_re_assigns_instead_of_closing() {
    // aMule re-runs the whole OP_IDCHANGE handler mid-session (ADR-0047,
    // LowID↔HighID transitions): the session must re-emit LoginAccepted
    // with the fresh assignment and keep running, not close as the former
    // DoubleIdChange violation did.
    let mut session = crate::fixture::logged_in_session(0);

    session.handle_bytes(&crate::fixture::bytes("login/id_change_with_tcp_flags.bin"));

    let outputs = drain(|| session.poll_output());
    assert!(
        matches!(
            outputs.as_slice(),
            [Output::Event(Ed2kEvent::LoginAccepted { .. })]
        ),
        "re-assignment re-emits LoginAccepted and nothing terminal: {outputs:?}"
    );

    assert_still_live(&mut session);
}
