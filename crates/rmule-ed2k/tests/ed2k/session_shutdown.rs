//! Shutting a session down: a local disconnect emits the event before the
//! close, and a second `OP_IDCHANGE` re-assigns our id instead of closing.

use rmule_ed2k::{CloseReason, Ed2kCommand, Ed2kEvent, Output};
use rmule_primitives::session::drain;

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

    // The session is still live: a disconnect still runs its ordered pair.
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
