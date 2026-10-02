//! The login deadline: while login is pending it closes the session with
//! `LoginTimeout`; once login resolves it is a no-op.

use rmule_ed2k::{CloseReason, Output};
use rmule_primitives::session::drain;

#[test]
fn login_deadline_closes_with_login_timeout_while_pending() {
    let mut s = crate::fixture::session(0);
    s.start();
    drain(|| s.poll_output()); // drain LoginRequested + LoginRequest write

    s.login_deadline_elapsed();

    let saw_close = drain(|| s.poll_output())
        .iter()
        .any(|output| matches!(output, Output::Close(CloseReason::LoginTimeout)));
    assert!(
        saw_close,
        "login_deadline_elapsed must Close(LoginTimeout) while login is pending"
    );
}

#[test]
fn login_deadline_is_noop_after_login_resolves() {
    let id_change = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/login/id_change_with_tcp_flags.bin"
    ))
    .unwrap();

    let mut s = crate::fixture::session(0);
    s.start();
    s.handle_bytes(&id_change); // IdChange → LoggedIn
    drain(|| s.poll_output());

    s.login_deadline_elapsed();
    assert!(
        s.poll_output().is_none(),
        "after login resolves, login_deadline_elapsed must be a no-op"
    );
}
