//! The login deadline on an eD2k `Connection`: it fires when the server never
//! answers the login, and it stays silent once the login has resolved.

use std::time::Duration;

use crate::fixture::test_session;
use rmule_ed2k::{CloseReason, Ed2kEvent};
use rmule_net::ed2k::{ConnectOptions, Connection};
use tokio::io::{AsyncReadExt, duplex};

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn login_timeout_fires_when_server_never_replies() {
    let (client_io, mut server_io) = duplex(64 * 1024);
    let options = ConnectOptions {
        login_timeout: Duration::from_millis(100),
        ..ConnectOptions::default()
    };
    let mut conn = Connection::spawn_with_options(test_session(), client_io, options);

    // Read (and discard) the LoginRequest from the server side, but do
    // not reply. The driver's login deadline must fire after 100 ms.
    let mut buf = vec![0u8; 1024];
    let _ = server_io.read(&mut buf).await.unwrap();

    let _ = conn.next_event().await; // LoginRequested
    // Advance the paused clock past the deadline; the next event must
    // be the synthesized Disconnected.
    tokio::time::advance(Duration::from_millis(101)).await;

    let Some(Ed2kEvent::Disconnected {
        reason: CloseReason::LoginTimeout,
    }) = conn.next_event().await
    else {
        panic!("expected Disconnected(LoginTimeout)");
    };
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn login_timeout_does_not_fire_after_login_resolves() {
    use tokio::io::AsyncWriteExt;

    let id_change = crate::fixture::ed2k_fixture("login/id_change_with_tcp_flags.bin");

    let (client_io, mut server_io) = duplex(64 * 1024);
    let options = ConnectOptions {
        login_timeout: Duration::from_millis(150),
        ..ConnectOptions::default()
    };
    let mut conn = Connection::spawn_with_options(test_session(), client_io, options);

    let mut buf = vec![0u8; 1024];
    let _ = server_io.read(&mut buf).await.unwrap();
    server_io.write_all(&id_change).await.unwrap();

    let _ = conn.next_event().await; // LoginRequested
    assert!(matches!(
        conn.next_event().await,
        Some(Ed2kEvent::LoginAccepted { .. })
    ));

    // Advance the paused clock well past what would have been the
    // login deadline. With paused time the auto-advance machinery only
    // moves the clock when no other futures are ready; combine with
    // `timeout` so the assertion stays deterministic regardless.
    tokio::time::advance(Duration::from_secs(60)).await;
    let next = tokio::time::timeout(Duration::from_secs(1), conn.next_event()).await;
    assert!(next.is_err(), "expected no further events; got {next:?}");
}
