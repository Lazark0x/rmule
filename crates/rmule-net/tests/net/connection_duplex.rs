//! The eD2k `Connection` handle over a duplex pipe — no socket, no DNS: it
//! surfaces the session's events and shuts down cleanly, dropping it aborts
//! the driver without a panic, and a shutdown wins against a server that
//! never stops pushing bytes.

use crate::fixture::{ed2k_fixture, test_session};
use rmule_ed2k::Ed2kEvent;
use rmule_net::ed2k::Connection;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

#[tokio::test(flavor = "current_thread")]
async fn connection_handle_surfaces_events_and_shuts_down_cleanly() {
    let (client_io, mut server_io) = duplex(64 * 1024);
    let mut conn = Connection::spawn_with_stream(test_session(), client_io);

    // Drain login bytes server-side, reply with IdChange so the session
    // reaches LoggedIn.
    let mut buf = vec![0u8; 1024];
    let _ = server_io.read(&mut buf).await.unwrap();
    server_io
        .write_all(&ed2k_fixture("login/id_change_with_tcp_flags.bin"))
        .await
        .unwrap();

    assert!(matches!(
        conn.next_event().await,
        Some(Ed2kEvent::LoginRequested { .. })
    ));
    assert!(matches!(
        conn.next_event().await,
        Some(Ed2kEvent::LoginAccepted { .. })
    ));

    conn.shutdown().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_connection_aborts_driver_without_panic() {
    let (client_io, _server_io) = duplex(64 * 1024);
    let conn = Connection::spawn_with_stream(test_session(), client_io);
    drop(conn);
    // Yield so the runtime processes the abort; passes if no panic / no
    // hung task.
    tokio::task::yield_now().await;
}

#[tokio::test(flavor = "current_thread")]
async fn shutdown_wins_against_a_chatty_server_pushing_bytes_nonstop() {
    // Regression guard for the driver's command/read arbitration: a server
    // that keeps the read arm permanently ready must not starve a queued
    // `Disconnect` past `SHUTDOWN_GRACE` (which would also lose capture
    // finalization) — `shutdown()` must return promptly regardless.
    let (client_io, mut server_io) = duplex(64 * 1024);
    let conn = Connection::spawn_with_stream(test_session(), client_io);

    // Spawn a "chatty server" task that keeps writing garbage to the
    // server side. The session will reject the bytes at the frame layer
    // and close itself with `ProtocolViolation`, but the test isn't
    // about that path — it's about the *shutdown command* being
    // delivered. Use a large constant burst so the read arm is
    // continuously ready while we negotiate shutdown.
    let chatty = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        // Bytes have valid 0xE3 protocol byte + huge length so the
        // decoder reports `TruncatedPacket` and keeps buffering rather
        // than closing — keeps the read arm busy without instantly
        // ending the session.
        let mut chunk = vec![0u8; 8192];
        chunk[0] = 0xE3;
        chunk[1] = 0xFF;
        chunk[2] = 0xFF;
        chunk[3] = 0x00;
        chunk[4] = 0x00;
        loop {
            if server_io.write_all(&chunk).await.is_err() {
                break;
            }
        }
    });

    // Give the driver a couple of poll cycles so it definitely starts
    // pumping the read arm, then issue shutdown.
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    // With cmd-first biased select, this must return within the 2 s
    // grace; pre-fix it would hang.
    let result = conn.shutdown().await;
    assert!(
        result.is_ok(),
        "shutdown should not be starved by chatty server reads: {result:?}"
    );

    chatty.abort();
}
