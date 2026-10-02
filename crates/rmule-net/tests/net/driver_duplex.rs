//! The eD2k driver over a duplex pipe, fed the captured welcome burst: every
//! event reaches the caller in wire order, and a peer FIN after the welcome
//! synthesizes the server-closed disconnect the session itself never emits.

use crate::fixture::{ed2k_fixture, test_session};
use rmule_ed2k::{CloseReason, Ed2kCommand, Ed2kEvent};
use rmule_net::ed2k::drive;
use tokio::io::{AsyncWriteExt, duplex};
use tokio::sync::mpsc;

#[tokio::test(flavor = "current_thread")]
async fn welcome_burst_events_flow_through_the_driver_in_order() {
    let (client_io, mut server_io) = duplex(64 * 1024);
    let session = test_session();
    let (cmd_tx, cmd_rx) = mpsc::channel(16);
    let (evt_tx, mut evt_rx) = mpsc::channel(64);

    let driver = tokio::spawn(drive(session, client_io, cmd_rx, evt_tx));

    // Consume the LoginRequest bytes the driver writes.
    use tokio::io::AsyncReadExt;
    let mut login_buf = vec![0u8; 1024];
    let n = server_io.read(&mut login_buf).await.unwrap();
    assert!(n > 0, "driver should write the LoginRequest");

    // Server replies with IdChange + ServerMessage back to back.
    let mut s2c = Vec::new();
    s2c.extend_from_slice(&ed2k_fixture("login/id_change_with_tcp_flags.bin"));
    s2c.extend_from_slice(&ed2k_fixture("server/server_message.bin"));
    server_io.write_all(&s2c).await.unwrap();

    assert!(matches!(
        evt_rx.recv().await,
        Some(Ed2kEvent::LoginRequested { .. })
    ));
    assert!(matches!(
        evt_rx.recv().await,
        Some(Ed2kEvent::LoginAccepted { .. })
    ));
    assert!(matches!(
        evt_rx.recv().await,
        Some(Ed2kEvent::ServerMessageReceived { .. })
    ));

    cmd_tx.send(Ed2kCommand::Disconnect).await.unwrap();

    let Some(Ed2kEvent::Disconnected {
        reason: CloseReason::Local,
    }) = evt_rx.recv().await
    else {
        panic!("expected Disconnected(Local) after Disconnect command");
    };

    driver.await.unwrap().unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn peer_fin_after_welcome_synthesizes_disconnected_server_closed() {
    let (client_io, mut server_io) = duplex(64 * 1024);
    let session = test_session();
    let (_cmd_tx, cmd_rx) = mpsc::channel(1);
    let (evt_tx, mut evt_rx) = mpsc::channel(64);

    let driver = tokio::spawn(drive(session, client_io, cmd_rx, evt_tx));

    // Drain the LoginRequest the driver writes.
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; 1024];
    let _ = server_io.read(&mut buf).await.unwrap();

    // Reply with IdChange then drop the server side — simulates the peer
    // closing the TCP socket cleanly.
    server_io
        .write_all(&ed2k_fixture("login/id_change_with_tcp_flags.bin"))
        .await
        .unwrap();
    drop(server_io);

    let mut events = Vec::new();
    while let Some(event) = evt_rx.recv().await {
        events.push(event);
    }

    assert!(
        matches!(
            events.last(),
            Some(Ed2kEvent::Disconnected {
                reason: CloseReason::ServerClosed
            })
        ),
        "last event should be Disconnected(ServerClosed); got {events:?}"
    );

    driver.await.unwrap().unwrap();
}
