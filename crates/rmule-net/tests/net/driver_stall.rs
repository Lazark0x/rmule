//! A socket its peer stopped reading, on a paused clock: the driver keeps
//! hearing the peer and the session, and ends the connection at its bound.

use std::time::Duration;

use crate::fixture::{ed2k_fixture, test_session};
use rmule_ed2k::{CloseReason, Ed2kCommand, Ed2kEvent};
use rmule_net::driver::WRITE_STALL_BOUND;
use rmule_net::ed2k::drive;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout};

/// Far past the bound on the paused clock: a driver that waits it out fails.
const NEVER: Duration = Duration::from_secs(4000);

/// A pipe of one byte, so the login in flight fills it.
fn full_pipe() -> (DuplexStream, DuplexStream) {
    duplex(1)
}

#[tokio::test(start_paused = true)]
async fn a_socket_nobody_reads_ends_at_the_stall_bound() {
    let (client_io, _nobody_reads) = full_pipe();
    let (_cmd_tx, cmd_rx) = mpsc::channel(4);
    let (evt_tx, mut evt_rx) = mpsc::channel(16);
    let began = Instant::now();
    let driver = tokio::spawn(drive(test_session(), client_io, cmd_rx, evt_tx));

    let mut last = None;
    while let Ok(Some(event)) = timeout(NEVER, evt_rx.recv()).await {
        last = Some(event);
    }

    assert!(
        matches!(
            last,
            Some(Ed2kEvent::Disconnected {
                reason: CloseReason::Io(std::io::ErrorKind::TimedOut)
            })
        ),
        "a stuck write ends the link and says so: {last:?}",
    );
    assert_eq!(began.elapsed(), WRITE_STALL_BOUND);
    assert!(driver.await.unwrap().is_err());
}

/// A byte every thirty seconds is slow, not stuck.
#[tokio::test(start_paused = true)]
async fn a_slow_reader_outlasts_the_bound_while_bytes_move() {
    let (client_io, mut slow_reader) = full_pipe();
    let (_cmd_tx, cmd_rx) = mpsc::channel(4);
    let (evt_tx, mut evt_rx) = mpsc::channel(16);
    tokio::spawn(drive(test_session(), client_io, cmd_rx, evt_tx));
    let mut byte = [0];

    for _ in 0..4 {
        tokio::time::sleep(Duration::from_secs(30)).await;
        slow_reader.read_exact(&mut byte).await.unwrap();
    }

    while let Ok(event) = evt_rx.try_recv() {
        assert!(!matches!(event, Ed2kEvent::Disconnected { .. }));
    }
}

#[tokio::test(start_paused = true)]
async fn a_stuck_write_still_hears_the_peer() {
    let (client_io, mut peer) = full_pipe();
    let (_cmd_tx, cmd_rx) = mpsc::channel(4);
    let (evt_tx, mut evt_rx) = mpsc::channel(16);
    tokio::spawn(drive(test_session(), client_io, cmd_rx, evt_tx));

    // The peer has read none of the login and answers anyway.
    let answer = [
        ed2k_fixture("login/id_change_with_tcp_flags.bin"),
        ed2k_fixture("server/server_message.bin"),
    ]
    .concat();
    tokio::spawn(async move {
        peer.write_all(&answer).await.unwrap();
        peer
    });

    let accepted = async {
        loop {
            match evt_rx.recv().await {
                Some(Ed2kEvent::LoginAccepted { .. }) => break,
                Some(_) => {}
                None => panic!("the link ended"),
            }
        }
    };
    timeout(WRITE_STALL_BOUND / 2, accepted)
        .await
        .expect("the driver read past its stuck write");
}

/// Nobody takes events, and the writes go on: a consumer that also waits on
/// this driver to take its command would otherwise wait on itself.
#[tokio::test(flavor = "current_thread")]
async fn a_full_event_channel_holds_no_write_back() {
    let (client_io, mut peer) = duplex(64 * 1024);
    let (cmd_tx, cmd_rx) = mpsc::channel(4);
    let (evt_tx, mut _unread) = mpsc::channel(1);
    tokio::spawn(drive(test_session(), client_io, cmd_rx, evt_tx));
    let mut login = [0; 1024];
    let _ = peer.read(&mut login).await.unwrap();

    // Fill the event channel past its one place from the wire.
    peer.write_all(
        &[
            ed2k_fixture("login/id_change_with_tcp_flags.bin"),
            ed2k_fixture("server/server_message.bin"),
        ]
        .concat(),
    )
    .await
    .unwrap();
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }

    timeout(
        Duration::from_secs(5),
        cmd_tx.send(Ed2kCommand::RequestServerList),
    )
    .await
    .expect("the driver took the command")
    .unwrap();
    let mut sent = [0; 64];
    let read = timeout(Duration::from_secs(5), peer.read(&mut sent)).await;
    assert!(
        read.expect("the command went out with events unread")
            .unwrap()
            > 0
    );
}
