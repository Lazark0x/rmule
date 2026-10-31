//! A socket its peer stopped reading, on a paused clock: the driver keeps
//! hearing the peer and the session, and ends the connection at its bound.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use crate::fixture::{ed2k_fixture, test_session};
use rmule_ed2k::{CloseReason, Ed2kCommand, Ed2kEvent};
use rmule_net::driver::{SendProgress, SendSide, WRITE_STALL_BOUND};
use rmule_net::ed2k::drive;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};
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

/// A socket the peer has filled, its send side read off a script the test
/// writes on the paused clock.
struct ScriptedSocket {
    pipe: DuplexStream,
    reading: Arc<Mutex<Option<SendProgress>>>,
}

impl SendSide for ScriptedSocket {
    fn send_progress(&self) -> Option<SendProgress> {
        *self.reading.lock().unwrap()
    }
}

impl AsyncRead for ScriptedSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.pipe).poll_read(cx, buf)
    }
}

impl AsyncWrite for ScriptedSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.pipe).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.pipe).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.pipe).poll_shutdown(cx)
    }
}

/// A driven link over a full socket, and what the test holds to script it.
struct StalledLink {
    reading: Arc<Mutex<Option<SendProgress>>>,
    peer: DuplexStream,
    events: mpsc::Receiver<Ed2kEvent>,
    _commands: mpsc::Sender<Ed2kCommand>,
}

impl StalledLink {
    fn drive(first: Option<SendProgress>) -> Self {
        let (pipe, peer) = full_pipe();
        let reading = Arc::new(Mutex::new(first));
        let socket = ScriptedSocket {
            pipe,
            reading: Arc::clone(&reading),
        };
        let (commands, cmd_rx) = mpsc::channel(4);
        let (evt_tx, events) = mpsc::channel(16);
        tokio::spawn(drive(test_session(), socket, cmd_rx, evt_tx));
        Self {
            reading,
            peer,
            events,
            _commands: commands,
        }
    }

    fn reads(&self, reading: Option<SendProgress>) {
        *self.reading.lock().unwrap() = reading;
    }

    /// Run until the link ends: how long that took from `began`.
    async fn ended(mut self, began: Instant) -> Duration {
        while let Ok(Some(event)) = timeout(NEVER, self.events.recv()).await {
            if matches!(
                event,
                Ed2kEvent::Disconnected {
                    reason: CloseReason::Io(io::ErrorKind::TimedOut)
                }
            ) {
                return began.elapsed();
            }
        }
        panic!("the link never timed out");
    }

    fn is_alive(&mut self) -> bool {
        while let Ok(event) = self.events.try_recv() {
            if matches!(event, Ed2kEvent::Disconnected { .. }) {
                return false;
            }
        }
        true
    }
}

/// The run behind this: 78,192 bytes left a full socket across 40 s in which
/// the write took none.
#[tokio::test(start_paused = true)]
async fn a_socket_whose_count_falls_outlives_the_bound_with_no_write_taken() {
    let mut link = StalledLink::drive(Some(SendProgress::Held(100_000)));

    tokio::time::sleep(WRITE_STALL_BOUND / 4).await;
    for step in 1..=5 {
        link.reads(Some(SendProgress::Held(100_000 - step * 1_000)));
        tokio::time::sleep(WRITE_STALL_BOUND / 2).await;
    }

    assert!(link.is_alive(), "the socket moved inside every bound");
}

#[tokio::test(start_paused = true)]
async fn a_socket_whose_count_stands_ends_at_the_bound() {
    let began = Instant::now();
    let link = StalledLink::drive(Some(SendProgress::Held(100_000)));

    assert_eq!(link.ended(began).await, WRITE_STALL_BOUND);
}

/// Windows answers the bytes acknowledged, which rise.
#[tokio::test(start_paused = true)]
async fn a_socket_whose_acked_count_rises_outlives_the_bound() {
    let mut link = StalledLink::drive(Some(SendProgress::Acked(5_000)));

    tokio::time::sleep(WRITE_STALL_BOUND / 2).await;
    link.reads(Some(SendProgress::Acked(6_000)));
    tokio::time::sleep(WRITE_STALL_BOUND).await;

    assert!(link.is_alive());
}

/// The drain that stops ends the link within one bound of the reading that
/// last saw it move.
#[tokio::test(start_paused = true)]
async fn a_drain_that_stops_ends_one_bound_after_the_last_fall() {
    let began = Instant::now();
    let link = StalledLink::drive(Some(SendProgress::Held(100_000)));

    tokio::time::sleep(WRITE_STALL_BOUND / 2).await;
    link.reads(Some(SendProgress::Held(90_000)));

    assert_eq!(link.ended(began).await, WRITE_STALL_BOUND * 2);
}

/// Its asks reach the session and leave the clock alone.
#[tokio::test(start_paused = true)]
async fn a_peer_that_asks_and_never_reads_still_ends_at_the_bound() {
    let began = Instant::now();
    let mut link = StalledLink::drive(Some(SendProgress::Held(100_000)));
    let ask = ed2k_fixture("server/server_message.bin");
    let mut peer = std::mem::replace(&mut link.peer, duplex(1).0);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(WRITE_STALL_BOUND / 8).await;
            peer.write_all(&ask).await.unwrap();
        }
    });

    assert_eq!(link.ended(began).await, WRITE_STALL_BOUND);
}

/// A socket that stops answering says nothing moved.
#[tokio::test(start_paused = true)]
async fn a_socket_that_loses_its_reading_ends_at_the_bound() {
    let began = Instant::now();
    let link = StalledLink::drive(Some(SendProgress::Held(100_000)));

    tokio::time::sleep(WRITE_STALL_BOUND / 2).await;
    link.reads(None);

    assert_eq!(link.ended(began).await, WRITE_STALL_BOUND);
}

/// One that never answered keeps the bound as it was.
#[tokio::test(start_paused = true)]
async fn a_socket_with_no_reading_ends_at_the_bound() {
    let began = Instant::now();
    let link = StalledLink::drive(None);

    assert_eq!(link.ended(began).await, WRITE_STALL_BOUND);
}
