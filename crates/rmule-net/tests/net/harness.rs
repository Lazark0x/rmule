//! The generic driver contract against a deterministic fake session, where
//! every close path can be provoked on demand: `start` writes the handshake,
//! a session-emitted `Disconnected` is never doubled by the driver's own,
//! peer EOF synthesizes one, and an elapsed deadline closes the session.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use rmule_net::driver::{DrivenSession, DriverOutput, run_driver};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::sync::mpsc;

#[derive(Debug, PartialEq, Eq)]
enum FakeEvent {
    Hello,
    Got(u8),
    Resolved,
    Bye(FakeReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FakeReason {
    Done,
    Eof,
    Io,
    Deadline,
}

/// Deterministic session mirroring the real close contract: `start` writes
/// `HELLO`; a `1` byte emits an event, `9` resolves the deadline, and any
/// other byte — like a command close or an elapsed deadline — emits the
/// session's own paired `Disconnected` then `Close`. Driver-originated EOF
/// and I/O closes are synthesized by the harness itself.
#[derive(Default)]
struct Fake {
    out: VecDeque<DriverOutput<FakeEvent, FakeReason>>,
}

impl Fake {
    /// Queue the session's own paired `Disconnected` then `Close` — the same
    /// terminal sequence every real session emits on a session-originated
    /// close.
    fn close(&mut self, reason: FakeReason) {
        self.out
            .push_back(DriverOutput::Event(FakeEvent::Bye(reason)));
        self.out.push_back(DriverOutput::Close(reason));
    }
}

impl DrivenSession for Fake {
    type Command = ();
    type Event = FakeEvent;
    type CloseReason = FakeReason;

    fn start(&mut self) {
        self.out.push_back(DriverOutput::Event(FakeEvent::Hello));
        self.out
            .push_back(DriverOutput::Write(Arc::from(&b"HELLO"[..])));
    }
    fn handle_command(&mut self, _command: ()) {
        self.close(FakeReason::Done);
    }
    fn handle_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            match b {
                1 => self.out.push_back(DriverOutput::Event(FakeEvent::Got(b))),
                9 => self.out.push_back(DriverOutput::Event(FakeEvent::Resolved)),
                _ => self.close(FakeReason::Done),
            }
        }
    }
    fn poll_output(&mut self) -> Option<DriverOutput<FakeEvent, FakeReason>> {
        self.out.pop_front()
    }
    fn disconnect_command() {}
    fn deadline_elapsed(&mut self) {
        self.close(FakeReason::Deadline);
    }
    fn resolves_deadline(event: &FakeEvent) -> bool {
        matches!(event, FakeEvent::Resolved)
    }
    fn disconnected_event(reason: FakeReason) -> FakeEvent {
        FakeEvent::Bye(reason)
    }
    fn close_label(reason: &FakeReason) -> &'static str {
        match reason {
            FakeReason::Done => "Done",
            FakeReason::Eof => "Eof",
            FakeReason::Io => "Io",
            FakeReason::Deadline => "Deadline",
        }
    }
    fn eof_close_reason() -> FakeReason {
        FakeReason::Eof
    }
    fn io_close_reason(_kind: std::io::ErrorKind) -> FakeReason {
        FakeReason::Io
    }
}

fn spawn_fake(
    deadline: Option<Duration>,
) -> (
    tokio::io::DuplexStream,
    mpsc::Sender<()>,
    mpsc::Receiver<FakeEvent>,
) {
    let (ours, theirs) = duplex(4096);
    let (cmd_tx, cmd_rx) = mpsc::channel(4);
    let (evt_tx, evt_rx) = mpsc::channel(16);
    tokio::spawn(run_driver::<Fake, _>(
        Fake::default(),
        ours,
        cmd_rx,
        evt_tx,
        deadline,
        None,
    ));
    (theirs, cmd_tx, evt_rx)
}

#[tokio::test]
async fn start_writes_handshake_and_forwards_events() {
    let (mut peer, cmd_tx, mut evt_rx) = spawn_fake(None);

    // The handshake write reaches the socket.
    let mut buf = vec![0u8; 8];
    let n = peer.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"HELLO");

    assert_eq!(evt_rx.recv().await, Some(FakeEvent::Hello));

    peer.write_all(&[1]).await.unwrap();
    assert_eq!(evt_rx.recv().await, Some(FakeEvent::Got(1)));

    drop(cmd_tx); // command channel close → disconnect_command → Bye(Done) + Close(Done)
    assert_eq!(evt_rx.recv().await, Some(FakeEvent::Bye(FakeReason::Done)));
    assert_eq!(evt_rx.recv().await, None);
}

#[tokio::test]
async fn session_emitted_disconnected_is_not_doubled() {
    let (mut peer, _cmd_tx, mut evt_rx) = spawn_fake(None);
    let _ = evt_rx.recv().await; // Hello
    let mut hello = vec![0u8; 8];
    let _ = peer.read(&mut hello).await.unwrap();

    peer.write_all(&[0]).await.unwrap(); // session emits Bye event THEN Close

    let mut byes = 0;
    while let Some(e) = evt_rx.recv().await {
        if matches!(e, FakeEvent::Bye(_)) {
            byes += 1;
        }
    }
    assert_eq!(byes, 1, "session-emitted Disconnected must not be doubled");
}

#[tokio::test]
async fn peer_eof_synthesizes_disconnected() {
    let (peer, _cmd_tx, mut evt_rx) = spawn_fake(None);
    let _ = evt_rx.recv().await; // Hello
    drop(peer); // EOF on read

    let mut last = None;
    while let Some(e) = evt_rx.recv().await {
        last = Some(e);
    }
    assert_eq!(last, Some(FakeEvent::Bye(FakeReason::Eof)));
}

#[tokio::test(start_paused = true)]
async fn deadline_drives_session_close() {
    let (_peer, _cmd_tx, mut evt_rx) = spawn_fake(Some(Duration::from_millis(50)));
    let _ = evt_rx.recv().await; // Hello
    tokio::time::advance(Duration::from_millis(51)).await;

    let mut last = None;
    while let Some(e) = evt_rx.recv().await {
        last = Some(e);
    }
    assert_eq!(
        last,
        Some(FakeEvent::Bye(FakeReason::Deadline)),
        "deadline notifies the session, which emits its own Close"
    );
}
