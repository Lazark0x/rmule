//! A failing write under the eD2k driver: the handshake write cannot land, and
//! the driver synthesizes the terminal I/O disconnect rather than hanging or
//! dropping the failure silently.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::fixture::test_session;
use rmule_ed2k::{CloseReason, Ed2kEvent};
use rmule_net::ed2k::drive;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

/// Reads block forever; the first write fails — so the handshake write
/// (LoginRequest) fails in the initial drain.
struct FailWriter;

impl AsyncRead for FailWriter {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for FailWriter {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "boom")))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn write_error_synthesizes_terminal_disconnected_io() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(4);
    let (evt_tx, mut evt_rx) = mpsc::channel(16);
    let driver = tokio::spawn(drive(test_session(), FailWriter, cmd_rx, evt_tx));

    // Consumer must observe a terminal Disconnected{Io} — not silence —
    // even though the failure is a write, not a read.
    let mut last = None;
    while let Some(event) = evt_rx.recv().await {
        last = Some(event);
    }
    assert!(
        matches!(
            last,
            Some(Ed2kEvent::Disconnected {
                reason: CloseReason::Io(_)
            })
        ),
        "write failure must synthesize a terminal Disconnected{{Io}}; got {last:?}"
    );
    assert!(
        driver.await.unwrap().is_err(),
        "driver returns the write error"
    );
}
