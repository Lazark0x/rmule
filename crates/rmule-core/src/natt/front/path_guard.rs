//! The **Punched Path Guard**: the wrapper that tells the NAT-T front when a
//! tunnel it handed away is finished with.
//!
//! Once a risen [`Tunnel`](rmule_net::natt::Tunnel) enters the serve pipeline
//! the front no longer holds it — the peer session does, and the session's end
//! is not an event the front can see. But the front still owns the ledgers
//! that path is in: its keepalive, and the tunnel registry entry that decides
//! whether a late datagram from that endpoint is injected or dropped.
//!
//! So the tunnel travels inside this guard, which is exactly the stream it
//! wraps plus one notice on `Drop`. The notice is the only correct signal
//! available: the dialect has no close frame, and a peer session that ends for
//! *any* reason — hello timeout, disconnect, the whole activity winding down —
//! drops its stream.

use std::pin::Pin;
use std::task::{Context, Poll};

use rmule_primitives::Ipv4Endpoint;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use super::Risen;

/// One open stream over a punched path, plus the front's closed-notice half.
pub(super) struct PunchedPathGuard<S> {
    stream: S,
    at: Ipv4Endpoint,
    front: mpsc::Sender<Risen>,
}

impl<S> PunchedPathGuard<S> {
    /// Wrap `stream`, which rides the punched path to `at`.
    pub(super) const fn new(stream: S, at: Ipv4Endpoint, front: mpsc::Sender<Risen>) -> Self {
        Self { stream, at, front }
    }
}

impl<S> Drop for PunchedPathGuard<S> {
    /// `try_send` because a `Drop` cannot await, and a lost notice costs only
    /// a keepalive on a path nothing uses any more — the 60 s keepalive bounds
    /// it, and the registry slot is freed by the `Tunnel` itself on drop.
    fn drop(&mut self) {
        let _ = self.front.try_send(Risen::Closed { at: self.at });
    }
}

// The three delegations are written out rather than derived: `S: Unpin` makes
// each one a `Pin::new` over the field, and a projection macro would add a
// dependency to hide four lines.
impl<S: AsyncRead + Unpin> AsyncRead for PunchedPathGuard<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PunchedPathGuard<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
