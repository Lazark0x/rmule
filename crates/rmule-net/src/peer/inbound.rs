//! The **Inbound Source** seam (ADR-0085): where an accepted peer connection
//! comes from, and the one-byte push-back that lets ADR-0042's byte-0
//! discrimination work on *any* stream rather than only a `TcpStream`.
//!
//! `TcpStream::peek` reads without consuming, which is convenient and
//! socket-specific. Pushing the byte back instead keeps the discrimination
//! honest on a stream the anonymous overlay (or a test) hands over, so the
//! accept path is not welded to one transport.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rmule_primitives::PeerEndpoint;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A stream whose first byte was read and put back: the next read sees it
/// again, then the underlying stream continues untouched. `None` pushes
/// nothing — a peer that closed before its first byte has no byte to give
/// back, and inventing one would feed the session a byte that never arrived.
pub struct PushBack<S> {
    inner: S,
    pushed: Option<u8>,
}

impl<S> PushBack<S> {
    /// Wrap `inner`, holding `pushed` to hand back before anything it reads.
    #[must_use]
    pub const fn new(inner: S, pushed: Option<u8>) -> Self {
        Self { inner, pushed }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PushBack<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(byte) = self.pushed {
            // A zero-capacity read cannot take the pushed byte; leave it for
            // the next call rather than reporting a read that moved nothing.
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            self.pushed = None;
            buf.put_slice(&[byte]);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PushBack<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Where inbound peer connections come from. The accept loop is a *source* of
/// streams plus the endpoint each dialer came from, so core's triage does not
/// care whether a connection arrived on the IPv4 listener, the IPv6 one, or
/// some later transport that is not a socket at all.
pub trait InboundSource: Send + Sync {
    /// The accepted stream type.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Await the next inbound connection.
    fn accept(&self) -> impl Future<Output = io::Result<(Self::Stream, PeerEndpoint)>> + Send;
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;

    #[tokio::test]
    async fn the_pushed_byte_is_read_first_then_the_stream_continues() {
        let stream = std::io::Cursor::new(b"\x02\x03".to_vec());
        let mut pushed = PushBack::new(stream, Some(0x01));

        let mut out = Vec::new();
        pushed.read_to_end(&mut out).await.expect("read");
        assert_eq!(out, [0x01, 0x02, 0x03]);

        // Nothing pushed: the stream reads exactly what it holds.
        let mut bare = PushBack::new(std::io::Cursor::new(b"\x02".to_vec()), None);
        let mut out = Vec::new();
        bare.read_to_end(&mut out).await.expect("read");
        assert_eq!(out, [0x02]);
    }
}
