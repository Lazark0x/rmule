//! The **Tunnel**: the reliable stream a punched UDP path carries, and the
//! whole point of the seam.
//!
//! A `Tunnel` is `AsyncRead + AsyncWrite + Unpin + Send` — exactly the bound
//! [`spawn_connection`](crate::driver::spawn_connection) already takes — so an
//! unmodified `PeerSession`, an unmodified `CryptStream` and the unmodified
//! capture tap run inside it. Nothing above this type knows a tunnel exists:
//! hello, SecIdent, file requests and block transfer are byte-for-byte what
//! they are over TCP, which is the same layering eMuleAI gets from attaching
//! its uTP socket *beneath* `CEMSocket`.
//!
//! Two engines, one stream type. uTP hands over `librqbit-utp`'s own
//! `UtpStream`; QUIC hands over the application half of a duplex the QUIC
//! driver task owns, so the 37-byte `EAQN1` proof gate lives inside the task
//! and not one byte crosses this type until it is accepted.

use std::pin::Pin;
use std::task::{Context, Poll};

use rmule_primitives::PeerEndpoint;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::registry::HeldSlot;
use crate::peer::PeerStreamRole;

/// The reliable stream over a punched path.
///
/// It owns its endpoint's **Tunnel Registry** slot: dropping the tunnel, for
/// any reason and in any family, is what ends the endpoint's admission.
pub struct Tunnel {
    peer: PeerEndpoint,
    transport: TunnelTransport,
    role: PeerStreamRole,
    stream: TunnelStream,
    /// Declared after `stream` so it drops after it: the stream's close is
    /// handed to its engine before the endpoint stops being admitted.
    _slot: HeldSlot,
}

/// Which engine raised a tunnel — carried for diagnostics and for the QUIC
/// blacklist, which is keyed on a *failed transport at an endpoint*.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelTransport {
    /// BEP-29 uTP under `0xB2 0x00`.
    Utp,
    /// QUIC under `0xB2 0x01`.
    Quic,
}

enum TunnelStream {
    Utp(librqbit_utp::UtpStream),
    /// The application half of the QUIC driver task's duplex. The task owns the
    /// other half and writes into it only after the proof is accepted.
    Quic(tokio::io::DuplexStream),
}

impl Tunnel {
    /// Wrap a live uTP stream.
    #[must_use]
    pub(crate) fn utp(
        peer: PeerEndpoint,
        role: PeerStreamRole,
        stream: librqbit_utp::UtpStream,
        slot: HeldSlot,
    ) -> Self {
        Self {
            peer,
            transport: TunnelTransport::Utp,
            role,
            stream: TunnelStream::Utp(stream),
            _slot: slot,
        }
    }

    /// Wrap the application half of a QUIC tunnel.
    #[must_use]
    pub(crate) fn quic(
        peer: PeerEndpoint,
        role: PeerStreamRole,
        stream: tokio::io::DuplexStream,
        slot: HeldSlot,
    ) -> Self {
        Self {
            peer,
            transport: TunnelTransport::Quic,
            role,
            stream: TunnelStream::Quic(stream),
            _slot: slot,
        }
    }

    /// The endpoint on the far side — what the session inside is talking to,
    /// and the key every registry and blacklist uses.
    #[must_use]
    pub const fn peer(&self) -> PeerEndpoint {
        self.peer
    }

    /// Which engine raised this tunnel.
    #[must_use]
    pub const fn transport(&self) -> TunnelTransport {
        self.transport
    }

    /// Which side opened it — and therefore which side's hello goes first.
    #[must_use]
    pub const fn role(&self) -> PeerStreamRole {
        self.role
    }
}

impl AsyncRead for Tunnel {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().stream {
            TunnelStream::Utp(stream) => Pin::new(stream).poll_read(cx, buf),
            TunnelStream::Quic(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Tunnel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut self.get_mut().stream {
            TunnelStream::Utp(stream) => Pin::new(stream).poll_write(cx, buf),
            TunnelStream::Quic(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().stream {
            TunnelStream::Utp(stream) => Pin::new(stream).poll_flush(cx),
            TunnelStream::Quic(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().stream {
            TunnelStream::Utp(stream) => Pin::new(stream).poll_shutdown(cx),
            TunnelStream::Quic(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}
