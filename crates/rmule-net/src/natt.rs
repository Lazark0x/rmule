//! **NAT-T transport** (ADR-0091): the `0xB2` demux on the client-UDP **Family
//! Pair**, the uTP and QUIC engines behind it, and the [`Tunnel`] an ordinary
//! peer session runs inside.
//!
//! Two firewalled peers cannot reach each other on the eD2k network. The field's
//! answer is to punch a hole with simultaneous datagrams and then raise a
//! reliable transport over the pinhole, and this module is that second half —
//! the transport. The introduction that produces the pinhole (rendezvous, punch,
//! endpoint hint) is the rendezvous layer's (`rmule_peer::natt`) and lives
//! under `0xC5`.
//!
//! # What makes it fit under an unmodified peer session
//!
//! [`Tunnel`] is `AsyncRead + AsyncWrite + Unpin + Send`, which is exactly the
//! bound [`spawn_connection`](crate::driver::spawn_connection) already takes. So
//! `PeerSession`, `CryptStream` and the capture tap run inside a tunnel
//! byte-for-byte as they run over TCP, and nothing above this module knows a
//! tunnel exists. eMuleAI gets the same property a different way — its uTP and
//! QUIC sockets are layers attached *beneath* `CEMSocket` — and the consequence
//! is the one that matters: hello, SecIdent, file requests and block transfer
//! are unchanged, and SecIdent v1 signs no address, so a tunnel cannot
//! invalidate a proof.
//!
//! # No engine owns a socket
//!
//! Both engines are fed by injection and emit through [`NattSender`], which
//! writes to the shared client-UDP pump. In a running node that injection is
//! core's **NAT-T Front** (`rmule_core::natt::front`, ADR-0091): it owns
//! this module's demux, feeds it from the client-UDP front's `0xB2` inbox, and
//! takes the [`Tunnel`]s that come out. That is not a convenience: the pinhole
//! a punch opened belongs to *that* bind, so a transport with its own socket
//! would have to punch again, through a mapping the coordinator never saw.
//! `librqbit-utp` exposes its `Transport` trait for exactly this, and `quinn`
//! its `AsyncUdpSocket`.
//!
//! # The demux, and what is never answered
//!
//! [`NattDemux`] splits the `0xB2` envelope by frame type — `0x00` uTP, `0x01`
//! QUIC, `0x02`/`0x03` CAPS/CAPS-ACK, `0xFF` KEY — and the [`TunnelRegistry`]
//! gates the two transport arms. A frame from an endpoint that neither holds nor
//! is opening a tunnel is dropped **before** an engine sees it, because a uTP
//! engine like libutp, handed an unknown connection's packet, answers with an
//! `ST_RESET` to an address nobody verified (aMule's deferred item A2); the
//! gate holds whatever the engine behind it would do, and rmule adds no reset. The dialect has no
//! failure frame of its own, so silence is the only correct answer to anything
//! malformed.
//!
//! # Obfuscation
//!
//! `0xB2` is on the never-obfuscated whitelist in its plaintext form, and a
//! transport frame is obfuscated once a [`NattFrame::Key`] frame supplied the
//! endpoint's hash — 10 s per endpoint between KEY frames, 10 minutes' life for
//! what one taught. `0xC5` signalling stays plaintext on purpose. ADR-0046's
//! never-obfuscated-whitelist amendment states the whole rule, including the
//! family: `0xB2` is carried in both, because no `0xB2` body names an address.
//!
//! [`NattFrame::Key`]: rmule_peer::natt::NattFrame::Key

mod demux;
mod keys;
mod quic;
mod registry;
mod send;
mod tunnel;
mod utp;

pub use demux::{NattDemux, NattDisposition, NattIdentity, NattStartError};
pub use keys::{KEY_FRAME_INTERVAL, LEARNED_HASH_TTL, NattKeyTable};
pub use quic::{
    NATT_QUIC_ALPN, NATT_QUIC_COMMON_NAME, NATT_QUIC_SNI, NattQuicIdentity, QuicEngine,
    QuicNattError, QuicTlsError, is_quic_long_header,
};
pub use registry::{
    Admission, DialingSlot, ExpectsSource, HeldSlot, OPENING_MAX, OPENING_PER_IP, OPENING_TTL,
    TunnelRegistry, TunnelSlot,
};
pub use send::{NattCrypt, NattDatagramSink, NattOwnHash, NattSender, SentFrame};
pub use tunnel::{Tunnel, TunnelTransport};
pub use utp::{UtpEngine, is_utp_syn};

use std::sync::Arc;

use rmule_primitives::PeerEndpoint;

/// The production [`NattDatagramSink`]: the shared client-UDP
/// [`ClientUdpSocket`](crate::ed2k::ClientUdpSocket), held behind the same `Arc`
/// the demux front and the serve reply drain hold, so every NAT-T datagram
/// leaves by the one advertised bind.
pub struct ClientUdpNattSink(pub Arc<crate::ed2k::ClientUdpSocket>);

impl NattDatagramSink for ClientUdpNattSink {
    async fn send_to(&self, peer: PeerEndpoint, datagram: &[u8]) -> std::io::Result<usize> {
        self.0.send_to_peer(peer, datagram).await?;
        Ok(datagram.len())
    }

    fn try_send_to(&self, peer: PeerEndpoint, datagram: &[u8]) -> std::io::Result<usize> {
        self.0.try_send_to_peer(peer, datagram)
    }

    fn poll_send_to(
        &self,
        cx: &mut std::task::Context<'_>,
        peer: PeerEndpoint,
        datagram: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.0.poll_send_to_peer(cx, peer, datagram)
    }

    fn local_addr(&self) -> std::net::SocketAddr {
        // Logging only, and a Family Pair has two binds, so the advertised
        // port on the wildcard address is the honest single answer.
        std::net::SocketAddr::from(([0, 0, 0, 0], self.0.local_port()))
    }
}
