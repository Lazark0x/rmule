//! The **QUIC engine**: `quinn` (the tokio driver over `quinn-proto`'s sans-I/O
//! state machine) behind an injected socket, with eMuleAI's pinned parameters
//! and the 37-byte `EAQN1` proof gate.
//!
//! Same seam as the uTP engine and for the same reason: datagrams are injected
//! by the demux and emitted through the shared client-UDP pump, so the pinhole
//! a punch opened is the pinhole QUIC uses. `quinn`'s `AsyncUdpSocket` is the
//! `Transport` trait's counterpart, and rmule implements it over a queue.
//!
//! **Not reachable on the wire yet.** `CT_MOD_MISCOPTIONS` bit 4 stays
//! dark until a live handshake is proven (ADR-0091), and this engine is only
//! constructed when the local posture serves QUIC — so what ships here is the
//! implementation and its deterministic proof, not an advertised capability.
//! No QUIC NAT-T connection has ever completed between two implementations;
//! rmule's first counterparty will be another rmule.

mod tls;

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rmule_peer::natt::{
    NattFrameType, QUIC_PROOF_LEN, QuicProof, QuicProofError, QuicProofVerdict,
};
use rmule_primitives::{PeerEndpoint, UserHash};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

pub use tls::{
    NATT_QUIC_ALPN, NATT_QUIC_COMMON_NAME, NATT_QUIC_SNI, NattQuicIdentity, QuicTlsError,
};

use super::registry::{Admission, DialingSlot, ExpectsSource, HeldSlot, TunnelRegistry};
use super::send::{NattDatagramSink, NattOwnHash, NattSender};
use super::tunnel::Tunnel;
use crate::peer::PeerStreamRole;

/// How many injected datagrams wait for the QUIC driver before one is dropped.
/// The same reasoning as the uTP queue: a shared socket must never stall behind
/// one tunnel, and QUIC's own loss recovery is the repair.
const INJECT_QUEUE_LEN: usize = 256;

/// The duplex buffer between the QUIC stream and the **Tunnel** the peer
/// session reads. One eD2k block request is well under this, so the bridge
/// never becomes the bottleneck the session would feel.
const BRIDGE_BUF: usize = 64 * 1024;

/// Whether a QUIC packet is a long-header one — the only kind that may open a
/// connection from a stranger, and the trigger for a **Key Frame**. RFC 9000
/// §17.2: the high bit of the first byte.
#[must_use]
pub fn is_quic_long_header(packet: &[u8]) -> bool {
    matches!(packet.first(), Some(first) if first & 0x80 != 0)
}

/// Why a QUIC tunnel could not be raised.
#[derive(Debug, thiserror::Error)]
pub enum QuicNattError {
    /// The TLS parameters could not be built.
    #[error(transparent)]
    Tls(#[from] QuicTlsError),

    /// The endpoint refused the dial before any packet left.
    #[error("the QUIC endpoint refused the dial: {0}")]
    Connect(#[from] quinn::ConnectError),

    /// The handshake did not complete — over a punched path this is the
    /// ordinary NAT failure, and it is discovered by timeout because the
    /// dialect defines no reset frame.
    #[error("the QUIC handshake did not complete: {0}")]
    Connection(#[from] quinn::ConnectionError),

    /// The proof could not be exchanged.
    #[error("the QUIC NAT-T proof could not be exchanged: {0}")]
    Proof(#[from] io::Error),

    /// The proof's bytes were not a proof.
    #[error("the QUIC NAT-T proof was malformed: {0}")]
    MalformedProof(#[from] QuicProofError),

    /// The proof was read and refused.
    #[error("the QUIC NAT-T proof was refused: {0}")]
    RefusedProof(QuicProofVerdict),

    /// Our own identity is not known yet. Proving with a zero sender hash
    /// would assert a false identity to the peer, so the exchange refuses
    /// rather than dial or accept with a placeholder.
    #[error("the QUIC NAT-T proof needs our own identity, which is not known yet")]
    NoIdentity,
}

/// rmule's `quinn::AsyncUdpSocket`: an injection queue in, the shared
/// client-UDP pump out.
struct InjectedQuicSocket<S> {
    inbound: Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
    sender: Arc<NattSender<S>>,
    bind: SocketAddr,
}

/// Always writable: [`InjectedQuicSocket::try_send`] never reports
/// `WouldBlock`, so there is nothing to wait for. Returning `Pending` here
/// with no waker registered would wedge the driver.
#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl<S> std::fmt::Debug for InjectedQuicSocket<S> {
    /// Opaque: `quinn` requires `Debug` on the socket, and the inject queue's
    /// contents are other peers' datagrams.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InjectedQuicSocket")
            .field("bind", &self.bind)
            .finish_non_exhaustive()
    }
}

impl<S: NattDatagramSink> AsyncUdpSocket for InjectedQuicSocket<S> {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    /// Frame, key-arm and (maybe) obfuscate one QUIC datagram, then hand it to
    /// the shared pump.
    ///
    /// A datagram the socket refuses right now is **dropped**, not deferred:
    /// deferring would need a waker this trait's signature does not carry, and
    /// a UDP path drops datagrams anyway. QUIC's loss recovery is the repair,
    /// which is exactly why it is a reliable transport over an unreliable one.
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let peer = crate::family::endpoint_of(transmit.destination);
        let opens = is_quic_long_header(transmit.contents);
        // A GSO batch is several datagrams in one buffer; the envelope is per
        // datagram, so a batch is split at its segment boundaries rather than
        // framed as one. `max_transmit_segments` is 1 below, so this is
        // belt-and-braces against a future quinn that batches anyway.
        let stride = transmit.segment_size.unwrap_or(transmit.contents.len());
        for segment in transmit.contents.chunks(stride.max(1)) {
            let _ = self.sender.try_send_transport(
                peer,
                NattFrameType::Quic,
                segment,
                opens,
                Instant::now(),
            );
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some(buf) = bufs.first_mut() else {
            return Poll::Ready(Ok(0));
        };
        let received = self
            .inbound
            .lock()
            .expect("the NAT-T inject queue is never poisoned")
            .poll_recv(cx);
        match received {
            Poll::Ready(Some((from, packet))) => {
                let len = packet.len().min(buf.len());
                buf[..len].copy_from_slice(&packet[..len]);
                meta[0] = RecvMeta {
                    addr: from,
                    len,
                    stride: len,
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the NAT-T demux closed the QUIC inject queue",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.bind)
    }

    /// One datagram per transmit. The envelope is per datagram, so segmentation
    /// offload would put several frames' worth of bytes behind one `0xB2 0x01`.
    fn max_transmit_segments(&self) -> usize {
        1
    }

    /// One datagram per receive: the demux hands them over individually, having
    /// already stripped one envelope each.
    fn max_receive_segments(&self) -> usize {
        1
    }
}

/// The node's QUIC NAT-T engine.
pub struct QuicEngine<S> {
    endpoint: quinn::Endpoint,
    inject: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    registry: Arc<Mutex<TunnelRegistry>>,
    own_hash: Arc<dyn NattOwnHash>,
    /// The endpoint erases the socket type behind `Arc<dyn AsyncUdpSocket>`, so
    /// nothing else in this struct mentions `S`. Keeping the parameter anyway
    /// ties an engine to the one sink whose pump it emits through, which is the
    /// invariant that makes "never owns a socket" checkable at compile time.
    sink: std::marker::PhantomData<fn() -> S>,
}

impl<S: NattDatagramSink> QuicEngine<S> {
    /// Start the engine over `sender`'s pump.
    ///
    /// Must be called on a Tokio runtime: `quinn` spawns its endpoint driver
    /// here, which is what makes injection asynchronous from the demux.
    ///
    /// # Errors
    /// [`QuicNattError`] when the TLS parameters or the endpoint were refused.
    pub fn start(
        own_hash: Arc<dyn NattOwnHash>,
        sender: Arc<NattSender<S>>,
        registry: Arc<Mutex<TunnelRegistry>>,
    ) -> Result<Self, QuicNattError> {
        let identity = NattQuicIdentity::generate()?;
        let (inject, inbound) = mpsc::channel(INJECT_QUEUE_LEN);
        let bind = sender.local_addr();
        let socket = Arc::new(InjectedQuicSocket {
            inbound: Mutex::new(inbound),
            sender,
            bind,
        });
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(identity.server_config()?),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(QuicNattError::Proof)?;
        endpoint.set_default_client_config(identity.client_config()?);
        Ok(Self {
            endpoint,
            inject,
            registry,
            own_hash,
            sink: std::marker::PhantomData,
        })
    }

    /// Hand one raw QUIC datagram from `peer` to the engine, subject to the
    /// **Tunnel Registry** — the same A2 rule the uTP engine takes, with a long
    /// header standing in for `ST_SYN`, opened only from an IP `expects`
    /// names.
    pub fn inject(
        &self,
        peer: PeerEndpoint,
        packet: &[u8],
        expects: &ExpectsSource<'_>,
        now: Instant,
    ) -> Admission {
        let admission = self
            .registry
            .lock()
            .expect("the NAT-T tunnel registry is never poisoned")
            .admit(peer, is_quic_long_header(packet), expects, now);
        if admission == Admission::Drop {
            return admission;
        }
        let addr = SocketAddr::new(peer.ip(), peer.port());
        if self.inject.try_send((addr, packet.to_vec())).is_err() {
            tracing::debug!(%peer, "QUIC inject queue full; datagram dropped");
        }
        admission
    }

    /// Dial `peer` and raise a **Tunnel**, exchanging the `EAQN1` proof before
    /// the tunnel is handed back.
    ///
    /// `expected_peer` is the hash we believe answers there, echoed into our
    /// own proof; `known_peer` is what we already hold for the endpoint, which
    /// is what a contradicting proof is judged against.
    ///
    /// # Errors
    /// [`QuicNattError`] — every variant blacklists QUIC for this endpoint at
    /// the caller's discretion (ADR-0091's 120 s window).
    pub async fn connect(
        &self,
        peer: PeerEndpoint,
        expected_peer: Option<UserHash>,
        known_peer: Option<UserHash>,
        endpoint_has_direct_caps: bool,
    ) -> Result<Tunnel, QuicNattError> {
        // The slot lives exactly as long as this future, cancellation included
        // The caller bounds the dial and retries it.
        let slot = DialingSlot::open(&self.registry, peer);
        let addr = SocketAddr::new(peer.ip(), peer.port());
        let result = async {
            let connection = self.endpoint.connect(addr, NATT_QUIC_SNI)?.await?;
            let (send, recv) = connection.open_bi().await?;
            self.gate(
                peer,
                send,
                recv,
                expected_peer,
                known_peer,
                endpoint_has_direct_caps,
            )
            .await
        }
        .await;
        match result {
            Ok(stream) => Ok(Tunnel::quic(
                peer,
                PeerStreamRole::Dialer,
                stream,
                slot.held(),
            )),
            // Dropping the slot releases it, and only while it is still ours.
            Err(error) => Err(error),
        }
    }

    /// Await the next inbound QUIC tunnel.
    ///
    /// # Errors
    /// [`QuicNattError`] when the handshake or the proof failed; `None` once
    /// the endpoint is closed.
    pub async fn accept(&self) -> Option<Result<Tunnel, QuicNattError>> {
        let incoming = self.endpoint.accept().await?;
        let peer = crate::family::endpoint_of(incoming.remote_address());
        Some(self.accept_one(peer, incoming).await)
    }

    async fn accept_one(
        &self,
        peer: PeerEndpoint,
        incoming: quinn::Incoming,
    ) -> Result<Tunnel, QuicNattError> {
        let connection = incoming.await?;
        let (send, recv) = connection.accept_bi().await?;
        // A responder does not know who dialed it, so its own proof carries a
        // null expectation — which is exactly the case the dialect accepts.
        let stream = self.gate(peer, send, recv, None, None, false).await?;
        let slot = HeldSlot::hold(&self.registry, peer);
        Ok(Tunnel::quic(peer, PeerStreamRole::Responder, stream, slot))
    }

    /// Exchange and judge the 37-byte proof, then bridge the stream.
    ///
    /// Both sides write their own proof before reading the peer's. eMuleAI
    /// builds *and* validates one on each side, and writing first is what makes
    /// the exchange deadlock-free; the ordering is `[pending]` against a
    /// capture, which does not exist because no two implementations have ever
    /// completed this handshake.
    ///
    /// The own-hash read happens here, at the handshake, not at
    /// [`Self::start`]: proving with a zero sender because the node had not
    /// identified itself yet would assert a false identity, so a still-absent
    /// hash refuses the exchange outright rather than write one.
    ///
    /// Not one application byte crosses the returned duplex until the verdict
    /// is [`QuicProofVerdict::Accept`] or `AcceptRefreshed`, which is the gate
    /// eMuleAI spells `m_bRemoteProofAccepted`.
    async fn gate(
        &self,
        peer: PeerEndpoint,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        expected_peer: Option<UserHash>,
        known_peer: Option<UserHash>,
        endpoint_has_direct_caps: bool,
    ) -> Result<tokio::io::DuplexStream, QuicNattError> {
        let Some(own_hash) = self.own_hash.user_hash() else {
            tracing::debug!(%peer, "QUIC NAT-T proof refused: our own identity is not known yet");
            return Err(QuicNattError::NoIdentity);
        };
        let ours = QuicProof {
            sender: own_hash,
            expected_recipient: expected_peer.unwrap_or(UserHash::from_bytes([0; 16])),
        };
        send.write_all(&ours.encode())
            .await
            .map_err(io::Error::other)?;
        let mut theirs = [0u8; QUIC_PROOF_LEN];
        recv.read_exact(&mut theirs)
            .await
            .map_err(|error| QuicNattError::Proof(io::Error::other(error)))?;
        let proof = QuicProof::decode(&theirs)?;
        match proof.judge(&own_hash, known_peer, endpoint_has_direct_caps) {
            QuicProofVerdict::Accept(_) | QuicProofVerdict::AcceptRefreshed { .. } => {}
            refused => {
                tracing::debug!(%peer, ?refused, "QUIC NAT-T proof refused; tunnel not raised");
                return Err(QuicNattError::RefusedProof(refused));
            }
        }
        let (app, engine) = tokio::io::duplex(BRIDGE_BUF);
        tokio::spawn(async move {
            let (mut engine_rx, mut engine_tx) = tokio::io::split(engine);
            let up = async {
                tokio::io::copy(&mut recv, &mut engine_tx).await?;
                engine_tx.shutdown().await
            };
            let down = async {
                tokio::io::copy(&mut engine_rx, &mut send).await?;
                send.shutdown().await.map_err(io::Error::other)
            };
            let _ = tokio::join!(up, down);
        });
        Ok(app)
    }

    /// Close the endpoint, ending the driver and every tunnel on it.
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"natt shutdown");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9000 §17.2: the high bit of the first byte is the long-header form,
    /// which is the only shape that may open a connection from a stranger.
    #[test]
    fn a_long_header_packet_is_the_quic_opener() {
        assert!(is_quic_long_header(&[0xC0, 0x00, 0x00, 0x00, 0x01]));
        assert!(is_quic_long_header(&[0x80]));
        assert!(!is_quic_long_header(&[0x40]), "short header");
        assert!(!is_quic_long_header(&[]), "no bytes name no form");
    }
}
