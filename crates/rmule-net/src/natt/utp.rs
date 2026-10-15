//! The **uTP engine**: `librqbit-utp` behind rmule's implementation of its
//! `Transport` seam.
//!
//! The library never binds a socket. Inbound datagrams are *injected* — the
//! demux strips the `0xB2 0x00` envelope and pushes the raw BEP-29 packet into
//! a queue this transport drains — and outbound ones are *emitted* back through
//! the shared client-UDP **Family Pair**, re-framed and obfuscated on the way.
//! That is the whole point: the pinhole a punch opened is the pinhole the
//! transport uses, so nothing has to punch twice.
//!
//! `ST_SYN` detection is the library's own `raw::UtpHeader::deserialize`, not a
//! hand-rolled `(byte0 >> 4) == 4`. The nibble test would be right today and
//! silently wrong the day the header gains a version.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;

use librqbit_dualstack_sockets::PollSendToVectored;
use librqbit_utp::raw::{Type, UtpHeader};
use librqbit_utp::{SocketOpts, Transport, UtpSocket};
use rmule_peer::natt::NattFrameType;
use rmule_primitives::PeerEndpoint;
use tokio::sync::mpsc;

use super::registry::{
    Admission, DialingSlot, ExpectsSource, HeldSlot, TunnelRegistry, TunnelSlot,
};
use super::send::{NattDatagramSink, NattSender};
use super::tunnel::Tunnel;
use crate::peer::PeerStreamRole;

/// How many injected datagrams wait for the uTP dispatcher before the demux
/// drops one. A datagram queue never back-pressures the socket it shares:
/// stalling the client-UDP front would stall every reask and every Kad
/// datagram behind one slow tunnel, so a full queue drops and traces — which is
/// what a lossy UDP path does anyway, and uTP retransmits.
const INJECT_QUEUE_LEN: usize = 256;

/// `librqbit-utp` 0.7.0 exports its `Transport` trait but **not** the
/// `UtpEnvironment` implementation its socket is generic over — only the
/// `UtpSocketUdp` alias that mentions it. So the environment type cannot be
/// named directly, and is recovered from that alias by projection through a
/// local trait. An upstream `pub use traits::DefaultUtpEnvironment` would
/// delete this.
trait UtpEnvOf {
    /// The environment type parameter.
    type Env;
}

impl<T, E> UtpEnvOf for UtpSocket<T, E> {
    type Env = E;
}

/// The default `UtpEnvironment` — real `Instant`s and real randomness.
type DefaultUtpEnv = <librqbit_utp::UtpSocketUdp as UtpEnvOf>::Env;

/// Whether a uTP packet is an `ST_SYN` — the one packet type that may open a
/// tunnel from a stranger, and the trigger for a **Key Frame**.
///
/// A packet the header parser cannot read is *not* an opener. Treating garbage
/// as a SYN would let a malformed datagram create a registry entry.
#[must_use]
pub fn is_utp_syn(packet: &[u8]) -> bool {
    UtpHeader::deserialize(packet).is_some_and(|(header, _)| header.get_type() == Type::ST_SYN)
}

/// rmule's `librqbit_utp::Transport`: an injection queue in, the shared
/// client-UDP pump out.
struct InjectedTransport<S> {
    inbound: Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
    sender: Arc<NattSender<S>>,
    bind: SocketAddr,
}

// `async fn` in a trait impl cannot state a `+ Sync` bound on the future it
// returns, and `librqbit_utp::Transport` requires exactly that — so these two
// are written as `-> impl Future` on purpose, not for want of the sugar.
#[allow(clippy::manual_async_fn)]
impl<S: NattDatagramSink> Transport for InjectedTransport<S> {
    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = io::Result<(usize, SocketAddr)>> + Send + Sync + 'a {
        async move {
            let (from, packet) = std::future::poll_fn(|cx| {
                self.inbound
                    .lock()
                    .expect("the NAT-T inject queue is never poisoned")
                    .poll_recv(cx)
            })
            .await
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "the NAT-T demux closed the uTP inject queue",
                )
            })?;
            // A uTP packet cannot exceed a datagram and the caller's buffer is
            // a full datagram's worth, so this only ever truncates if the
            // library shrinks its read buffer — in which case a short read is
            // a corrupt packet uTP will discard, not a panic.
            let len = packet.len().min(buf.len());
            buf[..len].copy_from_slice(&packet[..len]);
            Ok((len, from))
        }
    }

    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> impl Future<Output = io::Result<usize>> + Send + Sync + 'a {
        async move {
            self.sender
                .send_transport(
                    crate::family::endpoint_of(target),
                    NattFrameType::Utp,
                    buf,
                    is_utp_syn(buf),
                    Instant::now(),
                )
                .await
                .map(|_| buf.len())
        }
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.sender.poll_send_transport(
            cx,
            crate::family::endpoint_of(target),
            NattFrameType::Utp,
            buf,
            is_utp_syn(buf),
            Instant::now(),
        )
    }

    fn bind_addr(&self) -> SocketAddr {
        self.bind
    }
}

impl<S: NattDatagramSink> PollSendToVectored for InjectedTransport<S> {
    /// Gathered rather than scattered. A NAT-T frame is prefixed and may be
    /// RC4'd end to end, so the datagram that reaches the socket is a new
    /// buffer either way — a vectored send could not avoid the copy, and
    /// pretending otherwise would put the envelope in its own datagram.
    fn poll_send_to_vectored(
        &self,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        let mut packet = Vec::with_capacity(bufs.iter().map(|b| b.len()).sum());
        for buf in bufs {
            packet.extend_from_slice(buf);
        }
        Transport::poll_send_to(self, cx, &packet, target)
    }
}

/// The node's one uTP engine: one `librqbit-utp` socket multiplexing every
/// tunnel, fed by the demux and emitting through the shared pump.
pub struct UtpEngine<S> {
    socket: Arc<UtpSocket<InjectedTransport<S>, DefaultUtpEnv>>,
    inject: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    registry: Arc<Mutex<TunnelRegistry>>,
}

impl<S: NattDatagramSink> UtpEngine<S> {
    /// Start the engine over `sender`'s pump, sharing `registry` with the QUIC
    /// engine and the demux.
    ///
    /// Must be called on a Tokio runtime: `librqbit-utp` spawns its dispatcher
    /// task here, which is what makes injection asynchronous from the demux.
    ///
    /// # Errors
    /// Whatever `librqbit-utp` rejected in its socket options.
    pub fn start(
        sender: Arc<NattSender<S>>,
        registry: Arc<Mutex<TunnelRegistry>>,
    ) -> Result<Self, librqbit_utp::Error> {
        let (inject, inbound) = mpsc::channel(INJECT_QUEUE_LEN);
        let bind = sender.local_addr();
        let transport = InjectedTransport {
            inbound: Mutex::new(inbound),
            sender,
            bind,
        };
        let socket: Arc<UtpSocket<InjectedTransport<S>, DefaultUtpEnv>> =
            UtpSocket::new_with_opts(transport, DefaultUtpEnv::default(), SocketOpts::default())?;
        Ok(Self {
            socket,
            inject,
            registry,
        })
    }

    /// Hand one raw BEP-29 packet from `peer` to the engine, subject to the
    /// **Tunnel Registry**.
    ///
    /// A non-`ST_SYN` packet from an endpoint that neither holds nor is opening
    /// a tunnel is dropped here — before injection — and never answered: no
    /// `ST_RESET` goes to an unverified address (aMule's A2; the registry's
    /// module docs say why the gate stays although `librqbit-utp` itself
    /// drops such a packet). An `ST_SYN` opens a slot only from an IP
    /// `expects` names (ADR-0091, security rule 10). Returns the admission so
    /// the demux can trace and count it.
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
            .admit(peer, is_utp_syn(packet), expects, now);
        if admission == Admission::Drop {
            return admission;
        }
        let addr = SocketAddr::new(peer.ip(), peer.port());
        if self.inject.try_send((addr, packet.to_vec())).is_err() {
            // The dispatcher is behind, or gone. Dropping is what the path
            // itself does under load, and uTP's own retransmit is the recovery.
            tracing::debug!(%peer, "uTP inject queue full; datagram dropped");
        }
        admission
    }

    /// Dial `peer` and raise a **Tunnel**. The endpoint is registered *before*
    /// the dial so the answer to our own `ST_SYN` is admitted — nothing inbound
    /// opened the slot, because our opener went out.
    ///
    /// The slot is a [`DialingSlot`], so it lives exactly as long as this
    /// future: `librqbit-utp` sends its `ST_SYN` **once** and never retransmits
    /// it, so a caller that bounds the dial and retries is the only thing that
    /// makes a lost opener recoverable — and every such cancellation must
    /// release the slot.
    ///
    /// # Errors
    /// Whatever `librqbit-utp` reported: a handshake that never completed is
    /// the ordinary NAT failure, discovered by timeout because the dialect has
    /// no reset frame.
    pub async fn connect(&self, peer: PeerEndpoint) -> Result<Tunnel, librqbit_utp::Error> {
        let slot = DialingSlot::open(&self.registry, peer);
        let addr = SocketAddr::new(peer.ip(), peer.port());
        let stream = self.socket.connect(addr).await?;
        Ok(Tunnel::utp(
            peer,
            PeerStreamRole::Dialer,
            stream,
            slot.held(),
        ))
    }

    /// Whether `peer` already holds a live tunnel — what a caller asks before
    /// re-dialing, so a retry cannot raise a second tunnel on one path.
    #[must_use]
    pub fn holds(&self, peer: PeerEndpoint) -> bool {
        self.registry
            .lock()
            .expect("the NAT-T tunnel registry is never poisoned")
            .slot(peer)
            == Some(TunnelSlot::Held)
    }

    /// Await the next inbound tunnel — a peer whose `ST_SYN` we admitted and
    /// whose handshake completed.
    ///
    /// The endpoint's slot is held by the returned [`Tunnel`] and freed when it
    /// drops, in either family — so a caller that has no use for a tunnel (core
    /// adopts only IPv4 paths) ends its admission simply by dropping it.
    ///
    /// # Errors
    /// Whatever `librqbit-utp` reported; a dead dispatcher ends the accept loop.
    pub async fn accept(&self) -> Result<Tunnel, librqbit_utp::Error> {
        let stream = self.socket.accept().await?;
        let peer = crate::family::endpoint_of(stream.remote_addr());
        let slot = HeldSlot::hold(&self.registry, peer);
        Ok(Tunnel::utp(peer, PeerStreamRole::Responder, stream, slot))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The library's own parser, not a nibble test: a real `ST_SYN` reads as an
    /// opener and every other type does not.
    #[test]
    fn the_librarys_header_parser_names_the_syn() {
        // `(ST_SYN << 4) | version 1` = 0x41, then a 20-byte BEP-29 header.
        let mut syn = [0u8; 20];
        syn[0] = 0x41;
        assert!(is_utp_syn(&syn));

        let mut data = [0u8; 20];
        data[0] = 0x01; // ST_DATA, version 1
        assert!(!is_utp_syn(&data));

        let mut state = [0u8; 20];
        state[0] = 0x21; // ST_STATE, version 1
        assert!(!is_utp_syn(&state));
    }

    /// Garbage is not an opener. If it were, a malformed datagram from any
    /// forged source would create a registry entry and a KEY frame.
    #[test]
    fn an_unparsable_packet_is_not_an_opener() {
        assert!(!is_utp_syn(&[]));
        assert!(!is_utp_syn(&[0x41]));
        assert!(!is_utp_syn(&[0xFF; 8]), "too short for a BEP-29 header");
    }
}
