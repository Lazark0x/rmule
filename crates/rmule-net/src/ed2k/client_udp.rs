//! The shared **client-UDP datagram socket** (ADR-0057): the single bound
//! client-UDP port every counterparty sends to rmule's advertised UDP endpoint.
//! Unlike the ephemeral-only [`ServerUdpSocket`](crate::ed2k::ServerUdpSocket) (which
//! only ever *sends* to servers and reads replies back on its source address),
//! this port is **advertised** — its bound number rides the peer hello's
//! `CT_EMULE_UDPPORTS` tag — so `bind` takes an explicit port (`0` = ephemeral
//! for tests). The demux front (`rmule_core::client_udp`) owns the receive side
//! and routes each datagram by its leading protocol byte.
//!
//! One port, two sockets: this is a **Family Pair** (ADR-0085), so the
//! advertised number is true in both families and a datagram's recorded source
//! is its real one, never a `::ffff:` mapping.
//!
//! The socket also carries the **Prediction Fans** of ADR-0091's
//! port-prediction amendment: extra ephemeral sockets a birthday pairing
//! opens, merged into [`recv`](ClientUdpSocket::recv), and the **Prediction
//! Routes** every send path consults, so a Tunnel on a Fan socket reaches
//! everything above as if it were on the advertised bind.

mod prediction;

use std::net::{SocketAddr, SocketAddrV4};
use std::time::Duration;

use rmule_primitives::PeerEndpoint;

use crate::family::{FamilySelection, UdpFamilyPair};

pub use self::prediction::{PREDICTION_SOCKET_BUDGET, PredictionFanId, PredictionHit};

/// Read ceiling per datagram: one UDP datagram can never exceed 64 KiB, and a
/// zlib-packed Kad payload (`0xE5`) can approach that, so the shared front reads
/// with the same headroom the Kad driver does.
const RECV_BUF_LEN: usize = 64 * 1024;

/// A bound UDP Family Pair for the shared client-UDP surface (peer-UDP `0xC5`
/// plus the Kad `0xE4`/`0xE5` demux seam, ADR-0057).
pub struct ClientUdpSocket {
    pair: UdpFamilyPair,
    /// Receive scratch, reused across datagrams so the hot demux loop does not
    /// zero-allocate 64 KiB per datagram; only the exact received length is
    /// copied out. Uncontended in practice — one demux task owns the receive
    /// side — the lock merely keeps `recv` callable through the shared `Arc`.
    recv_scratch: tokio::sync::Mutex<Vec<u8>>,
    /// Port prediction's Fans and Routes. Empty unless a plan opened one, and
    /// an empty route table is one lock and one `is_empty` per send.
    prediction: prediction::PredictionFans,
}

impl ClientUdpSocket {
    /// Bind `port` in both **Address Families** (`0` = an OS-assigned ephemeral
    /// port, read back via [`local_port`](Self::local_port) and advertised
    /// as-is).
    ///
    /// # Errors
    /// Only when no family bound at all.
    pub async fn bind(port: u16) -> std::io::Result<Self> {
        Self::bind_with(port, FamilySelection::default()).await
    }

    /// Bind `port` in the selected families.
    ///
    /// # Errors
    /// Only when no selected family bound at all.
    pub async fn bind_with(port: u16, selection: FamilySelection) -> std::io::Result<Self> {
        Ok(Self {
            pair: UdpFamilyPair::bind(port, selection).await?,
            recv_scratch: tokio::sync::Mutex::new(vec![0u8; RECV_BUF_LEN]),
            prediction: prediction::PredictionFans::default(),
        })
    }

    /// The bound port — the truth the `CT_EMULE_UDPPORTS` advert derives from
    /// (ADR-0047 honest advertisement), shared by both families.
    #[must_use]
    pub const fn local_port(&self) -> u16 {
        self.pair.local_port()
    }

    /// What this pair's binds did — which families came up, and why any other
    /// did not.
    #[must_use]
    pub const fn binds(&self) -> &crate::family::FamilyBinds {
        self.pair.binds()
    }

    /// Send one datagram to an IPv4 destination (fire-and-forget; a short write
    /// is an error).
    ///
    /// # Errors
    /// Whatever the send returned.
    pub async fn send_to(&self, addr: SocketAddrV4, datagram: &[u8]) -> std::io::Result<()> {
        self.send_to_peer(crate::family::endpoint_of(addr.into()), datagram)
            .await
    }

    /// Send one datagram on the socket `peer`'s own family bound.
    ///
    /// # Errors
    /// [`std::io::ErrorKind::Unsupported`] when that family is absent, else
    /// whatever the send returned.
    pub async fn send_to_peer(&self, peer: PeerEndpoint, datagram: &[u8]) -> std::io::Result<()> {
        if let Some(routed) = self.prediction.route(peer) {
            let sent = routed
                .send_to(datagram, SocketAddr::new(peer.ip(), peer.port()))
                .await?;
            if sent != datagram.len() {
                return Err(std::io::Error::other("short UDP datagram write"));
            }
            return Ok(());
        }
        self.pair.send_to(peer, datagram).await
    }

    /// [`send_to_peer`](Self::send_to_peer) without awaiting — the shape
    /// `quinn`'s `AsyncUdpSocket::try_send` needs (ADR-0091's NAT-T QUIC
    /// engine).
    ///
    /// # Errors
    /// [`std::io::ErrorKind::Unsupported`] when that family is absent,
    /// `WouldBlock` when the socket cannot take it now, else whatever the send
    /// returned.
    pub fn try_send_to_peer(&self, peer: PeerEndpoint, datagram: &[u8]) -> std::io::Result<usize> {
        if let Some(routed) = self.prediction.route(peer) {
            return routed.try_send_to(datagram, SocketAddr::new(peer.ip(), peer.port()));
        }
        self.pair.try_send_to(peer, datagram)
    }

    /// [`send_to_peer`](Self::send_to_peer) as a `poll` — the shape
    /// `librqbit-utp`'s `Transport` needs (ADR-0091's NAT-T uTP engine).
    ///
    /// # Errors
    /// [`std::io::ErrorKind::Unsupported`] when that family is absent, else
    /// whatever the send returned.
    pub fn poll_send_to_peer(
        &self,
        cx: &mut std::task::Context<'_>,
        peer: PeerEndpoint,
        datagram: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if let Some(routed) = self.prediction.route(peer) {
            return routed.poll_send_to(cx, datagram, SocketAddr::new(peer.ip(), peer.port()));
        }
        self.pair.poll_send_to(cx, peer, datagram)
    }

    /// Receive the next datagram and the endpoint it truly came from, in
    /// whichever family carried it.
    ///
    /// A datagram a Prediction Fan socket received from its peer arrives here
    /// too, attributed to that peer's endpoint like any other.
    ///
    /// # Errors
    /// Whatever the receive returned.
    pub async fn recv(&self) -> std::io::Result<(Vec<u8>, PeerEndpoint)> {
        let mut scratch = self.recv_scratch.lock().await;
        let mut fanned = self.prediction.inlet().lock().await;
        tokio::select! {
            received = self.pair.recv(scratch.as_mut_slice()) => {
                let (len, from) = received?;
                Ok((scratch[..len].to_vec(), from))
            }
            // The fans hold a sender for as long as the socket lives, so the
            // inlet never closes under this arm.
            Some(fanned) = fanned.recv() => Ok(fanned),
        }
    }

    /// Open a **Prediction Fan**: up to `sockets` ephemeral IPv4 sockets for
    /// one attempt toward `peer`, the punch target, as many as
    /// [`PREDICTION_SOCKET_BUDGET`] has room for. A datagram from exactly
    /// `peer` on one of them installs a Prediction Route, is answered once
    /// with `answer`, is reported to `on_hit`, and joins [`recv`](Self::recv).
    ///
    /// # Errors
    /// When the budget has no room at all, or whatever a bind returned; the
    /// sockets bound before a failed bind are released and no reader runs.
    pub async fn open_prediction_fan(
        &self,
        peer: SocketAddrV4,
        sockets: usize,
        answer: Vec<u8>,
        on_hit: PredictionHit,
    ) -> std::io::Result<PredictionFanId> {
        self.prediction.open(peer, sockets, answer, on_hit).await
    }

    /// Fan sockets open right now, every Fan's and every Prediction Route's
    /// that outlived its Fan — what [`PREDICTION_SOCKET_BUDGET`] bounds.
    pub fn open_prediction_sockets(&self) -> usize {
        self.prediction.open_sockets()
    }

    /// Send `datagram` to `to` once from every socket of `fan`, `pace` apart.
    /// Returns how many datagrams left.
    pub async fn prediction_fan_burst(
        &self,
        fan: PredictionFanId,
        to: SocketAddrV4,
        datagram: &[u8],
        pace: Duration,
    ) -> usize {
        self.prediction.burst(fan, to, datagram, pace).await
    }

    /// Close `fan`. `keep_routes` keeps a socket that carries a Prediction
    /// Route, and so a Tunnel, alive past its Fan.
    pub fn close_prediction_fan(&self, fan: PredictionFanId, keep_routes: bool) {
        self.prediction.close(fan, keep_routes);
    }

    /// Release the Prediction Route for `remote`, if one is held: sends to it
    /// leave by the advertised bind again.
    pub fn release_prediction_route(&self, remote: SocketAddrV4) {
        self.prediction.release(remote);
    }
}
