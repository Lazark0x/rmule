//! The **Prediction Fan** and the **Prediction Route** (ADR-0091's
//! port-prediction amendment): the sockets the endpoint-dependent side of a
//! birthday pairing opens, and the route that makes a Tunnel on one of them
//! look to everything above like a Tunnel on the advertised bind.
//!
//! A Fan is N ephemeral IPv4 sockets opened for one attempt toward one peer
//! endpoint, the punch target. Each sends one empty `0xA1` toward it, and
//! that opens one fresh NAT mapping per socket. A datagram that later arrives
//! on Fan socket *j* **from that endpoint** is a hit:
//!
//! - a Prediction Route `peer endpoint → socket j` is installed, so every send
//!   to that endpoint from then on leaves by socket *j*, the one mapping the
//!   peer's filter admits;
//! - socket *j* answers one empty `0xA1`, so a peer that dials learns port *j*
//!   (the only exception to "nothing answers a punch", bounded to one reply
//!   per socket and only to the endpoint the Fan was opened for);
//! - the datagram joins the client-UDP inlet as if the advertised bind had
//!   received it.
//!
//! So the NAT-T front, its demux and the uTP engine are unchanged. They see
//! datagrams from the peer's endpoint and send to it, and the route decides
//! which socket carries them. A datagram from any other endpoint is dropped,
//! the peer's own address on another port included: a Fan socket belongs to
//! one endpoint, and a stranger behind the same CGNAT address must not be
//! able to take a route.
//!
//! **Ownership.** Every Fan socket is one [`FanSocket`] whose reader task is
//! aborted when its last holder drops it. The Fan holds it until the Fan
//! closes; a Route holds it for as long as the route stands. So a reader
//! never outlives every route on its socket, and a route never loses its
//! reader to a sibling's release. The sockets of a Fan are bound
//! **before** any reader is spawned, so a bind that fails part-way leaves no
//! task behind. And the sockets alive across every Fan and Route
//! are held under [`PREDICTION_SOCKET_BUDGET`].

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use rmule_peer::natt::{PREDICTION_ATTEMPTS, PREDICTION_FAN_SOCKETS};
use rmule_primitives::PeerEndpoint;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

#[cfg(test)]
mod tests;

/// Datagrams from Fan sockets waiting for the client-UDP pump. A Fan socket
/// only delivers from the one peer it was opened for, so the backlog is that
/// peer's traffic.
const INLET_BACKLOG: usize = 256;

/// Read ceiling per Fan datagram: a `0xB2` frame is MTU-sized, and the pump's
/// own 64 KiB ceiling is for zlib-packed Kad, which never arrives here.
const FAN_RECV_LEN: usize = 2048;

/// Fan-born sockets one client-UDP socket holds at once, across every open
/// Fan and every Prediction Route that outlived its Fan: two full Fans, the
/// most one plan ever needs. A Fan asked for beyond it opens
/// what room is left, and none at all when there is none.
pub const PREDICTION_SOCKET_BUDGET: usize = PREDICTION_FAN_SOCKETS * PREDICTION_ATTEMPTS as usize;

/// Which Fan, for [`close`](super::ClientUdpSocket::close_prediction_fan).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PredictionFanId(u64);

/// Told the peer endpoint whenever a Fan socket installs a Prediction Route.
pub type PredictionHit = Arc<dyn Fn(SocketAddrV4) + Send + Sync>;

/// One Fan socket and the reader behind it. The reader runs as long as one
/// holder — the Fan, or a Route — keeps this value alive, and is aborted
/// when the last one drops it.
struct FanSocket {
    socket: Arc<UdpSocket>,
    /// Set once the reader is spawned; empty only while the socket is being
    /// wired.
    reader: OnceLock<AbortHandle>,
    /// The budget this socket holds one unit of, returned on drop.
    live: Arc<AtomicUsize>,
}

impl Drop for FanSocket {
    fn drop(&mut self) {
        if let Some(reader) = self.reader.get() {
            reader.abort();
        }
        self.live.fetch_sub(1, Ordering::AcqRel);
    }
}

/// One open Fan: its sockets.
struct Fan {
    sockets: Vec<Arc<FanSocket>>,
}

/// One Prediction Route: the socket that carries the endpoint. It keeps that
/// socket's reader alive past the Fan's close.
struct Route {
    socket: Arc<FanSocket>,
}

type Routes = Arc<Mutex<HashMap<SocketAddrV4, Route>>>;

/// Every Fan and every Route one client-UDP socket holds.
pub(super) struct PredictionFans {
    next: AtomicU64,
    fans: Mutex<HashMap<u64, Fan>>,
    routes: Routes,
    /// Fan sockets alive right now, Fans and outliving Routes together.
    live: Arc<AtomicUsize>,
    inlet_tx: mpsc::Sender<(Vec<u8>, PeerEndpoint)>,
    inlet_rx: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, PeerEndpoint)>>,
}

impl Default for PredictionFans {
    fn default() -> Self {
        let (inlet_tx, inlet_rx) = mpsc::channel(INLET_BACKLOG);
        Self {
            next: AtomicU64::new(0),
            fans: Mutex::new(HashMap::new()),
            routes: Arc::new(Mutex::new(HashMap::new())),
            live: Arc::new(AtomicUsize::new(0)),
            inlet_tx,
            inlet_rx: tokio::sync::Mutex::new(inlet_rx),
        }
    }
}

impl Drop for PredictionFans {
    fn drop(&mut self) {
        // The readers hold the route table, so the table must let go of the
        // sockets — and so of the readers — before it can die with them.
        if let Ok(mut fans) = self.fans.lock() {
            fans.clear();
        }
        if let Ok(mut routes) = self.routes.lock() {
            routes.clear();
        }
    }
}

/// One ephemeral IPv4 socket, the way every Fan socket is bound.
fn bind_ephemeral() -> io::Result<Arc<UdpSocket>> {
    let (socket, _port) = crate::family::bind_udp((Ipv4Addr::UNSPECIFIED, 0).into())?;
    Ok(Arc::new(UdpSocket::from_std(socket)?))
}

impl PredictionFans {
    /// Bind up to `sockets` ephemeral IPv4 sockets for `peer`, as many as the
    /// budget has room for, and start a reader on each.
    pub(super) async fn open(
        &self,
        peer: SocketAddrV4,
        sockets: usize,
        answer: Vec<u8>,
        on_hit: PredictionHit,
    ) -> io::Result<PredictionFanId> {
        self.open_with(peer, sockets, answer, on_hit, bind_ephemeral)
    }

    /// [`open`](Self::open) with the binder handed in, so a test can make a
    /// bind fail part-way.
    ///
    /// Every socket is bound before any reader is spawned: a failure returns
    /// the sockets bound so far to the budget and leaves no task behind.
    pub(super) fn open_with(
        &self,
        peer: SocketAddrV4,
        sockets: usize,
        answer: Vec<u8>,
        on_hit: PredictionHit,
        mut bind: impl FnMut() -> io::Result<Arc<UdpSocket>>,
    ) -> io::Result<PredictionFanId> {
        let reserved = self.reserve(sockets);
        if reserved == 0 {
            return Err(io::Error::other(
                "prediction socket budget exhausted: no fan socket can open",
            ));
        }
        let mut bound = Vec::with_capacity(reserved);
        for _ in 0..reserved {
            match bind() {
                Ok(socket) => bound.push(socket),
                Err(error) => {
                    self.live.fetch_sub(reserved, Ordering::AcqRel);
                    return Err(error);
                }
            }
        }
        let sockets = bound
            .into_iter()
            .map(|socket| {
                let holder = Arc::new(FanSocket {
                    socket: Arc::clone(&socket),
                    reader: OnceLock::new(),
                    live: Arc::clone(&self.live),
                });
                let reader = tokio::spawn(read_fan_socket(
                    socket,
                    Arc::downgrade(&holder),
                    peer,
                    answer.clone(),
                    Arc::clone(&self.routes),
                    self.inlet_tx.clone(),
                    Arc::clone(&on_hit),
                ))
                .abort_handle();
                let _ = holder.reader.set(reader);
                holder
            })
            .collect();
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.fans
            .lock()
            .expect("prediction fans")
            .insert(id, Fan { sockets });
        Ok(PredictionFanId(id))
    }

    /// Take up to `wanted` units of the budget; returns how many were taken.
    fn reserve(&self, wanted: usize) -> usize {
        let mut taken = 0;
        let _ = self
            .live
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |live| {
                taken = wanted.min(PREDICTION_SOCKET_BUDGET.saturating_sub(live));
                Some(live + taken)
            });
        taken
    }

    /// Fan sockets alive right now: every open Fan's, and every Route's that
    /// outlived its Fan.
    pub(super) fn open_sockets(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }

    /// Send `datagram` to `to` once from every socket of `fan`, `pace` apart.
    /// Returns how many left. A send that fails costs that socket's mapping,
    /// not the burst.
    pub(super) async fn burst(
        &self,
        fan: PredictionFanId,
        to: SocketAddrV4,
        datagram: &[u8],
        pace: Duration,
    ) -> usize {
        let sockets: Vec<Arc<UdpSocket>> = self
            .fans
            .lock()
            .expect("prediction fans")
            .get(&fan.0)
            .map(|fan| {
                fan.sockets
                    .iter()
                    .map(|held| Arc::clone(&held.socket))
                    .collect()
            })
            .unwrap_or_default();
        let mut sent = 0;
        for (index, socket) in sockets.iter().enumerate() {
            if index > 0 && !pace.is_zero() {
                tokio::time::sleep(pace).await;
            }
            if socket.send_to(datagram, SocketAddr::V4(to)).await.is_ok() {
                sent += 1;
            }
        }
        sent
    }

    /// Close `fan`. With `keep_routes`, a socket that holds a Prediction Route
    /// survives the Fan, held by that route, and keeps its reader. Without
    /// it, the Fan's routes go too: the plan ended and no Tunnel rose on
    /// them. Either way every other socket of the Fan closes here, reader
    /// included.
    pub(super) fn close(&self, fan: PredictionFanId, keep_routes: bool) {
        let Some(fan) = self.fans.lock().expect("prediction fans").remove(&fan.0) else {
            return;
        };
        if !keep_routes {
            self.routes
                .lock()
                .expect("prediction routes")
                .retain(|_, route| {
                    !fan.sockets
                        .iter()
                        .any(|held| Arc::ptr_eq(&route.socket, held))
                });
        }
        drop(fan);
    }

    /// Drop the route for `remote`, and its socket once nothing else holds
    /// it.
    pub(super) fn release(&self, remote: SocketAddrV4) {
        let released = self
            .routes
            .lock()
            .expect("prediction routes")
            .remove(&remote);
        drop(released);
    }

    /// The socket a send to `peer` must leave by, when a route holds it.
    pub(super) fn route(&self, peer: PeerEndpoint) -> Option<Arc<UdpSocket>> {
        let PeerEndpoint::V4(peer) = peer else {
            return None;
        };
        let routes = self.routes.lock().expect("prediction routes");
        if routes.is_empty() {
            return None;
        }
        routes
            .get(&SocketAddrV4::new(peer.ip, peer.port))
            .map(|route| Arc::clone(&route.socket.socket))
    }

    /// The Fan inlet's receiving half, for the pump's `select!`.
    pub(super) fn inlet(&self) -> &tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, PeerEndpoint)>> {
        &self.inlet_rx
    }
}

/// One Fan socket's reader: drop everything not from `peer`; on the first
/// datagram from it while no route holds that endpoint, route it here, answer
/// once, and report the hit; hand every datagram from `peer` to the inlet.
///
/// `holder` is the socket's own [`FanSocket`], held weakly: a route is
/// installed only while something still holds the socket — the Fan, or an
/// earlier route — so a Fan that closed installs nothing more.
async fn read_fan_socket(
    socket: Arc<UdpSocket>,
    holder: Weak<FanSocket>,
    peer: SocketAddrV4,
    answer: Vec<u8>,
    routes: Routes,
    inlet: mpsc::Sender<(Vec<u8>, PeerEndpoint)>,
    on_hit: PredictionHit,
) {
    let mut buf = vec![0u8; FAN_RECV_LEN];
    let mut answered = false;
    loop {
        let Ok((len, from)) = socket.recv_from(&mut buf).await else {
            return;
        };
        let SocketAddr::V4(from) = from else { continue };
        if from != peer {
            continue;
        }
        let routed_here = {
            let mut routes = routes.lock().expect("prediction routes");
            match routes.entry(from) {
                Entry::Occupied(_) => false,
                Entry::Vacant(slot) => {
                    let Some(holder) = holder.upgrade() else {
                        return;
                    };
                    slot.insert(Route { socket: holder });
                    true
                }
            }
        };
        if routed_here {
            on_hit(from);
            if !answered {
                answered = true;
                let _ = socket.send_to(&answer, SocketAddr::V4(from)).await;
            }
        }
        let endpoint = crate::family::endpoint_of(SocketAddr::V4(from));
        if inlet.send((buf[..len].to_vec(), endpoint)).await.is_err() {
            return;
        }
    }
}
