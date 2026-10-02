//! The datagram seams: server-UDP (global search, global source lookup, and
//! the callbacks servers relay back) and client-UDP (peer reask), each behind
//! a trait so core drives datagrams without owning a socket.

use std::future::Future;
use std::net::SocketAddrV4;
use std::sync::{Arc, Mutex};

use rmule_ed2k::GlobCallbackRequest;
use rmule_net::family::{RECEIVE_ERROR_BACKOFF, ReceiveErrorBudget, ReceiveErrorOutcome};
use rmule_primitives::{Ipv4Endpoint, ServerEndpoint};
use tokio::sync::mpsc;

use crate::global_sources::GlobCallbackSend;

/// Datagram transport for server-UDP global source discovery (ADR-0051). `&self`
/// (not `&mut`) so the discovery task can send and receive on one socket from the
/// two arms of its `select!`. Sending is fire-and-forget; a non-answering server
/// is harmless over UDP.
pub(crate) trait ServerUdpTransport: Send + Sync + 'static {
    /// Send one plain datagram to the server's UDP port (its TCP port + 4).
    fn send_to(&self, server: ServerEndpoint, datagram: Vec<u8>)
    -> impl Future<Output = ()> + Send;

    /// Send a raw obfuscated crypt-ping to the server's obfuscation UDP port
    /// (TCP + 12; ADR-0046), contrasting `send_to`'s plain TCP + 4. The
    /// datagram is sent **unencrypted** — the server keys its encrypted `0x97`
    /// reply's RC4 on the crypt-ping challenge the datagram carries.
    fn send_crypt_ping(
        &self,
        server: ServerEndpoint,
        datagram: Vec<u8>,
    ) -> impl Future<Output = ()> + Send;

    /// Await the next datagram and the address it came from. `None` means the
    /// socket is closed, which ends the discovery task.
    fn recv(&self) -> impl Future<Output = Option<(Vec<u8>, Ipv4Endpoint)>> + Send;
}

/// One server-UDP socket, two readers: the discovery engine's global channel
/// (`ask` + `recv`) and the global-callback relay both drive it through an `Arc`.
/// The trait's `&self` sends and receives are already `Sync`, so sharing needs
/// no extra synchronization.
impl<T: ServerUdpTransport> ServerUdpTransport for Arc<T> {
    fn send_to(
        &self,
        server: ServerEndpoint,
        datagram: Vec<u8>,
    ) -> impl Future<Output = ()> + Send {
        (**self).send_to(server, datagram)
    }

    fn send_crypt_ping(
        &self,
        server: ServerEndpoint,
        datagram: Vec<u8>,
    ) -> impl Future<Output = ()> + Send {
        (**self).send_crypt_ping(server, datagram)
    }

    fn recv(&self) -> impl Future<Output = Option<(Vec<u8>, Ipv4Endpoint)>> + Send {
        (**self).recv()
    }
}

/// The global-callback relay (ADR-0051): the socket-side consumer
/// of the runner's per-server callback channel. It rides the server-UDP
/// transport that owns the socket, not the discovery engine's global channel —
/// which is now purely ask + receive (this arm moved off it). Each
/// [`GlobCallbackSend`] a download's runner emits becomes an
/// `OP_GLOBCALLBACKREQUEST` UDP-sent to the source-server, carrying rmule's own
/// contact and the target Low-ID; the send adapter maps the server's TCP
/// endpoint to its UDP port (TCP + 4). Ends when every callback sender drops
/// (Core shutting down).
pub(crate) async fn relay_global_callbacks<T: ServerUdpTransport>(
    transport: T,
    mut callback_rx: mpsc::Receiver<GlobCallbackSend>,
) {
    while let Some(send) = callback_rx.recv().await {
        let datagram = GlobCallbackRequest::new(send.requester, send.low_id)
            .encode_packet()
            .encode_udp();
        if let Ok(server) =
            ServerEndpoint::new(send.source_server.ip.to_string(), send.source_server.port)
        {
            transport.send_to(server, datagram).await;
        }
    }
}

/// Production `ServerUdpTransport` over a bound UDP socket (ADR-0051). Sends are
/// fire-and-forget to IPv4-literal servers; a DNS-host server is skipped (no
/// resolved address yet), consistent with the connected-server limitation
/// (ADR-0039).
pub(crate) struct RuntimeServerUdpTransport {
    socket: rmule_net::ed2k::ServerUdpSocket,
    /// Consecutive-error budget for this transport's `recv`:
    /// shared with the Kad driver's and client-UDP's own receive arms
    /// (`rmule_net::family::ReceiveErrorBudget`), held across calls so only
    /// a *run* of errors — not one blip — ends the engine.
    receive_budget: Mutex<ReceiveErrorBudget>,
}

impl RuntimeServerUdpTransport {
    pub(crate) async fn bind(
        port: u16,
        address_families: rmule_net::family::FamilySelection,
    ) -> std::io::Result<Self> {
        Ok(Self {
            socket: rmule_net::ed2k::ServerUdpSocket::bind_with(port, address_families).await?,
            receive_budget: Mutex::new(ReceiveErrorBudget::new()),
        })
    }

    /// What the server-UDP pair's bind did — which families came up, and why
    /// any other did not: read once, at the bind, for the
    /// **Half-Bound Pair** fact beside the bind table (`rmule_net::family`).
    #[must_use]
    pub(crate) const fn binds(&self) -> &rmule_net::family::FamilyBinds {
        self.socket.binds()
    }
}

impl ServerUdpTransport for RuntimeServerUdpTransport {
    async fn send_to(&self, server: ServerEndpoint, datagram: Vec<u8>) {
        if let Some(addr) = ipv4_server_addr(&server, SERVER_UDP_PORT_OFFSET) {
            let _ = self.socket.send_to(addr, &datagram).await;
        }
    }

    async fn send_crypt_ping(&self, server: ServerEndpoint, datagram: Vec<u8>) {
        if let Some(addr) = ipv4_server_addr(&server, SERVER_UDP_OBFUSCATION_PORT_OFFSET) {
            let _ = self.socket.send_to(addr, &datagram).await;
        }
    }

    /// Narrow every inbound datagram to IPv4 — the **server-UDP family
    /// ruling** (ADR-0087's second amendment).
    ///
    /// The ruling is per opcode and is written down in the ADR; the short form
    /// is that almost no server-UDP *body* stands in the way. `0x96`/`0x97`,
    /// the three global-search requests, `0x9A`/`0x94` and `0xA2`/`0xA3` name
    /// no address at all, and `0x9B` already has an IPv6 form — the **Sentinel
    /// Source** block. What fixes the family is **rmule's own ask**: every
    /// datagram on this surface answers a request rmule sent, §4.7 resolves
    /// servers A-first, and `send_to` below reaches only an IPv4 literal — so a
    /// datagram arriving from IPv6 answers nothing rmule asked.
    ///
    /// One body can never widen whatever the ask does: `0x9C`
    /// `OP_GLOBCALLBACKREQUEST` writes **rmule's own** contact as
    /// `<ip u32><port u16>` for the server to relay to a firewalled third party
    /// that then dials it. `HasEd2kWireForm` governs — a native-IPv6 rmule has
    /// no 32-bit form and must be omitted — and for a request whose entire
    /// content is that address, omitting is dropping. That is ADR-0087's `0x94`
    /// ruling, one surface over.
    ///
    /// The client-UDP half does **not** narrow: its front hands the demux the
    /// family the datagram truly arrived in and takes the per-opcode decision
    /// (`crate::client_udp`'s ruling table). The family decision belongs at the
    /// driver either way — never inside the pump, never inside a consumer.
    async fn recv(&self) -> Option<(Vec<u8>, Ipv4Endpoint)> {
        loop {
            match self.socket.recv().await {
                Ok((bytes, from)) => {
                    self.receive_budget
                        .lock()
                        .expect("server-UDP receive budget mutex poisoned")
                        .record_success();
                    match from.as_v4() {
                        Some(from) => return Some((bytes, from)),
                        None => tracing::debug!(
                            %from,
                            "dropping a server-UDP datagram from a family rmule never asked in"
                        ),
                    }
                }
                // A receive error was previously fatal on the very first
                // occurrence (`.ok()?`), ending global search, get-sources
                // and the status/desc chain over one transient blip. Now
                // tolerated up to the shared budget, same as the Kad
                // driver's and client-UDP's arms.
                Err(error) => {
                    // The lock guard must not outlive this statement: it is
                    // not `Send`, and the arm below awaits.
                    let outcome = self
                        .receive_budget
                        .lock()
                        .expect("server-UDP receive budget mutex poisoned")
                        .record_error(error.kind());
                    match outcome {
                        ReceiveErrorOutcome::Tolerated => {
                            tracing::debug!(%error, "transient server-UDP receive error");
                            tokio::time::sleep(RECEIVE_ERROR_BACKOFF).await;
                        }
                        ReceiveErrorOutcome::Exhausted { kind, consecutive } => {
                            tracing::warn!(
                                ?kind,
                                consecutive,
                                "server-UDP receive failed repeatedly; ending the engine"
                            );
                            return None;
                        }
                    }
                }
            }
        }
    }
}

/// Production [`ClientUdpTransport`](crate::client_udp::ClientUdpTransport) over
/// the shared client-UDP socket (ADR-0057): the demux front drains this to route
/// each inbound datagram (`0xC5` peer-UDP vs `0xE4`/`0xE5` Kad). The socket is
/// held behind an `Arc` so the reply drain (serve `SendClientUdp`) shares the one
/// bind for its sends.
pub(crate) struct RuntimeClientUdpTransport {
    socket: Arc<rmule_net::ed2k::ClientUdpSocket>,
    /// Consecutive-error budget for this transport's `recv`:
    /// shared with the Kad driver's and server-UDP's own receive arms
    /// (`rmule_net::family::ReceiveErrorBudget`), held across calls so only
    /// a *run* of errors — not one blip — ends the front.
    receive_budget: Mutex<ReceiveErrorBudget>,
}

impl RuntimeClientUdpTransport {
    pub(crate) fn new(socket: Arc<rmule_net::ed2k::ClientUdpSocket>) -> Self {
        Self {
            socket,
            receive_budget: Mutex::new(ReceiveErrorBudget::new()),
        }
    }
}

impl crate::client_udp::ClientUdpTransport for RuntimeClientUdpTransport {
    async fn recv(&self) -> Option<crate::client_udp::ClientUdpDatagram> {
        // Both families reach the front: the pair reports the family each
        // datagram truly arrived in and the demux front rules per opcode
        // (ADR-0087; `crate::client_udp`'s table). Narrowing here would decide
        // for every opcode at once, which is the thing ADR-0085 forbade.
        //
        // A receive error is tolerated up to the shared budget — the shared
        // UDP surface is lossy by nature (ICMP port-unreachable surfacing as
        // a receive error on some platforms) — but a *run* of them with no
        // successful receive between means a dead socket, not a lossy one.
        // Previously every error was retried forever, hot-spinning the front
        // the busy loop the closed-channel rule forbids; now the budget ends it deliberately,
        // and since Kad, the reask surface and NAT-T all ride this one socket
        // (ADR-0057), ending here is "the front went dark", counted and
        // logged once rather than spun forever.
        loop {
            match self.socket.recv().await {
                Ok((bytes, src)) => {
                    self.receive_budget
                        .lock()
                        .expect("client-UDP receive budget mutex poisoned")
                        .record_success();
                    return Some((src, bytes));
                }
                Err(error) => {
                    // The lock guard must not outlive this statement: it is
                    // not `Send`, and the arm below awaits.
                    let outcome = self
                        .receive_budget
                        .lock()
                        .expect("client-UDP receive budget mutex poisoned")
                        .record_error(error.kind());
                    match outcome {
                        ReceiveErrorOutcome::Tolerated => {
                            tracing::debug!(%error, "transient client-UDP receive error");
                            tokio::time::sleep(RECEIVE_ERROR_BACKOFF).await;
                        }
                        ReceiveErrorOutcome::Exhausted { kind, consecutive } => {
                            tracing::warn!(
                                ?kind,
                                consecutive,
                                "client-UDP receive failed repeatedly; ending the front \
                                 (Kad, reask and NAT-T all ride this one socket, ADR-0057)"
                            );
                            return None;
                        }
                    }
                }
            }
        }
    }
}

/// eD2k convention: a server's client-facing UDP port is its **TCP port + 4**
/// (aMule `ServerUDPSocket.cpp` — `SendPacket` targets `host->GetPort() + 4`, and
/// the receive side reads each answer's source as `port - 4`). The managed server
/// list holds TCP ports, so every plain server-UDP datagram (source queries and
/// per-server callbacks alike) is sent to that port + 4. Cite-and-rewrite only
/// (ADR-0004).
pub(crate) const SERVER_UDP_PORT_OFFSET: u16 = 4;

/// The **obfuscation** UDP port offset: a server's crypt datagrams target its
/// **TCP port + 12** (aMule `ServerList.cpp` — the obfuscated status ping's
/// `port_offset = 12`, and `GetServerByIPUDP` maps such a reply back via
/// `nUDPPort - 12`), contrasting the plain `+ 4` (ADR-0046).
pub(crate) const SERVER_UDP_OBFUSCATION_PORT_OFFSET: u16 = 12;

/// An IPv4-literal server's UDP address (its TCP port + `offset`), or `None`
/// for a DNS host or a port too high to offset.
fn ipv4_server_addr(server: &ServerEndpoint, offset: u16) -> Option<SocketAddrV4> {
    let udp_port = server.port().checked_add(offset)?;
    server
        .host()
        .parse::<std::net::Ipv4Addr>()
        .ok()
        .map(|ip| SocketAddrV4::new(ip, udp_port))
}

#[cfg(test)]
mod tests;
