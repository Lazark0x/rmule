//! The same-socket serve half of a connection rmule dialed (ADR-0031): a peer
//! that asks *us* for a file over the connection we opened to *it* is admitted
//! to the one upload slot queue exactly like an accepted connection.

use rmule_net::peer::Connection as PeerConnection;
use rmule_peer::{ConnectionCommand, ConnectionEvent, PeerCommand, PeerEvent, RequesterEvent};
use rmule_primitives::PeerEndpoint;
use tokio::sync::mpsc;

use super::InboundPeerDeps;
use super::inbound_triage::serve_side;
use super::kad_runtime::broker_peer_kad_handoff;
use super::peer_transfer::PeerWorkerEvent;
use super::serve_runtime::{ServeConnection, ServeInput, ServeOutput};

/// The slot through which dialed connections reach the serve activity.
/// `RuntimePeerTransferService` pushes each dialed connection's serve half
/// here; `StartServing` installs the sender and hands the receiver to the
/// `ServeTask`, so a same-socket requester is admitted to the one
/// `UploadSlotQueue` exactly like an accepted connection. **Empty while not
/// serving** — dialed connections then never produce a serve half, and the
/// router drops their Server Capability requests. Mirrors ADR-0032's
/// `SharedServerSession` slot.
pub(crate) type SharedDialedServeSink = crate::mailbox::Mailbox<ServeConnection>;

/// Where a dialed connection's router sends what the socket reads, built by
/// the worker that owns the connection: the download half, the serve half,
/// the worker event stream, and the node-wide folds a hello feeds.
pub(crate) struct DialedRoute {
    /// Requester Capability events and the facts the download waits on, to
    /// the download half.
    pub(crate) requester_tx: mpsc::Sender<PeerEvent>,
    /// Server Capability requests and the connection facts the serve side
    /// keeps, to the serve half.
    pub(crate) server_tx: mpsc::Sender<ServeInput>,
    /// Connection facts the download keeps: the peer's identity, whole at
    /// every revision, and its source asks.
    pub(crate) worker_evt_tx: mpsc::Sender<PeerWorkerEvent>,
    /// The node-wide services a hello feeds (the ed2k→Kad handoff, the IPv6
    /// quorum) and a side-channel frame is carried to — the same ones an
    /// accepted link reaches, since aMule's handlers do not ask who dialed.
    pub(crate) deps: InboundPeerDeps,
}

/// Own one dialed `PeerConnection` and split it into the two consumers
/// ADR-0031 names: every inbound `PeerEvent` is routed by its group — the
/// **download** half takes the Requester group (Requester Capability), the
/// **serve** half the Server group (Server Capability), the connection facts
/// go where each is kept — and `PeerCommand`s from either half are framed onto
/// the one socket. The concrete "two consumers over one connection" for a
/// dialed connection — the session is already bidirectional, so this is pure
/// orchestration.
///
/// The socket is shut down when every command sender is dropped (the download
/// worker finished and — if serving — the serve bridge closed) or the peer
/// disconnects. `Disconnected` is delivered to **both** halves so each frees
/// its per-connection state.
///
/// The router is the one sender of the peer's identity to the download once
/// the connection is up, so it reaches the download in the session's order:
/// whole at `Identified` (an adopted connection's worker sends the one the
/// accept side read before this router starts), then whole again at each
/// `IdentityRevised` — the source-exchange facts the Source Ask Clock reads
/// among them (ADR-0108).
pub(crate) async fn route_dialed_connection(
    mut conn: PeerConnection,
    mut peer_cmd_rx: mpsc::Receiver<PeerCommand>,
    route: DialedRoute,
) {
    // Set once every command sender let go: the session was told to close
    // after the last command, and the events it read before closing are still
    // forwarded — a file request's report among them — until it stops or the
    // grace runs out.
    let mut closing: Option<tokio::time::Instant> = None;
    loop {
        tokio::select! {
            command = peer_cmd_rx.recv(), if closing.is_none() => {
                // None: every sender dropped (download done and not serving) —
                // close the session behind the commands it already has.
                let Some(command) = command else {
                    let disconnect = PeerCommand::Connection(ConnectionCommand::Disconnect);
                    if conn.send(disconnect).await.is_err() {
                        break;
                    }
                    closing = Some(tokio::time::Instant::now() + rmule_net::driver::SHUTDOWN_GRACE);
                    continue;
                };
                if conn.send(command).await.is_err() {
                    break;
                }
            }
            () = tokio::time::sleep_until(closing.unwrap_or_else(tokio::time::Instant::now)),
                if closing.is_some() => break,
            event = conn.next_event() => {
                let Some(event) = event else { break }; // driver/peer gone
                if route.dispatch(conn.peer_endpoint(), event).await == Routed::Closed {
                    break;
                }
            }
        }
    }
    let _ = conn.shutdown().await;
}

/// Whether the connection is still open after an event was routed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Routed {
    Open,
    Closed,
}

impl DialedRoute {
    /// Send one event to the half that keeps its group.
    async fn dispatch(&self, peer: PeerEndpoint, event: PeerEvent) -> Routed {
        match event {
            PeerEvent::Connection(fact) => return self.connection_fact(peer, fact).await,
            // Whether the file request carried a source ask (ADR-0108): the
            // download half alone stamps it. The facts it was framed under
            // are the identity's, which reached the download first.
            PeerEvent::Requester(RequesterEvent::FileRequestSent { sources_asked, .. }) => {
                if sources_asked {
                    let _ = self.worker_evt_tx.send(PeerWorkerEvent::SourcesAsked).await;
                }
            }
            // A closed serve half (not serving / serve task gone) just drops
            // the request; the download half keeps running.
            PeerEvent::Server(request) => {
                let _ = self.server_tx.send(ServeInput::Server(request)).await;
            }
            // The side-channel frames (Kad firewall checks, buddy keepalive,
            // `0x99`) go where an accepted link's go: aMule's
            // `ClientTCPSocket.cpp` handlers run on whichever socket they
            // arrive on, whoever dialed it.
            PeerEvent::Side(side) => serve_side(&self.deps, peer, side),
            // A gone download worker drops its events; the socket stays up
            // for the serve half until every `peer_cmd_tx` is dropped or the
            // peer disconnects.
            event @ (PeerEvent::Requester(_) | PeerEvent::Notice(_)) => {
                let _ = self.requester_tx.send(event).await;
            }
        }
        Routed::Open
    }

    /// Route one fact about the link to every half that keeps it.
    async fn connection_fact(&self, peer: PeerEndpoint, fact: ConnectionEvent) -> Routed {
        match fact {
            ConnectionEvent::Identified { identity } => {
                // ed2k→Kad handoff (ADR-0067): a dialed peer that carries a
                // Kad node hint bootstraps our Kad node — aMule's
                // `ConnectionEstablished` handoff on the outbound side too. A
                // no-op unless the peer advertised a usable Kad contact and Kad
                // is running.
                broker_peer_kad_handoff(&self.deps.kad_bootstrap, peer, &identity).await;
                // And its `CT_MOD_YOUR_IP` reflection casts one vote into the
                // IPv6 quorum (ADR-0084/0087), the dial side of the same fold.
                crate::address_learning::record_peer_ipv6_vote(
                    &self.deps.addresses,
                    peer,
                    &identity,
                );
                // The identity, to the download ahead of the `Identified` its
                // worker waits on, so it precedes the worker's `Connected`
                // and every revision the session reads after it.
                let _ = self
                    .worker_evt_tx
                    .send(PeerWorkerEvent::Identity(identity.clone()))
                    .await;
                // Both halves need identify: the download half to proceed past
                // the handshake, the serve half to key credit.
                let fact = ConnectionEvent::Identified { identity };
                let _ = self
                    .requester_tx
                    .send(PeerEvent::Connection(fact.clone()))
                    .await;
                let _ = self.server_tx.send(ServeInput::Connection(fact)).await;
            }
            ConnectionEvent::Disconnected { .. } => {
                let _ = self
                    .requester_tx
                    .send(PeerEvent::Connection(fact.clone()))
                    .await;
                let _ = self.server_tx.send(ServeInput::Connection(fact)).await;
                return Routed::Closed;
            }
            // A connection-lifecycle fact (ADR-0041), forwarded straight to the
            // worker event stream: the transfer loops drain requester events
            // only while a command is in flight, so routing it there would park
            // the verification behind an idle worker.
            ConnectionEvent::IdentityVerified {
                user_hash,
                public_key,
            } => {
                let _ = self
                    .worker_evt_tx
                    .send(PeerWorkerEvent::IdentityVerified {
                        user_hash,
                        public_key,
                    })
                    .await;
            }
            // A revision, whole, to both halves that keep the identity: the
            // download's record and the serve side's connection.
            ConnectionEvent::IdentityRevised { ref identity, .. } => {
                let _ = self
                    .worker_evt_tx
                    .send(PeerWorkerEvent::Identity(identity.clone()))
                    .await;
                let _ = self.server_tx.send(ServeInput::Connection(fact)).await;
            }
            // The rest is the download half's: the hello wait reads a refusal,
            // and nothing else here is kept by either half.
            ConnectionEvent::HelloSent
            | ConnectionEvent::HelloRefused { .. }
            | ConnectionEvent::SecureIdentFailed { .. } => {
                let _ = self.requester_tx.send(PeerEvent::Connection(fact)).await;
            }
        }
        Routed::Open
    }
}

/// Carry the serve half of a dialed connection both ways: the router's serve
/// inputs reach the serve task as they are, and the serve task's outputs
/// become `PeerCommand`s framed onto the shared socket via `peer_cmd_tx`.
/// Unlike the accepted bridge (which owns the whole socket), here the socket
/// is shared with the download half, so a serve-flow end (`Disconnect`) stops
/// serving **without** tearing the socket down — the download half may still
/// be pulling. Dropping this task's `peer_cmd_tx` clone lets the router close
/// the socket once the download half is also done.
pub(crate) async fn bridge_dialed_serve(
    mut server_rx: mpsc::Receiver<ServeInput>,
    mut serve_cmd_rx: mpsc::Receiver<ServeOutput>,
    peer_cmd_tx: mpsc::Sender<PeerCommand>,
    serve_evt_tx: mpsc::Sender<ServeInput>,
) {
    loop {
        tokio::select! {
            command = serve_cmd_rx.recv() => {
                let command = match command {
                    None | Some(ServeOutput::Disconnect) => break,
                    Some(ServeOutput::Server(command)) => PeerCommand::Server(command),
                };
                if peer_cmd_tx.send(command).await.is_err() {
                    break;
                }
            }
            input = server_rx.recv() => {
                let Some(input) = input else { break };
                let disconnected = input.is_disconnect();
                if serve_evt_tx.send(input).await.is_err() || disconnected {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
