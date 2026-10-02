//! The same-socket serve half of a connection rmule dialed (ADR-0031): a peer
//! that asks *us* for a file over the connection we opened to *it* is admitted
//! to the one upload slot queue exactly like an accepted connection.

use std::sync::Arc;

use rmule_net::peer::Connection as PeerConnection;
use rmule_peer::{PeerCommand, PeerEvent, SourceExchangeSupport};
use tokio::sync::{Mutex, mpsc};

use super::kad_runtime::{SharedKadBootstrap, broker_peer_kad_handoff};
use super::peer_transfer::PeerWorkerEvent;
use super::serve_projection::{
    is_server_capability_event, serve_command_to_peer, serve_event_from_peer,
};
use super::serve_runtime::{ServeConnCommand, ServeConnEvent, ServeConnection};

/// The slot through which dialed connections reach the serve activity.
/// `RuntimePeerTransferService` pushes each dialed connection's serve half
/// here; `StartServing` installs the sender and hands the receiver to the
/// `ServeTask`, so a same-socket requester is admitted to the one
/// `UploadSlotQueue` exactly like an accepted connection. **Empty while not
/// serving** — dialed connections then never produce a serve half, and the
/// router drops their Server Capability requests. Mirrors ADR-0032's
/// `SharedServerSession` slot.
pub(crate) type SharedDialedServeSink = Arc<Mutex<Option<mpsc::Sender<ServeConnection>>>>;

/// Where a dialed connection's router sends what the socket reads, built by
/// the worker that owns the connection: the download half, the serve half,
/// the worker event stream, and the node-wide folds a hello feeds.
pub(crate) struct DialedRoute {
    /// Requester Capability events, to the download half.
    pub(crate) requester_tx: mpsc::Sender<PeerEvent>,
    /// Server Capability events, to the serve half.
    pub(crate) server_tx: mpsc::Sender<PeerEvent>,
    /// Connection facts the download keeps (source exchange, identity, contact).
    pub(crate) worker_evt_tx: mpsc::Sender<PeerWorkerEvent>,
    /// An adopted connection's source-exchange facts, read from its hello at
    /// accept; `None` for a dialed one, whose hello the router reads itself.
    pub(crate) adopted_support: Option<SourceExchangeSupport>,
    /// The ed2k→Kad handoff a hello's Kad hint feeds (ADR-0067).
    pub(crate) kad_bootstrap: SharedKadBootstrap,
    /// The IPv6 quorum a hello's reflection votes into (ADR-0084/0087).
    pub(crate) addresses: crate::address_learning::SharedAddressLearning,
}

/// Own one dialed `PeerConnection` and split it into the two consumers
/// ADR-0031 names: every inbound `PeerEvent` is fanned to the **download** half
/// (Requester Capability) or the **serve** half (Server Capability), and
/// `PeerCommand`s from either half are framed onto the one socket. The concrete
/// "two consumers over one connection" for a dialed connection — the
/// session is already bidirectional, so this is pure orchestration.
///
/// The socket is shut down when every command sender is dropped (the download
/// worker finished and — if serving — the serve bridge closed) or the peer
/// disconnects. `Disconnected` is delivered to **both** halves so each frees
/// its per-connection state.
///
/// The router is the one sender of the peer's source-exchange facts to the
/// download (ADR-0108), so they reach it in the session's order: the hello's
/// at `PeerIdentified` — or, for an adopted connection whose hello was read at
/// accept, `adopted_support` before anything else — then each file request's
/// and each `OP_EMULEINFO` revision's.
pub(crate) async fn route_dialed_connection(
    mut conn: PeerConnection,
    mut peer_cmd_rx: mpsc::Receiver<PeerCommand>,
    route: DialedRoute,
) {
    let DialedRoute {
        requester_tx,
        server_tx,
        worker_evt_tx,
        adopted_support,
        kad_bootstrap,
        addresses,
    } = route;
    if let Some(support) = adopted_support {
        let _ = worker_evt_tx
            .send(PeerWorkerEvent::SourceExchange { support })
            .await;
    }
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
                    if conn.send(PeerCommand::Disconnect).await.is_err() {
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
                if matches!(event, PeerEvent::Disconnected { .. }) {
                    let _ = requester_tx.send(event.clone()).await;
                    let _ = server_tx.send(event).await;
                    break;
                }
                if let PeerEvent::PeerIdentified { identity } = &event {
                    // ed2k→Kad handoff (ADR-0067): a dialed peer that carries
                    // a Kad node hint bootstraps our Kad node — aMule's
                    // `ConnectionEstablished` handoff on the outbound side too. A
                    // no-op unless the peer advertised a usable Kad contact and
                    // Kad is running.
                    broker_peer_kad_handoff(
                        &kad_bootstrap,
                        conn.peer_endpoint(),
                        identity,
                    )
                    .await;
                    // And its `CT_MOD_YOUR_IP` reflection casts one vote into
                    // the IPv6 quorum (ADR-0084/0087), the dial side of the
                    // same fold.
                    crate::address_learning::record_peer_ipv6_vote(
                        &addresses,
                        conn.peer_endpoint(),
                        identity,
                    );
                    // The hello's source-exchange facts, ahead of any revision
                    // the session reads after it (ADR-0108).
                    let _ = worker_evt_tx
                        .send(PeerWorkerEvent::SourceExchange {
                            support: identity.source_exchange(),
                        })
                        .await;
                    // Both halves need identify: the download half to proceed
                    // past the handshake, the serve half to key credit.
                    let _ = requester_tx.send(event.clone()).await;
                    let _ = server_tx.send(event).await;
                    continue;
                }
                // A connection-lifecycle fact (ADR-0041), forwarded straight to
                // the worker event stream: the transfer loops drain requester
                // events only while a command is in flight, so routing it there
                // would park the verification behind an idle worker.
                let event = match event {
                    PeerEvent::PeerIdentityVerified { user_hash, public_key } => {
                        let _ = worker_evt_tx
                            .send(PeerWorkerEvent::IdentityVerified { user_hash, public_key })
                            .await;
                        continue;
                    }
                    // Both halves show the peer's software: the source
                    // row through the worker stream, the upload row through
                    // the serve half.
                    // The reask contact an `OP_EMULEINFO` named, to both
                    // halves as the hello's is: the worker's reask pool and
                    // the serve side's wait list.
                    PeerEvent::PeerReaskContactRevised {
                        udp_port,
                        udp_version,
                    } => {
                        let _ = worker_evt_tx
                            .send(PeerWorkerEvent::UdpContact {
                                udp_port,
                                udp_version,
                            })
                            .await;
                        let _ = server_tx
                            .send(PeerEvent::PeerReaskContactRevised {
                                udp_port,
                                udp_version,
                            })
                            .await;
                        continue;
                    }
                    // The source-exchange facts the session framed the
                    // file request under, and whether it asked (ADR-0108),
                    // and any later revision by an `OP_EMULEINFO`: the
                    // download half alone keeps them, in the session's order.
                    PeerEvent::FileRequestSent {
                        support,
                        sources_asked,
                        ..
                    } => {
                        let _ = worker_evt_tx
                            .send(PeerWorkerEvent::SourceExchange { support })
                            .await;
                        if sources_asked {
                            let _ = worker_evt_tx.send(PeerWorkerEvent::SourcesAsked).await;
                        }
                        continue;
                    }
                    PeerEvent::PeerSourceExchangeRevised { support } => {
                        let _ = worker_evt_tx
                            .send(PeerWorkerEvent::SourceExchange { support })
                            .await;
                        continue;
                    }
                    PeerEvent::PeerSoftwareRevised { software } => {
                        let _ = worker_evt_tx
                            .send(PeerWorkerEvent::SoftwareRevised {
                                software: software.clone(),
                            })
                            .await;
                        let _ = server_tx
                            .send(PeerEvent::PeerSoftwareRevised { software })
                            .await;
                        continue;
                    }
                    event => event,
                };
                if is_server_capability_event(&event) {
                    // A closed serve half (not serving / serve task gone) just
                    // drops the request; the download half keeps running.
                    let _ = server_tx.send(event).await;
                } else if requester_tx.send(event).await.is_err() {
                    // The download worker is gone; drop its events and keep the
                    // socket alive for the serve half. The loop still exits when
                    // every `peer_cmd_tx` is dropped or the peer disconnects.
                    continue;
                }
            }
        }
    }
    let _ = conn.shutdown().await;
}

/// Translate the serve half of a dialed connection both ways: the router's
/// Server Capability `PeerEvent`s become `ServeConnEvent`s for the serve task,
/// and the serve task's `ServeConnCommand`s become `PeerCommand`s framed onto
/// the shared socket via `peer_cmd_tx`. Unlike `translate_serve_connection`
/// (which owns the whole socket for an accepted connection), here the socket
/// is shared with the download half, so a serve-flow end (`Disconnect`) stops
/// serving **without** tearing the socket down — the download half may still
/// be pulling. Dropping this task's `peer_cmd_tx` clone lets the router close
/// the socket once the download half is also done.
pub(crate) async fn bridge_dialed_serve(
    mut server_rx: mpsc::Receiver<PeerEvent>,
    mut serve_cmd_rx: mpsc::Receiver<ServeConnCommand>,
    peer_cmd_tx: mpsc::Sender<PeerCommand>,
    serve_evt_tx: mpsc::Sender<ServeConnEvent>,
) {
    loop {
        tokio::select! {
            command = serve_cmd_rx.recv() => {
                let Some(command) = command else { break };
                if matches!(command, ServeConnCommand::Disconnect) {
                    break;
                }
                if peer_cmd_tx.send(serve_command_to_peer(command)).await.is_err() {
                    break;
                }
            }
            event = server_rx.recv() => {
                let Some(event) = event else { break };
                if let Some(serve) = serve_event_from_peer(event) {
                    let disconnected = matches!(serve, ServeConnEvent::Disconnected);
                    if serve_evt_tx.send(serve).await.is_err() || disconnected {
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
