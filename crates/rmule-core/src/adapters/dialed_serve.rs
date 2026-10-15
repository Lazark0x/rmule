//! The same-socket serve half of a connection rmule dialed (ADR-0031): a peer
//! that asks *us* for a file over the connection we opened to *it* is admitted
//! to the one upload slot queue exactly like an accepted connection.

use rmule_net::peer::Connection as PeerConnection;
use rmule_peer::{
    ConnectionCommand, ConnectionEvent, PeerCommand, PeerEvent, PeerIdentity, RequesterEvent,
};
use rmule_primitives::PeerEndpoint;
use tokio::sync::mpsc;

use super::InboundPeerDeps;
use super::inbound_triage::serve_side;
use super::kad_runtime::broker_peer_kad_handoff;
use super::peer_link::{DownloadHalf, Filing, LinkJoin, LinkName, Riders, recv_join};
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
/// the worker that owns the connection: the download that dialed it — the
/// link's first rider — the serve half, and the node-wide folds a hello
/// feeds.
pub(crate) struct DialedRoute {
    /// The download that dialed or adopted the link: its Requester
    /// Capability events and the facts it waits on go to it, and its
    /// commands come from it.
    pub(crate) rider: DownloadHalf,
    /// Server Capability requests and the connection facts the serve side
    /// keeps, to the serve half.
    pub(crate) server_tx: mpsc::Sender<ServeInput>,
    /// The serve half's commands, framed onto the link; closed when serving
    /// ends, or at once when the node does not serve.
    pub(crate) serve_cmd_rx: mpsc::Receiver<PeerCommand>,
    /// The node-wide services a hello feeds (the ed2k→Kad handoff, the IPv6
    /// quorum) and a side-channel frame is carried to — the same ones an
    /// accepted link reaches, since aMule's handlers do not ask who dialed —
    /// and the Peer Links the link is filed in once identified.
    pub(crate) deps: InboundPeerDeps,
    /// The identity an adopted link's accept side read off its hello; `None`
    /// for a dialed link, whose hello is still to come.
    pub(crate) identified: Option<PeerIdentity>,
}

/// Own one dialed `PeerConnection` and split it into the two consumers
/// ADR-0031 names: every inbound `PeerEvent` is routed by its group — the
/// **download** riding the link takes the Requester group, the **serve** half
/// the Server group, the connection facts go where each is kept — and
/// `PeerCommand`s from either half are framed onto the one socket.
///
/// Once the peer is identified the link is a **Peer Link** (ADR-0107, "One
/// peer, one link"): filed under every name its hello proves, so another
/// download of the peer rides it in turn instead of dialing a second link
/// aMule would answer by dropping this one. One download rides at a time;
/// when the rider's worker lets go, the oldest waiter takes the link.
///
/// The socket is shut down when the serve half and every download let it go,
/// or the peer disconnects. `Disconnected` is delivered to the rider and the
/// serve half so each frees its per-connection state; a waiter learns the
/// link ended and dials.
///
/// The router is the one sender of the peer's identity to the rider once the
/// connection is up, so it reaches the download in the session's order:
/// whole at `Identified` (an adopted connection's worker sends the one the
/// accept side read before this router starts), then whole again at each
/// `IdentityRevised` — the source-exchange facts the Source Ask Clock reads
/// among them (ADR-0108).
pub(crate) async fn route_dialed_connection(mut conn: PeerConnection, route: DialedRoute) {
    let DialedRoute {
        rider,
        server_tx,
        mut serve_cmd_rx,
        deps,
        identified,
    } = route;
    let remote = conn.peer_endpoint();
    let mut riders = Riders::seated(rider);
    // A link rmule dialed reaches the peer where it was dialed, whatever
    // listen port its hello names; an adopted link's remote end is the
    // peer's own dial out, which no dial reaches.
    let dialed_at = identified.is_none().then_some(remote);
    let mut link = DialedLink {
        dialed_at,
        identity: None,
        filing: None,
        joins: None,
    };
    if let Some(identity) = identified {
        link.identified(&deps, remote, identity);
    }
    let halves = Halves {
        server_tx,
        deps: &deps,
    };
    let mut serving = true;
    // Set once every half let go: the session was told to close after the
    // last command, and the events it read before closing are still
    // forwarded — a file request's report among them — until it stops or the
    // grace runs out.
    let mut closing: Option<tokio::time::Instant> = None;
    loop {
        let open = closing.is_none();
        tokio::select! {
            command = riders.next_command(), if open => match command {
                Some(command) => {
                    if conn.send(command).await.is_err() {
                        break;
                    }
                }
                None => {
                    riders.rider_left(link.identity.as_ref());
                    if !serving && riders.is_empty() {
                        closing = close(&mut conn).await;
                        if closing.is_none() {
                            break;
                        }
                    }
                }
            },
            command = serve_cmd_rx.recv(), if open && serving => match command {
                Some(command) => {
                    if conn.send(command).await.is_err() {
                        break;
                    }
                }
                None => {
                    serving = false;
                    if riders.is_empty() {
                        closing = close(&mut conn).await;
                        if closing.is_none() {
                            break;
                        }
                    }
                }
            },
            join = recv_join(&mut link.joins), if open && link.joins.is_some() => match (join, &link.identity) {
                (Some(join), Some(identity)) => riders.take(join, identity),
                (Some(_), None) => {}
                // Every name of the link went to newer links.
                (None, _) => link.joins = None,
            },
            () = tokio::time::sleep_until(closing.unwrap_or_else(tokio::time::Instant::now)),
                if closing.is_some() => break,
            event = conn.next_event() => {
                let Some(event) = event else { break }; // driver/peer gone
                match halves.dispatch(remote, event, riders.rider()).await {
                    Routed::Open => {}
                    Routed::Identified(identity) => link.identified(&deps, remote, identity),
                    Routed::Revised(identity) => link.revised(remote, identity),
                    Routed::Offered(answer) => {
                        if let Some(answer) = answer
                            && conn.send(PeerCommand::Connection(answer)).await.is_err()
                        {
                            break;
                        }
                    }
                    Routed::Closed => break,
                }
            }
        }
    }
    let _ = conn.shutdown().await;
}

/// Tell the session to close behind the commands it already has; the grace
/// deadline, or `None` when the driver is gone already.
async fn close(conn: &mut PeerConnection) -> Option<tokio::time::Instant> {
    let disconnect = PeerCommand::Connection(ConnectionCommand::Disconnect);
    conn.send(disconnect).await.ok()?;
    Some(tokio::time::Instant::now() + rmule_net::driver::SHUTDOWN_GRACE)
}

/// What a dialed link knows of its peer and where it is filed.
struct DialedLink {
    /// Where rmule dialed the peer, for a link it dialed.
    dialed_at: Option<PeerEndpoint>,
    identity: Option<PeerIdentity>,
    filing: Option<Filing>,
    joins: Option<mpsc::Receiver<LinkJoin>>,
}

impl DialedLink {
    /// The peer identified: file the link under its names.
    fn identified(&mut self, deps: &InboundPeerDeps, remote: PeerEndpoint, identity: PeerIdentity) {
        let (filing, joins) = deps.peer_links.file(remote, self.names(remote, &identity));
        self.filing = Some(filing);
        self.joins = Some(joins);
        self.identity = Some(identity);
    }

    /// The names the link proves: its hello's, and where it was dialed.
    fn names(&self, remote: PeerEndpoint, identity: &PeerIdentity) -> Vec<LinkName> {
        let mut names = LinkName::of(remote, identity);
        if let Some(dialed_at) = self.dialed_at
            && !names.contains(&LinkName::Endpoint(dialed_at))
        {
            names.push(LinkName::Endpoint(dialed_at));
        }
        names
    }

    /// The session revised the peer: its names follow.
    fn revised(&mut self, remote: PeerEndpoint, identity: PeerIdentity) {
        let names = self.names(remote, &identity);
        if let Some(filing) = &mut self.filing {
            filing.refile(names);
        }
        self.identity = Some(identity);
    }
}

/// Whether the connection is still open after an event was routed, and what
/// it learned of the peer.
enum Routed {
    Open,
    Identified(PeerIdentity),
    Revised(PeerIdentity),
    /// The peer offered a changed Client ID; the answer, when it takes it.
    Offered(Option<ConnectionCommand>),
    Closed,
}

/// The halves a dialed link's events reach besides its rider.
struct Halves<'a> {
    server_tx: mpsc::Sender<ServeInput>,
    deps: &'a InboundPeerDeps,
}

impl Halves<'_> {
    /// Send one event to the half that keeps its group: the rider's, when
    /// one rides.
    async fn dispatch(
        &self,
        peer: PeerEndpoint,
        event: PeerEvent,
        rider: Option<&DownloadHalf>,
    ) -> Routed {
        match event {
            PeerEvent::Connection(fact) => return self.connection_fact(peer, fact, rider).await,
            // Whether the file request carried a source ask (ADR-0108): the
            // riding download alone stamps it. The facts it was framed under
            // are the identity's, which reached the download first.
            PeerEvent::Requester(RequesterEvent::FileRequestSent { sources_asked, .. }) => {
                if sources_asked && let Some(rider) = rider {
                    let _ = rider
                        .worker_evt_tx
                        .send(PeerWorkerEvent::SourcesAsked)
                        .await;
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
            PeerEvent::Side(side) => serve_side(self.deps, peer, side),
            // With no download riding, the link's own pull concerns nobody;
            // the socket stays up for the serve half and the waiters.
            event @ (PeerEvent::Requester(_) | PeerEvent::Notice(_)) => {
                if let Some(rider) = rider {
                    let _ = rider.requester_tx.send(event).await;
                }
            }
        }
        Routed::Open
    }

    /// Route one fact about the link to every half that keeps it.
    async fn connection_fact(
        &self,
        peer: PeerEndpoint,
        fact: ConnectionEvent,
        rider: Option<&DownloadHalf>,
    ) -> Routed {
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
                let fact = ConnectionEvent::Identified {
                    identity: identity.clone(),
                };
                if let Some(rider) = rider {
                    let _ = rider
                        .worker_evt_tx
                        .send(PeerWorkerEvent::Identity(identity.clone()))
                        .await;
                    // Both halves need identify: the download half to proceed
                    // past the handshake, the serve half to key credit.
                    let _ = rider
                        .requester_tx
                        .send(PeerEvent::Connection(fact.clone()))
                        .await;
                }
                let _ = self.server_tx.send(ServeInput::Connection(fact)).await;
                return Routed::Identified(identity);
            }
            ConnectionEvent::Disconnected { .. } => {
                if let Some(rider) = rider {
                    let _ = rider
                        .requester_tx
                        .send(PeerEvent::Connection(fact.clone()))
                        .await;
                }
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
                if let Some(rider) = rider {
                    let _ = rider
                        .worker_evt_tx
                        .send(PeerWorkerEvent::IdentityVerified {
                            user_hash,
                            public_key,
                        })
                        .await;
                }
            }
            // A revision, whole, to both halves that keep the identity: the
            // riding download's record and the serve side's connection.
            ConnectionEvent::IdentityRevised { ref identity, .. } => {
                let identity = identity.clone();
                if let Some(rider) = rider {
                    let _ = rider
                        .worker_evt_tx
                        .send(PeerWorkerEvent::Identity(identity.clone()))
                        .await;
                }
                let _ = self.server_tx.send(ServeInput::Connection(fact)).await;
                return Routed::Revised(identity);
            }
            // The rest is the download half's: the hello wait reads a refusal,
            // and nothing else here is kept by either half.
            // Whether a changed Low ID stands is the node's to say: it
            // knows the servers (ADR-0107).
            ConnectionEvent::ClientIdOffered { client_id, server } => {
                return Routed::Offered(self.deps.peer_links.take_client_id(client_id, server));
            }
            ConnectionEvent::HelloSent
            | ConnectionEvent::HelloRefused { .. }
            | ConnectionEvent::SecureIdentFailed { .. } => {
                if let Some(rider) = rider {
                    let _ = rider.requester_tx.send(PeerEvent::Connection(fact)).await;
                }
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
