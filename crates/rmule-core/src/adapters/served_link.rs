//! The **Served Link**: an accepted link that took the serve road, and the one
//! road a download takes to that peer while the link lives (ADR-0107, "One
//! peer, one link").
//!
//! aMule holds one client per peer and asks it for a download over the socket
//! it already has (`BaseClient.cpp:1489-1496`); a second link from the same
//! address and port makes it drop the first (`ClientList.cpp:400-403`), and
//! whatever the first carried — our upload to it — ends. So every served link
//! is filed under the address a dial would reach its peer at — the link's own
//! address with the hello's listen port, the address the peer is a source at
//! — and a download about to dial that address joins the link instead: its
//! requests go out on the link, the link's requester events come back to it,
//! and the link stays up while either half still needs it, as a dialed link
//! does (ADR-0031). One download rides a link at a time; another dials.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rmule_net::peer::Connection as PeerConnection;
use rmule_peer::{ConnectionEvent, PeerCommand, PeerEvent, PeerIdentity, RequesterEvent};
use rmule_primitives::PeerEndpoint;
use tokio::sync::{mpsc, oneshot};

use super::InboundPeerDeps;
use super::inbound_triage::serve_side;
use super::peer_transfer::PeerWorkerEvent;
use super::serve_runtime::{ServeInput, ServeOutput};
use crate::service::PortTestClosedBy;

/// The served links, each under the address a dial would reach its peer at.
/// One cell shared by the accept path, which files each link, and the dial
/// path, which joins one (ADR-0048 "Identity ownership").
#[derive(Clone, Default)]
pub(crate) struct SharedServedLinks(Arc<Mutex<Book>>);

#[derive(Default)]
struct Book {
    filed: u64,
    links: HashMap<PeerEndpoint, (u64, mpsc::Sender<LinkJoin>)>,
}

/// A download's ask to ride a served link, answered with the peer's identity
/// as the link holds it.
struct LinkJoin {
    half: DownloadHalf,
    accepted: oneshot::Sender<PeerIdentity>,
}

/// A download's half of a served link.
struct DownloadHalf {
    /// The link's requester events and its close, to the worker.
    requester_tx: mpsc::Sender<PeerEvent>,
    /// The identity revisions and source asks the download keeps.
    worker_evt_tx: mpsc::Sender<PeerWorkerEvent>,
    /// The worker's commands, framed onto the link; closed when it is done.
    peer_cmd_rx: mpsc::Receiver<PeerCommand>,
}

/// A served link a download joined: the peer as the link knows it, and the
/// download's two ends of the link.
pub(crate) struct JoinedLink {
    pub(crate) identity: PeerIdentity,
    pub(crate) peer_cmd_tx: mpsc::Sender<PeerCommand>,
    pub(crate) requester_rx: mpsc::Receiver<PeerEvent>,
}

impl SharedServedLinks {
    /// File a served link under `dial` for as long as the returned filing
    /// lives. A link filed later under the same address replaces this one:
    /// aMule keeps a client on its newest socket.
    fn file(&self, dial: PeerEndpoint) -> (Filing, mpsc::Receiver<LinkJoin>) {
        let (join_tx, join_rx) = mpsc::channel(1);
        let mut book = self.0.lock().expect("served links lock");
        book.filed += 1;
        let filed = book.filed;
        book.links.insert(dial, (filed, join_tx));
        let filing = Filing {
            links: self.clone(),
            dial,
            filed,
        };
        (filing, join_rx)
    }

    /// Join the served link filed under `peer`, reporting to `worker_evt_tx`;
    /// `None` when no link is filed there, it ended, or a download rides it
    /// already — the caller dials then.
    pub(crate) async fn join(
        &self,
        peer: PeerEndpoint,
        worker_evt_tx: &mpsc::Sender<PeerWorkerEvent>,
    ) -> Option<JoinedLink> {
        let link = {
            let book = self.0.lock().expect("served links lock");
            book.links.get(&peer).map(|(_, join_tx)| join_tx.clone())?
        };
        let (peer_cmd_tx, peer_cmd_rx) = mpsc::channel(16);
        let (requester_tx, requester_rx) = mpsc::channel(64);
        let (accepted, answer) = oneshot::channel();
        let half = DownloadHalf {
            requester_tx,
            worker_evt_tx: worker_evt_tx.clone(),
            peer_cmd_rx,
        };
        link.send(LinkJoin { half, accepted }).await.ok()?;
        let identity = answer.await.ok()?;
        Some(JoinedLink {
            identity,
            peer_cmd_tx,
            requester_rx,
        })
    }
}

/// One link's place in the book, given up when the link ends — unless a newer
/// link took the address since.
struct Filing {
    links: SharedServedLinks,
    dial: PeerEndpoint,
    filed: u64,
}

impl Drop for Filing {
    fn drop(&mut self) {
        if let Ok(mut book) = self.links.0.lock()
            && book
                .links
                .get(&self.dial)
                .is_some_and(|(filed, _)| *filed == self.filed)
        {
            book.links.remove(&self.dial);
        }
    }
}

/// Drive one accepted, identified link that took the serve road, filed as a
/// **Served Link** so a download of its peer can ride it. Its `Server`
/// requests and `Connection` facts go up to the serve task, its side-channel
/// frames to the node-wide services, and the serve task's commands down to
/// the session — and, once a download joined, that download's commands down
/// and its requester events back. Runs until the peer closes, or until
/// neither the serve side nor a download holds the link any more.
///
/// Three buddy legs live here (socket unification, ADR-0061): an inbound
/// `OP_BUDDYPING` routes to the buddy slot — which pongs back **on this same
/// held link** iff this connection is the attached buddy link — an inbound
/// `OP_CALLBACK` is consumed on *any* served link, and the connection's close
/// detaches the held link, freeing the buddy slot at once (aMule frees
/// `m_pBuddy` when the buddy's socket dies).
///
/// Returns who closed the connection: the peer session's own close reason
/// when it ended there, rmule when every half let it go.
pub(super) async fn drive_served_link(
    mut conn: PeerConnection,
    mut identity: PeerIdentity,
    mut command_rx: mpsc::Receiver<ServeOutput>,
    event_tx: mpsc::Sender<ServeInput>,
    deps: InboundPeerDeps,
) -> PortTestClosedBy {
    let remote = conn.peer_endpoint();
    let (_filing, joins) = deps
        .served_links
        .file(remote.with_port(identity.tcp_port()));
    let mut joins = Some(joins);
    let mut serving = true;
    let mut download: Option<DownloadHalf> = None;
    let closed_by = loop {
        tokio::select! {
            command = command_rx.recv(), if serving => match command {
                Some(ServeOutput::Server(command)) => {
                    if conn.send(PeerCommand::Server(command)).await.is_err() {
                        // The driver stopped first; its paired `Disconnected`
                        // is queued behind whatever it said before.
                        break close_reason(&mut conn).await;
                    }
                }
                // The serve side let the link go: it ends with it, unless a
                // download still rides it.
                None | Some(ServeOutput::Disconnect) => {
                    if download.is_none() {
                        break PortTestClosedBy::Us;
                    }
                    serving = false;
                }
            },
            join = recv_join(&mut joins), if joins.is_some() => match join {
                // A link carries one download at a time; a second one is
                // refused and dials.
                Some(LinkJoin { half, accepted }) => {
                    if download.is_none() && accepted.send(identity.clone()).is_ok() {
                        download = Some(half);
                    }
                }
                // A newer link of the same peer took the address.
                None => joins = None,
            },
            command = recv_download(&mut download), if download.is_some() => match command {
                Some(command) => {
                    if conn.send(command).await.is_err() {
                        break close_reason(&mut conn).await;
                    }
                }
                None => {
                    download = None;
                    if !serving {
                        break PortTestClosedBy::Us;
                    }
                }
            },
            event = conn.next_event() => {
                let Some(event) = event else {
                    if serving {
                        let _ = event_tx.send(ServeInput::closed_here()).await;
                    }
                    break PortTestClosedBy::DriverEnded;
                };
                match route(&deps, remote, event, &mut identity, &event_tx, serving, download.as_ref()).await {
                    Routed::Open => {}
                    Routed::ServeGone => {
                        if download.is_none() {
                            break PortTestClosedBy::Us;
                        }
                        serving = false;
                    }
                    Routed::Closed(closed_by) => break closed_by,
                }
            }
        }
    };
    let _ = conn.shutdown().await;
    // When this connection was the held buddy link, its close frees the
    // buddy slot at once so a fresh recruit can take it.
    if deps.buddy_slot.on_link_closed(remote) {
        tracing::debug!(
            peer = ?remote,
            "held buddy link closed; buddy slot released"
        );
    }
    closed_by
}

/// What routing one event left of the link.
enum Routed {
    Open,
    /// The serve task is gone; the link lives on only for a download.
    ServeGone,
    /// The peer closed it, and this is who closed it.
    Closed(PortTestClosedBy),
}

/// Carry one event read off the link to the halves that keep it: the serve
/// task while `serving`, the joined `download` when there is one, and the
/// node-wide services for a side-channel frame. `identity` follows the
/// session's revisions, so a download joining later starts from the current
/// one.
async fn route(
    deps: &InboundPeerDeps,
    remote: PeerEndpoint,
    event: PeerEvent,
    identity: &mut PeerIdentity,
    event_tx: &mpsc::Sender<ServeInput>,
    serving: bool,
    download: Option<&DownloadHalf>,
) -> Routed {
    let input = match event {
        PeerEvent::Server(request) => ServeInput::Server(request),
        PeerEvent::Connection(fact) => {
            if let ConnectionEvent::IdentityRevised {
                identity: revised, ..
            } = &fact
            {
                *identity = revised.clone();
                if let Some(download) = download {
                    let _ = download
                        .worker_evt_tx
                        .send(PeerWorkerEvent::Identity(revised.clone()))
                        .await;
                }
            }
            if let ConnectionEvent::Disconnected { reason } = &fact {
                let closed_by = PortTestClosedBy::from(reason);
                if let Some(download) = download {
                    let _ = download
                        .requester_tx
                        .send(PeerEvent::Connection(fact.clone()))
                        .await;
                }
                if serving {
                    let _ = event_tx.send(ServeInput::Connection(fact)).await;
                }
                return Routed::Closed(closed_by);
            }
            ServeInput::Connection(fact)
        }
        PeerEvent::Side(side) => {
            serve_side(deps, remote, side);
            return Routed::Open;
        }
        // Whether the joined download's file request carried a source ask
        // (ADR-0108), as a dialed link's router reports it.
        PeerEvent::Requester(RequesterEvent::FileRequestSent { sources_asked, .. }) => {
            if sources_asked && let Some(download) = download {
                let _ = download
                    .worker_evt_tx
                    .send(PeerWorkerEvent::SourcesAsked)
                    .await;
            }
            return Routed::Open;
        }
        // The link's own pull and its notices are the joined download's; with
        // none they concern nobody.
        event @ (PeerEvent::Requester(_) | PeerEvent::Notice(_)) => {
            if let Some(download) = download {
                let _ = download.requester_tx.send(event).await;
            }
            return Routed::Open;
        }
    };
    if serving && event_tx.send(input).await.is_err() {
        return Routed::ServeGone;
    }
    Routed::Open
}

async fn recv_join(joins: &mut Option<mpsc::Receiver<LinkJoin>>) -> Option<LinkJoin> {
    match joins {
        Some(joins) => joins.recv().await,
        None => std::future::pending().await,
    }
}

async fn recv_download(download: &mut Option<DownloadHalf>) -> Option<PeerCommand> {
    match download {
        Some(download) => download.peer_cmd_rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Drain a connection whose driver has stopped to its paired `Disconnected`
/// and say who closed it.
async fn close_reason(conn: &mut PeerConnection) -> PortTestClosedBy {
    while let Some(event) = conn.next_event().await {
        if let PeerEvent::Connection(ConnectionEvent::Disconnected { reason }) = event {
            return (&reason).into();
        }
    }
    PortTestClosedBy::DriverEnded
}

#[cfg(test)]
mod tests;
