//! An accepted link that took the serve road, or one the serve side dialed
//! back to a waiter it promoted (ADR-0057), driven as a **Peer Link**
//! (ADR-0107, "One peer, one link"): filed under every name its hello proves,
//! so a download of its peer rides it rather than dial a second link aMule
//! would answer by dropping this one (`ClientList.cpp:400-403`), ending our
//! upload to it. The link stays up while a download holds it, or its serve
//! side once the peer asked it anything, or the buddy slot, as a dialed link
//! does (ADR-0031, ADR-0107 invariant 9).

use rmule_net::peer::Connection as PeerConnection;
use rmule_peer::{
    ConnectionCommand, ConnectionEvent, PeerCommand, PeerEvent, PeerIdentity, RequesterCommand,
    RequesterEvent,
};
use rmule_primitives::PeerEndpoint;
use tokio::sync::mpsc;

use super::InboundPeerDeps;
use super::inbound_triage::serve_side;
use super::peer_link::{DialInFlight, LinkName, Riders, ServeHold, recv_join};
use super::peer_transfer::PeerWorkerEvent;
use super::serve_runtime::{ServeInput, ServeOutput};
use crate::service::PortTestClosedBy;

/// Drive one accepted, identified link that took the serve road, filed as a
/// **Peer Link** so a download of its peer can ride it. Its `Server` requests
/// and `Connection` facts go up to the serve task, its side-channel frames to
/// the node-wide services, and the serve task's commands down to the session
/// — and the riding download's commands down and its requester events back.
/// Runs until the peer closes, or until neither the serve side nor a download
/// holds the link any more: a download's leaving closes a link the peer never
/// asked anything over and the buddy slot does not hold (ADR-0107 invariant 9).
///
/// Three buddy legs live here (socket unification, ADR-0061): an inbound
/// `OP_BUDDYPING` routes to the buddy slot — which pongs back **on this same
/// held link** iff this connection is the attached buddy link — an inbound
/// `OP_CALLBACK` is consumed on *any* served link, and the connection's close
/// detaches the held link, freeing the buddy slot at once (aMule frees
/// `m_pBuddy` when the buddy's socket dies).
///
/// A link the serve side dialed back comes with its `dialed` Dial in Flight:
/// it keeps that filing, moved to its hello's names and where it was dialed,
/// and the serve side holds it from the dial.
///
/// Returns who closed the connection: the peer session's own close reason
/// when it ended there, rmule when every half let it go.
pub(super) async fn drive_served_link(
    mut conn: PeerConnection,
    mut identity: PeerIdentity,
    mut command_rx: mpsc::Receiver<ServeOutput>,
    event_tx: mpsc::Sender<ServeInput>,
    deps: InboundPeerDeps,
    dialed: Option<DialInFlight>,
) -> PortTestClosedBy {
    let remote = conn.peer_endpoint();
    let dialed_at = dialed.is_some().then_some(remote);
    let names = LinkName::proven(remote, &identity, dialed_at);
    let (mut filing, joins, mut serve) = match dialed {
        Some(dial) => {
            let (mut filing, joins) = dial.into_parts();
            filing.refile(names);
            (
                filing,
                joins,
                ServeHold::dialed(remote, deps.buddy_slot.clone()),
            )
        }
        None => {
            let (filing, joins) = deps.peer_links.file(remote, names);
            (
                filing,
                joins,
                ServeHold::new(remote, deps.buddy_slot.clone()),
            )
        }
    };
    let mut joins = Some(joins);
    let mut riders = Riders::default();
    let closed_by = loop {
        tokio::select! {
            command = command_rx.recv(), if serve.serving() => match command {
                Some(ServeOutput::Server(command)) => {
                    if conn.send(PeerCommand::Server(command)).await.is_err() {
                        // The driver stopped first; its paired `Disconnected`
                        // is queued behind whatever it said before.
                        break close_reason(&mut conn).await;
                    }
                }
                // The serve side let the link go: it ends with it, unless a
                // download still holds it.
                None | Some(ServeOutput::Disconnect) => {
                    if riders.is_empty() {
                        break PortTestClosedBy::Us;
                    }
                    serve.serve_ended();
                }
            },
            join = recv_join(&mut joins), if joins.is_some() => match join {
                Some(join) => riders.take(join, Some(&identity)),
                // Every name of the link went to newer links.
                None => joins = None,
            },
            command = riders.next_command() => match command {
                Some(command) => {
                    if conn.send(command).await.is_err() {
                        break close_reason(&mut conn).await;
                    }
                }
                None => {
                    // An unasked grant the leaving rider never asked on is
                    // nobody's now: it goes back before the link stays up for
                    // another half or closes (ADR-0056 item 3); the session
                    // sends nothing when none stands.
                    if riders.rider_left(Some(&identity)) {
                        let decline = PeerCommand::Requester(RequesterCommand::DeclineSlot);
                        if conn.send(decline).await.is_err() {
                            break close_reason(&mut conn).await;
                        }
                    }
                    if riders.is_empty() && !serve.holds() {
                        if serve.serving() {
                            let _ = event_tx.send(ServeInput::closed_here()).await;
                        }
                        break PortTestClosedBy::Us;
                    }
                }
            },
            event = conn.next_event() => {
                let Some(event) = event else {
                    if serve.serving() {
                        let _ = event_tx.send(ServeInput::closed_here()).await;
                    }
                    break PortTestClosedBy::DriverEnded;
                };
                let routed = route(&deps, remote, event, &mut identity, &event_tx, serve.serving(), riders.rider()).await;
                match routed {
                    Routed::Open => {}
                    Routed::Pulled => serve.pulled(),
                    Routed::Revised => {
                        filing.refile(LinkName::proven(remote, &identity, dialed_at));
                    }
                    Routed::Offered(answer) => {
                        if let Some(answer) = answer
                            && conn.send(PeerCommand::Connection(answer)).await.is_err()
                        {
                            break close_reason(&mut conn).await;
                        }
                    }
                    Routed::ServeGone => {
                        if riders.is_empty() {
                            break PortTestClosedBy::Us;
                        }
                        serve.serve_ended();
                    }
                    // An uploader's grant nobody on the link asked for: the
                    // download awaiting it rides the link, or it goes back
                    // (ADR-0057). A riding download's own ask is about to be
                    // granted.
                    Routed::SlotOffered => {
                        if !riders.is_ridden()
                            && !deps
                                .peer_links
                                .offer_grant(&LinkName::proven(remote, &identity, dialed_at))
                        {
                            let decline = PeerCommand::Requester(RequesterCommand::DeclineSlot);
                            if conn.send(decline).await.is_err() {
                                break close_reason(&mut conn).await;
                            }
                        }
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
    /// The peer asked the serve side something over the link.
    Pulled,
    /// The session revised the peer's identity; the link's names follow it.
    Revised,
    /// The peer offered a changed Client ID; the answer, when it takes it.
    Offered(Option<ConnectionCommand>),
    /// The serve task is gone; the link lives on only for a download.
    ServeGone,
    /// The peer granted a slot nobody on the link asked for.
    SlotOffered,
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
    download: Option<&super::peer_link::DownloadHalf>,
) -> Routed {
    let mut revised_now = false;
    let input = match event {
        PeerEvent::Server(request) => {
            if serving && event_tx.send(ServeInput::Server(request)).await.is_err() {
                return Routed::ServeGone;
            }
            return Routed::Pulled;
        }
        // Whether a changed Low ID stands is the node's to say: it knows the
        // servers (ADR-0107).
        PeerEvent::Connection(ConnectionEvent::ClientIdOffered { client_id, server }) => {
            return Routed::Offered(deps.peer_links.take_client_id(client_id, server));
        }
        PeerEvent::Connection(fact) => {
            if let ConnectionEvent::IdentityRevised {
                identity: revised, ..
            } = &fact
            {
                revised_now = true;
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
        PeerEvent::Requester(RequesterEvent::SlotOffered) => return Routed::SlotOffered,
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
    if revised_now {
        Routed::Revised
    } else {
        Routed::Open
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
