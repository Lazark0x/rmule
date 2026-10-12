//! Triage of an accepted inbound connection: a called-back Low-ID source is
//! adopted by the download that requested it (ADR-0039), a **Dialer Tunnel**
//! raised toward a claimed target is adopted by the download whose callback
//! went silent (ADR-0091), and anything else is admitted as a serve
//! connection. Who gets a connection is the **Awaited Inbound** registry's
//! answer to one question; this module asks it and carries the answer out.
//!
//! The two adoption roads meet here, and not one step earlier, because this is
//! where the hello is — and both roads decide on what the peer *says*, not on
//! where the bytes came from. It is also the one place downstream of the IP
//! filter and the ban gate, so neither road can skip them.

use std::time::{Duration, Instant};

use rmule_net::peer::Connection as PeerConnection;
use rmule_peer::{ConnectionEvent, PeerCommand, PeerEvent, PeerIdentity, SideEvent};
use rmule_primitives::{PeerEndpoint, UserHash};
use tokio::sync::mpsc;

use crate::buddy_link::SharedBuddySlot;
use crate::service::PortTestClosedBy;

use super::awaited_inbound::{
    AdoptionBrief, AwaitedInbound, CallbackKey, InboundArrival, InboundVerdict,
};
use super::dialed_serve::SharedDialedServeSink;
use super::hello_wait::{Opening, await_hello};
use super::kad_runtime::{
    SharedKadBootstrap, SharedKadPump, broker_peer_kad_handoff, report_kad_firewall_ack,
    report_kad_udp_firewall_request,
};
use super::peer_transfer::PeerWorker;
use super::peer_transfer::worker::drive_peer_worker;
use super::serve_runtime::{ServeInput, ServeOutput};

/// The runtime handles the inbound accept path threads as **one value** —
/// accept → triage → adopt/serve — instead of a positional parade. Grouped so
/// an arm cannot silently drop a handle mid-chain: a positional `buddy_slot`
/// can be left out of one arm and the held link leaks, which a struct field
/// cannot reproduce — every consumer names what it takes.
#[derive(Clone)]
pub(crate) struct InboundPeerDeps {
    /// How long an adopted worker waits for a granted download slot.
    pub(crate) slot_wait_timeout: Duration,
    /// Where a serving dialed/adopted connection's serve half is pushed (ADR-0031).
    pub(crate) dialed_serve_sink: SharedDialedServeSink,
    /// The ed2k→Kad handoff sink (ADR-0067) every identified peer is offered to.
    pub(crate) kad_bootstrap: SharedKadBootstrap,
    /// The running Kad node's signal sink (ADR-0058): where an inbound
    /// `OP_KAD_FWTCPCHECK_ACK` is carried so the requester cycle can count it.
    pub(crate) kad_pump: SharedKadPump,
    /// The held buddy link (ADR-0061) an identified recruit attaches to.
    pub(crate) buddy_slot: SharedBuddySlot,
    /// The **Address Learning** store an identified peer's `CT_MOD_YOUR_IP`
    /// reflection votes into (ADR-0084/0087).
    pub(crate) addresses: crate::address_learning::SharedAddressLearning,
    /// The core-owned Peer Roster (ADR-0059): consulted for an
    /// inbound `OP_FWCHECKUDPREQ`'s helper-bias question — whether the
    /// dialing peer's IP is one we already have an active upload, download or
    /// chat with.
    pub(crate) peer_roster: crate::peer_roster::SharedPeerRoster,
    /// **Kad Presence**: whether a Kad node runs, and as which
    /// Kad ID — the gate and the check a served link's `0x99` is read against.
    pub(crate) kad_presence: super::KadPresenceView,
    /// The file-known predicate: a served link's `0x99` naming a
    /// file we neither share nor download dials nothing.
    pub(crate) file_known: crate::known_files::SharedFileKnown,
    /// Where a served link's `0x99` dial-back enters the serve pipeline, as
    /// the firewalled front's does (ADR-0061 route 4).
    pub(crate) tunnel_admit: super::SharedTunnelAdmit,
    /// Where an accepted peer's refused hello is reported (ADR-0050).
    pub(crate) hello_refusals: crate::hello_refusals::SharedHelloRefusals,
}

/// How an accepted connection left [`triage_inbound_connection`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InboundEnd {
    /// The connection closed here, and this is who closed it.
    Closed(PortTestClosedBy),
    /// It was adopted as a download worker, which drives it on.
    Adopted,
}

/// The inbound accept-router (ADR-0039): drive one accepted `Connection` to its
/// hello, then ask the **Awaited Inbound** registry who gets it. The raw
/// connection and its identify are owned here, in the adapter — the only place
/// the download (adopt) and serve sinks both live — so the decision is made
/// before serve-bridging. An adopted connection becomes an **Adopted Inbound
/// Worker** for the download that awaited it; an unclaimed one is served
/// exactly as before. The handshake guarantees no serve-capability event
/// precedes `Identified`, so nothing is lost by waiting for identify before
/// deciding.
///
/// `dialed_toward` is the target User Hash a NAT-T punch raised this stream
/// toward (ADR-0091), `None` for every stream this node did not aim.
///
/// Returns how the connection left the router: closed here, with who closed
/// it, or adopted.
pub(crate) async fn triage_inbound_connection(
    mut conn: PeerConnection,
    dialed_toward: Option<UserHash>,
    command_rx: mpsc::Receiver<ServeOutput>,
    event_tx: mpsc::Sender<ServeInput>,
    awaited: AwaitedInbound,
    deps: InboundPeerDeps,
) -> InboundEnd {
    // Drain until the peer identifies; that yields the `(connected_server,
    // client_id)` correlation key.
    let remote = conn.peer_endpoint();
    let opening = await_hello(&mut conn, &deps.hello_refusals, |side| {
        report_side_before_hello(&deps, remote, side);
    })
    .await;
    let identity = match opening {
        Opening::Identified(identity) => *identity,
        Opening::Closed(reason) => {
            let closed_by = PortTestClosedBy::from(&reason);
            let _ = event_tx
                .send(ServeInput::Connection(ConnectionEvent::Disconnected {
                    reason,
                }))
                .await;
            let _ = conn.shutdown().await;
            return InboundEnd::Closed(closed_by);
        }
        Opening::Ended => {
            let _ = event_tx.send(ServeInput::closed_here()).await;
            let _ = conn.shutdown().await;
            return InboundEnd::Closed(PortTestClosedBy::DriverEnded);
        }
    };

    // ed2k→Kad handoff (ADR-0067): an accepted peer that carries a Kad node
    // hint bootstraps our Kad node — aMule's `ConnectionEstablished` handoff, on
    // every connected peer regardless of the callback routing below. A no-op
    // unless the peer advertised a usable Kad contact and Kad is running.
    broker_peer_kad_handoff(&deps.kad_bootstrap, conn.peer_endpoint(), &identity).await;
    // The IPv6 corroboration quorum (ADR-0084/0087): a peer that reflected our
    // address back casts one vote, keyed on where we observed *it*. Three
    // distinct observers inside the window carry it, and the locally-assigned
    // filter is what keeps any number of them from making us advertise a
    // foreign address.
    crate::address_learning::record_peer_ipv6_vote(
        &deps.addresses,
        conn.peer_endpoint(),
        &identity,
    );

    // Socket unification (ADR-0061): if this identified inbound peer IS the
    // recruited buddy (hash match — aMule attaches the incoming socket to the
    // already-known client), HOLD its command sender as the persistent buddy
    // link every relay/pong rides — the buddy is firewalled, so this inbound
    // dial is the only link that can ever reach it. Attached before the
    // adopt/serve split so a buddy that is also adopted as a download worker
    // still carries relays; each arm then detaches on its own close (the serve
    // bridge inline, the adopted worker in its drive wrapper) — nothing else
    // frees the slot, so a missed detach would refuse every future recruit
    // until a Kad restart.
    if deps.buddy_slot.try_attach(
        conn.peer_endpoint(),
        identity.user_hash(),
        conn.command_sender(),
    ) {
        tracing::debug!(
            peer = %conn.peer_endpoint(),
            // Carried so a bench flow can assert the hello hash against a
            // pin without a separate capture of the hello
            // packet itself.
            hello_user_hash = %identity.user_hash().to_hex_upper(),
            "buddy link attached: the recruited buddy's inbound connection is now held"
        );
    }

    // The one question (ADR-0039, ADR-0091): how the connection came in and
    // what its hello says. The key carries the concrete server the peer
    // reports; the runner resolved any connected-server `None` when it filed.
    let arrival = match dialed_toward {
        Some(target) => InboundArrival::DialedToward(target),
        None => InboundArrival::Accepted,
    };
    let reported = CallbackKey {
        server: identity.connected_server(),
        low_id: identity.client_id(),
    };
    match awaited.triage(arrival, identity.user_hash(), reported) {
        InboundVerdict::Adopt(adoption) => {
            // The registration is spent; the hand-over waits on the download
            // outside the registry's lock. A download that ended since gives
            // no permit, and the connection takes the serve road below.
            if let Ok(permit) = adoption.adopt_tx.reserve().await {
                // Retract the (already-registered) serve connection, build a
                // download worker over the raw socket, and hand it over under
                // the callback's key, whichever road landed.
                let _ = event_tx.send(ServeInput::Readopted).await;
                let peer = conn.peer_endpoint();
                let worker = adopt_inbound_worker(conn, peer, &identity, adoption.brief, deps);
                permit.send((adoption.callback, worker));
                return InboundEnd::Adopted;
            }
        }
        InboundVerdict::Mismatch => {
            // It arrived down a path only this node's own punch opened, so
            // nothing else wanted it: closed rather than served.
            tracing::info!(
                peer = %conn.peer_endpoint(),
                reported = ?identity.user_hash(),
                "a punched path's peer is not the target it was raised for; adoption refused"
            );
            let _ = event_tx.send(ServeInput::closed_here()).await;
            let _ = conn.shutdown().await;
            return InboundEnd::Closed(PortTestClosedBy::Us);
        }
        InboundVerdict::Unclaimed => {}
    }
    // Hand the serve side the identification the hello wait consumed, then
    // serve.
    let _ = event_tx
        .send(ServeInput::Connection(ConnectionEvent::Identified {
            identity,
        }))
        .await;
    InboundEnd::Closed(serve_bridge_loop(conn, command_rx, event_tx, deps).await)
}

/// A Kad firewall-check frame that arrived before the hello: a dial-back can
/// ack before its hello is folded into an identity, and the requester cycle
/// and the UDP Firewall Helper need only the IP (ADR-0058). Any other
/// side-channel frame waits for an identified link and is dropped.
fn report_side_before_hello(deps: &InboundPeerDeps, remote: PeerEndpoint, side: SideEvent) {
    match side {
        SideEvent::KadFirewallCheckAck => report_kad_firewall_ack(&deps.kad_pump, remote),
        SideEvent::KadUdpFirewallCheckRequested { request } => {
            report_kad_udp_firewall_request(&deps.kad_pump, remote, request, &deps.peer_roster);
        }
        SideEvent::BuddyPingReceived
        | SideEvent::BuddyCallbackReceived { .. }
        | SideEvent::BuddyReaskCallbackReceived { .. }
        | SideEvent::PublicIpAnswered
        | SideEvent::PublicIpRequestUnanswerable => {}
    }
}

/// Build an **Adopted Inbound Worker** (ADR-0039) over a pre-connected,
/// already-identified inbound `conn` (a called-back Low-ID peer): the dial-free,
/// identify-free sibling of [`RuntimePeerTransferService`](crate::RuntimePeerTransferService)'s `start_peer_worker`. It
/// spawns the shared [`drive_peer_worker`] with `identified = Some(identity)` —
/// the accept-side identity is the one the download starts from, so an adopted
/// peer's hello stance and serving buddy reach its record and the run's hello
/// buddies as a dialed peer's do. A revision the session read after the hello
/// waits in the connection's event queue, which the worker's router forwards
/// right after that identity, so the download ends on the session's — and
/// returns the `PeerWorker`
/// handle for the download runner to register.
fn adopt_inbound_worker(
    conn: PeerConnection,
    peer: PeerEndpoint,
    identity: &PeerIdentity,
    brief: AdoptionBrief,
    deps: InboundPeerDeps,
) -> PeerWorker {
    let AdoptionBrief {
        file,
        own_status,
        want_sources,
    } = brief;
    let (command_tx, command_rx) = mpsc::channel(8);
    let (event_tx, event_rx) = mpsc::channel(16);
    let identity = identity.clone();
    tokio::spawn(async move {
        drive_peer_worker(
            conn,
            peer,
            file,
            own_status,
            want_sources,
            Some(identity),
            command_rx,
            event_tx,
            // The adopted peer already identified during accept, where the
            // handoff was already brokered and its hello can no longer be
            // refused; the drive body re-runs no identify.
            deps.clone(),
        )
        .await;
        // ADR-0061: the adopted connection may double as the held buddy
        // link (the attach ran before the adopt/serve split). The drive's end
        // means that socket is done, so detach and free the slot exactly as
        // the serve arm's close does — a no-op when this peer never attached.
        deps.buddy_slot.on_link_closed(peer);
    });
    PeerWorker::new(peer, command_tx, event_rx)
}

/// Bridge one accepted peer `Connection` to the serve task: its `Server`
/// requests and `Connection` facts go up as they are, its side-channel frames
/// go to the node-wide services, and the serve task's `Server` commands go
/// down to the session. Runs until the connection closes or core drops the
/// command channel. Entered post-identify by [`triage_inbound_connection`] for a
/// connection that was not adopted as a download worker.
///
/// Three buddy legs live here (socket unification, ADR-0061): an inbound
/// `OP_BUDDYPING` routes to the buddy slot — which pongs back **on this same
/// held link** iff this connection is the attached buddy link — an inbound
/// `OP_CALLBACK` is consumed on *any* served link (see [`served_callback`]),
/// and the connection's close detaches the held link,
/// freeing the buddy slot at once (aMule frees `m_pBuddy` when the buddy's
/// socket dies).
///
/// Returns who closed the connection: the peer session's own close reason
/// when it ended there, rmule when core let the connection go.
async fn serve_bridge_loop(
    mut conn: PeerConnection,
    mut command_rx: mpsc::Receiver<ServeOutput>,
    event_tx: mpsc::Sender<ServeInput>,
    deps: InboundPeerDeps,
) -> PortTestClosedBy {
    let remote = conn.peer_endpoint();
    let closed_by = loop {
        tokio::select! {
            command = command_rx.recv() => {
                let command = match command {
                    None | Some(ServeOutput::Disconnect) => break PortTestClosedBy::Us,
                    Some(ServeOutput::Server(command)) => PeerCommand::Server(command),
                };
                if conn.send(command).await.is_err() {
                    // The driver stopped first; its paired `Disconnected`
                    // is queued behind whatever it said before.
                    break close_reason(&mut conn).await;
                }
            }
            event = conn.next_event() => {
                let input = match event {
                    None => {
                        let _ = event_tx.send(ServeInput::closed_here()).await;
                        break PortTestClosedBy::DriverEnded;
                    }
                    Some(PeerEvent::Server(request)) => ServeInput::Server(request),
                    Some(PeerEvent::Connection(fact)) => ServeInput::Connection(fact),
                    Some(PeerEvent::Side(side)) => {
                        serve_side(&deps, remote, side);
                        continue;
                    }
                    // A served link's own pull and its notices concern no
                    // serve decision.
                    Some(PeerEvent::Requester(_) | PeerEvent::Notice(_)) => continue,
                };
                let closed = match &input {
                    ServeInput::Connection(ConnectionEvent::Disconnected { reason }) => {
                        Some(PortTestClosedBy::from(reason))
                    }
                    _ => None,
                };
                if event_tx.send(input).await.is_err() {
                    break closed.unwrap_or(PortTestClosedBy::Us);
                }
                if let Some(closed_by) = closed {
                    break closed_by;
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

/// Carry one side-channel frame a served link read to the node-wide service
/// that answers it.
pub(super) fn serve_side(deps: &InboundPeerDeps, remote: PeerEndpoint, side: SideEvent) {
    match side {
        SideEvent::KadFirewallCheckAck => {
            // ADR-0058 requester, the v7+ ack path: this peer dialed us back
            // because we asked it to prove our TCP port open, and this packet
            // is that proof. It rides the serve bridge because a dial-back
            // *is* an ordinary inbound peer session — the Kad-ignorant peer
            // crate reports the packet, and the node decides whether the IP
            // was one we checked.
            report_kad_firewall_ack(&deps.kad_pump, remote);
            tracing::debug!(
                peer = ?remote,
                "OP_KAD_FWTCPCHECK_ACK routed to the Kad requester cycle"
            );
        }
        SideEvent::KadUdpFirewallCheckRequested { request } => {
            // ADR-0058, rmule as UDP Firewall Helper: the requester dialed us
            // to send this, and the answer is a Kad datagram — so, like the
            // `0xA8` above, it leaves the serve bridge for the node.
            report_kad_udp_firewall_request(&deps.kad_pump, remote, request, &deps.peer_roster);
            tracing::debug!(peer = ?remote, "OP_FWCHECKUDPREQ routed to the Kad node");
        }
        SideEvent::BuddyPingReceived => {
            // ADR-0061 keepalive: the pong decision (is this connection the
            // held buddy link?) and the pong send (over that same held link)
            // both live in the slot; a stranger's ping is refused there
            // silently, exactly like aMule's `GetBuddy() != client` drop.
            let disposition = deps.buddy_slot.on_buddy_ping(remote, Instant::now());
            tracing::debug!(
                peer = ?remote,
                ?disposition,
                "OP_BUDDYPING routed to the buddy slot"
            );
        }
        SideEvent::BuddyCallbackReceived { callback } => {
            served_callback::consume(deps, remote, &callback);
        }
        // A buddy reask relay rides only our own buddy link, which the
        // firewalled front owns; the public-IP ask was answered by the
        // session.
        SideEvent::BuddyReaskCallbackReceived { .. }
        | SideEvent::PublicIpAnswered
        | SideEvent::PublicIpRequestUnanswerable => {}
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

mod served_callback;

#[cfg(test)]
mod tests;
