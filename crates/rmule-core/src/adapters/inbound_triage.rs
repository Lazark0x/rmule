//! Triage of an accepted inbound connection: a called-back Low-ID source is
//! adopted by the download that requested it (ADR-0039), a **Dialer Tunnel**
//! raised toward a claimed target is adopted by the download whose callback
//! went silent (ADR-0091), and anything else is admitted as a serve
//! connection. Holds the callback table the requesting runners register into
//! and this triage consumes.
//!
//! The two adoption roads meet here, and not one step earlier, because this is
//! where the hello is — and both roads decide on what the peer *says*, not on
//! where the bytes came from. It is also the one place downstream of the IP
//! filter and the ban gate, so neither road can skip them.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rmule_net::peer::Connection as PeerConnection;
use rmule_peer::{PartBitmap, PeerEvent, PeerIdentity};
use rmule_primitives::{ClientId, Ed2kFileLink, Ipv4Endpoint, PeerEndpoint, UserHash};
use tokio::sync::{Mutex, mpsc};

use crate::buddy_link::SharedBuddySlot;
use crate::service::PortTestClosedBy;

use super::dialed_serve::SharedDialedServeSink;
use super::kad_runtime::{
    SharedKadBootstrap, SharedKadPump, broker_peer_kad_handoff, report_kad_firewall_ack,
    report_kad_udp_firewall_request,
};
use super::peer_transfer::PeerWorker;
use super::peer_transfer::worker::drive_peer_worker;
use super::serve_projection::{serve_command_to_peer, serve_event_from_peer};
use super::serve_runtime::{ServeConnCommand, ServeConnEvent};
use super::tunnel_claims::{SharedTunnelClaims, TunnelClaimVerdict};

/// Identifies one pending Low-ID callback (ADR-0039 / ADR-0051) — the single key
/// `download::state`'s `DownloadState` owns and threads verbatim through
/// its deadline heap, its adoption routing, and this [`SharedCallbackTable`].
/// `low_id` is the source's server-assigned id (unique only per server, so the
/// server namespaces it); `server` is the server that relays the callback and
/// that the called-back peer reports as its `connected_server`:
/// - `None` — the *connected-server* form: the download's own connected server.
///   The sans-I/O brain does not hold that endpoint (a runtime fact, like the
///   clock), so it leaves `None`; the runner resolves it to the live connected
///   server when it registers or retracts this routing index.
/// - `Some(server)` — a *per-server global* callback (ADR-0051): the source-server that
///   answered `OP_GLOBFOUNDSOURCES` and relays the callback.
///
/// In this table the `server` is always the concrete endpoint the inbound peer
/// reports (the runner has resolved any `None`) — a `None` here could never match
/// an inbound hello. It stays `Option` because a DNS-named server's hello encodes
/// `0.0.0.0:0` → `None`; such a callback simply degrades to the timeout.
///
/// It lives here, not in `download::state`, so that the vocabulary it shares
/// with [`SharedCallbackTable`] and `PeerWorkerEvent`/`PeerWorkerCommand` has
/// one home and the `download::state -> adapters` dependency direction holds;
/// the lifecycle (the pending set and all callback policy) is still the brain's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CallbackKey {
    pub(crate) server: Option<Ipv4Endpoint>,
    pub(crate) low_id: ClientId,
}

/// The core-owned table the inbound accept-router consults to adopt a
/// called-back Low-ID peer (ADR-0039) — the [`SharedDialedServeSink`] ownership
/// pattern inverted (serve → download). The core actor owns the `Arc`; it clones
/// one to the serve adapter (which matches inbound hellos against it) and one to
/// each download's runner (which registers an entry per requested callback).
/// One entry per download per key, the oldest adopted first (ADR-0107).
pub(crate) type SharedCallbackTable = Arc<Mutex<PendingCallbacks>>;

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
/// hello, then route by a Low-ID callback match. The raw connection and its
/// identify are owned here, in the adapter — the only place the download (adopt)
/// and serve sinks both live — so the decision is made before serve-bridging.
/// On a match the connection becomes an **Adopted Inbound Worker** for the
/// requesting download; with no match it is served exactly as before. The
/// handshake guarantees no serve-capability event precedes `PeerIdentified`, so
/// nothing is lost by waiting for identify before deciding.
///
/// `dialed_toward` is the second adoption road (ADR-0091): the target User
/// Hash a NAT-T punch raised this stream toward, `None` for every stream this
/// node did not aim. It is consulted before the callback key and decided on
/// the same hello.
///
/// Returns how the connection left the router: closed here, with who closed
/// it, or adopted.
pub(crate) async fn triage_inbound_connection(
    mut conn: PeerConnection,
    dialed_toward: Option<UserHash>,
    command_rx: mpsc::Receiver<ServeConnCommand>,
    event_tx: mpsc::Sender<ServeConnEvent>,
    callbacks: SharedCallbackTable,
    tunnel_claims: SharedTunnelClaims,
    deps: InboundPeerDeps,
) -> InboundEnd {
    // Drain until the peer identifies; that yields the `(connected_server,
    // client_id)` correlation key. A disconnect or a stray pre-identify serve
    // event is handled exactly as the serve bridge would.
    let identity = loop {
        match conn.next_event().await {
            Some(PeerEvent::PeerIdentified { identity }) => break identity,
            // The opening was refused by name (ADR-0050); the close follows.
            Some(PeerEvent::HelloRefused { refusal }) => deps.hello_refusals.report(refusal).await,
            Some(PeerEvent::Disconnected { reason }) => {
                let _ = event_tx.send(ServeConnEvent::Disconnected).await;
                let _ = conn.shutdown().await;
                return InboundEnd::Closed((&reason).into());
            }
            None => {
                let _ = event_tx.send(ServeConnEvent::Disconnected).await;
                let _ = conn.shutdown().await;
                return InboundEnd::Closed(PortTestClosedBy::DriverEnded);
            }
            Some(PeerEvent::KadFirewallCheckAck) => {
                // A dial-back can ack before its hello has been folded into an
                // identity here; the requester cycle needs only the IP.
                report_kad_firewall_ack(&deps.kad_pump, conn.peer_endpoint());
            }
            Some(PeerEvent::KadUdpFirewallCheckRequested { request }) => {
                report_kad_udp_firewall_request(
                    &deps.kad_pump,
                    conn.peer_endpoint(),
                    request,
                    &deps.peer_roster,
                );
            }
            Some(other) => {
                if let Some(serve) = serve_event_from_peer(other)
                    && event_tx.send(serve).await.is_err()
                {
                    let _ = conn.shutdown().await;
                    return InboundEnd::Closed(PortTestClosedBy::Us);
                }
            }
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

    // The NAT-T road first (ADR-0091), when this stream was raised by a punch
    // rmule aimed at a named target. It outranks the callback key because it
    // is the stronger evidence — we asked for *this hash*, and the hello
    // either confirms it or the connection is not what was asked for. A
    // refused adoption is closed rather than served: it arrived down a path
    // only this node's own punch opened, so nothing else wanted it, and the
    // claim stays pending for the target that may still come.
    if let Some(target) = dialed_toward {
        match tunnel_claims.rule(target, identity.user_hash()).await {
            TunnelClaimVerdict::Adopted(entry) => {
                let _ = event_tx.send(ServeConnEvent::Readopted).await;
                // The hello just confirmed this peer: report it
                // back to the front exactly as a closed path does, so it can
                // end their attempt and take any hold still waiting to dial
                // them with it — every adoption, not only one an address
                // alone could not attribute, since the front's own end is a
                // no-op for a peer it never held an attempt for.
                tunnel_claims.identified(identity.user_hash());
                let peer = conn.peer_endpoint();
                let worker = adopt_inbound_worker(
                    conn,
                    peer,
                    &identity,
                    entry.file,
                    entry.own_status,
                    entry.want_sources,
                    deps,
                );
                // The *callback's* key, not a tunnel key: NAT traversal is an
                // additional attempt on one pending callback, so the brain
                // ends exactly one of them whichever road landed.
                let _ = entry.adopt_tx.send((entry.callback, worker)).await;
                return InboundEnd::Adopted;
            }
            TunnelClaimVerdict::HelloMismatch => {
                tracing::info!(
                    peer = %conn.peer_endpoint(),
                    reported = ?identity.user_hash(),
                    "a punched path's peer is not the target it was raised for; adoption refused"
                );
                let _ = event_tx.send(ServeConnEvent::Disconnected).await;
                let _ = conn.shutdown().await;
                return InboundEnd::Closed(PortTestClosedBy::Us);
            }
            // Nobody is waiting for this target: the serve road, unchanged.
            TunnelClaimVerdict::Unclaimed => {}
        }
    }

    // Match the inbound peer against the pending-callback table. A match removes
    // the entry (claiming this adoption) and routes the connection to that
    // download; no match flows to serve, as before. The key carries the concrete
    // server the peer reports — the runner resolved any connected-server `None`
    // to it at registration, so this matches directly.
    let key = CallbackKey {
        server: identity.connected_server(),
        low_id: identity.client_id(),
    };
    let adopted = callbacks.lock().await.adopt(&key);
    // A buddy callback's dial-back reports no key the table holds — a Kad
    // candidate is in no server's namespace — so it is matched by the User
    // Hash its hello names, and only for a claim that asked for a dial-back
    // (ADR-0061 route 4). Consulted only on a key miss, so the
    // ADR-0039 road is unchanged.
    let dial_back = match adopted {
        Some(_) => None,
        None => tunnel_claims.adopt_dial_back(identity.user_hash()).await,
    };
    if let Some(entry) = dial_back {
        let _ = event_tx.send(ServeConnEvent::Readopted).await;
        // The same report a NAT-T road adoption makes above —
        // this dial-back's claim just named itself too.
        tunnel_claims.identified(identity.user_hash());
        let peer = conn.peer_endpoint();
        let worker = adopt_inbound_worker(
            conn,
            peer,
            &identity,
            entry.file,
            entry.own_status,
            entry.want_sources,
            deps,
        );
        let _ = entry.adopt_tx.send((entry.callback, worker)).await;
        return InboundEnd::Adopted;
    }
    match adopted {
        Some(entry) => {
            // Retract the (already-registered) serve connection, build a download
            // worker over the raw socket, and hand it to the requesting download.
            let _ = event_tx.send(ServeConnEvent::Readopted).await;
            // An ADR-0039 callback match is also an adoption a
            // confirmed hello granted, so it reports the same way.
            tunnel_claims.identified(identity.user_hash());
            let peer = conn.peer_endpoint();
            let worker = adopt_inbound_worker(
                conn,
                peer,
                &identity,
                entry.file,
                entry.own_status,
                entry.want_sources,
                deps,
            );
            let _ = entry.adopt_tx.send((key, worker)).await;
            InboundEnd::Adopted
        }
        None => {
            // Re-emit the identity the bridge would have surfaced, then serve.
            // The peer's advertised client-UDP reask contact rides now that the
            // live front binds and serves peer-UDP (ADR-0057): a queued waiter's
            // inbound `OP_REASKFILEPING` matches on it by IP + port.
            let (udp_port, udp_version) = identity.client_udp_reask().unwrap_or((0, 0));
            let _ = event_tx
                .send(ServeConnEvent::Identified {
                    user_hash: identity.user_hash(),
                    client_id: identity.client_id(),
                    connected_server: identity.connected_server(),
                    // The peer's advertised eD2k listen port — its own source
                    // coordinate for source-exchange serving (ADR-0055 §Serving).
                    tcp_port: identity.tcp_port(),
                    udp_port,
                    udp_version,
                    extended_requests_version: identity.extended_requests_version(),
                    crypt: identity.crypt_stance(),
                    ipv6: identity.peer_ipv6(),
                    software: identity.software().clone(),
                })
                .await;
            InboundEnd::Closed(serve_bridge_loop(conn, command_rx, event_tx, deps).await)
        }
    }
}

/// Build an **Adopted Inbound Worker** (ADR-0039) over a pre-connected,
/// already-identified inbound `conn` (a called-back Low-ID peer): the dial-free,
/// identify-free sibling of [`RuntimePeerTransferService`](crate::RuntimePeerTransferService)'s `start_peer_worker`. It
/// spawns the shared [`drive_peer_worker`] with `identified = Some(identity)` —
/// the accept-side identity's own hello stance and serving buddy ride through
/// with it, so an adopted peer seeds `hello_crypts` and the
/// brain's hello buddies too — and returns the `PeerWorker`
/// handle for the download runner to register.
fn adopt_inbound_worker(
    conn: PeerConnection,
    peer: PeerEndpoint,
    identity: &PeerIdentity,
    file: Ed2kFileLink,
    own_status: PartBitmap,
    want_sources: bool,
    deps: InboundPeerDeps,
) -> PeerWorker {
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
            deps.slot_wait_timeout,
            deps.dialed_serve_sink,
            // The adopted peer already identified during accept, where the handoff
            // was already brokered; the drive body re-runs no identify, so this sink
            // simply goes unused for it (no double-broker).
            deps.kad_bootstrap,
            deps.addresses,
            // Identified at accept, so its hello can no longer be refused.
            deps.hello_refusals,
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

/// Bridge one accepted peer `Connection` to the narrow serve vocab: peer
/// serve-side `PeerEvent`s become `ServeConnEvent`s, and `ServeConnCommand`s
/// become `PeerCommand`s. Runs until the connection closes or core drops the
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
    mut command_rx: mpsc::Receiver<ServeConnCommand>,
    event_tx: mpsc::Sender<ServeConnEvent>,
    deps: InboundPeerDeps,
) -> PortTestClosedBy {
    let InboundPeerDeps {
        buddy_slot,
        kad_pump,
        peer_roster,
        ..
    } = &deps;
    let remote = conn.peer_endpoint();
    let closed_by = loop {
        tokio::select! {
            command = command_rx.recv() => {
                let Some(command) = command else { break PortTestClosedBy::Us };
                if matches!(command, ServeConnCommand::Disconnect) {
                    break PortTestClosedBy::Us;
                }
                if conn.send(serve_command_to_peer(command)).await.is_err() {
                    // The driver stopped first; its paired `Disconnected`
                    // is queued behind whatever it said before.
                    break close_reason(&mut conn).await;
                }
            }
            event = conn.next_event() => {
                let Some(event) = event else {
                    let _ = event_tx.send(ServeConnEvent::Disconnected).await;
                    break PortTestClosedBy::DriverEnded;
                };
                if matches!(event, PeerEvent::KadFirewallCheckAck) {
                    // ADR-0058 requester, the v7+ ack path: this peer dialed us
                    // back because we asked it to prove our TCP port open, and
                    // this packet is that proof. It rides the serve bridge
                    // because a dial-back *is* an ordinary inbound peer session
                    // — the Kad-ignorant peer crate reports the packet, and the
                    // node decides whether the IP was one we checked.
                    report_kad_firewall_ack(kad_pump, remote);
                    tracing::debug!(
                        peer = ?remote,
                        "OP_KAD_FWTCPCHECK_ACK routed to the Kad requester cycle"
                    );
                    continue;
                }
                if let PeerEvent::KadUdpFirewallCheckRequested { request } = event {
                    // ADR-0058, rmule as UDP Firewall Helper: the requester
                    // dialed us to send this, and the answer is a Kad
                    // datagram — so, like the `0xA8` above, it leaves the
                    // serve bridge for the node.
                    report_kad_udp_firewall_request(kad_pump, remote, request, peer_roster);
                    tracing::debug!(
                        peer = ?remote,
                        "OP_FWCHECKUDPREQ routed to the Kad node"
                    );
                    continue;
                }
                if matches!(event, PeerEvent::BuddyPingReceived) {
                    // ADR-0061 keepalive: the pong decision (is this connection
                    // the held buddy link?) and the pong send (over that same
                    // held link) both live in the slot; a stranger's ping is
                    // refused there silently, exactly like aMule's
                    // `GetBuddy() != client` drop.
                    let disposition = buddy_slot.on_buddy_ping(remote, Instant::now());
                    tracing::debug!(
                        peer = ?remote,
                        ?disposition,
                        "OP_BUDDYPING routed to the buddy slot"
                    );
                    continue;
                }
                if let PeerEvent::BuddyCallbackReceived { callback } = event {
                    served_callback::consume(&deps, remote, &callback);
                    continue;
                }
                // The serve vocabulary carries no close reason; it is read
                // here, before the projection drops it.
                let closed = match &event {
                    PeerEvent::Disconnected { reason } => Some(PortTestClosedBy::from(reason)),
                    _ => None,
                };
                if let Some(serve) = serve_event_from_peer(event) {
                    if event_tx.send(serve).await.is_err() {
                        break closed.unwrap_or(PortTestClosedBy::Us);
                    }
                    if let Some(closed_by) = closed {
                        break closed_by;
                    }
                }
            }
        }
    };
    let _ = conn.shutdown().await;
    // When this connection was the held buddy link, its close frees the
    // buddy slot at once so a fresh recruit can take it.
    if buddy_slot.on_link_closed(remote) {
        tracing::debug!(
            peer = ?remote,
            "held buddy link closed; buddy slot released"
        );
    }
    closed_by
}

/// Drain a connection whose driver has stopped to its paired `Disconnected`
/// and say who closed it.
async fn close_reason(conn: &mut PeerConnection) -> PortTestClosedBy {
    while let Some(event) = conn.next_event().await {
        if let PeerEvent::Disconnected { reason } = event {
            return (&reason).into();
        }
    }
    PortTestClosedBy::DriverEnded
}

mod pending_callbacks;
mod served_callback;

pub(crate) use pending_callbacks::{PendingCallbackEntry, PendingCallbacks};

#[cfg(test)]
mod tests;
