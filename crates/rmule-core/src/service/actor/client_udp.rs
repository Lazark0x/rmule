//! Bringing up the **one client-UDP socket**'s front (ADR-0057): the demuxing
//! engine, the send drain every reply rides, the routing of downloader-consumed
//! reask replies to the download whose ping each answers (ADR-0107), and the
//! **NAT-T Front** (ADR-0091) that drives `rmule_net::natt` from this same
//! bind.
//!
//! It is one file because it is one bind: the reask surface, the NAT-T
//! transport and the Kad inlet are three tenants of a single socket, and the
//! order they are woven in is the thing that has to stay right.

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::adapters::RuntimeClientUdpTransport;
use crate::buddy_link::SharedBuddySlot;
use crate::client_udp::{
    ClientUdpDatagram, ClientUdpEngine, ClientUdpSend, PeerUdpCrypt, encrypt_client_udp_send,
    os_datagram_nonce,
};
use crate::own_identity::SharedOwnIdentity;
use crate::service::{CoreConfig, CoreEvent, SharedReaskReplySink};

/// Bring up the client-UDP front on the one bound socket: the demuxing engine,
/// the send drain, the routing of downloader-consumed reask replies
/// (`0x91`/`0x92`/`0x93`, ADR-0057) to the download whose ping each answers
/// (ADR-0107), and the **NAT-T Front** (ADR-0091) that drives
/// `rmule_net::natt` from this same bind. Returns the reask-ping inbox
/// (`0x90`) the serve task takes on `StartServing` and the send half.
pub(super) fn spawn_client_udp_front(
    socket: Arc<rmule_net::ed2k::ClientUdpSocket>,
    config: &CoreConfig,
    own_identity: &SharedOwnIdentity,
    sinks: ClientUdpSinks<'_>,
    diagnostics: &crate::diagnostics::DiagnosticsState,
    natt: NattFrontWiring<'_>,
) -> (
    Option<mpsc::Receiver<ClientUdpDatagram>>,
    Option<mpsc::Sender<ClientUdpSend>>,
) {
    // The ADR-0046 per-datagram crypt layer, armed by the one `peer_crypt`
    // policy (off by default). Receive is dual-path from here on; send is
    // gated per datagram at the drain below.
    let peer_udp_crypt = config
        .peer_crypt
        .map(|policy| PeerUdpCrypt::new(own_identity.clone(), policy.crypt_stance()));
    let (reply_tx, mut reply_rx) = mpsc::channel::<ClientUdpSend>(32);
    let (engine, inboxes) = ClientUdpEngine::new(
        RuntimeClientUdpTransport::new(Arc::clone(&socket)),
        peer_udp_crypt,
        // The shared enacted buddy slot (ADR-0061): the front's 0x94 relay
        // rides the held buddy link it holds.
        sinks.buddy_slot.clone(),
        // The firewalled front's command half (ADR-0061/0091):
        // where a standalone `0xA0` and an inbound `0x95` go. Empty until the
        // front below installs it, which is a datagram dropped rather than a
        // decision taken without a buddy slot to gate it against.
        natt.firewalled_front.clone(),
        // Where the front reports a datagram refused for its **Address
        // Family** (the `0x94` ruling, ADR-0087).
        diagnostics.clone(),
        // The front's own send half — it answers a rendezvous it relayed
        // with an endpoint hint, from this same socket (ADR-0091).
        reply_tx.clone(),
        // Where a running Kad node installs its inbound half (ADR-0057):
        // empty until `EnableKad`, empty again once the node stops.
        sinks.kad_inlet,
    );
    tokio::spawn(engine.run());
    // The send drain: each serve/download `SendClientUdp` datagram (an
    // uploader reply or a downloader `0x90` reask ping) rides the one bound
    // socket back to the peer's UDP endpoint. This is where aMule obfuscates
    // too (`CMuleUDPSocket::SendControlData`), so the crypt gate and its OS
    // entropy live here rather than at the sans-I/O sites that framed the
    // plaintext.
    let send_crypt = config
        .peer_crypt
        .map(|policy| PeerUdpCrypt::new(own_identity.clone(), policy.crypt_stance()));
    let drain_socket = Arc::clone(&socket);
    tokio::spawn(async move {
        while let Some(send) = reply_rx.recv().await {
            let (to, datagram) =
                encrypt_client_udp_send(send_crypt.as_ref(), send, os_datagram_nonce);
            // The Family Pair picks the socket the destination's family
            // needs (ADR-0085): a reask reply leaves by the half its ping
            // arrived on, so the peer sees the source address it keyed its
            // own crypt on.
            if let Err(error) = drain_socket.send_to_peer(to, &datagram).await {
                tracing::debug!(%error, %to, "transient client-UDP reply send error");
            }
        }
    });
    // The quartet names no file, so a reply goes to the one download whose
    // `0x90` to that endpoint is in flight (ADR-0107) — aMule's one requested
    // file per client — and a reply nothing asked for drops. A pool that has
    // fallen behind costs its reply, counted, rather than backing up the
    // front's inbox.
    let routes = Arc::clone(sinks.reask_reply);
    let mut reask_reply_rx = inboxes.reask_reply;
    let reply_diagnostics = diagnostics.clone();
    tokio::spawn(async move {
        while let Some(datagram) = reask_reply_rx.recv().await {
            let sink = routes
                .lock()
                .expect("reask reply sink mutex")
                .route_reply(datagram.0, std::time::Instant::now());
            match sink {
                Some(tx) => {
                    if tx.try_send(datagram).is_err() {
                        reply_diagnostics.count_peer_udp_inbox_drop();
                    }
                }
                None => {
                    reply_diagnostics.count_reask_reply_unasked();
                    tracing::debug!(from = %datagram.0, "a reask reply answered no ping in flight");
                }
            }
        }
    });
    // The **firewalled front** (ADR-0061), spawned before the
    // NAT-T front it reaches: its inlets are this socket's `0x95`/`0xA0` and
    // the buddy TCP link, and its acting verdicts become bursts the NAT-T
    // front fires on this same bind.
    natt.firewalled_front
        .install(crate::firewalled::front::spawn(
            crate::firewalled::front::FirewalledWiring {
                hello: natt.hello_adverts.clone(),
                reach: natt.reach.clone(),
                admit: natt.admit.clone(),
                // A relayed reask re-enters the ordinary `0x90` reply matrix
                // through the serve task's own inbox, so one shape reaches
                // `ServeState` whether it arrived by socket or by relay.
                reask_ping: inboxes.reask_ping_injector,
                addresses: own_identity.addresses().clone(),
                file_known: natt.file_known.clone(),
                diagnostics: diagnostics.clone(),
                kad_presence: natt.kad_presence.clone(),
                events: Some(natt.events.clone()),
            },
        ));
    spawn_natt_front(
        &socket,
        config,
        own_identity,
        diagnostics,
        &reply_tx,
        inboxes.natt,
        natt,
    );
    (Some(inboxes.reask_ping), Some(reply_tx))
}

/// The core-owned cells the client-UDP front hands datagrams to, beside the
/// inboxes it returns. All three are late-bound by their own concern's
/// lifetime — a recruited buddy, an active download, a running Kad node — and
/// the front reads them per datagram rather than holding what they point at.
pub(super) struct ClientUdpSinks<'a> {
    pub(super) buddy_slot: &'a SharedBuddySlot,
    pub(super) reask_reply: &'a SharedReaskReplySink,
    pub(super) kad_inlet: crate::client_udp::SharedKadInlet,
}

/// The cells the **NAT-T Front** reaches that the client-UDP front does not
/// otherwise hold.
pub(super) struct NattFrontWiring<'a> {
    /// **Self Reach**, whose NAT-T family is the front's cell —
    /// installed here — and which the firewalled front reads.
    pub(super) reach: &'a crate::reachability::SharedSelfReach,
    pub(super) admit: crate::adapters::SharedTunnelAdmit,
    /// The **Pending Tunnel Claim** table, so a retired **Traversal Attempt**
    /// reaches the download that was waiting on it.
    pub(super) claims: crate::adapters::SharedTunnelClaims,
    pub(super) peer_pin: crate::adapters::SharedPeerPin,
    pub(super) events: mpsc::WeakSender<CoreEvent>,
    /// The **firewalled front**'s two cells (ADR-0061) — its slot
    /// rides the one Hello Adverts read its buddy dial states.
    /// It is spawned beside the NAT-T front because it is the same bind's
    /// tenant: its acting verdicts become bursts on this socket, and the two
    /// opcodes it consumes arrive on it.
    pub(super) hello_adverts: crate::adapters::HelloAdverts,
    pub(super) firewalled_front: crate::firewalled::front::SharedFirewalledFront,
    /// The file-known predicate: the firewalled front's `0x99`
    /// gate reads it inline, never awaiting the actor.
    pub(super) file_known: crate::known_files::SharedFileKnown,
    /// **Kad Presence**: the firewalled front's `0x99`/`0x95`
    /// gates' "is Kad running" input, read live rather than carried by a
    /// task-local copy.
    pub(super) kad_presence: crate::adapters::KadPresenceView,
}

/// Start the **NAT-T Front** (ADR-0091) over the one bound client-UDP socket.
///
/// It must be *this* socket: the pinhole a punch opens belongs to this bind,
/// so a transport with a socket of its own would have to punch again through a
/// mapping no coordinator ever saw. A front that cannot start is a
/// configuration fault in an engine, and it costs rung 1 alone — everything
/// else on this socket keeps running.
fn spawn_natt_front(
    socket: &Arc<rmule_net::ed2k::ClientUdpSocket>,
    config: &CoreConfig,
    own_identity: &SharedOwnIdentity,
    diagnostics: &crate::diagnostics::DiagnosticsState,
    client_udp: &mpsc::Sender<ClientUdpSend>,
    inbox: mpsc::Receiver<ClientUdpDatagram>,
    natt: NattFrontWiring<'_>,
) {
    let stance = config
        .peer_crypt
        .map_or(rmule_primitives::CryptStance::disabled(), |policy| {
            policy.crypt_stance()
        });
    // Armed exactly when the peer-UDP crypt layer is, and by the same policy:
    // a NAT-T KEY frame asserts our hash, which invites a peer to obfuscate
    // toward a receiver that must be able to dual-path decrypt.
    let crypt: Option<Box<dyn rmule_net::natt::NattCrypt>> = config.peer_crypt.map(|_| {
        Box::new(crate::natt::front::OwnIdentityNattCrypt(
            own_identity.clone(),
        )) as Box<dyn rmule_net::natt::NattCrypt>
    });
    let identity = rmule_net::natt::NattIdentity {
        local: crate::natt::front::RMULE_NATT_CLAIM,
        crypt_options: crate::client_udp::direct_callback_connect_options(stance),
    };
    // The demux reads this cell per CAPS frame rather than a value captured
    // here at bind, when no credentialed activity has necessarily run yet
    // A node that has not identified itself answers no CAPS
    // probe until it does, instead of answering every probe with a hash that
    // was never its own. The KEY frame is unaffected — it reads the same live
    // cell through `NattCrypt`, tolerating a zero-hash placeholder.
    let own_hash: Arc<dyn rmule_net::natt::NattOwnHash> = Arc::new(own_identity.clone());
    let wiring = crate::natt::front::NattWiring {
        client_udp: client_udp.clone(),
        addresses: own_identity.addresses().clone(),
        admit: natt.admit,
        claims: natt.claims,
        peer_pin: natt.peer_pin,
        diagnostics: diagnostics.clone(),
        // Off is `None`: no Own Mapping is read and no socket is ever
        // consulted for a route, so the knob off is today's behaviour exactly.
        prediction: match config.natt.port_prediction {
            rmule_peer::natt::PortPrediction::Off => None,
            knob @ rmule_peer::natt::PortPrediction::Birthday => {
                Some(crate::natt::front::PredictionWiring {
                    knob,
                    socket: Arc::clone(socket),
                })
            }
        },
        events: Some(natt.events),
    };
    match crate::natt::front::spawn(
        rmule_net::natt::ClientUdpNattSink(Arc::clone(socket)),
        identity,
        own_hash,
        crypt,
        wiring,
        inbox,
    ) {
        Ok(commands) => natt.reach.natt().install(commands),
        Err(error) => {
            tracing::warn!(%error, "NAT-T front disabled: an engine refused to start");
        }
    }
}
