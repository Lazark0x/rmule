//! **The claim the socket unification exists to make** (ADR-0057): one bound
//! UDP port carries the peer-UDP reask surface, the NAT-T transport frames and
//! a whole running Kad node — and every counterparty sees the *same* source
//! port, which is what makes the mapping a serving buddy observed at the
//! `0x51` recruit the mapping a NAT-T punch has to reach.
//!
//! The assembly is the one `service::actor::spawn_client_udp_front` builds: a
//! real `ClientUdpSocket` **Family Pair** on loopback, the `ClientUdpEngine`
//! draining it, the production send drain behind it, and a real
//! `rmule_net::kad` node started over the same bind with its inlet installed
//! in the front's slot. Nothing is faked below the socket — the datagrams
//! cross the loopback interface.
//!
//! What this leg does **not** re-prove: the reask reply *matrix*
//! (`ServeState::on_reask_ping`). Its answers are already driven over this
//! same front, end to end, by `serve::runner::tests`; here the reply is framed
//! at the inbox and pushed through the production egress, because the fact
//! under test is the **port it leaves by**, not the bytes it carries.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use rmule_kad::{KadCommand, KadEvent, KadId, KadNodeConfig, KadNodeEndpoint};
use rmule_net::ed2k::ClientUdpSocket;
use rmule_net::family::FamilySelection;
use rmule_peer::{natt::NattFrame, queue_full_datagram};
use rmule_primitives::{Ipv4Endpoint, PeerEndpoint, UserHash};
use tokio::sync::mpsc;

use super::{ClientUdpEngine, ClientUdpSend, SharedKadInlet};
use crate::adapters::RuntimeClientUdpTransport;
use crate::buddy_link::SharedBuddySlot;
use crate::diagnostics::DiagnosticsState;

/// How long any one step of the leg may take before the loopback is declared
/// broken rather than slow.
const STEP: Duration = Duration::from_secs(5);

/// The three protocols on one socket, and the one source port the peer sees.
#[tokio::test(flavor = "multi_thread")]
async fn one_bound_port_carries_the_reask_surface_natt_and_a_live_kad_node() {
    // IPv4 only: Kad is IPv4 end to end (ADR-0085) and the loopback the two
    // sides meet on is `127.0.0.1`. Port 0, so parallel runs cannot collide —
    // the *configured* port is a deployment's choice, never a test's.
    let socket = Arc::new(
        ClientUdpSocket::bind_with(0, FamilySelection::v4_only())
            .await
            .expect("a loopback client-UDP pair binds"),
    );
    let unified_port = socket.local_port();

    // The front, as the actor assembles it: the demux engine, the Kad inlet
    // slot it reads per datagram, and the send drain every reply rides.
    let kad_inlet = SharedKadInlet::default();
    let (reply_tx, mut reply_rx) = mpsc::channel::<ClientUdpSend>(16);
    let (engine, mut inboxes) = ClientUdpEngine::new(
        RuntimeClientUdpTransport::new(Arc::clone(&socket)),
        None,
        SharedBuddySlot::default(),
        crate::firewalled::front::SharedFirewalledFront::default(),
        DiagnosticsState::default(),
        reply_tx.clone(),
        kad_inlet.clone(),
    );
    tokio::spawn(engine.run());
    let drain = Arc::clone(&socket);
    tokio::spawn(async move {
        while let Some(send) = reply_rx.recv().await {
            let _ = drain.send_to_peer(send.to, &send.datagram).await;
        }
    });

    // A real Kad node over that same bind — no socket of its own.
    let (inlet_tx, inlet_rx) = mpsc::channel(rmule_net::kad::KAD_INLET_CAPACITY);
    let node = rmule_net::kad::spawn_over(
        rmule_net::kad::KadNetConfig {
            node: KadNodeConfig {
                id: KadId::from_bytes([0x11; KadId::BYTE_LEN]),
                tcp_port: 4662,
                udp_port: 0,
                user_hash: UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
            },
            capture_dir: None,
            nodes_dat_path: None,
            firewall_self_check: false,
            datagram_obfuscation: false,
            verify_keys: None,
            contact_admission: None,
        },
        rmule_net::kad::KadInlet {
            datagrams: inlet_rx,
            socket: Arc::clone(&socket),
            traffic: rmule_net::kad::KadTraffic::default(),
        },
    )
    .await
    .expect("the Kad node starts over the shared bind");
    *kad_inlet.lock().expect("kad inlet mutex") = Some(inlet_tx);

    // --- The counterparties. ------------------------------------------------

    // A whole standalone Kad node: it dials our unified port and stores us at
    // whatever endpoint our answer came from.
    let mut counterparty = rmule_net::kad::spawn(
        rmule_net::kad::KadNetConfig {
            node: KadNodeConfig {
                id: KadId::from_bytes([0x22; KadId::BYTE_LEN]),
                tcp_port: 4662,
                udp_port: 0,
                user_hash: UserHash::from_bytes([0x22; UserHash::BYTE_LEN]),
            },
            capture_dir: None,
            nodes_dat_path: None,
            firewall_self_check: false,
            datagram_obfuscation: false,
            verify_keys: None,
            contact_admission: None,
        },
        (Ipv4Addr::LOCALHOST, 0).into(),
    )
    .await
    .expect("the counterparty Kad node binds");

    // A plain peer socket for the two eD2k-side protocols.
    let peer = ClientUdpSocket::bind_with(0, FamilySelection::v4_only())
        .await
        .expect("a peer socket binds");
    let us = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, unified_port));

    // --- 1. `0xC5` — the peer-UDP reask surface. ----------------------------

    let ping = rmule_peer::ReaskFilePing {
        file_hash: rmule_primitives::FileHash::from_bytes([0x33; 16]),
        part_status: None,
        complete_sources: None,
    }
    .encode_udp();
    peer.send_to_peer(us, &ping).await.expect("the ping leaves");
    let (from, routed) = tokio::time::timeout(STEP, inboxes.reask_ping.recv())
        .await
        .expect("the reask ping reaches the serve inbox")
        .expect("the front is running");
    assert_eq!(routed, ping);
    // Answered through the production egress — the queue-full the matrix
    // returns for an unknown pinger on a full queue.
    reply_tx
        .send(ClientUdpSend::plaintext(from, queue_full_datagram()))
        .await
        .expect("the send drain is running");
    let (answer, answered_from) = tokio::time::timeout(STEP, peer.recv())
        .await
        .expect("the reask answer comes back")
        .expect("receive succeeds");
    assert_eq!(answer, queue_full_datagram());
    assert_eq!(
        answered_from, us,
        "the reask answer leaves by the one bound port"
    );

    // --- 2. `0xB2` — the NAT-T transport frame. -----------------------------

    let frame = NattFrame::Key(UserHash::from_bytes([0x44; 16])).encode();
    peer.send_to_peer(us, &frame)
        .await
        .expect("the frame leaves");
    let (natt_from, natt_frame) = tokio::time::timeout(STEP, inboxes.natt.recv())
        .await
        .expect("the NAT-T frame reaches the front's inbox")
        .expect("the front is running");
    assert_eq!(natt_frame, frame);
    assert_eq!(
        natt_from,
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, peer.local_port())),
    );

    // --- 3. `0xE4` — a whole Kad conversation. ------------------------------

    counterparty
        .command(KadCommand::Bootstrap {
            endpoint: KadNodeEndpoint::new(Ipv4Addr::LOCALHOST, unified_port),
        })
        .await
        .expect("the counterparty accepts commands");
    let stored = tokio::time::timeout(STEP, async {
        loop {
            match counterparty.next_event().await.expect("the driver lives") {
                KadEvent::ContactAdded { id, endpoint }
                    if id == KadId::from_bytes([0x11; KadId::BYTE_LEN]) =>
                {
                    return endpoint;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("the unified node answers the bootstrap over the shared socket");

    // The whole point, in one assertion: the Kad contact a counterparty stores
    // for us names the same port the reask answer came from. A buddy that
    // recruits us over Kad therefore observes the mapping a Tunnel rides.
    assert_eq!(
        stored,
        KadNodeEndpoint::new(Ipv4Addr::LOCALHOST, unified_port),
        "Kad, the reask surface and the NAT-T frames share one source port"
    );

    let _ = counterparty.shutdown().await;
    let summary = node.shutdown().await.expect("the unified node stops");
    assert!(
        summary.datagrams_in >= 1 && summary.datagrams_out >= 1,
        "the Kad node really spoke over the shared socket: {summary:?}"
    );
}
