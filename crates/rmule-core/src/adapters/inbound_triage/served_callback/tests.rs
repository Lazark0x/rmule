//! A served link's `OP_CALLBACK` (`0x99`), end to end through the real accept
//! router: the peer is an ordinary served connection — no buddy
//! recruited, nothing attached — because aMule's `OP_CALLBACK` arm reads no
//! buddy/role state.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use rmule_kad::KadId;
use rmule_net::peer::{ConnectOptions as PeerConnectOptions, PeerListener};
use rmule_peer::{Callback, ConnectionEvent};
use rmule_primitives::{FileHash, Ipv4Endpoint, PeerEndpoint, UserHash};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::adapters::dialed_serve::SharedDialedServeSink;
use crate::adapters::inbound_triage::{InboundPeerDeps, triage_inbound_connection};
use crate::adapters::kad_runtime::{KadPresenceView, SharedKadBootstrap};
use crate::adapters::serve_runtime::{AdmittedPeer, ServeInput, ServeOutput};
use crate::adapters::{AwaitedInbound, SharedKadPump, SharedTunnelAdmit};
use crate::buddy_link::SharedBuddySlot;
use crate::diagnostics::DiagnosticsState;
use crate::known_files::SharedFileKnown;

/// Asymmetric, so a check that compared the wrong word order could not pass.
const OUR_KAD_ID: [u8; KadId::BYTE_LEN] = [
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
];

/// The `0x99` check field addressed to `id`: its bit-inverse.
fn addressed_to(id: [u8; KadId::BYTE_LEN]) -> [u8; KadId::BYTE_LEN] {
    id.map(|b| !b)
}

/// What a leg holds while the served link runs: the peer's own socket, the
/// serve channels the bridge needs alive, and the counters it reads.
struct ServedLink {
    peer: TcpStream,
    _commands: mpsc::Sender<ServeOutput>,
    _events: mpsc::Receiver<ServeInput>,
    diagnostics: DiagnosticsState,
}

impl ServedLink {
    async fn send(&mut self, callback: &Callback) {
        self.peer
            .write_all(&callback.encode_packet().encode())
            .await
            .expect("the 0x99 is framed up the served link");
    }
}

/// Accept one plain dialer through the production triage with `deps`, and
/// wait for it to be served (identified, not adopted, not attached).
async fn served_link(deps: InboundPeerDeps, diagnostics: DiagnosticsState) -> ServedLink {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the inbound listener");
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let dialer_hash = UserHash::from_bytes([0x5E; UserHash::BYTE_LEN]);
    let dial = async {
        let mut peer = TcpStream::connect(bound).await.expect("dial the listener");
        peer.write_all(&rmule_testkit::wire::hello_bytes(
            dialer_hash,
            "served-peer",
        ))
        .await
        .expect("the hello is framed");
        peer
    };
    let (accepted, peer) = tokio::join!(
        listener.accept(
            rmule_testkit::peer_session::serverless_ctx(),
            PeerConnectOptions::default()
        ),
        dial,
    );
    let conn = accepted.expect("accept the dialer");
    let (commands, command_rx) = mpsc::channel(4);
    let (event_tx, mut events) = mpsc::channel(16);
    tokio::spawn(triage_inbound_connection(
        conn,
        None,
        command_rx,
        event_tx,
        AwaitedInbound::default(),
        deps,
    ));
    loop {
        match timeout(Duration::from_secs(2), events.recv())
            .await
            .expect("the dialer identifies within 2s")
        {
            Some(ServeInput::Connection(ConnectionEvent::Identified { .. })) => break,
            Some(_) => continue,
            None => panic!("the accept router ended before the dialer identified"),
        }
    }
    ServedLink {
        peer,
        _commands: commands,
        _events: events,
        diagnostics,
    }
}

/// Wait until the relayed-callback counters read `(dialed, dropped)`.
async fn counted(diagnostics: &DiagnosticsState, dialed: u64, dropped: u64) {
    timeout(Duration::from_secs(2), async {
        loop {
            let session = diagnostics.snapshot().session;
            if session.relayed_callbacks_dialed_total == dialed
                && session.relayed_callbacks_dropped_total == dropped
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        let session = diagnostics.snapshot().session;
        panic!(
            "expected {dialed} dialed / {dropped} dropped, read {} / {}",
            session.relayed_callbacks_dialed_total, session.relayed_callbacks_dropped_total
        )
    });
}

/// A `0x99` on a link *we serve* is acted on exactly as aMule's
/// `case OP_CALLBACK:` acts on one (`ClientTCPSocket.cpp:1743-1772`) — Kad
/// running, the check field inverting to our own Kad ID, the file known —
/// and the dial-back toward the carried endpoint enters the serve pipeline by
/// the admit seam, as the dialer's side. Each gate's refusal is counted and
/// dials nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_served_links_callback_dials_the_requester_back_and_counts_each_drop() {
    // The requester that asked to be dialed: a bare acceptor, so its accept is
    // the dial-back's whole observable.
    let acceptor = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the requester's acceptor");
    let requester = Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        acceptor.local_addr().expect("bound").port(),
    );
    let known = FileHash::from_bytes([
        0x8E, 0x30, 0x2D, 0xB5, 0xB8, 0x06, 0xA2, 0x5C, 0x93, 0x85, 0xFC, 0x23, 0xF2, 0x10, 0x62,
        0xD2,
    ]);

    let kad = KadPresenceView::default();
    let file_known = SharedFileKnown::default();
    file_known.share(known);
    let tunnel_admit = SharedTunnelAdmit::default();
    let (accept_tx, mut admitted) = mpsc::channel::<AdmittedPeer>(4);
    tunnel_admit.install_for_test(
        &accept_tx,
        rmule_testkit::peer_session::serverless_ctx(),
        crate::adapters::HelloAdverts::default(),
    );
    let buddy_slot = SharedBuddySlot::default();
    let diagnostics = DiagnosticsState::default();
    buddy_slot.install_diagnostics(diagnostics.clone());

    let mut link = served_link(
        InboundPeerDeps {
            slot_wait_timeout: Duration::from_secs(5),
            dialed_serve_sink: SharedDialedServeSink::default(),
            kad_bootstrap: SharedKadBootstrap::default(),
            kad_pump: SharedKadPump::default(),
            buddy_slot,
            addresses: crate::address_learning::SharedAddressLearning::new(),
            peer_roster: crate::peer_roster::SharedPeerRoster::default(),
            kad_presence: kad.clone(),
            file_known,
            tunnel_admit,
            hello_refusals: crate::hello_refusals::SharedHelloRefusals::default(),
        },
        diagnostics,
    )
    .await;

    let ours = Callback {
        buddy_id: addressed_to(OUR_KAD_ID),
        file_hash: known,
        requester,
    };

    // Kad down: no node runs, so nothing is ours to answer.
    link.send(&ours).await;
    counted(&link.diagnostics, 0, 1).await;

    let _running = kad.lease(KadId::from_bytes(OUR_KAD_ID));
    // Not for us: the check field inverts to somebody else's Kad ID.
    link.send(&Callback {
        buddy_id: addressed_to([0x44; KadId::BYTE_LEN]),
        ..ours
    })
    .await;
    counted(&link.diagnostics, 0, 2).await;
    // File unknown: we neither share nor download it.
    link.send(&Callback {
        file_hash: FileHash::from_bytes([0xEE; FileHash::BYTE_LEN]),
        ..ours
    })
    .await;
    counted(&link.diagnostics, 0, 3).await;

    // All three gates pass: the requester is dialed.
    link.send(&ours).await;
    let (_dialed_back, _) = timeout(Duration::from_secs(2), acceptor.accept())
        .await
        .expect("the dial-back reached the requester within 2s")
        .expect("the requester accepted it");
    let AdmittedPeer {
        conn,
        dialed_toward,
        ..
    } = timeout(Duration::from_secs(2), admitted.recv())
        .await
        .expect("the dial-back entered the serve pipeline within 2s")
        .expect("the admit channel stayed open");
    assert_eq!(conn.peer_endpoint(), PeerEndpoint::V4(requester));
    assert_eq!(
        dialed_toward, None,
        "a callback dial-back is aimed at no hash this node named"
    );
    counted(&link.diagnostics, 1, 3).await;
    assert_eq!(
        link.diagnostics
            .snapshot()
            .session
            .relayed_callbacks_no_buddy_total,
        0,
        "the served role has no held-link prerequisite to miss"
    );
}
