//! **What this module proves**: two whole NAT-T fronts, each over
//! a *real* bound client-UDP **Family Pair**, raise a Tunnel between them and
//! carry a real `PeerSession` hello inside it. No fake wire anywhere — the
//! datagrams cross the loopback interface through the same
//! `ClientUdpEngine` → NAT-T inbox → `NattDemux` → uTP engine path a running
//! node uses, and the tunnel is adopted through the same
//! [`SharedTunnelAdmit`](crate::adapters::SharedTunnelAdmit) seam the serve
//! adapter's accept pump fills.
//!
//! # Where the leg enters, and why not higher
//!
//! It enters at the front's **punch-this-endpoint-for-this-peer** operation —
//! `NattCommand::Introduced`, the same command an ed2k-server `0x61`
//! introduction produces — and not at an endpoint hint.
//!
//! That is an honest constraint, not a shortcut. A hint naming `127.0.0.1`
//! can never be believed: `is_public_punch_address` refuses loopback (kno's
//! audit finding F1) and the self-punch guard refuses our own interfaces
//! (amule#1177 correction 4). Both guards are correct, neither is weakened
//! here, and neither is given a test-only bypass. Hint acceptance is proven instead in
//! the pure tier, against public addresses —
//! `requester::tests::a_hint_is_acted_on_only_when_expected_trusted_public_and_not_ourselves`
//! and this module's sibling `tests.rs` — so the two legs together cover the
//! ladder end to end with the guards intact.

use std::sync::Arc;
use std::time::Duration;

use rmule_net::ed2k::ClientUdpSocket;
use rmule_net::family::FamilySelection;
use rmule_net::natt::{ClientUdpNattSink, NattOwnHash};
use rmule_net::peer::Connection as PeerConnection;
use rmule_peer::PeerHandshakeContext;
use rmule_peer::natt::{CapsFrame, NattConnectOptions, NattFrame, NattTransport};
use rmule_primitives::{ClientId, ClientIdentity, Ed2kText, FileHash};

use super::*;
use crate::adapters::hello_wait::{Opening, await_hello};
use crate::adapters::{AdmittedPeer, RuntimeClientUdpTransport, SharedTunnelAdmit};
use crate::buddy_link::SharedBuddySlot;
use crate::client_udp::ClientUdpEngine;
use crate::hello_refusals::SharedHelloRefusals;

/// One whole node's client-UDP surface: the bound socket, the demux front, the
/// send drain and the NAT-T front — assembled exactly as
/// `service::actor::spawn_client_udp_front` assembles them.
///
/// # A `Node` is kept whole, or the node is gone
///
/// Every task this fixture starts is kept alive by a *field* of this struct,
/// and nothing else holds them: [`Self::commands`] is the NAT-T front's only
/// command sender, so dropping it ends the front task — which owns the NAT-T
/// inbox receiver, so the node's client-UDP engine then drops every `0xB2`
/// datagram at `route_natt` and every dial in flight hangs out its full
/// `DIAL_TIMEOUT`. [`Self::admit_tx`] is the only strong sender behind the
/// admit cell's weak one, so dropping it makes every adoption
/// `PipelineClosed`.
///
/// That is a trap, because an `async move` block captures **disjointly**
/// (RFC 2229): `tokio::spawn(async move { node.accepted.recv().await })`
/// captures the receiver alone and drops the rest of the node at the spawn —
/// silently killing the front while the leg waits on a dial that can never
/// complete. Hand the whole node to [`Self::drain_accepted`]
/// instead of reaching for the field.
pub(super) struct Node {
    pub(super) port: u16,
    commands: mpsc::Sender<NattCommand>,
    pub(super) accepted: mpsc::Receiver<AdmittedPeer>,
    /// The one counter surface both halves of this node write: the client-UDP
    /// engine's inbox drops and the front's tunnel and retirement tallies. A
    /// leg reads it to say what the wire did rather than what it hoped.
    pub(super) diagnostics: DiagnosticsState,
    /// Held so the admit cell's weak sender stays upgradable for the leg.
    admit_tx: mpsc::Sender<AdmittedPeer>,
    /// This node's own **Awaited Inbound** registry — the exact instance
    /// its front's `NattWiring.claims` was built over, so a leg that also
    /// hands a raw accepted connection to `triage_inbound_connection` reaches
    /// the same registry the front installed its risen-report sender on.
    /// Production shares one instance the same way; a fixture that
    /// built its own separate registry would report nothing this front ever
    /// reads.
    pub(super) claims: crate::adapters::AwaitedInbound,
}

fn ctx(user_hash: UserHash, nickname: &str) -> PeerHandshakeContext {
    PeerHandshakeContext {
        identity: ClientIdentity::new(user_hash, Ed2kText::from_utf8(nickname), 4662, 0x3C),
        client_id: ClientId::from_u32(0x1000_0001),
        ed2k_client_id: ClientId::from_u32(0x1000_0001),
        public_ip: None,
        connected_server: None,
    }
}

impl Node {
    /// Bind and start one node whose NAT-T identity is exactly `identity`,
    /// read live rather than fixed at this call — so a caller may publish
    /// `identity`'s hash after this returns and prove the demux answers a
    /// CAPS probe it could not have answered a moment earlier.
    /// `ctx_hash` is the separate eD2k hello identity a risen tunnel's peer
    /// session presents; the two coincide in [`Self::start`] but a test with
    /// no tunnel to raise may pass anything.
    ///
    /// IPv4 only: a punch is IPv4 end to end, and the loopback the two halves
    /// meet on is `127.0.0.1`.
    pub(super) async fn start_with_identity(
        identity: crate::own_identity::SharedOwnIdentity,
        ctx_hash: UserHash,
        nickname: &str,
    ) -> Self {
        Self::start_on(
            bound_client_udp_socket().await,
            identity,
            ctx_hash,
            nickname,
        )
        .await
    }

    /// Start one node over a client-UDP socket the caller already bound. A leg
    /// binds one ahead of the node only when it must aim a dial at a node that
    /// does not exist yet — see [`discard_queued`].
    async fn start_on(
        socket: ClientUdpSocket,
        identity: crate::own_identity::SharedOwnIdentity,
        ctx_hash: UserHash,
        nickname: &str,
    ) -> Self {
        let socket = Arc::new(socket);
        let port = socket.local_port();
        let diagnostics = DiagnosticsState::default();
        let (reply_tx, mut reply_rx) = mpsc::channel(64);
        let (engine, inboxes) = ClientUdpEngine::new(
            RuntimeClientUdpTransport::new(Arc::clone(&socket)),
            crate::client_udp::PeerUdpCrypt::disarmed(),
            SharedBuddySlot::default(),
            crate::firewalled::front::SharedFirewalledFront::default(),
            diagnostics.clone(),
            reply_tx.clone(),
            // No Kad node in this assembly: the inlet stays empty, which is
            // what the front reads as "nothing to hand a Kad datagram to".
            crate::client_udp::SharedKadInlet::default(),
        );
        tokio::spawn(engine.run());
        let drain = Arc::clone(&socket);
        tokio::spawn(async move {
            while let Some(send) = reply_rx.recv().await {
                let _ = drain.send_to_peer(send.to, &send.datagram).await;
            }
        });

        let (admit_tx, accepted) = mpsc::channel(4);
        let admit = SharedTunnelAdmit::default();
        admit.install_for_test(
            &admit_tx,
            ctx(ctx_hash, nickname),
            crate::adapters::HelloAdverts::default(),
        );
        let claims = crate::adapters::AwaitedInbound::default();
        let commands = spawn(
            ClientUdpNattSink(socket),
            NattIdentity {
                local: RMULE_NATT_CLAIM,
            },
            Arc::new(identity) as Arc<dyn NattOwnHash>,
            None,
            NattWiring {
                client_udp: reply_tx,
                // Only buddy legs run here: no server is asked.
                server: crate::natt::server_punch::CoordinatorSession::default(),
                reach: crate::reachability::SharedSelfReach::new(
                    crate::KadReachLevel::fixed(false),
                    crate::own_identity::SharedOwnIdentity::default(),
                    SharedNattFront::default(),
                ),
                addresses: crate::address_learning::SharedAddressLearning::default(),
                admit,
                claims: claims.clone(),
                peer_pin: crate::adapters::SharedPeerPin::default(),
                roster: crate::peer_roster::SharedPeerRoster::default(),
                diagnostics: diagnostics.clone(),
                events: None,
                prediction: None,
            },
            inboxes.natt,
        )
        .expect("the uTP engine starts");
        Self {
            port,
            commands,
            accepted,
            diagnostics,
            admit_tx,
            claims,
        }
    }

    /// Bind and start one node whose identity is already known — the common
    /// case every tunnel-raising leg in this file uses.
    pub(super) async fn start(user_hash: UserHash, nickname: &str) -> Self {
        Self::start_over(bound_client_udp_socket().await, user_hash, nickname).await
    }

    /// The same, over a socket the leg bound — and dialed — before this node.
    pub(super) async fn start_over(
        socket: ClientUdpSocket,
        user_hash: UserHash,
        nickname: &str,
    ) -> Self {
        let identity = crate::own_identity::SharedOwnIdentity::default();
        identity.set_user_hash(user_hash);
        Self::start_on(socket, identity, user_hash, nickname).await
    }

    /// Drain this node's admitted path from a task of its own, forwarding what
    /// it takes — the shape a leg needs when it must triage one side while the
    /// other is still rising.
    ///
    /// The **whole node** moves into the task, which is the entire point: see
    /// the disjoint-capture trap on [`Node`]. Taking `self` by value is what
    /// makes the safe shape the only shape.
    pub(super) fn drain_accepted(self) -> mpsc::Receiver<AdmittedPeer> {
        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            let mut node = self;
            while let Some(admitted) = node.accepted.recv().await {
                if tx.send(admitted).await.is_err() {
                    return;
                }
            }
        });
        rx
    }

    /// Fill this node's admit channel to capacity with connections nothing
    /// will ever read, so the next adoption meets a serve pipeline that has
    /// stopped draining — the production condition a busy serve runner
    /// reaches while it is inside an `enact` await with sixteen admissions
    /// already queued.
    pub(super) fn stall_admit(&self) {
        loop {
            let (dummy, _held) = tokio::io::duplex(64);
            let conn = PeerConnection::over_stream(
                dummy,
                PeerEndpoint::V4(Ipv4Endpoint::new(std::net::Ipv4Addr::LOCALHOST, 1)),
                rmule_net::peer::PeerStreamRole::Responder,
                ctx(UserHash::from_bytes([0; UserHash::BYTE_LEN]), "stall"),
                rmule_net::peer::ConnectOptions::default(),
            );
            if self
                .admit_tx
                .try_send(AdmittedPeer {
                    conn,
                    dialed_toward: None,
                    awaited_server: None,
                })
                .is_err()
            {
                return;
            }
        }
    }

    /// Tell this node it was introduced to `peer` at loopback `port`, on
    /// `role`'s side — the command an `OP_LOWID_HOLEPUNCH_INFO` produces.
    pub(super) async fn introduced_to(
        &self,
        peer: UserHash,
        port: u16,
        role: rmule_ed2k::HolepunchRole,
    ) {
        self.commands
            .send(NattCommand::Introduced {
                peer_hash: peer,
                target: Ipv4Endpoint::new(std::net::Ipv4Addr::LOCALHOST, port),
                role,
                burst: false,
                source: rmule_peer::natt::PunchTargetSource::Observed,
            })
            .await
            .expect("the front is running");
    }

    /// Arm a **buddy**-coordinated attempt toward `peer`, relayed by a buddy
    /// this fixture controls at `buddy_udp`.
    ///
    /// This is the one way to put a *real* held burst on the front's ledger
    /// without ever routing a punch through loopback: `on_hint`'s source
    /// check is against `buddy_udp`, which this fixture is free to bind
    /// anywhere it likes, but the endpoint the hint *names to punch* is read
    /// straight off the packet body and is `is_public_punch_address`'s to
    /// judge — see `a_tunnel_adopted_cancels_a_still_pending_hold_toward_the_same_peer`.
    pub(super) async fn begin_toward(
        &self,
        peer: UserHash,
        buddy_id: [u8; rmule_peer::BUDDY_ID_LEN],
        buddy_udp: Ipv4Endpoint,
    ) {
        self.commands
            .send(NattCommand::Traverse {
                coordinator: AttemptCoordinator::Buddy {
                    buddy_id,
                    buddy_udp,
                },
                owner: Some(AttemptOwner {
                    target: peer,
                    facts: crate::callback::NattFacts {
                        on_our_server: false,
                        supports_natt: true,
                        buddy: None,
                        advertised_udp: None,
                    },
                    offer: crate::natt::RendezvousOffer {
                        // The buddy in this fixture is our own test code and
                        // never reads what we claim about ourselves.
                        our_user_hash: UserHash::from_bytes([0; UserHash::BYTE_LEN]),
                        options: NattConnectOptions::advertise(0, true, false),
                        file_hash: None,
                        claimed_endpoint: None,
                        transport: NattTransport::Utp,
                    },
                }),
            })
            .await
            .expect("the front is running");
    }
}

/// An IPv4 client-UDP socket on a port the OS picks — no fixed number, so
/// parallel legs and parallel runs cannot collide.
async fn bound_client_udp_socket() -> ClientUdpSocket {
    ClientUdpSocket::bind_with(0, FamilySelection::v4_only())
        .await
        .expect("a loopback client-UDP pair binds")
}

/// Throw away every datagram queued on a socket no node reads yet, and count
/// the uTP `ST_SYN` openers among them.
///
/// This is how a leg aims a dial at a node that has not started: it holds the
/// node's socket — so no parallel test can take the port before the node
/// does — and discards what arrived before handing the socket
/// over. An opener discarded here reached nothing that could answer it, the
/// one condition a re-dial has to be proven against, because `librqbit-utp`
/// never sends that opener again. A held port draws no ICMP port-unreachable,
/// so the dialer learns nothing a free port would have told it; the count is
/// what proves an opener actually arrived and was lost.
async fn discard_queued(socket: &ClientUdpSocket) -> usize {
    // `(ST_SYN << 4) | version 1`, the first byte of a uTP SYN.
    const UTP_SYN: u8 = 0x41;
    let mut syns = 0;
    // The openers left the dialer long before this runs; a short quiet spell
    // means the kernel queue is empty.
    while let Ok(received) = tokio::time::timeout(Duration::from_millis(100), socket.recv()).await {
        let (datagram, _) = received.expect("a loopback receive succeeds");
        if matches!(NattFrame::decode(&datagram), Ok(NattFrame::Utp(packet)) if packet.first() == Some(&UTP_SYN))
        {
            syns += 1;
        }
    }
    syns
}

/// Wait for a connection's peer to identify, through the one hello wait every
/// connection shares (a refused hello is reported, and its close follows).
async fn identified(conn: &mut PeerConnection) -> UserHash {
    match await_hello(conn, &SharedHelloRefusals::default(), |_| {}).await {
        Opening::Identified(identity) => identity.user_hash(),
        Opening::Closed(reason) => panic!("the tunnelled session closed: {reason:?}"),
        Opening::Ended => panic!("the driver ended before the peer identified"),
    }
}

/// A punched path carries an ordinary eD2k conversation, end to end through a
/// running node's own machinery.
///
/// The initiator dials and the responder accepts — the dialect's asymmetry, so
/// one tunnel rises rather than two — and both sides' `PeerSession` completes
/// its hello inside it. Nothing in `rmule-peer`, nothing in the driver and
/// nothing in the serve pipeline was told a UDP pinhole is underneath.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_fronts_raise_a_tunnel_over_loopback_and_carry_a_hello() {
    let (a_hash, b_hash) = (
        UserHash::from_bytes([0xAA; UserHash::BYTE_LEN]),
        UserHash::from_bytes([0xBB; UserHash::BYTE_LEN]),
    );
    let mut a = Node::start(a_hash, "rmule-punch-a").await;
    let mut b = Node::start(b_hash, "rmule-punch-b").await;

    // Both sides are told at once, as the server tells them: the side named
    // initiator dials, the other records its expectation and accepts.
    b.introduced_to(a_hash, a.port, rmule_ed2k::HolepunchRole::Responder)
        .await;
    a.introduced_to(b_hash, b.port, rmule_ed2k::HolepunchRole::Initiator)
        .await;

    let deadline = Duration::from_secs(20);
    let dialed = tokio::time::timeout(deadline, a.accepted.recv())
        .await
        .expect("the dialer's tunnel entered the serve pipeline")
        .expect("the admit channel is open");
    assert_eq!(
        dialed.dialed_toward,
        Some(b_hash),
        "a dialed tunnel names the target its punch was aimed at (ADR-0091)"
    );
    let accepted = tokio::time::timeout(deadline, b.accepted.recv())
        .await
        .expect("the responder's tunnel entered the serve pipeline")
        .expect("the admit channel is open");
    assert_eq!(
        accepted.dialed_toward, None,
        "an accepted tunnel was aimed at us by somebody else; no download may claim it"
    );
    let mut dialed = dialed.conn;
    let mut accepted = accepted.conn;

    let (seen_by_a, seen_by_b) = tokio::join!(identified(&mut dialed), identified(&mut accepted));
    assert_eq!(seen_by_a, b_hash, "the dialer identified the responder");
    assert_eq!(seen_by_b, a_hash, "the responder identified the dialer");

    dialed.shutdown().await.expect("shutdown");
    accepted.shutdown().await.expect("shutdown");
}

/// The same tunnel rises when **neither** side's admitted path is drained by
/// the test's own task.
///
/// The configuration is the one a 30 s hang was once reported from, and the hang
/// was the fixture's: an `async move` block that mentions only
/// `node.accepted` captures that field alone and drops the node's command
/// sender with it, ending the NAT-T front task — after which the dialer's
/// client-UDP engine drops the responder's `ST_STATE` at `route_natt` and the
/// dial waits out its whole `DIAL_TIMEOUT`. [`Node::drain_accepted`] takes the
/// node by value so that shape cannot be written; this proves the safe one
/// raises the tunnel, and that the dialer's inbox dropped nothing on the way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tunnel_rises_with_both_admitted_paths_drained_off_task() {
    let (a_hash, b_hash) = (
        UserHash::from_bytes([0xAA; UserHash::BYTE_LEN]),
        UserHash::from_bytes([0xBB; UserHash::BYTE_LEN]),
    );
    let a = Node::start(a_hash, "rmule-punch-a").await;
    let b = Node::start(b_hash, "rmule-punch-b").await;
    let (a_port, b_port) = (a.port, b.port);
    let a_diagnostics = a.diagnostics.clone();

    b.introduced_to(a_hash, a_port, rmule_ed2k::HolepunchRole::Responder)
        .await;
    a.introduced_to(b_hash, b_port, rmule_ed2k::HolepunchRole::Initiator)
        .await;
    let mut a_accepted = a.drain_accepted();
    let mut b_accepted = b.drain_accepted();

    let deadline = Duration::from_secs(20);
    let dialed = tokio::time::timeout(deadline, a_accepted.recv())
        .await
        .expect("the dialer's tunnel entered the serve pipeline")
        .expect("the admit channel is open");
    assert_eq!(dialed.dialed_toward, Some(b_hash));
    let accepted = tokio::time::timeout(deadline, b_accepted.recv())
        .await
        .expect("the responder's tunnel entered the serve pipeline")
        .expect("the admit channel is open");
    assert_eq!(accepted.dialed_toward, None);
    assert_eq!(
        a_diagnostics.snapshot().session.natt_inbox_drops_total,
        0,
        "the dialer's NAT-T inbox took every datagram: a front that ended \
         would have dropped the answer to its own SYN"
    );
}

/// A serve pipeline that has stopped draining must not starve the front.
///
/// The front's loop is the one thread of control that feeds the demux, so
/// anything it awaits on a consumer it does not drain stalls **every** NAT-T
/// path on the node, not just the tunnel being handed over. Here the hub's
/// admit channel is full before the first tunnel rises, exactly as a busy
/// serve runner leaves it while it is inside an `enact` await; the second
/// peer's dial must still complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_serve_pipeline_does_not_starve_the_front() {
    let hub_hash = UserHash::from_bytes([0xCC; UserHash::BYTE_LEN]);
    let (first_hash, second_hash) = (
        UserHash::from_bytes([0xD1; UserHash::BYTE_LEN]),
        UserHash::from_bytes([0xD2; UserHash::BYTE_LEN]),
    );
    let hub = Node::start(hub_hash, "rmule-punch-hub").await;
    let mut first = Node::start(first_hash, "rmule-punch-first").await;
    let mut second = Node::start(second_hash, "rmule-punch-second").await;
    hub.stall_admit();

    hub.introduced_to(first_hash, first.port, rmule_ed2k::HolepunchRole::Responder)
        .await;
    first
        .introduced_to(hub_hash, hub.port, rmule_ed2k::HolepunchRole::Initiator)
        .await;
    let deadline = Duration::from_secs(20);
    tokio::time::timeout(deadline, first.accepted.recv())
        .await
        .expect("the first peer's dial completed")
        .expect("the admit channel is open");
    // The hub's front has now taken that tunnel off its risen channel and is
    // handing it to a pipeline that will never take it.
    tokio::time::sleep(Duration::from_millis(200)).await;

    hub.introduced_to(
        second_hash,
        second.port,
        rmule_ed2k::HolepunchRole::Responder,
    )
    .await;
    second
        .introduced_to(hub_hash, hub.port, rmule_ed2k::HolepunchRole::Initiator)
        .await;
    tokio::time::timeout(deadline, second.accepted.recv())
        .await
        .expect("the second peer's dial completed while the hub's pipeline was stalled")
        .expect("the admit channel is open");
    assert_eq!(
        hub.diagnostics.snapshot().session.natt_inbox_drops_total,
        0,
        "a stalled hand-off never stops the front draining its NAT-T inbox"
    );
}

/// A dial whose first opener lands on nothing is recovered by the **re-dial**,
/// inside one attempt.
///
/// `librqbit-utp` sends a connect's `ST_SYN` once and never retransmits it, so
/// a responder whose front is not yet assembled when the opener arrives can
/// never be reached by that dial — and before this, the dialer sat on that one
/// `connect()` for the attempt's whole 120 s while its registry slot was pruned
/// out from under it at 30 s. Here the responder's socket is held unread while
/// the first opener arrives, that opener is thrown away, and only then does
/// the responder start over the same socket; the tunnel rises on a later
/// opener within one attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dial_whose_first_opener_lands_on_nothing_is_recovered_by_the_redial() {
    let (a_hash, b_hash) = (
        UserHash::from_bytes([0xAA; UserHash::BYTE_LEN]),
        UserHash::from_bytes([0xBB; UserHash::BYTE_LEN]),
    );
    let b_socket = bound_client_udp_socket().await;
    let mut a = Node::start(a_hash, "rmule-redial-a").await;
    a.introduced_to(
        b_hash,
        b_socket.local_port(),
        rmule_ed2k::HolepunchRole::Initiator,
    )
    .await;

    // Past the per-dial bound: the first opener is queued on a socket nothing
    // reads, and nothing will re-send it.
    tokio::time::sleep(super::dialing::DIAL_ATTEMPT_TIMEOUT + Duration::from_millis(500)).await;
    assert!(
        discard_queued(&b_socket).await >= 1,
        "the first opener reached the responder's port and was thrown away"
    );
    let mut b = Node::start_over(b_socket, b_hash, "rmule-redial-b").await;
    b.introduced_to(a_hash, a.port, rmule_ed2k::HolepunchRole::Responder)
        .await;

    let deadline = super::dialing::DIAL_BUDGET / 2;
    let dialed = tokio::time::timeout(deadline, a.accepted.recv())
        .await
        .expect("the re-dial reached the responder inside one attempt")
        .expect("the admit channel is open");
    assert_eq!(dialed.dialed_toward, Some(b_hash));
    tokio::time::timeout(deadline, b.accepted.recv())
        .await
        .expect("the responder accepted the opener it was awake for")
        .expect("the admit channel is open");
    assert!(
        a.diagnostics.snapshot().session.natt_dials_total > 1,
        "the attempt spent more than one opener, which is the whole point"
    );
}

/// A CAPS probe over real loopback, through a front assembled the production
/// way: the identity is published *after* [`Node::start_with_identity`]
/// returns, exactly the ordering `service::actor::spawn_client_udp_front`
/// cannot guarantee against every credentialed activity. No
/// answer arrives before the hash is set; the very same probe is answered
/// once it is; a probe naming some other hash still draws nothing once
/// identity exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_caps_probe_is_silent_before_identity_and_answered_once_published() {
    let acquired = UserHash::from_bytes([0x77; UserHash::BYTE_LEN]);
    let identity = crate::own_identity::SharedOwnIdentity::default();
    // `ctx_hash` never matters here: no tunnel rises in this leg.
    let node = Node::start_with_identity(identity.clone(), acquired, "rmule-late-hash").await;

    let probe_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("a loopback probe socket binds");
    let node_addr = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, node.port));
    let probe_naming = |expected: UserHash| {
        NattFrame::Caps(CapsFrame {
            connect_options: NattConnectOptions::advertise(0, true, false),
            sender: UserHash::from_bytes([0xEE; UserHash::BYTE_LEN]),
            expected_recipient: expected,
            file_hash: FileHash::from_bytes([0; FileHash::BYTE_LEN]),
        })
        .encode()
    };

    probe_socket
        .send_to(&probe_naming(acquired), node_addr)
        .await
        .expect("send");
    let mut buf = [0u8; 128];
    assert!(
        tokio::time::timeout(Duration::from_millis(300), probe_socket.recv_from(&mut buf))
            .await
            .is_err(),
        "no CAPS-ACK before the node's own identity is known"
    );

    identity.set_user_hash(acquired);

    probe_socket
        .send_to(&probe_naming(acquired), node_addr)
        .await
        .expect("send");
    let (len, _from) =
        tokio::time::timeout(Duration::from_secs(10), probe_socket.recv_from(&mut buf))
            .await
            .expect("a CAPS-ACK arrives once identity is known")
            .expect("recv");
    let decoded = match NattFrame::decode(&buf[..len]).expect("our own frame decodes") {
        NattFrame::CapsAck(caps) => caps,
        other => panic!("expected a CAPS-ACK, got {other:?}"),
    };
    assert_eq!(
        decoded.sender, acquired,
        "the CAPS-ACK carries the hash acquired after start, not a captured one"
    );

    probe_socket
        .send_to(
            &probe_naming(UserHash::from_bytes([0x11; UserHash::BYTE_LEN])),
            node_addr,
        )
        .await
        .expect("send");
    assert!(
        tokio::time::timeout(Duration::from_millis(300), probe_socket.recv_from(&mut buf))
            .await
            .is_err(),
        "a probe naming another node still draws nothing once identity exists"
    );
}

/// A Tunnel adopted through the ordinary dial path cancels a hold still
/// pending toward the *same* peer.
///
/// `end_attempt` is the one door every ending of a Traversal Attempt goes
/// through, and it takes the peer's held burst with it — but the
/// sans-I/O harness cannot raise a real [`Tunnel`], so that leg was proven
/// only by bench run `1790123658`. Here a buddy this fixture controls answers
/// a real rendezvous with a real `EndpointHint`: the hint names `1.2.3.4`, a
/// publicly-routable address nothing is listening on and not one of
/// `is_public_punch_address`'s excluded ranges, so the hold arms exactly as it
/// would for a genuine hint — no guard weakened, no test-only bypass, and the
/// address a punch is ever aimed at over this leg is still never loopback.
/// Before that hold's own deadline, a coordinator introduces the two nodes
/// over real loopback exactly as this file's sibling tests do, and the
/// ordinary dial raises the Tunnel. The hold must die with the attempt: past
/// its own deadline, no burst leaves for the fake address and no second dial
/// is spawned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tunnel_adopted_cancels_a_still_pending_hold_toward_the_same_peer() {
    let (a_hash, b_hash) = (
        UserHash::from_bytes([0xAA; UserHash::BYTE_LEN]),
        UserHash::from_bytes([0xBB; UserHash::BYTE_LEN]),
    );
    let mut a = Node::start(a_hash, "rmule-hold-a").await;
    let mut b = Node::start(b_hash, "rmule-hold-b").await;

    // A buddy this fixture controls, bound to loopback: `on_hint`'s source
    // check is against exactly this endpoint, so a hint claiming to come from
    // it is believed.
    let buddy_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("a loopback buddy probe binds");
    let buddy_udp = Ipv4Endpoint::new(
        std::net::Ipv4Addr::LOCALHOST,
        buddy_socket.local_addr().expect("bound").port(),
    );
    let buddy_id = [0xCC; rmule_peer::BUDDY_ID_LEN];

    a.begin_toward(b_hash, buddy_id, buddy_udp).await;
    // The relay round trip this exchange measures: the hold below arms for
    // half of it (`burst_delay`), long enough that the loopback tunnel raised
    // below has every chance to rise and be adopted first.
    tokio::time::sleep(Duration::from_millis(800)).await;
    let fake_public = Ipv4Endpoint::new(std::net::Ipv4Addr::new(1, 2, 3, 4), 9999);
    let hint = EndpointHint {
        target: b_hash,
        buddy_id,
        file_hash: None,
        target_endpoint: fake_public,
        options: NattConnectOptions::from_byte(0),
    };
    let a_addr = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, a.port));
    buddy_socket
        .send_to(&hint.encode_udp(), a_addr)
        .await
        .expect("send");

    // The ordinary dial, exactly as
    // `two_fronts_raise_a_tunnel_over_loopback_and_carry_a_hello` raises it:
    // a coordinator introduces the same peer over real loopback, and the side
    // that asked dials.
    b.introduced_to(a_hash, a.port, rmule_ed2k::HolepunchRole::Responder)
        .await;
    a.introduced_to(b_hash, b.port, rmule_ed2k::HolepunchRole::Initiator)
        .await;

    let deadline = Duration::from_secs(20);
    let dialed = tokio::time::timeout(deadline, a.accepted.recv())
        .await
        .expect("the dialer's tunnel entered the serve pipeline")
        .expect("the admit channel is open");
    assert_eq!(
        dialed.dialed_toward,
        Some(b_hash),
        "the dialed path names the peer whose hold this leg is proving against"
    );
    tokio::time::timeout(deadline, b.accepted.recv())
        .await
        .expect("the responder's tunnel entered the serve pipeline")
        .expect("the admit channel is open");

    let after_adoption = a.diagnostics.snapshot().session;
    assert_eq!(
        after_adoption.natt_dials_total, 1,
        "one dial: the real one that just rose"
    );
    assert_eq!(
        after_adoption.natt_tunnels_dialed_total, 1,
        "one tunnel: the real one that just rose"
    );

    // Past the hold's own deadline, and then some: if it survived adoption,
    // its burst has fired at the fake address and a second dial toward it has
    // spawned (`dials.arm` sees no in-flight entry left behind by the risen
    // Tunnel — `DialSchedule::risen` removed it — so a second dial is a fresh
    // one, not a refusal).
    tokio::time::sleep(Duration::from_millis(900)).await;
    let after_wait = a.diagnostics.snapshot().session;
    assert_eq!(
        after_wait.natt_dials_total, 1,
        "the peer's hold died when the attempt ended in adoption: no second \
         dial toward the hint's fake address"
    );
    assert_eq!(
        after_wait.natt_tunnels_dialed_total, 1,
        "still one tunnel: adoption ended the attempt the hold belonged to"
    );
}
