//! The ADR-0061 route 2 **enactment**: `CoreCommand::ReachPeer` on a firewalled
//! peer that advertised direct-UDP callback puts a real `OP_DIRECTCALLBACKREQ`
//! (`0x95`) on the bound client-UDP socket, addressed to the peer's **Kad** UDP
//! port.
//!
//! The datagram is read off a real socket, so this exercises the whole live path
//! the capture bench drives — command → chooser → `direct_callback_datagram` →
//! the one client-UDP send drain → `send_to` — rather than the chooser alone
//! (which `callback.rs`'s own tests already pin).
//!
//! aMule receives this on `CClientUDPSocket::OnPacketReceived`
//! (`ClientUDPSocket.cpp:277`): its Kad UDP port and its client UDP port are one
//! socket, demuxed on the leading protocol byte, which is why the direct callback
//! is addressed to the Kad port and still lands in the eMule-protocol handler.

use std::net::{Ipv4Addr, SocketAddrV4};

use crate::fixture::{VerdictOnlyKad, identity_with_port};
use crate::fixture::{dead_port, free_port, serving_started};
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreError, CoreEvent, DownloadFailure, PeerReach,
    PeerReachRoute, PeerTransferService, PeerWorker, ServeCommand, ServeConnection,
    ServeRuntimeService, SourceLookupOutcome, SourceLookupService,
};
use rmule_ed2k::OfferedFile;
use rmule_peer::{DirectCallbackReq, PeerHandshakeContext};
use rmule_primitives::{
    ClientId, ClientIdentity, Ed2kFileLink, Ipv4Endpoint, PeerEndpoint, ServerEndpoint,
    SourceLookupTarget,
};
use rmule_testkit::FakeEd2kServer;
use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};

#[derive(Clone)]
struct UnusedSourceLookup;
impl SourceLookupService for UnusedSourceLookup {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        std::future::pending().await
    }
}

struct UnusedPeerTransfer;
impl PeerTransferService for UnusedPeerTransfer {
    async fn start_peer_worker(
        &mut self,
        _peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        _file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        Err(DownloadFailure::NoUsableSources)
    }
}

/// A serve runtime that binds nothing: the listener's *port* is all route 2
/// reads (it is what the `0x95` body invites the peer to dial), and the accept
/// loop is not part of this path.
struct QuietServeRuntime;
impl ServeRuntimeService for QuietServeRuntime {
    async fn start(
        &mut self,
        _identity: rmule_primitives::ClientIdentity,
        listen_addr: SocketAddrV4,
    ) -> Result<SocketAddrV4, CoreError> {
        Ok(listen_addr)
    }
    async fn accept(&mut self) -> Option<ServeConnection> {
        std::future::pending().await
    }
    async fn announce(
        &mut self,
        files: Vec<OfferedFile>,
    ) -> Result<rmule_core::AnnounceOutcome, CoreError> {
        Ok(rmule_core::AnnounceOutcome::Announced {
            file_count: files.len(),
        })
    }
}

const OUR_LISTEN_PORT: u16 = 4663;

fn our_identity() -> ClientIdentity {
    identity_with_port(OUR_LISTEN_PORT)
}

/// A firewalled peer that advertised direct-UDP callback at `kad_udp` — route
/// 2's whole precondition on the counterparty's side.
fn firewalled_peer(kad_udp: Ipv4Endpoint) -> PeerReach {
    PeerReach {
        // A server-assigned id below the LowID threshold: the callback tree's
        // entry condition.
        id: ClientId::from_u32(42),
        tcp: PeerEndpoint::V4(Ipv4Endpoint::new(kad_udp.ip, 4662)),
        supports_direct_udp_callback: true,
        kad_udp: Some(kad_udp),
        // Off our server and buddy-less, so nothing but route 2 can fire: a
        // `0x95` on the socket cannot be some other route's byte.
        on_our_server: false,
        buddy: None,
        ipv6: None,
        // Route 2 needs no ledger key; rung 1's does, and is not this test's.
        user_hash: None,
        supports_natt: false,
    }
}

async fn serving_core(kad: VerdictOnlyKad) -> Core {
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .user_hash(our_identity().user_hash())
        .source_lookup(UnusedSourceLookup)
        .peer_transfer(UnusedPeerTransfer)
        .serve_runtime(QuietServeRuntime)
        .kad(kad)
        .build();
    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, OUR_LISTEN_PORT),
        credentials: our_identity().into(),
    }))
    .await
    .expect("start serving");
    // Route 2 names the *actually-bound* listener port, which the serve task
    // publishes as it announces `ServingStarted` — wait for it so a reach
    // below never races the bind (a pre-bind reach honestly reports
    // `DirectUdpUnavailable`).
    serving_started(&mut core).await;
    core
}

/// Drain events until the reach verdict arrives (serving emits its own first).
async fn next_reach_route(core: &mut Core) -> PeerReachRoute {
    timeout(Duration::from_secs(5), async {
        loop {
            match core.next_event().await.expect("core still running") {
                CoreEvent::PeerReachRouted { route, .. } => return route,
                _ => continue,
            }
        }
    })
    .await
    .expect("the reach verdict arrives")
}

#[tokio::test]
async fn reaching_a_direct_callback_peer_emits_a_0x95_to_its_kad_udp_port() {
    // Stand in for the firewalled counterparty's Kad UDP port — the endpoint
    // aMule's own direct callback is addressed to (`GetKadPort()`).
    let peer_kad_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the peer's Kad UDP port");
    let peer_kad_addr = peer_kad_socket.local_addr().expect("peer kad addr");
    let peer_kad_udp = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, peer_kad_addr.port());

    let mut core = serving_core(VerdictOnlyKad { open: true }).await;
    core.send(CoreCommand::ReachPeer(firewalled_peer(peer_kad_udp)))
        .await
        .expect("reach the peer");

    assert_eq!(
        next_reach_route(&mut core).await,
        PeerReachRoute::DirectUdp {
            target_kad_udp: peer_kad_udp
        }
    );

    let mut datagram = [0u8; 64];
    let (len, _from) = timeout(
        Duration::from_secs(5),
        peer_kad_socket.recv_from(&mut datagram),
    )
    .await
    .expect("the 0x95 arrives on the peer's Kad UDP port")
    .expect("recv");

    // Byte-decoded, not shape-checked: the body must invite the peer to dial the
    // port we actually listen on, under the identity it will match the dial-back
    // to (`CClientList::GetClientsByHash`).
    assert_eq!(
        DirectCallbackReq::decode_udp(&datagram[..len]),
        Ok(DirectCallbackReq {
            our_tcp_port: OUR_LISTEN_PORT,
            our_user_hash: our_identity().user_hash(),
            // No `peer_crypt` policy: every crypt bit dark, and aMule never sets
            // the direct-callback bit on its own outbound callback either.
            connect_options: 0x00,
        })
    );
}

#[tokio::test]
async fn a_firewalled_us_drops_the_same_peer_low_to_low_and_emits_nothing() {
    // Same peer, same advert — but our own ADR-0058 verdict reads firewalled, so
    // the chooser never reaches route 2 (aMule `DS_LOWTOLOWIP`). The socket
    // staying silent is the point: the gate is real, not decorative.
    let peer_kad_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the peer's Kad UDP port");
    let peer_kad_udp = Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        peer_kad_socket.local_addr().expect("addr").port(),
    );

    let mut core = serving_core(VerdictOnlyKad { open: false }).await;
    core.send(CoreCommand::ReachPeer(firewalled_peer(peer_kad_udp)))
        .await
        .expect("reach the peer");

    assert_eq!(
        next_reach_route(&mut core).await,
        PeerReachRoute::Dropped {
            reason: rmule_core::PeerReachDropReason::LowToLow
        }
    );

    let mut datagram = [0u8; 64];
    assert!(
        timeout(
            Duration::from_millis(300),
            peer_kad_socket.recv_from(&mut datagram)
        )
        .await
        .is_err(),
        "a dropped candidate puts no datagram on the wire"
    );
}

/// The `0x95` body must invite the peer to the port the listener *actually
/// bound*, never the requested one: `listen_addr` port 0 is documented as
/// OS-chosen (`ServeRuntimeService::start`), so an invitation naming the
/// requested 0 would be dead. Production serve runtime (the builder default)
/// so the bind is real; the dead "server" only fails the login, which never
/// fails serving.
#[tokio::test]
async fn the_0x95_invites_the_actually_bound_port_when_the_os_chose_it() {
    let peer_kad_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the peer's Kad UDP port");
    let peer_kad_udp = Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        peer_kad_socket.local_addr().expect("addr").port(),
    );

    // An unreachable "server": the connect fails fast, so the route's
    // verdict is reached without a login in the way.
    let _unreachable_server = dead_port().await;

    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .user_hash(our_identity().user_hash())
        .source_lookup(UnusedSourceLookup)
        .peer_transfer(UnusedPeerTransfer)
        .kad(VerdictOnlyKad { open: true })
        .build();
    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        credentials: our_identity().into(),
    }))
    .await
    .expect("start serving");
    let bound = serving_started(&mut core).await;
    assert_ne!(bound.port(), 0, "the OS chose a real port");

    core.send(CoreCommand::ReachPeer(firewalled_peer(peer_kad_udp)))
        .await
        .expect("reach the peer");
    assert_eq!(
        next_reach_route(&mut core).await,
        PeerReachRoute::DirectUdp {
            target_kad_udp: peer_kad_udp
        }
    );

    let mut datagram = [0u8; 64];
    let (len, _from) = timeout(
        Duration::from_secs(5),
        peer_kad_socket.recv_from(&mut datagram),
    )
    .await
    .expect("the 0x95 arrives on the peer's Kad UDP port")
    .expect("recv");
    let req = DirectCallbackReq::decode_udp(&datagram[..len]).expect("OP_DIRECTCALLBACKREQ");
    assert_eq!(
        req.our_tcp_port,
        bound.port(),
        "the invitation names the bound port, never the requested 0"
    );
}

/// aMule `CamuleApp::IsFirewalled`: a live eD2K **High-ID** alone proves TCP
/// reachability (`!serverconnect->IsLowID()` returns un-firewalled before Kad
/// is even consulted), so Kad idle/unproven must not demote a LowID reach to
/// the LowID→LowID drop. Full production wiring (`Core::new`): the serve
/// start answers the `FakeEd2kServer`'s Back-Connect Probe during login
/// and lands High-ID, Kad is never enabled (the ADR-0058 verdict stays
/// Firewalled) — and route 2 still fires a real `0x95`.
#[tokio::test]
async fn a_server_high_id_opens_route_2_while_kad_is_unproven() {
    let peer_kad_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the peer's Kad UDP port");
    let peer_kad_udp = Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        peer_kad_socket.local_addr().expect("addr").port(),
    );

    let server = FakeEd2kServer::start().await;
    let server_ep =
        ServerEndpoint::parse_host_port(&server.local_addr().to_string()).expect("server endpoint");

    // Serve on a KNOWN port with identity.tcp_port == listen port, so the
    // probe's back-connect hello is answered during the login.
    let p = free_port().await;
    let mut core = Core::new(CoreConfig::default(), rmule_testkit::memory_store());
    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, p),
        credentials: identity_with_port(p).into(),
    }))
    .await
    .expect("start serving");
    serving_started(&mut core).await;
    rmule_testkit::connect_to(&core, &server_ep, identity_with_port(p).into()).await;
    // Premise guard, not the assertion: the probe granted High-ID, so a
    // failure below is the route wiring, not a Low-ID login. Awaited, because
    // `ServingStarted` is the *bind* fact — the login it causes lands later
    // and on its own trail.
    let ids = timeout(Duration::from_secs(10), server.assigned_ids_after(1))
        .await
        .expect("the serve start's login reaches the server");
    assert!(
        ids.first().is_some_and(|id| id.is_high_id()),
        "the serve login must earn High-ID, got {ids:?}"
    );

    core.send(CoreCommand::ReachPeer(firewalled_peer(peer_kad_udp)))
        .await
        .expect("reach the peer");
    assert_eq!(
        next_reach_route(&mut core).await,
        PeerReachRoute::DirectUdp {
            target_kad_udp: peer_kad_udp
        },
        "a server High-ID with Kad unproven must still open route 2"
    );

    // The invitation is real and names the port we serve on.
    let mut datagram = [0u8; 64];
    let (len, _from) = timeout(
        Duration::from_secs(5),
        peer_kad_socket.recv_from(&mut datagram),
    )
    .await
    .expect("the 0x95 arrives on the peer's Kad UDP port")
    .expect("recv");
    let req = DirectCallbackReq::decode_udp(&datagram[..len]).expect("OP_DIRECTCALLBACKREQ");
    assert_eq!(req.our_tcp_port, p, "the invitation names the serving port");
}
