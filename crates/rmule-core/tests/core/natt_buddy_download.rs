//! A **Kad buddy source row** driving a real `Core`'s download, end to end
//! Down every road it can open:
//!
//! - **the punch** (ADR-0091 rung 1) for a downloader that cannot be dialed
//!   back: the admission rule gives the row the punch road, and a real
//!   rendezvous datagram leaves the bound client-UDP socket addressed to the
//!   publisher's **serving buddy**;
//! - **the buddy callback** (ADR-0061 route 4) for one that can: the
//!   download claims the dial-back by the row's User Hash, and when the
//!   publisher dials in it is adopted and the file completes;
//! - **the direct-UDP callback** (ADR-0061 route 2) when the row
//!   states its own `SupportsDirectUDPCallback` bit: the admission rule takes
//!   it ahead of the buddy's, and a real `0x95` lands on a socket bound at
//!   the row's own Kad UDP endpoint rather than the buddy's;
//! - **the type-6 row**, the one that needs no buddy: published
//!   by an rmule node, stored and served back by another, read by the Kad
//!   reader, and taking the direct-UDP road in a real download.
//!
//! Before Kad rows carried their rung-1 facts, no channel could put a buddy
//! on a Low-ID candidate at all, so the buddy arm of the route tree was unreachable from any download and the
//! three `natt-buddy-*` bench rows had to be driven through
//! `CoreCommand::ReachPeer`. This leg is the claim that the channel is now
//! whole: nothing here names a peer by hand — the row goes in at the Kad seam
//! and the datagram comes out on a socket.
//!
//! **Where the punch leg stops.** The Tunnel itself cannot rise on loopback from here:
//! the target's endpoint hint would have to name `127.0.0.1`, which
//! `is_public_punch_address` correctly refuses (ADR-0091), and
//! neither that guard nor the self-punch guard is weakened for a test. The
//! rise and the download's adoption of the risen Tunnel are proven below the
//! guards in `natt::front::live` and `adapters::inbound_triage::tests::verdicts`,
//! which this leg meets at the claim. The callback leg stops short of the `0x52`
//! itself: a scripted Kad seam has no node to send it from, so the event says
//! nothing was emitted, and the bytes are proven against the captured aMule
//! row in `rmule-kad`'s `buddy_publish_capture`.

use rmule_testkit::HANG_GUARD;
use std::net::Ipv4Addr;
use std::time::Duration;

use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadFailure, KadEnableConfig,
    KadRuntimeFactory, KadSourceChannel, PeerReachRoute, PeerTransferService, PeerWorker,
    SourceLookupOutcome, SourceLookupService,
};
use rmule_kad::KadId;
use rmule_peer::natt::RendezvousBody;
use rmule_peer::{PeerHandshakeContext, ReaskCallbackUdp};
use rmule_primitives::{
    ClientIdentity, Ed2kFileLink, Ed2kText, FileHash, Informant, Ipv4Endpoint, PeerEndpoint,
    ServerEndpoint, SightedBuddy, SourceLookupTarget, SourceRoad, SourceSighting, UserHash,
};
use rmule_testkit::file_link_without_part_hash_set;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::fixture::kad_enable_config;

/// The publisher's identity on the row — what the rendezvous ledger and the
/// tunnel claim are both keyed by.
const TARGET_HASH: UserHash = UserHash::from_bytes([0xAB; UserHash::BYTE_LEN]);
/// Our own, as `kad_enable_config` states it: the hash the buddy relays on.
const OUR_HASH: UserHash = UserHash::from_bytes([0x42; UserHash::BYTE_LEN]);
/// The buddy's Kad ID — the `0x94` relay key the buddy routes by.
const BUDDY_ID: [u8; 16] = [0x7A; 16];

/// A server lookup that always fails: the row must arrive over Kad, and a
/// server source would give the download another road to take.
#[derive(Clone)]
struct FailingSourceLookup;

impl SourceLookupService for FailingSourceLookup {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        Err(DownloadFailure::ServerDisconnected)
    }
}

/// A transfer service that refuses every dial: a buddy row names no dialable
/// endpoint, so a worker spawned here would mean the row took the wrong road.
struct NeverDials;

impl PeerTransferService for NeverDials {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        _file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        panic!("a buddy-reachable Kad row has no dialable endpoint, yet {peer} was dialed");
    }
}

/// The Kad seam, answering every source search with one scripted row.
struct OneRowChannel {
    row: SourceSighting,
    answers_tx: mpsc::Sender<(FileHash, Vec<SourceSighting>)>,
    answers_rx: tokio::sync::Mutex<mpsc::Receiver<(FileHash, Vec<SourceSighting>)>>,
}

impl OneRowChannel {
    fn new(row: SourceSighting) -> Self {
        let (answers_tx, answers_rx) = mpsc::channel(8);
        Self {
            row,
            answers_tx,
            answers_rx: tokio::sync::Mutex::new(answers_rx),
        }
    }
}

impl KadSourceChannel for OneRowChannel {
    async fn search_sources(&self, target: SourceLookupTarget) {
        let _ = self
            .answers_tx
            .send((target.file_hash(), vec![self.row]))
            .await;
    }

    async fn publish_source(&self, _target: SourceLookupTarget) {}

    async fn next_sources(&self) -> Option<(FileHash, Vec<SourceSighting>)> {
        self.answers_rx.lock().await.recv().await
    }
}

struct OneRowKad {
    channel: Option<OneRowChannel>,
}

impl OneRowKad {
    fn answering(row: SourceSighting) -> Self {
        Self {
            channel: Some(OneRowChannel::new(row)),
        }
    }
}

impl KadRuntimeFactory for OneRowKad {
    type Channel = OneRowChannel;

    async fn start(
        &mut self,
        _config: &KadEnableConfig,
        _node: &rmule_core::KadNodeIdentity,
        _bind: rmule_core::ClientUdpBind,
        _cells: &rmule_core::KadCells,
    ) -> Result<OneRowChannel, rmule_core::CoreError> {
        Ok(self.channel.take().expect("kad started once"))
    }
}

/// One decoded type-3/5 row: a firewalled publisher reachable only through the
/// buddy at `buddy_udp`. `connect_options` is eMuleAI's byte — crypt plus
/// `CONNECT_OPT_NAT_TRAVERSAL_UTP`, the bit that is the buddy coordinator's
/// only voucher for the target (ADR-0091).
fn buddy_row(buddy_udp: Ipv4Endpoint) -> SourceSighting {
    buddy_row_stating(buddy_udp, 0x81)
}

/// [`buddy_row`] with another connect-options byte.
fn buddy_row_stating(buddy_udp: Ipv4Endpoint, connect_options: u8) -> SourceSighting {
    SourceSighting::by_road(
        SourceRoad::Buddy {
            buddy: SightedBuddy {
                buddy_id: BUDDY_ID,
                buddy_udp: Some(buddy_udp),
            },
            // The publisher's observed Kad UDP address, as a storer records it.
            kad_udp: Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 77), 4672),
            tcp_port: 4662,
        },
        Some(TARGET_HASH),
        Some(rmule_primitives::SourceCryptOptions::from_byte(
            connect_options,
        )),
        Informant::Own,
    )
}

/// A download over a Kad-only world: the server lookup fails, the row arrives
/// over the Kad seam, and nothing is dialable.
async fn downloading_core(row: SourceSighting, bytes: &[u8], dir: &std::path::Path) -> Core {
    let core = Core::builder(
        CoreConfig {
            kad_sweep_interval: Duration::from_millis(10),
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
    .settings(rmule_testkit::in_download_dir(
        rmule_core::CoreSettings::default(),
        dir,
    ))
    .user_hash(OUR_HASH)
    .source_lookup(FailingSourceLookup)
    .peer_transfer(NeverDials)
    .kad(OneRowKad::answering(row))
    .build();

    core.send(CoreCommand::EnableKad(kad_enable_config()))
        .await
        .expect("kad enabled");
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link_without_part_hash_set("buddy-sourced.bin", bytes),
        // A server nothing listens on: the lookup fails and Kad carries it.
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 1).expect("server endpoint")),
        name: rmule_testkit::file_name("buddy-sourced.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .expect("download started");
    core
}

/// The headline case: a download whose only source is a Kad buddy row
/// begins a **buddy rendezvous** — the candidate reaches the coordinator, and
/// what leaves the socket is a `0x94` the buddy can route and the target can
/// read.
#[tokio::test]
async fn a_kad_buddy_row_drives_a_download_to_rendezvous_with_the_targets_buddy() {
    // The buddy's Kad UDP port, played by a real socket: the rendezvous is
    // addressed here, exactly as `CUpDownClient`'s buddy callback would be.
    let buddy_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the buddy's UDP port");
    let buddy_udp = Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        buddy_socket.local_addr().expect("addr").port(),
    );

    let bytes = b"a file only a firewalled publisher has".to_vec();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut core = downloading_core(buddy_row(buddy_udp), &bytes, dir.path()).await;

    let mut datagram = [0u8; 256];
    let (len, _from) = timeout(HANG_GUARD, buddy_socket.recv_from(&mut datagram))
        .await
        .expect("the rendezvous reaches the buddy")
        .expect("recv");

    // Byte-decoded, not shape-checked: the buddy routes by the `buddy_id` the
    // row carried, and the body names *us* — the hash the target's answer and
    // the tunnel claim are both matched by.
    let relay = ReaskCallbackUdp::decode_udp(&datagram[..len]).expect("an OP_REASKCALLBACKUDP");
    assert_eq!(
        relay.buddy_id, BUDDY_ID,
        "the relay is keyed by the buddy ID the Kad row named"
    );
    let body = RendezvousBody::from_forwarded(&relay.forwarded)
        .expect("marked as a rendezvous")
        .expect("well-formed");
    assert_eq!(body.requester, OUR_HASH);
    assert!(
        body.options.requests_endpoint_hint(),
        "a requester with no address of its own asks the buddy to observe one"
    );

    // And the verdict the rest of the session reads says which coordinator
    // carried it.
    let route = timeout(HANG_GUARD, async {
        loop {
            match core.next_event().await.expect("core still running") {
                CoreEvent::PeerReachRouted { route, .. } => return route,
                _ => continue,
            }
        }
    })
    .await
    .expect("the reach verdict arrives");
    assert_eq!(
        route,
        PeerReachRoute::NatTraversal {
            buddy_id: KadId::from_bytes(BUDDY_ID),
            buddy_udp,
        },
        "the coordinator is the target's serving buddy, not our server"
    );

    // The claim the adoption half is matched by: registered before the ask
    // left the runner, and keyed by the row's User Hash — an unclaimable
    // fallback would mean a risen Tunnel took the serve road instead.
    let session = core.diagnostics_snapshot().session;
    assert_eq!(session.natt_download_fallbacks_total, 1);
    assert_eq!(
        session.natt_download_fallbacks_unclaimable_total, 0,
        "the Tunnel is claimed for this download"
    );
}

/// The callback leg: a High-ID downloader with a bound listener asks an aMule
/// row's buddy for a callback — the road aMule itself takes, since the row's
/// `TAG_ENCRYPTION` of `0x00` states no NAT-T — and the publisher's dial-back,
/// which names itself only by its User Hash, becomes the download's worker.
#[tokio::test]
async fn a_callable_downloader_adopts_the_publishers_dial_back_and_completes_the_file() {
    let out = tempfile::tempdir().unwrap();
    let bytes = vec![0x5A_u8; 4096];
    let file = rmule_testkit::file_link("buddy-callback.bin", &bytes);

    // The connected server grants High-ID and holds no source for the file:
    // the only source is the Kad row.
    let server = rmule_testkit::FakeEd2kServer::start().await;
    let server_ep = ServerEndpoint::parse_host_port(&server.local_addr().to_string()).unwrap();
    let row = buddy_row_stating(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 9000), 0x00);
    let p = crate::fixture::free_port().await;
    let mut core = Core::builder(
        CoreConfig {
            kad_sweep_interval: Duration::from_millis(10),
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
    .settings(rmule_testkit::in_download_dir(
        crate::fixture::settings_on(p),
        out.path(),
    ))
    .user_hash(OUR_HASH)
    .peer_transfer(NeverDials)
    .kad(OneRowKad::answering(row))
    .build();

    core.send(CoreCommand::Serve(rmule_core::ServeCommand::StartServing {
        listen_addr: std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, p),
    }))
    .await
    .unwrap();
    let listen = crate::fixture::serving_started(&mut core).await;
    rmule_testkit::connect_to(&core, &server_ep).await;
    core.send(CoreCommand::EnableKad(kad_enable_config()))
        .await
        .expect("kad enabled");
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server_ep),
        name: rmule_testkit::file_name("buddy-callback.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    buddy_callback_to_completion(
        &mut core,
        listen,
        bytes,
        &out.path().join("buddy-callback.bin"),
    )
    .await;
}

/// The buddy-callback road from the route onward: the download reports the
/// buddy's callback, the publisher dials our `listen`er back as aMule does on
/// `OP_CALLBACK`, and the file completes byte-equal at `output`.
async fn buddy_callback_to_completion(
    core: &mut Core,
    listen: std::net::SocketAddrV4,
    bytes: Vec<u8>,
    output: &std::path::Path,
) {
    let name = output
        .file_name()
        .and_then(|name| name.to_str())
        .expect("a file name")
        .to_owned();
    let expected = bytes.clone();
    // The road is the buddy's callback, and the claim was registered before
    // this verdict could be reported.
    let route = crate::fixture::next_matching(core, |event| {
        matches!(event, CoreEvent::PeerReachRouted { .. })
    })
    .await;
    assert!(
        matches!(
            route,
            CoreEvent::PeerReachRouted {
                route: PeerReachRoute::Buddy { buddy_id, emitted_to: None },
                ..
            } if buddy_id == KadId::from_bytes(BUDDY_ID)
        ),
        "a callable downloader asks the buddy, not the punch: {route:?}"
    );

    // The publisher, as aMule dials back on `OP_CALLBACK`: not on any server,
    // so its hello carries no key the ADR-0039 table could match — only its
    // User Hash, which is what the download claimed.
    let ctx = PeerHandshakeContext {
        identity: ClientIdentity::new(
            TARGET_HASH,
            Ed2kText::from_utf8("firewalled-publisher"),
            crate::fixture::dead_port().await,
            60,
        ),
        client_id: rmule_primitives::ClientId::from_u32(1),
        ed2k_client_id: rmule_primitives::ClientId::from_u32(1),
        public_ip: None,
        connected_server: None,
    };
    let mut publisher = rmule_net::peer::Connection::connect(
        PeerEndpoint::V4(Ipv4Endpoint::new(*listen.ip(), listen.port())),
        ctx,
        rmule_net::peer::ConnectOptions::default(),
    )
    .await
    .expect("the publisher dials our listener");
    let serving = tokio::spawn(async move {
        crate::fixture::serve_called_back(&mut publisher, &name, &bytes).await;
    });

    loop {
        match timeout(HANG_GUARD, core.next_event())
            .await
            .expect("core emitted an event")
            .expect("core event stream stayed open")
        {
            CoreEvent::Download(rmule_core::DownloadEvent::DownloadCompleted { .. }) => break,
            CoreEvent::Download(rmule_core::DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    }
    assert_eq!(
        std::fs::read(output).unwrap(),
        expected,
        "the file completed byte-equal from the adopted dial-back"
    );
    let _ = serving.await;
}

/// AMule's `CanDoCallback` is the union `IsFirewalled` is — "Only
/// Kad Connected - Kad Open" is callable (`amule.cpp:3238-3241`). A downloader
/// with no server at all, whose Kad TCP verdict reads open and whose listener
/// is bound, takes the buddy's callback exactly as a High-ID one does, and the
/// dial-back completes the file.
#[tokio::test]
async fn a_kad_only_open_downloader_takes_the_buddy_callback_road() {
    let out = tempfile::tempdir().unwrap();
    let bytes = vec![0xA5_u8; 4096];
    let file = rmule_testkit::file_link("kad-only-callback.bin", &bytes);
    // No server anywhere: serving's login and the download's lookup both fail,
    // so no session self-fact exists and only the Kad verdict can make us
    // callable.
    let no_server = ServerEndpoint::new("127.0.0.1", crate::fixture::dead_port().await)
        .expect("server endpoint");
    let row = buddy_row_stating(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 9000), 0x00);
    let p = crate::fixture::free_port().await;
    let mut core = Core::builder(
        CoreConfig {
            kad_sweep_interval: Duration::from_millis(10),
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
    .settings(rmule_testkit::in_download_dir(
        crate::fixture::settings_on(p),
        out.path(),
    ))
    .user_hash(OUR_HASH)
    .source_lookup(FailingSourceLookup)
    .peer_transfer(NeverDials)
    .kad(OneRowKad::answering(row))
    // The ADR-0058 TCP verdict a real node would have reached, injected as
    // a level.
    .kad_reach(rmule_core::KadReachLevel::fixed(true))
    .build();

    core.send(CoreCommand::Serve(rmule_core::ServeCommand::StartServing {
        listen_addr: std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, p),
    }))
    .await
    .unwrap();
    let listen = crate::fixture::serving_started(&mut core).await;
    core.send(CoreCommand::EnableKad(kad_enable_config()))
        .await
        .expect("kad enabled");
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(no_server),
        name: rmule_testkit::file_name("kad-only-callback.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    buddy_callback_to_completion(
        &mut core,
        listen,
        bytes,
        &out.path().join("kad-only-callback.bin"),
    )
    .await;
}

/// The direct-UDP leg: a row that carries the type-6 verdict
/// is reached by its own `0x95`, straight to its own Kad UDP endpoint — not
/// its buddy's `0x52`, even though the row names one too (a synthetic
/// combination: no real aMule row states both — a type-3/5 row
/// with bit 3 alone falls to its buddy instead, `DownloadQueue.cpp:1797`).
/// Driven the same way route 4 already is: nothing here names a peer by
/// hand, the row goes in at the Kad seam and the datagram comes out on the
/// socket the row's own endpoint names.
#[tokio::test]
async fn a_kad_row_with_the_direct_callback_bit_draws_a_0x95_toward_its_own_endpoint() {
    let out = tempfile::tempdir().unwrap();
    // The row's own Kad UDP port, played by a real socket: the `0x95` is
    // addressed here.
    let target_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the row's own UDP port");
    let target_kad_udp = Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        target_socket.local_addr().expect("addr").port(),
    );

    let bytes = vec![0x11_u8; 4096];
    let file = rmule_testkit::file_link("direct-udp.bin", &bytes);

    // A High-ID downloader with a bound listener — the direct-UDP road, like
    // the buddy callback's, invites the target to dial it back.
    let server = rmule_testkit::FakeEd2kServer::start().await;
    let server_ep = ServerEndpoint::parse_host_port(&server.local_addr().to_string()).unwrap();
    // A type-6 row: bit 3, no NAT-T, no crypt. The road is the fact the
    // admission rule gates on — bit 3 alone on a buddy row would fall to the
    // buddy.
    let row = SourceSighting::by_road(
        SourceRoad::DirectUdpCallback {
            kad_udp: target_kad_udp,
            tcp_port: 4662,
        },
        Some(TARGET_HASH),
        Some(rmule_primitives::SourceCryptOptions::from_byte(0x08)),
        Informant::Own,
    );
    let p = crate::fixture::free_port().await;
    let mut core = Core::builder(
        CoreConfig {
            kad_sweep_interval: Duration::from_millis(10),
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
    .settings(rmule_testkit::in_download_dir(
        crate::fixture::settings_on(p),
        out.path(),
    ))
    .user_hash(OUR_HASH)
    .peer_transfer(NeverDials)
    .kad(OneRowKad::answering(row))
    .build();

    core.send(CoreCommand::Serve(rmule_core::ServeCommand::StartServing {
        listen_addr: std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, p),
    }))
    .await
    .unwrap();
    let _listen = crate::fixture::serving_started(&mut core).await;
    rmule_testkit::connect_to(&core, &server_ep).await;
    core.send(CoreCommand::EnableKad(kad_enable_config()))
        .await
        .expect("kad enabled");
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server_ep),
        name: rmule_testkit::file_name("direct-udp.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    let mut datagram = [0u8; 64];
    let (len, _from) = timeout(HANG_GUARD, target_socket.recv_from(&mut datagram))
        .await
        .expect("the 0x95 reaches the row's own endpoint")
        .expect("recv");

    let req = rmule_peer::DirectCallbackReq::decode_udp(&datagram[..len])
        .expect("an OP_DIRECTCALLBACKREQ");
    assert_eq!(
        req.our_tcp_port, p,
        "the target is invited to dial our listener back"
    );
    assert_eq!(req.our_user_hash, OUR_HASH);

    let route = crate::fixture::next_matching(&mut core, |event| {
        matches!(event, CoreEvent::PeerReachRouted { .. })
    })
    .await;
    assert!(
        matches!(
            route,
            CoreEvent::PeerReachRouted {
                route: PeerReachRoute::DirectUdp { target_kad_udp: t },
                ..
            } if t == target_kad_udp
        ),
        "the direct-UDP road is taken: {route:?}"
    );
}

/// The whole type-6 channel, with no row written by hand: an
/// rmule publisher told the direct-callback bit publishes into a bare
/// storer, the row that storer serves back is read by the widened Kad
/// reader, and a real downloading `Core` fed that row takes the direct-UDP
/// road toward the publisher's own Kad socket — the address the storer
/// observed, not one the row claimed.
#[tokio::test]
async fn a_published_type_6_row_served_back_by_a_storer_takes_the_direct_udp_road() {
    let out = tempfile::tempdir().unwrap();
    use std::net::SocketAddr;

    let bytes = vec![0x22_u8; 4096];
    let file = rmule_testkit::file_link("type-6.bin", &bytes);
    let target = SourceLookupTarget::new(file.file_hash, file.size);
    let key = rmule_kad::KadSourceLookupRequest::new(target).kad_target();

    let bare = |id: KadId, user_hash: UserHash| rmule_net::kad::KadNetConfig {
        node: rmule_kad::KadNodeConfig {
            id,
            tcp_port: 4662,
            udp_port: 0,
            user_hash,
        },
        capture_dir: None,
        nodes_dat_path: None,
        firewall_self_check: false,
        obfuscation: None,
        contact_admission: None,
    };
    let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    // The storer sits on the file's Kad key, so the publish walk ends at it.
    let storer = rmule_net::kad::spawn(bare(key, UserHash::from_bytes([0xCC; 16])), loopback)
        .await
        .expect("storer binds");
    let publisher =
        rmule_net::kad::spawn(bare(KadId::from_bytes([0x5E; 16]), TARGET_HASH), loopback)
            .await
            .expect("publisher binds");
    let (SocketAddr::V4(storer_addr), SocketAddr::V4(publisher_addr)) =
        (storer.local_addr(), publisher.local_addr())
    else {
        panic!("both bound IPv4 loopback");
    };
    for command in [
        rmule_kad::KadCommand::SetPublishConnectOptions {
            options: Some(0x08),
        },
        rmule_kad::KadCommand::Bootstrap {
            endpoint: rmule_kad::KadNodeEndpoint::new(*storer_addr.ip(), storer_addr.port()),
        },
    ] {
        publisher.command(command).await.expect("publisher alive");
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    publisher
        .command(rmule_kad::KadCommand::PublishSource {
            request: rmule_kad::KadPublishRequest::new(target),
        })
        .await
        .expect("publisher alive");

    let searcher = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let search = rmule_testkit::kad_source::search_datagram(key, 0, file.size);
    let candidate = timeout(HANG_GUARD, async {
        let mut buffer = [0u8; 2048];
        loop {
            searcher.send_to(&search, storer_addr).await.unwrap();
            let Ok(Ok((len, _))) =
                timeout(Duration::from_millis(300), searcher.recv_from(&mut buffer)).await
            else {
                continue;
            };
            let Ok(rmule_kad::KadDecoded::Plain(envelope)) =
                rmule_kad::decode_exact(&buffer[..len])
            else {
                continue;
            };
            if envelope.opcode() != 0x3B {
                continue;
            }
            if let Some(row) = rmule_kad::decode_source_result(&envelope)
                .expect("the storer's 0x3B decodes")
                .into_iter()
                .find(|row| {
                    row.facts()
                        .is_some_and(|facts| facts.user_hash == TARGET_HASH)
                })
            {
                return row;
            }
        }
    })
    .await
    .expect("the storer re-served the publish");
    let publisher_kad_udp = Ipv4Endpoint::new(*publisher_addr.ip(), publisher_addr.port());
    assert_eq!(
        candidate.facts().map(|facts| facts.source_type),
        Some(6),
        "the bit made the row type 6"
    );
    assert_eq!(candidate.direct_udp_callback(), Some(publisher_kad_udp));

    // A High-ID downloader with a bound listener, fed exactly that row.
    let server = rmule_testkit::FakeEd2kServer::start().await;
    let server_ep = ServerEndpoint::parse_host_port(&server.local_addr().to_string()).unwrap();
    let p = crate::fixture::free_port().await;
    let mut core = Core::builder(
        CoreConfig {
            kad_sweep_interval: Duration::from_millis(10),
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
    .settings(rmule_testkit::in_download_dir(
        crate::fixture::settings_on(p),
        out.path(),
    ))
    .user_hash(OUR_HASH)
    .peer_transfer(NeverDials)
    .kad(OneRowKad::answering(
        candidate
            .sighting(Informant::Own)
            .expect("a type-6 row is a sighting"),
    ))
    .build();
    core.send(CoreCommand::Serve(rmule_core::ServeCommand::StartServing {
        listen_addr: std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, p),
    }))
    .await
    .unwrap();
    let _listen = crate::fixture::serving_started(&mut core).await;
    rmule_testkit::connect_to(&core, &server_ep).await;
    core.send(CoreCommand::EnableKad(kad_enable_config()))
        .await
        .expect("kad enabled");
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server_ep),
        name: rmule_testkit::file_name("type-6.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    let route = crate::fixture::next_matching(&mut core, |event| {
        matches!(event, CoreEvent::PeerReachRouted { .. })
    })
    .await;
    assert!(
        matches!(
            route,
            CoreEvent::PeerReachRouted {
                route: PeerReachRoute::DirectUdp { target_kad_udp: t },
                ..
            } if t == publisher_kad_udp
        ),
        "the type-6 row takes the direct-UDP road to the publisher's own socket: {route:?}"
    );
    let _ = publisher.shutdown().await;
    let _ = storer.shutdown().await;
}
