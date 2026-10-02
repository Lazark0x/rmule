//! Legs that need a handle the builder wires in and a live core, both:
//! `CoreBuilder::kad` re-wiring — a served link's `0x99`/`0x95`
//! Kad gate must track whichever factory the builder chain ends with — and
//! the download activity's **file-known** entry across its stop and death
//! (ADR-0093).

use std::net::{Ipv4Addr, SocketAddrV4};

use rmule_kad::KadId;
use rmule_peer::Callback;
use rmule_primitives::{
    ClientIdentity, Ed2kText, FileHash, Ipv4Endpoint, ServerEndpoint, SourceLookupTarget, UserHash,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::Duration;

use crate::adapters::{
    ClientUdpBind, KadEnableConfig, KadPresenceView, KadRuntimeFactory, KadSourceChannel,
};
use crate::kad_sources::KadAnswer;
use crate::{
    Core, CoreCommand, CoreConfig, CoreError, CoreEvent, ScanCommand, ScanEvent, ServeCommand,
    ServeEvent,
};

/// A Kad factory that owns its own **Kad Presence** cell, which the Kad
/// Activity leases when it starts (ADR-0093) — "running its
/// lease" (the Done-when's phrase) without a real `rmule-net-kad` node
/// underneath. `kad_presence` is the [`KadRuntimeFactory`] trait method
/// `CoreBuilder::kad` must read from *this* installed factory rather than the
/// default it replaces.
#[derive(Default)]
struct LeasedKadFactory {
    presence: KadPresenceView,
}

/// Never asked to search, publish or read sources: the test enables Kad only
/// to run its presence lease, never a discovery.
struct NeverSearches;

impl KadSourceChannel for NeverSearches {
    async fn search_sources(&self, _target: SourceLookupTarget) {}

    async fn publish_source(&self, _target: SourceLookupTarget) {}

    async fn next_sources(&self) -> Option<(FileHash, KadAnswer)> {
        std::future::pending().await
    }
}

impl KadRuntimeFactory for LeasedKadFactory {
    type Channel = NeverSearches;

    async fn start(
        &mut self,
        _config: &KadEnableConfig,
        _bind: ClientUdpBind,
    ) -> Result<Self::Channel, CoreError> {
        Ok(NeverSearches)
    }

    fn kad_presence(&self) -> KadPresenceView {
        self.presence.clone()
    }
}

/// The one eD2k identity both `EnableKad` (its dial-back context) and
/// `StartServing` (its login credentials) present — production shares one
/// identity between the two the same way (ADR-0069).
fn identity() -> ClientIdentity {
    ClientIdentity::new(
        UserHash::from_bytes([0x42; UserHash::BYTE_LEN]),
        Ed2kText::from_utf8("issue-427"),
        4662,
        60,
    )
}

/// The `KadEnableConfig` this leg drives `EnableKad` with — serverless, since
/// nothing here ever dials Kad's own socket.
fn kad_enable_config(kad_id: KadId) -> KadEnableConfig {
    KadEnableConfig {
        kad_id,
        peer_credentials: identity().into(),
        bootstrap: Vec::new(),
        contacts: Vec::new(),
        nodes_dat_path: None,
        assume_open_reachability: false,
        kad_udp_key: 0,
        kad_capture_dir: None,
        kad_shutdown: None,
    }
}

/// Drain `core`'s events until one matches `want`, and hand it back.
async fn next_expected(core: &mut Core, want: impl Fn(&CoreEvent) -> bool) -> CoreEvent {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let event = core.next_event().await.expect("core alive");
            if want(&event) {
                return event;
            }
        }
    })
    .await
    .expect("the expected event arrived")
}

/// **The done-when this leg pins:** `CoreBuilder::kad` installs
/// a replacement factory *after* `Core::builder`'s default wiring already
/// bound the serve runtime to the default `RuntimeKadFactory`'s own **Kad
/// Presence**. Before the fix, that bound view was never re-pointed, so a
/// served link's `0x99` read Kad-down forever no matter what the installed
/// factory's own lease said. Here the installed factory leases a Kad ID,
/// a peer dials the real bound listener and sends a `0x99` whose buddy-ID
/// inverts to that ID and whose file is genuinely shared: only a served
/// runtime reading the *installed* factory's presence can reach `Dial` and
/// count it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kad_rewires_the_served_links_kad_presence_to_the_installed_factory() {
    let our_kad_id = KadId::from_bytes([0x0A; KadId::BYTE_LEN]);
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .kad(LeasedKadFactory::default())
        .build();

    core.send(CoreCommand::EnableKad(kad_enable_config(our_kad_id)))
        .await
        .expect("core accepts EnableKad");

    // A real file, genuinely shared, so `file_shared_or_downloading` is
    // true and the only gate left standing between "dropped" and "dialed"
    // is the Kad Presence the served runtime reads.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("known.bin");
    std::fs::write(&path, b"issue-427 served-link kad-up proof").expect("write the shared file");
    core.send(CoreCommand::Scan(ScanCommand::AddSharedDirectory {
        path: dir.path().to_path_buf(),
    }))
    .await
    .expect("core accepts AddSharedDirectory");
    let CoreEvent::Scan(ScanEvent::ConsentRequested { dir: asked, .. }) =
        next_expected(&mut core, |event| {
            matches!(event, CoreEvent::Scan(ScanEvent::ConsentRequested { .. }))
        })
        .await
    else {
        unreachable!("filtered for ConsentRequested")
    };
    core.send(CoreCommand::Scan(ScanCommand::Answer {
        dir: asked,
        share: true,
    }))
    .await
    .expect("core accepts the answer");
    let file_hash = match next_expected(&mut core, |event| {
        matches!(event, CoreEvent::Serve(ServeEvent::FileShared { .. }))
    })
    .await
    {
        CoreEvent::Serve(ServeEvent::FileShared { file_hash }) => file_hash,
        other => unreachable!("filtered for FileShared: {other:?}"),
    };

    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        // Nothing listens here — the bind is the whole contract;
        // the login this also causes is not what this leg proves.
        credentials: identity().into(),
    }))
    .await
    .expect("core accepts StartServing");
    let listen_addr = match next_expected(&mut core, |event| {
        matches!(
            event,
            CoreEvent::Serve(ServeEvent::ServingStarted { .. } | ServeEvent::ServingFailed { .. })
        )
    })
    .await
    {
        CoreEvent::Serve(ServeEvent::ServingStarted { listen_addr }) => listen_addr,
        other => panic!("the listener never bound: {other:?}"),
    };

    // An ordinary dialer: hello, then a `0x99` addressed to our installed
    // factory's leased Kad ID, naming the file just shared. TCP orders the
    // two frames regardless of when the server's bridge starts reading —
    // no synchronization with the accept/triage race is needed.
    let mut peer = TcpStream::connect(SocketAddrV4::new(*listen_addr.ip(), listen_addr.port()))
        .await
        .expect("dial the bound listener");
    peer.write_all(&rmule_testkit::wire::hello_bytes(
        UserHash::from_bytes([0x5E; UserHash::BYTE_LEN]),
        "issue-427-dialer",
    ))
    .await
    .expect("the hello is framed");
    let mut buddy_id = *our_kad_id.as_bytes();
    for b in &mut buddy_id {
        *b = !*b;
    }
    let callback = Callback {
        buddy_id,
        file_hash,
        requester: Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 1),
    };
    peer.write_all(&callback.encode_packet().encode())
        .await
        .expect("the 0x99 is framed");

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if core
                .diagnostics_snapshot()
                .session
                .relayed_callbacks_dialed_total
                == 1
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect(
        "the served link's 0x99 dialed back — the installed factory's own \
         Kad Presence reached the serve runtime, not the default's",
    );
}

/// A server lookup that never answers: the download it serves stays in its
/// lookup, alive, until it is stopped.
#[derive(Clone)]
struct SilentLookup;

impl crate::adapters::SourceLookupService for SilentLookup {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<crate::SourceLookupOutcome, crate::DownloadFailure> {
        std::future::pending().await
    }
}

/// A server lookup that fails at once: with no discovery channel armed the
/// download it serves dies `NoUsableSources`-style on its own.
#[derive(Clone)]
struct RefusingLookup;

impl crate::adapters::SourceLookupService for RefusingLookup {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<crate::SourceLookupOutcome, crate::DownloadFailure> {
        // A filtered server is a failure, where one that does not answer is
        // a wait for a connection (ADR-0097).
        Err(crate::DownloadFailure::ServerFiltered)
    }
}

fn start_download(seed: u8, dir: &std::path::Path) -> CoreCommand {
    CoreCommand::Download(crate::DownloadCommand::StartDownload {
        file: rmule_primitives::Ed2kFileLink {
            name: Ed2kText::from_utf8("lifecycle.bin"),
            size: 1024,
            file_hash: FileHash::from_bytes([seed; FileHash::BYTE_LEN]),
            part_hash_set: None,
            aich_root: None,
            ipv6_sources: Vec::new(),
            sources: Default::default(),
        },
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 1).expect("server endpoint")),
        credentials: identity().into(),
        output_path: dir.join(format!("lifecycle-{seed}.bin")),
    })
}

/// The id of the download the core just queued.
async fn queued(core: &mut Core) -> crate::DownloadId {
    match next_expected(core, |event| {
        matches!(
            event,
            CoreEvent::Download(crate::DownloadEvent::DownloadQueued { .. })
        )
    })
    .await
    {
        CoreEvent::Download(crate::DownloadEvent::DownloadQueued { download_id, .. }) => {
            download_id
        }
        other => unreachable!("filtered for DownloadQueued: {other:?}"),
    }
}

/// A command round trip, several times over: the actor's `select!` picks a
/// ready arm at random, so after this any finish notice queued before it has
/// almost surely been drained.
async fn settle(core: &mut Core) {
    for _ in 0..8 {
        core.send(CoreCommand::DumpDiagnostics)
            .await
            .expect("core alive");
        next_expected(core, |event| {
            matches!(event, CoreEvent::DiagnosticsSnapshot { .. })
        })
        .await;
    }
}

/// ADR-0093's download stop: the stop returns the file-known entry the start
/// stamped, so a cancelled download's late finish notice can no longer clear
/// the hash of the download started after it.
#[tokio::test]
async fn a_stopped_download_returns_its_file_known_entry_and_its_late_finish_clears_nothing() {
    let builder = Core::builder(
        CoreConfig {
            source_lookup_timeout: Duration::from_secs(3600),
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
    .source_lookup(SilentLookup);
    let known = builder.node.cells.file_known.clone();
    let mut core = builder.build();
    let dir = tempfile::tempdir().expect("tempdir");

    core.send(start_download(1, dir.path()))
        .await
        .expect("start");
    let mut running = queued(&mut core).await;
    for seed in 2..8u8 {
        // Back to back, so the cancelled run's finish notice and the next
        // start race for the actor's next turn.
        core.send(CoreCommand::Download(
            crate::DownloadCommand::CancelDownload {
                download_id: running,
            },
        ))
        .await
        .expect("cancel");
        core.send(start_download(seed, dir.path()))
            .await
            .expect("start");
        running = queued(&mut core).await;
        settle(&mut core).await;
        assert!(
            known.contains(FileHash::from_bytes([seed; FileHash::BYTE_LEN])),
            "the running download's hash survives the cancelled one's finish"
        );
        assert!(!known.contains(FileHash::from_bytes([seed - 1; FileHash::BYTE_LEN])));
    }
}

/// The **Download Set**: every running download's file is
/// known, and retiring one returns only its own entry — the downloads beside
/// it stay dialable for the firewalled front's `0x99` gate.
#[tokio::test]
async fn retiring_one_of_several_downloads_leaves_the_others_known() {
    let builder = Core::builder(
        CoreConfig {
            source_lookup_timeout: Duration::from_secs(3600),
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
    .source_lookup(SilentLookup);
    let known = builder.node.cells.file_known.clone();
    let mut core = builder.build();
    let dir = tempfile::tempdir().expect("tempdir");
    let hash = |seed: u8| FileHash::from_bytes([seed; FileHash::BYTE_LEN]);

    let mut ids = Vec::new();
    for seed in 1..=3u8 {
        core.send(start_download(seed, dir.path()))
            .await
            .expect("start");
        ids.push(queued(&mut core).await);
    }
    assert!((1..=3).all(|seed| known.contains(hash(seed))));

    core.send(CoreCommand::Download(
        crate::DownloadCommand::CancelDownload {
            download_id: ids[1],
        },
    ))
    .await
    .expect("cancel");
    settle(&mut core).await;
    assert!(!known.contains(hash(2)), "the cancelled download's entry");
    assert!(known.contains(hash(1)) && known.contains(hash(3)));
}

/// ADR-0093's download death: a run that ends on its own retires through the
/// same place a stop does, returning its file-known entry.
#[tokio::test]
async fn a_dead_download_returns_its_file_known_entry() {
    let builder = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .source_lookup(RefusingLookup);
    let known = builder.node.cells.file_known.clone();
    let mut core = builder.build();
    let dir = tempfile::tempdir().expect("tempdir");

    core.send(start_download(9, dir.path()))
        .await
        .expect("start");
    next_expected(&mut core, |event| {
        matches!(
            event,
            CoreEvent::Download(crate::DownloadEvent::DownloadFailed { .. })
        )
    })
    .await;
    settle(&mut core).await;
    assert!(!known.contains(FileHash::from_bytes([9; FileHash::BYTE_LEN])));
}

/// An adapter injected through `CoreBuilder::peer_transfer`
/// adopts every cell the builder owns — here the ban store: a candidate the
/// node banned is never dialed by the injected adapter. Before, an injected
/// adapter kept its own empty ban store, IP filter, Address Learning and Kad
/// handoff, so `rmule-tools download` dialed around the node's bans.
#[tokio::test]
async fn an_injected_dial_adapter_meets_the_node_s_ban_store() {
    use crate::adapters::{PeerTransferService, PeerWorkerEvent, RuntimePeerTransferService};

    let listener = rmule_net::peer::PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let mut builder = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .peer_transfer(RuntimePeerTransferService::new(
            crate::DEFAULT_SLOT_WAIT_TIMEOUT,
        ));
    builder
        .node
        .cells
        .ban_store
        .lock()
        .await
        .ban(std::net::IpAddr::V4(*bound.ip()), std::time::Instant::now());

    let mut worker = builder
        .peer_transfer
        .start_peer_worker(
            rmule_primitives::PeerEndpoint::V4(rmule_primitives::Ipv4Endpoint::new(
                *bound.ip(),
                bound.port(),
            )),
            crate::adapters::tests::dialed_serve_ctx(),
            rmule_primitives::Ed2kFileLink {
                name: rmule_primitives::Ed2kText::from_utf8("dummy"),
                size: 4096,
                file_hash: FileHash::from_bytes([0xAB; FileHash::BYTE_LEN]),
                part_hash_set: None,
                aich_root: None,
                ipv6_sources: Vec::new(),
                sources: Default::default(),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), worker.next_event())
            .await
            .expect("the refusal is reported within 2s"),
        Some(PeerWorkerEvent::DialEnded {
            cause: crate::service::DialEnd::Banned
        })
    );
    assert_eq!(
        worker.next_event().await,
        Some(PeerWorkerEvent::Disconnected)
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(300),
            listener.accept(
                crate::adapters::tests::dialed_serve_ctx(),
                rmule_net::peer::ConnectOptions::default()
            )
        )
        .await
        .is_err(),
        "the node's ban reaches the injected adapter's dial gate"
    );
}

/// A serve runtime whose release never finishes: the stand-in for a serve
/// task that cannot reach its own end, as one parked writing to a peer that
/// stopped reading would be.
struct WedgedServeRuntime;

impl crate::ServeRuntimeService for WedgedServeRuntime {
    async fn start(
        &mut self,
        _identity: ClientIdentity,
        _listen_addr: SocketAddrV4,
    ) -> Result<SocketAddrV4, CoreError> {
        Ok(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4662))
    }

    async fn accept(&mut self) -> Option<crate::ServeConnection> {
        std::future::pending().await
    }

    async fn announce(
        &mut self,
        files: Vec<rmule_ed2k::OfferedFile>,
    ) -> Result<crate::AnnounceOutcome, CoreError> {
        Ok(crate::AnnounceOutcome::Announced {
            file_count: files.len(),
        })
    }

    async fn release(&mut self) {
        std::future::pending::<()>().await;
    }
}

/// ADR-0093 invariant 3: a stopped serve task that
/// never ends is aborted after its grace, so `StopServing` — and the quit
/// that runs it — still finishes, reading `TaskFailed` for the adapter the
/// abort took with it. Unbounded, the actor would await it forever.
#[tokio::test(start_paused = true)]
async fn a_serve_task_that_never_ends_is_aborted_after_its_grace() {
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .serve_runtime(WedgedServeRuntime)
        .build();
    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        credentials: identity().into(),
    }))
    .await
    .unwrap();
    next_expected(&mut core, |e| {
        matches!(e, CoreEvent::Serve(ServeEvent::ServingStarted { .. }))
    })
    .await;

    core.send(CoreCommand::Serve(ServeCommand::StopServing))
        .await
        .unwrap();
    let stopped = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let CoreEvent::Serve(ServeEvent::ServingStopped { reason }) =
                core.next_event().await.expect("core alive")
            {
                return reason;
            }
        }
    })
    .await
    .expect("the stop finishes although the task never would");
    assert_eq!(stopped, crate::ServeStopReason::TaskFailed);
}
