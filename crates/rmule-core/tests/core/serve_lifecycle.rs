//! Serve activity lifecycle + queue policy, driven by a fake serve runtime.
use crate::fixture::sized_file;
use rmule_core::DurableSharedFileRegistry;
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadFailure, PeerTransferService, PeerWorker,
    ServeCommand, ServeConnection, ServeEvent, ServeInput, ServeOutput, ServeRuntimeService,
    ServeStartFailure, ShareSource, SharedFileEntry, SharedFileRegistry, SourceLookupOutcome,
    SourceLookupService,
};
use rmule_ed2k::OfferedFile;
use rmule_peer::{
    ConnectionEvent, PartRanges, PeerCloseReason, PeerHandshakeContext, ServerCommand, ServerEvent,
};
use rmule_primitives::{
    ClientId, Ed2kFileLink, FileHash, FileHashSummary, PeerEndpoint, PeerSource, SourceLookupTarget,
};
use rmule_testkit::HANG_GUARD;
use std::net::SocketAddrV4;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::time::timeout;

mod retire;

// --- unused download adapters (serve-only) --------------------------------
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

/// A fake serve runtime: `accept()` yields pre-scripted connections one at a
/// time, then blocks. Records the announced file count. Each handle here is a
/// `ServeConnection` whose event side the test drives and whose command side
/// the test observes.
struct FakeServeRuntime {
    pending: Vec<ServeConnection>,
    announced: Arc<Mutex<usize>>,
    /// Inject a serve-start failure that is *not* a bind — the production
    /// adapter's only failure is `CoreError::ListenerBind`, so this exercises
    /// the `ServeStartFailure::Adapter` arm a foreign adapter lands on.
    start_fails: bool,
}
impl ServeRuntimeService for FakeServeRuntime {
    async fn start(
        &mut self,
        _identity: rmule_primitives::ClientIdentity,
        _listen_addr: SocketAddrV4,
    ) -> Result<SocketAddrV4, rmule_core::CoreError> {
        if self.start_fails {
            return Err(rmule_core::CoreError::Repository(
                "listener bind failed (injected)".into(),
            ));
        }
        Ok("127.0.0.1:4662".parse().unwrap())
    }
    async fn accept(&mut self) -> Option<ServeConnection> {
        if self.pending.is_empty() {
            std::future::pending::<()>().await;
        }
        Some(self.pending.remove(0))
    }
    async fn announce(
        &mut self,
        files: Vec<OfferedFile>,
    ) -> Result<rmule_core::AnnounceOutcome, rmule_core::CoreError> {
        *self.announced.lock().unwrap() = files.len();
        Ok(rmule_core::AnnounceOutcome::Announced {
            file_count: files.len(),
        })
    }
}

/// A serve runtime whose listener each start takes from a script, so a test can
/// kill one activity's listener — drop its sender — and start the next over a
/// live one. `accept` answering `None` is exactly what the production adapter
/// reports at this seam when its accept pump dies.
struct RestartableServeRuntime {
    /// One accept stream per start, in order.
    listeners: Vec<mpsc::Receiver<ServeConnection>>,
    /// The stream the current activity accepts from; empty before the first
    /// start and after the activity released it.
    accepts: Option<mpsc::Receiver<ServeConnection>>,
}
impl ServeRuntimeService for RestartableServeRuntime {
    async fn start(
        &mut self,
        _identity: rmule_primitives::ClientIdentity,
        _listen_addr: SocketAddrV4,
    ) -> Result<SocketAddrV4, rmule_core::CoreError> {
        assert!(
            !self.listeners.is_empty(),
            "the script must hold a listener for every start",
        );
        self.accepts = Some(self.listeners.remove(0));
        Ok("127.0.0.1:4662".parse().unwrap())
    }
    async fn accept(&mut self) -> Option<ServeConnection> {
        self.accepts.as_mut()?.recv().await
    }
    async fn announce(
        &mut self,
        files: Vec<OfferedFile>,
    ) -> Result<rmule_core::AnnounceOutcome, rmule_core::CoreError> {
        Ok(rmule_core::AnnounceOutcome::Announced {
            file_count: files.len(),
        })
    }
    async fn release(&mut self) {
        self.accepts = None;
    }
}

/// Build a connection pair: the returned `ServeConnection` is handed to the
/// fake runtime; the test keeps the peer's command receiver + event sender.
fn conn_pair(
    peer: PeerEndpoint,
) -> (
    ServeConnection,
    mpsc::Sender<ServeInput>,
    mpsc::Receiver<ServeOutput>,
) {
    let (cmd_tx, cmd_rx) = mpsc::channel(16);
    let (evt_tx, evt_rx) = mpsc::channel(16);
    (ServeConnection::new(peer, cmd_tx, evt_rx), evt_tx, cmd_rx)
}

fn peer(port: u16) -> PeerEndpoint {
    PeerSource::new(ClientId::from_u32(0x0100_007F), port)
        .as_peer_endpoint()
        .unwrap()
}

async fn next_serve_event(core: &mut Core) -> ServeEvent {
    loop {
        let event = timeout(HANG_GUARD, core.next_event())
            .await
            .expect("core emitted a serve event")
            .expect("event stream open");
        if let CoreEvent::Serve(serve) = event {
            return serve;
        }
    }
}

/// Pump serve events until one matches — for a leg that waits on a *later*
/// fact and does not care what the activity said on the way there.
async fn next_matching_serve_event(
    core: &mut Core,
    pred: impl Fn(&ServeEvent) -> bool,
) -> ServeEvent {
    loop {
        let event = next_serve_event(core).await;
        if pred(&event) {
            return event;
        }
    }
}

#[tokio::test]
async fn serve_grants_within_budget_then_queues_and_promotes_on_disconnect() {
    let served_file = sized_file(1234);
    let file_hash = FileHash::from_bytes([0x55; FileHash::BYTE_LEN]);
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    registry
        .clone()
        .share(SharedFileEntry {
            file_hash,
            file_size: 1234,
            path: served_file.path().to_path_buf(),
            name: "served.bin".into(),
            source: ShareSource::Explicit,
            modified: None,
            part_hashes: Vec::new(),
        })
        .unwrap();

    let (conn_a, evt_a, mut cmd_a) = conn_pair(peer(1));
    let (conn_b, evt_b, mut cmd_b) = conn_pair(peer(2));
    let announced = Arc::new(Mutex::new(0));
    let serve_runtime = FakeServeRuntime {
        pending: vec![conn_a, conn_b],
        announced: announced.clone(),
        start_fails: false,
    };

    // Budget 1 so the second requester must queue.
    let config = CoreConfig {
        upload_slot_budget: 1,
        max_upload_queue_len: 8,
        ..CoreConfig::default()
    };
    let mut core = Core::builder(config, store)
        .settings(rmule_core::CoreSettings::default())
        .source_lookup(UnusedSourceLookup)
        .peer_transfer(UnusedPeerTransfer)
        .serve_runtime(serve_runtime)
        .build();

    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: "0.0.0.0:0".parse().unwrap(),
    }))
    .await
    .unwrap();

    assert!(matches!(
        next_serve_event(&mut core).await,
        ServeEvent::ServingStarted { .. }
    ));
    assert_eq!(
        next_serve_event(&mut core).await,
        ServeEvent::FilesAnnounced { file_count: 1 }
    );
    assert_eq!(*announced.lock().unwrap(), 1);

    // Peer A requests a slot → granted (budget 1).
    evt_a
        .send(ServeInput::Server(ServerEvent::SlotRequested { file_hash }))
        .await
        .unwrap();
    assert_eq!(
        cmd_a.recv().await.unwrap(),
        ServeOutput::Server(ServerCommand::GrantSlot { file_hash })
    );
    assert_eq!(
        next_serve_event(&mut core).await,
        ServeEvent::UploadSlotGranted {
            peer: peer(1),
            file_hash,
            software: None,
        }
    );

    // Peer B requests a slot → queued at rank 1.
    evt_b
        .send(ServeInput::Server(ServerEvent::SlotRequested { file_hash }))
        .await
        .unwrap();
    assert_eq!(
        cmd_b.recv().await.unwrap(),
        ServeOutput::Server(ServerCommand::SetQueueRank { rank: 1 })
    );
    assert_eq!(
        next_serve_event(&mut core).await,
        ServeEvent::PeerQueued {
            peer: peer(2),
            rank: 1,
            file_hash,
            software: None,
        }
    );

    // Peer A disconnects → peer B promoted (granted), slot released event.
    evt_a
        .send(ServeInput::Connection(ConnectionEvent::Disconnected {
            reason: PeerCloseReason::PeerClosed,
        }))
        .await
        .unwrap();
    assert_eq!(
        cmd_b.recv().await.unwrap(),
        ServeOutput::Server(ServerCommand::GrantSlot { file_hash })
    );
    assert_eq!(
        next_serve_event(&mut core).await,
        ServeEvent::UploadSlotGranted {
            peer: peer(2),
            file_hash,
            software: None,
        }
    );
    assert_eq!(
        next_serve_event(&mut core).await,
        ServeEvent::UploadSlotReleased { peer: peer(1) }
    );
}

/// ADR-0056: `OP_CANCELTRANSFER` runs the same release/promote batch as a
/// disconnect, but — the fact `serve/state.rs`'s pure decision tests cannot
/// show, since they never touch the runner's connection map — the canceller's
/// connection stays registered: a fresh ask over the *same* connection right
/// after is admitted (routed a reply) rather than silently dropped the way it
/// would be had the runner torn the entry down as it does on `Disconnected`.
#[tokio::test]
async fn serve_transfer_cancel_frees_the_slot_keeps_the_connection_and_promotes_the_next_waiter() {
    let served_file = sized_file(1234);
    let file_hash = FileHash::from_bytes([0x56; FileHash::BYTE_LEN]);
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    registry
        .clone()
        .share(SharedFileEntry {
            file_hash,
            file_size: 1234,
            path: served_file.path().to_path_buf(),
            name: "served.bin".into(),
            source: ShareSource::Explicit,
            modified: None,
            part_hashes: Vec::new(),
        })
        .unwrap();

    let (conn_a, evt_a, mut cmd_a) = conn_pair(peer(31));
    let (conn_b, evt_b, mut cmd_b) = conn_pair(peer(32));
    let announced = Arc::new(Mutex::new(0));
    let serve_runtime = FakeServeRuntime {
        pending: vec![conn_a, conn_b],
        announced: announced.clone(),
        start_fails: false,
    };

    // Budget 1 so the second requester must queue.
    let config = CoreConfig {
        upload_slot_budget: 1,
        max_upload_queue_len: 8,
        ..CoreConfig::default()
    };
    let mut core = Core::builder(config, store)
        .settings(rmule_core::CoreSettings::default())
        .source_lookup(UnusedSourceLookup)
        .peer_transfer(UnusedPeerTransfer)
        .serve_runtime(serve_runtime)
        .build();

    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: "0.0.0.0:0".parse().unwrap(),
    }))
    .await
    .unwrap();

    assert!(matches!(
        next_serve_event(&mut core).await,
        ServeEvent::ServingStarted { .. }
    ));
    assert_eq!(
        next_serve_event(&mut core).await,
        ServeEvent::FilesAnnounced { file_count: 1 }
    );
    assert_eq!(*announced.lock().unwrap(), 1);

    // A granted, B queued.
    evt_a
        .send(ServeInput::Server(ServerEvent::SlotRequested { file_hash }))
        .await
        .unwrap();
    assert_eq!(
        cmd_a.recv().await.unwrap(),
        ServeOutput::Server(ServerCommand::GrantSlot { file_hash })
    );
    assert_eq!(
        next_serve_event(&mut core).await,
        ServeEvent::UploadSlotGranted {
            peer: peer(31),
            file_hash,
            software: None,
        }
    );
    evt_b
        .send(ServeInput::Server(ServerEvent::SlotRequested { file_hash }))
        .await
        .unwrap();
    assert_eq!(
        cmd_b.recv().await.unwrap(),
        ServeOutput::Server(ServerCommand::SetQueueRank { rank: 1 })
    );
    assert_eq!(
        next_serve_event(&mut core).await,
        ServeEvent::PeerQueued {
            peer: peer(32),
            rank: 1,
            file_hash,
            software: None,
        }
    );

    // A cancels (OP_CANCELTRANSFER) instead of disconnecting: B is promoted
    // exactly as on a disconnect...
    evt_a
        .send(ServeInput::Server(ServerEvent::TransferCancelled {
            file_hash,
        }))
        .await
        .unwrap();
    assert_eq!(
        cmd_b.recv().await.unwrap(),
        ServeOutput::Server(ServerCommand::GrantSlot { file_hash })
    );
    assert_eq!(
        next_serve_event(&mut core).await,
        ServeEvent::UploadSlotGranted {
            peer: peer(32),
            file_hash,
            software: None,
        }
    );
    assert_eq!(
        next_serve_event(&mut core).await,
        ServeEvent::UploadSlotReleased { peer: peer(31) }
    );

    // ...but unlike a disconnect, A's connection is never torn down: a fresh
    // ask over the same connection is admitted at the tail (rank 1, the
    // position B just vacated) instead of being silently dropped by a runner
    // that no longer recognizes the peer.
    evt_a
        .send(ServeInput::Server(ServerEvent::SlotRequested { file_hash }))
        .await
        .unwrap();
    assert_eq!(
        timeout(HANG_GUARD, cmd_a.recv())
            .await
            .expect("A's connection must stay registered across a cancel")
            .unwrap(),
        ServeOutput::Server(ServerCommand::SetQueueRank { rank: 1 })
    );
}

#[tokio::test]
async fn serve_start_failure_emits_serving_failed_not_a_hang() {
    // A serve runtime whose start() errors must answer with `ServingFailed`, so
    // a `download start --serve` waiter aborts instead of hanging forever on
    // `ServingStarted` (cycle-11 regression, c1ba767). The answer now
    // names the cause and the adapter survives, so the retry below is a real
    // retry rather than silence — that is what the second event proves.
    let serve_runtime = FakeServeRuntime {
        pending: vec![],
        announced: Arc::new(Mutex::new(0)),
        start_fails: true,
    };
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .source_lookup(UnusedSourceLookup)
        .peer_transfer(UnusedPeerTransfer)
        .serve_runtime(serve_runtime)
        .build();

    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: "0.0.0.0:0".parse().unwrap(),
    }))
    .await
    .unwrap();

    let event = timeout(HANG_GUARD, next_serve_event(&mut core))
        .await
        .expect("serve-start failure must surface, not hang");
    assert_eq!(
        event,
        ServeEvent::ServingFailed {
            reason: ServeStartFailure::Adapter
        }
    );

    // The retry a failure invites: the adapter was not burned with the failed
    // start, so the same command is answered again rather than swallowed.
    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: "0.0.0.0:0".parse().unwrap(),
    }))
    .await
    .unwrap();
    assert_eq!(
        timeout(HANG_GUARD, next_serve_event(&mut core))
            .await
            .expect("a retry after a failed start is answered, never ignored"),
        ServeEvent::ServingFailed {
            reason: ServeStartFailure::Adapter
        }
    );
}

#[tokio::test]
async fn serve_skips_ranges_already_sent_on_a_granted_slot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("served.bin");
    let bytes: Vec<u8> = (0..512).map(|i| (i % 251) as u8).collect();
    tokio::fs::write(&path, &bytes).await.unwrap();
    let file_hash = FileHashSummary::digest_bytes(&bytes).file_hash();

    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    registry
        .clone()
        .share(SharedFileEntry {
            file_hash,
            file_size: bytes.len() as u64,
            path: path.clone(),
            name: "served.bin".into(),
            source: ShareSource::Explicit,
            modified: None,
            part_hashes: Vec::new(),
        })
        .unwrap();

    let (conn, evt, mut cmd) = conn_pair(peer(10));
    let announced = Arc::new(Mutex::new(0));
    let serve_runtime = FakeServeRuntime {
        pending: vec![conn],
        announced,
        start_fails: false,
    };
    let mut core = Core::builder(CoreConfig::default(), store)
        .settings(rmule_core::CoreSettings::default())
        .source_lookup(UnusedSourceLookup)
        .peer_transfer(UnusedPeerTransfer)
        .serve_runtime(serve_runtime)
        .build();

    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: "0.0.0.0:0".parse().unwrap(),
    }))
    .await
    .unwrap();
    assert!(matches!(
        next_serve_event(&mut core).await,
        ServeEvent::ServingStarted { .. }
    ));
    assert_eq!(
        next_serve_event(&mut core).await,
        ServeEvent::FilesAnnounced { file_count: 1 }
    );

    evt.send(ServeInput::Server(ServerEvent::SlotRequested { file_hash }))
        .await
        .unwrap();
    assert_eq!(
        cmd.recv().await.unwrap(),
        ServeOutput::Server(ServerCommand::GrantSlot { file_hash })
    );
    assert_eq!(
        next_serve_event(&mut core).await,
        ServeEvent::UploadSlotGranted {
            peer: peer(10),
            file_hash,
            software: None,
        }
    );

    let first = PartRanges::new([(0, 100), (100, 200), (200, 300)]).unwrap();
    evt.send(ServeInput::Server(ServerEvent::PartsRequested {
        file_hash,
        ranges: first,
    }))
    .await
    .unwrap();
    assert_send_block(&mut cmd, file_hash, 0, 100, &bytes).await;
    assert_send_block(&mut cmd, file_hash, 100, 200, &bytes).await;
    assert_send_block(&mut cmd, file_hash, 200, 300, &bytes).await;

    let overlapping = PartRanges::new([(100, 200), (200, 300), (300, 400)]).unwrap();
    evt.send(ServeInput::Server(ServerEvent::PartsRequested {
        file_hash,
        ranges: overlapping,
    }))
    .await
    .unwrap();
    assert_send_block(&mut cmd, file_hash, 300, 400, &bytes).await;
}

async fn assert_send_block(
    cmd: &mut mpsc::Receiver<ServeOutput>,
    file_hash: FileHash,
    start: u64,
    end: u64,
    file_bytes: &[u8],
) {
    let command = timeout(HANG_GUARD, cmd.recv())
        .await
        .expect("serve command emitted")
        .expect("serve command stream open");
    let ServeOutput::Server(ServerCommand::SendBlock {
        file_hash: actual_hash,
        start: actual_start,
        end: actual_end,
        bytes,
    }) = command
    else {
        panic!("expected SendBlock, got {command:?}");
    };
    assert_eq!(actual_hash, file_hash);
    assert_eq!(actual_start, start);
    assert_eq!(actual_end, end);
    assert_eq!(bytes, file_bytes[start as usize..end as usize]);
}

/// Acceptance: the builder with custom adapters (source lookup, peer
/// transfer, serve runtime) over the store-opened registry and credit store
/// both builds and serves. A shared directory's file lands in the registry — the announced
/// count proves it is wired — and the slot grant drives the serve queue over
/// the credit store, with the test never touching either seam directly.
#[tokio::test]
async fn builder_mixed_override_over_default_registry_and_credit_serves() {
    let dir = tempfile::tempdir().unwrap();
    let bytes: Vec<u8> = (0..512).map(|i| (i % 251) as u8).collect();
    tokio::fs::write(dir.path().join("mixed.bin"), &bytes)
        .await
        .unwrap();
    let file_hash = FileHashSummary::digest_bytes(&bytes).file_hash();

    let (conn, evt, mut cmd) = conn_pair(peer(7));
    let serve_runtime = FakeServeRuntime {
        pending: vec![conn],
        announced: Arc::new(Mutex::new(0)),
        start_fails: false,
    };
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .source_lookup(UnusedSourceLookup)
        .peer_transfer(UnusedPeerTransfer)
        .serve_runtime(serve_runtime)
        .build();

    assert_eq!(
        rmule_testkit::share_directory(&mut core, dir.path()).await,
        vec![file_hash]
    );

    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: "0.0.0.0:0".parse().unwrap(),
    }))
    .await
    .unwrap();
    assert!(matches!(
        next_serve_event(&mut core).await,
        ServeEvent::ServingStarted { .. }
    ));
    assert_eq!(
        next_serve_event(&mut core).await,
        ServeEvent::FilesAnnounced { file_count: 1 }
    );

    evt.send(ServeInput::Server(ServerEvent::SlotRequested { file_hash }))
        .await
        .unwrap();
    assert_eq!(
        cmd.recv().await.unwrap(),
        ServeOutput::Server(ServerCommand::GrantSlot { file_hash })
    );
    assert_eq!(
        next_serve_event(&mut core).await,
        ServeEvent::UploadSlotGranted {
            peer: peer(7),
            file_hash,
            software: None,
        }
    );
}

/// `Core::shutdown()` returns after a serving session.
///
/// Shutdown is "close the command channel, then drain the event stream to its
/// end" — and that end only comes when every task holding a `CoreEvent` sender
/// has gone. The actor ends a serve activity on its own way out by *dropping*
/// it, never by sending `true`, so a serve loop that reads its closed stop
/// channel as a spurious wakeup outlives the actor forever — spinning at full
/// speed on a core, with shutdown parked behind it. Every front end shuts down;
/// none of them may hang.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_returns_after_a_serving_session() {
    let serve_runtime = FakeServeRuntime {
        pending: vec![],
        announced: Arc::new(Mutex::new(0)),
        start_fails: false,
    };
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .source_lookup(UnusedSourceLookup)
        .peer_transfer(UnusedPeerTransfer)
        .serve_runtime(serve_runtime)
        .build();

    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: "0.0.0.0:0".parse().unwrap(),
    }))
    .await
    .unwrap();
    assert!(matches!(
        next_serve_event(&mut core).await,
        ServeEvent::ServingStarted { .. }
    ));

    timeout(HANG_GUARD, core.shutdown())
        .await
        .expect("Core::shutdown returns after a serving session");
}
