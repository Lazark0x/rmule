//! The download command surface a front-end drives: several downloads side
//! by side, what the core rejects (a duplicate file, an unknown id), what it persists before the
//! protocol adapter answers, and what a restart recovers. Pause, resume, and
//! failure each land a distinct durable lifecycle.
use crate::fixture::host_binds_ipv6;
use crate::fixture::identity;
use crate::fixture::next_matching;
use crate::fixture::stub_link;
use rmule_core::DownloadRepository;
use rmule_core::{
    Core, CoreCommand, CoreCommandRejectReason, CoreConfig, CoreEvent, DownloadCommand,
    DownloadEvent, DownloadFailure, DownloadId, DownloadLifecycle, DownloadMetadataOrigin,
    DurableDownloadRepository, PeerTransferService, PeerWorker, PeerWorkerCommand, PeerWorkerEvent,
    SourceLookupOutcome, SourceLookupService, open_durable_store,
};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{
    ClientId, Ed2kFileLink, ExchangedSource, PeerEndpoint, PeerSource, ServerEndpoint,
    SourceLookupTarget,
};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::time::{Duration, timeout};

fn file_link() -> Ed2kFileLink {
    stub_link("example.bin", 3, 0x11)
}

/// The **Download Set**: starting a file while others run adds
/// it beside them. Every start is accepted, and every one is still live
/// afterwards — each answers its own pause, which only a download the set
/// holds can do. Newest first: a later download's run is still waiting its
/// turn at the one source-lookup seam the first one holds, and its stop must
/// reach it there.
#[tokio::test]
async fn several_downloads_run_side_by_side() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .source_lookup(PendingSourceLookup)
        .peer_transfer(UnreachablePeerTransfer)
        .build();

    let mut ids = Vec::new();
    for seed in [0x21, 0x22, 0x23] {
        let name = format!("file-{seed:02x}.bin");
        core.send(start_command(
            stub_link(&name, 3, seed),
            dir.path().join(&name),
        ))
        .await
        .unwrap();
        match next_start_verdict(&mut core).await {
            CoreEvent::Download(DownloadEvent::DownloadQueued { download_id, .. }) => {
                ids.push(download_id);
            }
            refused => panic!("start {seed:#x} beside {ids:?} was refused: {refused:?}"),
        }
    }

    for download_id in ids.into_iter().rev() {
        core.send(CoreCommand::Download(DownloadCommand::PauseDownload {
            download_id,
        }))
        .await
        .unwrap();
        let answer = next_matching(&mut core, |event| {
            matches!(
                event,
                CoreEvent::Download(DownloadEvent::DownloadPaused { .. })
                    | CoreEvent::CommandRejected { .. }
            )
        })
        .await;
        assert!(
            matches!(answer, CoreEvent::Download(DownloadEvent::DownloadPaused { download_id: id }) if id == download_id),
            "download {download_id:?} was not live beside the others: {answer:?}",
        );
    }
}

/// The one start the set refuses: the same file again while a live
/// download already holds it.
#[tokio::test]
async fn starting_a_file_already_downloading_is_refused_as_a_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .source_lookup(PendingSourceLookup)
        .peer_transfer(UnreachablePeerTransfer)
        .build();

    core.send(start_command(file_link(), dir.path().join("a.bin")))
        .await
        .unwrap();
    next_queued_id(&mut core).await;
    core.send(start_command(file_link(), dir.path().join("b.bin")))
        .await
        .unwrap();
    let verdict = next_start_verdict(&mut core).await;
    assert!(
        matches!(
            verdict,
            CoreEvent::CommandRejected {
                reason: CoreCommandRejectReason::DuplicateDownload
            }
        ),
        "expected DuplicateDownload, got {verdict:?}",
    );
}

fn start_command(file: Ed2kFileLink, output_path: std::path::PathBuf) -> CoreCommand {
    CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        credentials: identity().into(),
        output_path,
    })
}

/// A start's answer: its `DownloadQueued`, or the refusal in its place.
async fn next_start_verdict(core: &mut Core) -> CoreEvent {
    next_matching(core, |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadQueued { .. })
                | CoreEvent::CommandRejected { .. }
        )
    })
    .await
}

/// A row for `file` at `path` in `store`, driven to `lifecycle` — the history a
/// re-add meets.
fn seeded_row(
    store: &Arc<rmule_core::DurableStore>,
    file: &Ed2kFileLink,
    path: std::path::PathBuf,
    lifecycle: &[DownloadLifecycle],
) {
    let repo = DurableDownloadRepository::new(Arc::clone(store));
    let record = repo
        .create_download(
            file,
            Some(&ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
            &rmule_core::DownloadPaths::from_final_path(path),
        )
        .unwrap();
    for state in lifecycle {
        repo.set_lifecycle(record.id(), *state).unwrap();
    }
}

fn idle_core(store: &Arc<rmule_core::DurableStore>) -> Core {
    Core::builder(CoreConfig::default(), Arc::clone(store))
        .source_lookup(PendingSourceLookup)
        .peer_transfer(UnreachablePeerTransfer)
        .build()
}

/// ADR-0100, re-adding a **Cancelled** file: the confirm's yes starts the file
/// again at the place it was once started — the cancelled row gives up the
/// `.part` path it no longer writes.
#[tokio::test]
async fn a_file_cancelled_before_starts_again_at_the_same_place() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let path = dir.path().join("again.bin");
    seeded_row(
        &store,
        &file_link(),
        path.clone(),
        &[DownloadLifecycle::Cancelled],
    );
    let mut core = idle_core(&store);

    core.send(start_command(file_link(), path)).await.unwrap();
    let verdict = next_start_verdict(&mut core).await;
    assert!(
        matches!(
            verdict,
            CoreEvent::Download(DownloadEvent::DownloadQueued { .. })
        ),
        "a cancelled file is started again, got {verdict:?}",
    );
}

/// ADR-0100, re-adding a **Have** file: its completed copy still lies at the
/// old path, which a new download must not overwrite — refused there, started
/// at a free name beside it.
#[tokio::test]
async fn a_file_on_disk_is_started_again_only_at_a_free_path() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let path = dir.path().join("have.bin");
    seeded_row(
        &store,
        &file_link(),
        path.clone(),
        &[DownloadLifecycle::Active, DownloadLifecycle::Completed],
    );
    std::fs::write(&path, b"abc").unwrap();
    let mut core = idle_core(&store);

    core.send(start_command(file_link(), path)).await.unwrap();
    let verdict = next_start_verdict(&mut core).await;
    assert!(
        matches!(
            verdict,
            CoreEvent::CommandRejected {
                reason: CoreCommandRejectReason::DownloadPathConflict
            }
        ),
        "the file on disk is never overwritten, got {verdict:?}",
    );
    core.send(start_command(file_link(), dir.path().join("have (1).bin")))
        .await
        .unwrap();
    let verdict = next_start_verdict(&mut core).await;
    assert!(
        matches!(
            verdict,
            CoreEvent::Download(DownloadEvent::DownloadQueued { .. })
        ),
        "a completed file is started again at a free path, got {verdict:?}",
    );
}

/// The **File History** a front end marks results with: the registry's
/// entries with their paths, the Had Set with the names its files last had,
/// and the downloads cancelled before completing — not the completed or live
/// ones.
#[tokio::test]
async fn the_file_history_names_the_shared_files_and_the_cancelled_downloads() {
    use rmule_core::SharedFileRegistry;
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let shared = stub_link("shared.bin", 7, 0x31);
    let had = stub_link("had.bin", 5, 0x34);
    let registry = rmule_core::DurableSharedFileRegistry::new(Arc::clone(&store));
    for (file, name) in [(&shared, "shared.bin"), (&had, "had.bin")] {
        registry
            .share(rmule_core::SharedFileEntry {
                file_hash: file.file_hash,
                file_size: file.size,
                path: dir.path().join(name),
                name: name.to_string(),
                source: rmule_core::ShareSource::Explicit,
                part_hashes: Vec::new(),
                modified: None,
            })
            .unwrap();
    }
    registry
        .gone(had.file_hash, &dir.path().join("had.bin"))
        .unwrap();
    let cancelled = stub_link("gone.bin", 9, 0x32);
    seeded_row(
        &store,
        &cancelled,
        dir.path().join("gone.bin"),
        &[DownloadLifecycle::Cancelled],
    );
    seeded_row(
        &store,
        &stub_link("live.bin", 11, 0x33),
        dir.path().join("live.bin"),
        &[],
    );
    // The shared file is on disk, so no look can withhold it.
    std::fs::write(dir.path().join("shared.bin"), [0_u8; 7]).unwrap();
    let mut core = idle_core(&store);

    core.send(CoreCommand::DumpFileHistory).await.unwrap();
    let CoreEvent::FileHistory { history } = next_matching(&mut core, |event| {
        matches!(event, CoreEvent::FileHistory { .. })
    })
    .await
    else {
        unreachable!("matched above")
    };
    assert_eq!(
        history.shared,
        [rmule_core::file_history::SharedFileFact {
            identity: rmule_core::file_history::Ed2kIdentity::new(shared.file_hash, 7),
            path: dir.path().join("shared.bin"),
            withheld: None,
        }]
    );
    assert_eq!(
        history
            .had
            .iter()
            .map(|file| (
                file.identity.file_hash,
                file.identity.file_size,
                file.name.as_str()
            ))
            .collect::<Vec<_>>(),
        [(had.file_hash, 5, "had.bin")]
    );
    assert_eq!(
        history.cancelled,
        [rmule_core::file_history::Ed2kIdentity::new(
            cancelled.file_hash,
            9
        )]
    );
}

#[tokio::test]
async fn cancel_unknown_download_is_rejected() {
    // A host with no IPv6 would open with each pair's missing-family fact
    // Bound v4-only there, the rejection is still the first
    // thing this core says.
    let config = if host_binds_ipv6() {
        CoreConfig::default()
    } else {
        CoreConfig {
            address_families: rmule_net::family::FamilySelection::v4_only(),
            ..CoreConfig::default()
        }
    };
    let mut core = Core::new(config, rmule_testkit::memory_store());
    core.send(CoreCommand::Download(DownloadCommand::CancelDownload {
        download_id: DownloadId::from_u64(99),
    }))
    .await
    .unwrap();

    let event = core.next_event().await.expect("core emitted next event");
    assert!(
        matches!(
            event,
            CoreEvent::CommandRejected {
                reason: CoreCommandRejectReason::UnknownDownload
            }
        ),
        "expected CommandRejected(UnknownDownload) but saw {event:?}",
    );
}

#[tokio::test]
async fn durable_start_creates_record_before_fake_protocol_adapter_completes() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let output_path = dir.path().join("download.bin");
    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .source_lookup(PendingSourceLookup)
        .peer_transfer(UnreachablePeerTransfer)
        .build();

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link(),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        credentials: identity().into(),
        output_path: output_path.clone(),
    }))
    .await
    .unwrap();

    let download_id = loop {
        let event = timeout(Duration::from_secs(2), core.next_event())
            .await
            .expect("core emitted queued event")
            .expect("core event stream stayed open");
        if let CoreEvent::Download(DownloadEvent::DownloadQueued { download_id, .. }) = event {
            break download_id;
        }
    };

    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let record = repo.load_download(download_id).unwrap();
    assert_eq!(record.lifecycle(), DownloadLifecycle::Queued);
    assert_eq!(record.paths().final_path(), output_path.as_path());
}

#[tokio::test]
async fn pause_download_persists_paused_and_emits_event() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .source_lookup(PendingSourceLookup)
        .peer_transfer(UnreachablePeerTransfer)
        .build();

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link(),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        credentials: identity().into(),
        output_path: dir.path().join("download.bin"),
    }))
    .await
    .unwrap();
    let download_id = next_queued_id(&mut core).await;

    core.send(CoreCommand::Download(DownloadCommand::PauseDownload {
        download_id,
    }))
    .await
    .unwrap();
    let paused = next_matching(&mut core, |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadPaused { .. })
        )
    })
    .await;
    assert!(
        matches!(paused, CoreEvent::Download(DownloadEvent::DownloadPaused { download_id: id }) if id == download_id),
        "expected DownloadPaused for {download_id:?} but saw {paused:?}",
    );

    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    assert_eq!(
        repo.load_download(download_id).unwrap().lifecycle(),
        DownloadLifecycle::Paused
    );
}

#[tokio::test]
async fn startup_recovery_emits_recovered_without_source_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let created = repo
        .create_download(
            &file_link(),
            Some(&ServerEndpoint::new("persisted.example", 4661).unwrap()),
            &rmule_core::DownloadPaths::from_final_path(dir.path().join("download.bin")),
        )
        .unwrap();
    repo.set_lifecycle(created.id(), DownloadLifecycle::Active)
        .unwrap();
    let lookups = Arc::new(StdMutex::new(Vec::new()));
    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .source_lookup(RecordingSourceLookup::new(Arc::clone(&lookups)))
        .peer_transfer(UnreachablePeerTransfer)
        .build();

    let recovered = next_matching(&mut core, |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadRecovered { .. })
        )
    })
    .await;
    let expected_id = created.id();
    assert!(
        matches!(
            &recovered,
            CoreEvent::Download(DownloadEvent::DownloadRecovered {
                download_id,
                state: DownloadLifecycle::Active,
                failure: None,
                file_hash,
                metadata,
            }) if *download_id == expected_id
                && *file_hash == file_link().file_hash
                && metadata.name == file_link().name
                && metadata.size == file_link().size
                && metadata.origin == DownloadMetadataOrigin::Link,
        ),
        "expected DownloadRecovered(Active) with the persisted name/size for {expected_id:?} but saw {recovered:?}",
    );
    tokio::time::sleep(Duration::from_millis(20)).await;

    assert!(lookups.lock().unwrap().is_empty());
}

#[tokio::test]
async fn start_surfaces_the_stored_name_and_exact_size_on_both_paths() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .source_lookup(PendingSourceLookup)
        .peer_transfer(UnreachablePeerTransfer)
        .build();

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link(),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        credentials: identity().into(),
        output_path: dir.path().join("download.bin"),
    }))
    .await
    .unwrap();

    let queued = next_matching(&mut core, |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadQueued { .. })
        )
    })
    .await;
    let CoreEvent::Download(DownloadEvent::DownloadQueued {
        download_id,
        metadata,
        ..
    }) = queued
    else {
        unreachable!("matched above")
    };
    assert_eq!(metadata.name, file_link().name);
    assert_eq!(metadata.size, file_link().size);
    assert_eq!(metadata.origin, DownloadMetadataOrigin::Link);

    // The level path reports the same facts, so a snapshot-only consumer and
    // an event-only consumer never disagree about the file.
    let snapshot = core.diagnostics_snapshot();
    let row = snapshot
        .downloads
        .get(&download_id)
        .expect("a started download opens its diagnostics row");
    assert_eq!(row.metadata, metadata);
}

#[tokio::test]
async fn resume_performs_a_fresh_source_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let persisted_server = ServerEndpoint::new("persisted.example", 4661).unwrap();
    let created = repo
        .create_download(
            &file_link(),
            Some(&persisted_server),
            &rmule_core::DownloadPaths::from_final_path(dir.path().join("download.bin")),
        )
        .unwrap();
    repo.set_lifecycle(created.id(), DownloadLifecycle::Paused)
        .unwrap();
    let lookups = Arc::new(StdMutex::new(Vec::new()));
    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .source_lookup(RecordingSourceLookup::new(Arc::clone(&lookups)))
        .peer_transfer(PendingPeerTransfer)
        .build();

    core.send(CoreCommand::Download(DownloadCommand::ResumeDownload {
        download_id: created.id(),
        credentials: identity().into(),
    }))
    .await
    .unwrap();

    assert!(matches!(
        next_matching(&mut core, |event| matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadProgressRestored { .. })
        ))
        .await,
        CoreEvent::Download(DownloadEvent::DownloadProgressRestored {
            verified_parts: 0,
            verified_bytes: 0,
            ..
        })
    ));
    let resumed = next_matching(&mut core, |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadResumed { .. })
        )
    })
    .await;
    let expected_id = created.id();
    assert!(
        matches!(
            resumed,
            CoreEvent::Download(DownloadEvent::DownloadResumed { download_id }) if download_id == expected_id,
        ),
        "expected DownloadResumed for {expected_id:?} but saw {resumed:?}",
    );
    let _ = next_matching(&mut core, |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::SourcesFound { .. })
        )
    })
    .await;

    assert_eq!(
        lookups.lock().unwrap().as_slice(),
        &[SourceLookupTarget::new(
            file_link().file_hash,
            file_link().size
        )]
    );
    let snapshot = core.diagnostics_snapshot();
    let row = snapshot
        .downloads
        .get(&created.id())
        .expect("a resumed download opens its diagnostics row");
    assert_eq!(row.metadata, *created.metadata());
}

#[tokio::test]
async fn a_server_failure_persists_failed_not_paused() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .source_lookup(FailingSourceLookup)
        .peer_transfer(UnreachablePeerTransfer)
        .build();

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link(),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        credentials: identity().into(),
        output_path: dir.path().join("download.bin"),
    }))
    .await
    .unwrap();
    let download_id = next_queued_id(&mut core).await;
    let failed = next_matching(&mut core, |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadFailed { .. })
        )
    })
    .await;
    assert!(matches!(
        failed,
        CoreEvent::Download(DownloadEvent::DownloadFailed {
            reason: DownloadFailure::ServerFiltered,
            ..
        })
    ));

    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let record = repo.load_download(download_id).unwrap();
    assert_eq!(record.lifecycle(), DownloadLifecycle::Failed);
    assert_eq!(record.failure(), Some(&DownloadFailure::ServerFiltered));
}

#[tokio::test]
async fn sourceless_lookup_terminates_by_default_instead_of_hanging_forever() {
    // A plain `download start`
    // against a sourceless file must not block on `OP_FOUNDSOURCES` forever.
    // `PendingSourceLookup` never resolves — modeling a connected-but-silent
    // server exactly like the Lugdunum test eserver (ADR-0040), which never
    // sends `OP_FOUNDSOURCES` for a hash it has no sources for. An explicit
    // short `source_lookup_timeout` proves the *configured* bound fires: the
    // download terminates (fails, rather than hanging) and stays Failed —
    // not Paused — in storage, exactly like any other source-lookup error.
    // (That the default is finite at all — not this 50 ms test value, but the
    // 30 s real default — is guaranteed by `CoreConfig::default`.)
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let config = CoreConfig {
        source_lookup_timeout: Duration::from_millis(50),
        ..CoreConfig::default()
    };
    let mut core = Core::builder(config, Arc::clone(&store))
        .source_lookup(PendingSourceLookup)
        .peer_transfer(UnreachablePeerTransfer)
        .build();

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link(),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        credentials: identity().into(),
        output_path: dir.path().join("download.bin"),
    }))
    .await
    .unwrap();
    let download_id = next_queued_id(&mut core).await;
    // `next_matching` caps each recv at 2 s (40x the configured 50 ms bound):
    // if that bound regressed back to unbounded, this test would fail
    // on that per-event timeout rather than hang the suite.
    let failed = next_matching(&mut core, |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadFailed { .. })
        )
    })
    .await;
    assert!(matches!(
        failed,
        CoreEvent::Download(DownloadEvent::DownloadFailed {
            reason: DownloadFailure::SourceLookupTimedOut,
            ..
        })
    ));

    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    assert_eq!(
        repo.load_download(download_id).unwrap().lifecycle(),
        DownloadLifecycle::Failed
    );
}

#[derive(Clone)]
struct PendingSourceLookup;

impl SourceLookupService for PendingSourceLookup {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        std::future::pending().await
    }
}

/// A server the IP filter refuses: a failure, where a server that does not
/// answer leaves the download waiting for a connection (ADR-0097).
#[derive(Clone)]
struct FailingSourceLookup;

impl SourceLookupService for FailingSourceLookup {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        Err(DownloadFailure::ServerFiltered)
    }
}

#[derive(Clone)]
struct RecordingSourceLookup {
    calls: Arc<StdMutex<Vec<SourceLookupTarget>>>,
}

impl RecordingSourceLookup {
    fn new(calls: Arc<StdMutex<Vec<SourceLookupTarget>>>) -> Self {
        Self { calls }
    }
}

impl SourceLookupService for RecordingSourceLookup {
    async fn lookup_sources(
        &mut self,
        target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        self.calls.lock().unwrap().push(target);
        Ok(SourceLookupOutcome {
            client_id: ClientId::from_u32(0x0100_007F),
            sources: vec![ExchangedSource::plain(PeerSource::new(
                ClientId::from_u32(0x0100_007F),
                4663,
            ))],
        })
    }
}

struct PendingPeerTransfer;

impl PeerTransferService for PendingPeerTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        _file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            while let Some(command) = command_rx.recv().await {
                if matches!(command, PeerWorkerCommand::Shutdown { .. }) {
                    break;
                }
            }
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

struct UnreachablePeerTransfer;

impl PeerTransferService for UnreachablePeerTransfer {
    async fn start_peer_worker(
        &mut self,
        _peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        _file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        panic!("peer transfer should not start before source lookup completes")
    }
}

async fn next_queued_id(core: &mut Core) -> DownloadId {
    match next_matching(core, |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadQueued { .. })
        )
    })
    .await
    {
        CoreEvent::Download(DownloadEvent::DownloadQueued { download_id, .. }) => download_id,
        _ => unreachable!("matcher only returns queued event"),
    }
}
