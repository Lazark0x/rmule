//! Sharing a file: what the unshare command accepts and rejects, and
//! the auto-share a completed download triggers — including the part hash
//! set the link's authority carries into the registry, and the Had Set an
//! unshare of a gone file joins and a completed download leaves.
use std::sync::Arc;

use crate::fixture::identity;
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent, DownloadFailure,
    DownloadedPart, PeerDownloadOutcome, PeerTransferService, PeerWorker, PeerWorkerCommand,
    PeerWorkerEvent, ServeCommand, ServeEvent, ShareRejectReason, ShareSource, SharedFileRegistry,
    SourceLookupOutcome, SourceLookupService,
};
use rmule_core::{DurableSharedFileRegistry, DurableStore};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{
    ClientId, Ed2kFileLink, Ed2kText, ExchangedSource, FileHashSummary, PeerEndpoint, PeerSource,
    ServerEndpoint, SourceLookupTarget,
};
use rmule_testkit::file_link_without_part_hash_set;
use tokio::time::{Duration, timeout};

// Adapters that are never invoked in serve-only tests (no StartDownload).
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

/// A serving core on `store` — the registry it shares through is the default
/// seam the builder opens there, so a test holding its own
/// [`DurableSharedFileRegistry`] on the same store sees exactly what core wrote.
fn serve_core(store: Arc<DurableStore>) -> Core {
    Core::builder(CoreConfig::default(), store)
        .source_lookup(UnusedSourceLookup)
        .peer_transfer(UnusedPeerTransfer)
        .build()
}

async fn next_serve_event(core: &mut Core) -> ServeEvent {
    loop {
        let event = timeout(Duration::from_secs(2), core.next_event())
            .await
            .expect("core emitted a serve event")
            .expect("core event stream stayed open");
        if let CoreEvent::Serve(serve) = event {
            return serve;
        }
    }
}

#[tokio::test]
async fn unshare_file_command_removes_the_entry() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = b"unshare me".to_vec();
    tokio::fs::write(dir.path().join("doc.bin"), &bytes)
        .await
        .unwrap();
    let hash = FileHashSummary::digest_bytes(&bytes).file_hash();

    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    let mut core = serve_core(store);
    assert_eq!(
        rmule_testkit::share_directory(&mut core, dir.path()).await,
        vec![hash]
    );

    core.send(CoreCommand::Serve(ServeCommand::UnshareFile {
        file_hash: hash,
    }))
    .await
    .unwrap();

    assert_eq!(
        next_serve_event(&mut core).await,
        ServeEvent::FileUnshared { file_hash: hash }
    );
    assert_eq!(registry.get(hash).unwrap(), None);
    assert!(
        registry.had_set().list().unwrap().is_empty(),
        "the file is still on disk: an unshare is not a vanish"
    );
}

/// The row is a completed download's, outside any shared directory. The
/// Registry Check may withhold it first, when its start look meets the file
/// already gone; the unshare still finds it gone and makes it Had.
#[tokio::test]
async fn unsharing_a_file_already_gone_puts_it_in_the_had_set() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("left.bin");
    let bytes = b"deleted behind our back".to_vec();
    tokio::fs::write(&path, &bytes).await.unwrap();
    let hash = FileHashSummary::digest_bytes(&bytes).file_hash();

    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    registry
        .share(rmule_core::SharedFileEntry {
            file_hash: hash,
            file_size: bytes.len() as u64,
            path: path.clone(),
            name: "left.bin".to_string(),
            source: ShareSource::CompletedDownload,
            part_hashes: Vec::new(),
            modified: None,
        })
        .unwrap();
    let mut core = serve_core(store);
    tokio::fs::remove_file(&path).await.unwrap();

    core.send(CoreCommand::Serve(ServeCommand::UnshareFile {
        file_hash: hash,
    }))
    .await
    .unwrap();
    let left = loop {
        match next_serve_event(&mut core).await {
            ServeEvent::FileWithheld { .. } => {}
            other => break other,
        }
    };
    assert_eq!(left, ServeEvent::FileUnshared { file_hash: hash });
    let had = registry.had_set().list().unwrap();
    assert_eq!(had.len(), 1);
    assert_eq!(
        (
            had[0].identity.file_hash,
            had[0].identity.file_size,
            had[0].name.as_str()
        ),
        (hash, bytes.len() as u64, "left.bin")
    );
}

#[tokio::test]
async fn unshare_unknown_file_is_rejected() {
    let mut core = serve_core(rmule_testkit::memory_store());
    let hash = rmule_primitives::FileHash::from_bytes([0x99; rmule_primitives::FileHash::BYTE_LEN]);

    core.send(CoreCommand::Serve(ServeCommand::UnshareFile {
        file_hash: hash,
    }))
    .await
    .unwrap();

    assert_eq!(
        next_serve_event(&mut core).await,
        ServeEvent::ShareRejected {
            reason: ShareRejectReason::NotShared
        }
    );
}

// ---------------------------------------------------------------------------
// Auto-share on completed download (Task 7)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ScriptedSourceLookup {
    outcome: SourceLookupOutcome,
}
impl SourceLookupService for ScriptedSourceLookup {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        Ok(self.outcome.clone())
    }
}

struct ScriptedPeerTransfer {
    expected_peer: PeerEndpoint,
    outcome: PeerDownloadOutcome,
}
impl PeerTransferService for ScriptedPeerTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        _file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        assert_eq!(peer, self.expected_peer);
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let outcome = self.outcome.clone();
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            while let Some(command) = command_rx.recv().await {
                match command {
                    PeerWorkerCommand::RequestPart {
                        plan,
                        resume_offset,
                    } => {
                        if let Some(part) = outcome
                            .parts
                            .iter()
                            .find(|part| part.part_index == plan.part_index)
                        {
                            let start = (resume_offset.saturating_sub(part.offset) as usize)
                                .min(part.bytes.len());
                            let _ = event_tx
                                .send(PeerWorkerEvent::BlockReceived {
                                    part_index: part.part_index,
                                    offset: resume_offset,
                                    bytes: part.bytes[start..].to_vec(),
                                })
                                .await;
                            let _ = event_tx
                                .send(PeerWorkerEvent::PartStreamed {
                                    part_index: part.part_index,
                                })
                                .await;
                        }
                    }
                    PeerWorkerCommand::RequestAich { .. } => {}
                    PeerWorkerCommand::RequestAichFileHash => {}
                    PeerWorkerCommand::Shutdown { .. } => break,
                }
            }
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

#[tokio::test]
async fn completed_download_auto_registers_into_the_shared_file_registry() {
    let bytes = b"hello world".to_vec();
    let link = file_link_without_part_hash_set("example.bin", &bytes);
    let high = PeerSource::new(ClientId::from_u32(0x0100_007F), 4663);
    let peer = high.as_peer_endpoint().unwrap();
    let source = ScriptedSourceLookup {
        outcome: SourceLookupOutcome {
            client_id: ClientId::from_u32(0x0100_007F),
            sources: vec![ExchangedSource::plain(high)],
        },
    };
    let transfer = ScriptedPeerTransfer {
        expected_peer: peer,
        outcome: PeerDownloadOutcome {
            peer_hashes: Vec::new(),
            parts: vec![DownloadedPart {
                part_index: 0,
                offset: 0,
                bytes: bytes.clone(),
            }],
        },
    };
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    let mut core = Core::builder(CoreConfig::default(), store)
        .source_lookup(source)
        .peer_transfer(transfer)
        .build();

    let output_dir = tempfile::tempdir().expect("temp dir");
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: link.clone(),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        credentials: identity().into(),
        output_path: output_dir.path().join("autoshare.bin"),
    }))
    .await
    .unwrap();

    // The auto-share fact is emitted by the actor after the download
    // completes (DownloadCompleted -> task-finished signal -> register).
    let shared = loop {
        let event = timeout(Duration::from_secs(2), core.next_event())
            .await
            .expect("core emitted next event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Serve(ServeEvent::FileShared { file_hash }) => break file_hash,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    };

    assert_eq!(shared, link.file_hash);
    let entry = registry
        .get(link.file_hash)
        .unwrap()
        .expect("completed download is auto-registered");
    assert_eq!(entry.file_size, bytes.len() as u64);
    assert_eq!(entry.source, ShareSource::CompletedDownload);
}

#[tokio::test]
async fn auto_share_persists_the_link_authority_part_hash_set() {
    // Two full parts so the link carries a real part hash set; the download
    // verifies against it (LinkPartHashSet authority) without persisting it
    // as "provisional", so the auto-share must answer the link's set rather
    // than an empty one.
    let part = 9_728_000_usize;
    let bytes = vec![0xE7_u8; part * 2];
    let summary = FileHashSummary::digest_bytes(&bytes);
    let link = Ed2kFileLink {
        name: Ed2kText::from_utf8("two-parts.bin"),
        size: bytes.len() as u64,
        file_hash: summary.file_hash(),
        part_hash_set: summary.part_hash_set().cloned(),
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    };
    let expected = summary
        .part_hash_set()
        .expect("two-part file has a hash set")
        .hashes()
        .to_vec();

    let high = PeerSource::new(ClientId::from_u32(0x0100_007F), 4663);
    let peer = high.as_peer_endpoint().unwrap();
    let source = ScriptedSourceLookup {
        outcome: SourceLookupOutcome {
            client_id: ClientId::from_u32(0x0100_007F),
            sources: vec![ExchangedSource::plain(high)],
        },
    };
    let transfer = ScriptedPeerTransfer {
        expected_peer: peer,
        outcome: PeerDownloadOutcome {
            peer_hashes: Vec::new(), // peer sends no hash set -> LinkPartHashSet authority
            parts: vec![
                DownloadedPart {
                    part_index: 0,
                    offset: 0,
                    bytes: bytes[..part].to_vec(),
                },
                DownloadedPart {
                    part_index: 1,
                    offset: part as u64,
                    bytes: bytes[part..].to_vec(),
                },
            ],
        },
    };
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    let dir = tempfile::tempdir().unwrap();
    let mut core = Core::builder(CoreConfig::default(), store)
        .source_lookup(source)
        .peer_transfer(transfer)
        .build();

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: link.clone(),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        credentials: identity().into(),
        output_path: dir.path().join("auto-share-link-authority.bin"),
    }))
    .await
    .unwrap();

    let shared = loop {
        let event = timeout(Duration::from_secs(5), core.next_event())
            .await
            .expect("core emitted next event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Serve(ServeEvent::FileShared { file_hash }) => break file_hash,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    };
    assert_eq!(shared, link.file_hash);
    assert_eq!(registry.hash_set(link.file_hash).unwrap(), Some(expected));
}

#[tokio::test]
async fn a_shared_directory_stores_the_part_hash_set_for_a_multi_part_file() {
    use rmule_primitives::FileHashSummary;

    let dir = tempfile::tempdir().unwrap();
    // Two full parts so a part hash set exists.
    let bytes = vec![0xCD_u8; (9_728_000 * 2) as usize];
    tokio::fs::write(dir.path().join("multi.bin"), &bytes)
        .await
        .unwrap();
    let summary = FileHashSummary::digest_bytes(&bytes);
    let expected = summary
        .part_hash_set()
        .expect("two-part file has a hash set")
        .hashes()
        .to_vec();

    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    let mut core = serve_core(store);
    rmule_testkit::share_directory(&mut core, dir.path()).await;

    assert_eq!(
        registry.hash_set(summary.file_hash()).unwrap(),
        Some(expected)
    );
}

/// ADR-0100, re-adding a **Had** file: the confirm's yes is an ordinary
/// start, and once the download completes and is shared its hash leaves the
/// Had Set — the file is on disk again.
#[tokio::test]
async fn a_had_file_downloaded_again_leaves_the_had_set_when_it_is_whole() {
    let bytes = b"had once".to_vec();
    let link = file_link_without_part_hash_set("had.bin", &bytes);
    let high = PeerSource::new(ClientId::from_u32(0x0100_007F), 4663);
    let source = ScriptedSourceLookup {
        outcome: SourceLookupOutcome {
            client_id: ClientId::from_u32(0x0100_007F),
            sources: vec![ExchangedSource::plain(high)],
        },
    };
    let transfer = ScriptedPeerTransfer {
        expected_peer: high.as_peer_endpoint().unwrap(),
        outcome: PeerDownloadOutcome {
            peer_hashes: Vec::new(),
            parts: vec![DownloadedPart {
                part_index: 0,
                offset: 0,
                bytes: bytes.clone(),
            }],
        },
    };
    let output_dir = tempfile::tempdir().expect("temp dir");
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    // Shared once, then found gone.
    let old_path = output_dir.path().join("had.bin");
    registry
        .share(rmule_core::SharedFileEntry {
            file_hash: link.file_hash,
            file_size: link.size,
            path: old_path.clone(),
            name: "had.bin".into(),
            source: ShareSource::DownloadDirectory,
            part_hashes: Vec::new(),
            modified: None,
        })
        .unwrap();
    assert!(registry.gone(link.file_hash, &old_path).unwrap());
    assert_eq!(registry.had_set().list().unwrap().len(), 1);

    let mut core = Core::builder(CoreConfig::default(), store)
        .source_lookup(source)
        .peer_transfer(transfer)
        .build();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: link.clone(),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        credentials: identity().into(),
        output_path: output_dir.path().join("had (1).bin"),
    }))
    .await
    .unwrap();
    loop {
        let event = timeout(Duration::from_secs(2), core.next_event())
            .await
            .expect("core emitted next event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Serve(ServeEvent::FileShared { file_hash }) => {
                assert_eq!(file_hash, link.file_hash);
                break;
            }
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    }
    assert!(registry.had_set().list().unwrap().is_empty());
}
