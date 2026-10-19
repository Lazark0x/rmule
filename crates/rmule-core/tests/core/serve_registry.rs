//! Sharing a file: what the unshare command accepts and rejects, and
//! the auto-share a completed download triggers — including the part hash
//! set the link's authority carries into the registry, the Had Set an
//! unshare of a gone file joins and a completed download leaves, and the
//! refusal that withholds a download completed under a refused folder until
//! the refusal lifts.
use rmule_testkit::HANG_GUARD;
use std::path::PathBuf;
use std::sync::Arc;

use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent, DownloadFailure,
    DownloadedPart, PeerDownloadOutcome, PeerTransferService, PeerWorker, PeerWorkerCommand,
    PeerWorkerEvent, ServeCommand, ServeEvent, ShareGuards, ShareRejectReason, ShareSource,
    SharedFileRegistry, SourceLookupOutcome, SourceLookupService, WithheldReason,
};
use rmule_core::{
    DownloadLifecycle, DownloadPaths, DownloadRepository, DurableDownloadRepository,
    DurableSharedFileRegistry, DurableStore,
};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{
    ClientId, Ed2kFileLink, Ed2kText, FileHashSummary, Informant, PeerEndpoint, PeerSource,
    ServerEndpoint, SourceLookupTarget, SourceSighting,
};
use rmule_testkit::{StaticPeerTransfer, file_link_without_part_hash_set, source_with_high_id};
use tokio::time::timeout;

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
        .settings(rmule_core::CoreSettings::default())
        .source_lookup(UnusedSourceLookup)
        .peer_transfer(UnusedPeerTransfer)
        .build()
}

async fn next_serve_event(core: &mut Core) -> ServeEvent {
    loop {
        let event = timeout(HANG_GUARD, core.next_event())
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
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let advertised = rmule_testkit::every_part(file.size);
        assert_eq!(peer, self.expected_peer);
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let outcome = self.outcome.clone();
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(advertised).await;
            while let Some(command) = command_rx.recv().await {
                match command {
                    PeerWorkerCommand::AskSlot => {
                        let _ = event_tx.send(PeerWorkerEvent::SlotGranted).await;
                    }
                    PeerWorkerCommand::RequestHashSet => {}
                    PeerWorkerCommand::RequestBlocks { blocks } => {
                        rmule_testkit::emit_blocks(&event_tx, &outcome.parts, &blocks).await;
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
    let output_dir = tempfile::tempdir().expect("temp dir");
    let bytes = b"hello world".to_vec();
    let link = file_link_without_part_hash_set("example.bin", &bytes);
    let high = PeerSource::new(ClientId::from_u32(0x0100_007F), 4663);
    let peer = high.as_peer_endpoint().unwrap();
    let source = ScriptedSourceLookup {
        outcome: SourceLookupOutcome {
            client_id: ClientId::from_u32(0x0100_007F),
            sources: vec![SourceSighting::plain(high, Informant::Own)],
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
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            output_dir.path(),
        ))
        .source_lookup(source)
        .peer_transfer(transfer)
        .build();

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: link.clone(),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_testkit::file_name("autoshare.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    // The auto-share fact is emitted by the actor after the download
    // completes (DownloadCompleted -> task-finished signal -> register).
    let shared = loop {
        let event = timeout(HANG_GUARD, core.next_event())
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
            sources: vec![SourceSighting::plain(high, Informant::Own)],
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
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            dir.path(),
        ))
        .source_lookup(source)
        .peer_transfer(transfer)
        .build();

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: link.clone(),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_testkit::file_name("auto-share-link-authority.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    let shared = loop {
        let event = timeout(HANG_GUARD, core.next_event())
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
            sources: vec![SourceSighting::plain(high, Informant::Own)],
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
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            output_dir.path(),
        ))
        .source_lookup(source)
        .peer_transfer(transfer)
        .build();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: link.clone(),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_testkit::file_name("had (1).bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();
    loop {
        let event = timeout(HANG_GUARD, core.next_event())
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

/// A core over `store` whose download directory, named `download_dir`, leads
/// to the home the guards refuse (ADR-0101), with one peer serving `bytes`
/// whole.
fn refused_home_core(
    store: Arc<DurableStore>,
    download_dir: &std::path::Path,
    home: &std::path::Path,
    bytes: &[u8],
) -> Core {
    Core::builder(CoreConfig::default(), store)
        .settings(rmule_core::CoreSettings {
            download_dir: Some(download_dir.to_path_buf()),
            ..rmule_core::CoreSettings::default()
        })
        .share_guards(ShareGuards {
            home: Some(home.to_path_buf()),
            data_dir: None,
        })
        .source_lookup(source_with_high_id())
        .peer_transfer(StaticPeerTransfer {
            expected_plan_count: 1,
            outcome: PeerDownloadOutcome {
                peer_hashes: Vec::new(),
                parts: vec![DownloadedPart {
                    part_index: 0,
                    offset: 0,
                    bytes: bytes.to_vec(),
                }],
            },
        })
        .build()
}

/// A download of `link` an earlier run started into `output`, when the
/// guards passed its folder, resumed by a [`refused_home_core`] — the guards
/// changed between the runs — and completed: answers the core and why the
/// finished file is withheld. A share of it fails the test.
async fn complete_withheld(
    download_dir: &std::path::Path,
    home: &std::path::Path,
    link: &Ed2kFileLink,
    output: PathBuf,
    bytes: &[u8],
) -> (Core, WithheldReason) {
    let store = rmule_testkit::memory_store();
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let record = repo
        .create_download(link, None, &DownloadPaths::from_final_path(output))
        .unwrap();
    repo.set_lifecycle(record.id(), DownloadLifecycle::Paused)
        .unwrap();
    let mut core = refused_home_core(store, download_dir, home, bytes);
    core.send(CoreCommand::Download(DownloadCommand::ResumeDownload {
        download_id: record.id(),
    }))
    .await
    .unwrap();
    let reason = withheld_on_completion(&mut core, link).await;
    (core, reason)
}

/// Why `link`'s completed file is withheld; a share of it fails the test.
async fn withheld_on_completion(core: &mut Core, link: &Ed2kFileLink) -> WithheldReason {
    loop {
        let event = timeout(HANG_GUARD, core.next_event())
            .await
            .expect("core emitted next event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Serve(ServeEvent::FileShared { file_hash })
                if file_hash == link.file_hash =>
            {
                panic!("a download completed into a refused download directory was shared")
            }
            CoreEvent::Serve(ServeEvent::FileWithheld {
                file_hash, reason, ..
            }) if file_hash == link.file_hash => return reason,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    }
}

/// A download that completes into a download directory the guards refuse
/// (ADR-0101) — one an earlier run started there, since a start into a
/// refused directory is refused — is recorded, withheld as refused, and never
/// offered: the mark every offer reads — the serve snapshot, the Kad
/// publisher, the File History — holds it from the moment its row is written.
#[tokio::test]
async fn a_download_completing_into_a_refused_download_directory_is_withheld_never_shared() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let home = std::fs::canonicalize(tmp.path()).expect("canonical home");
    let bytes = b"finished in the home".to_vec();
    let link = file_link_without_part_hash_set("home.bin", &bytes);

    let (mut core, reason) =
        complete_withheld(&home, &home, &link, home.join("home.bin"), &bytes).await;
    assert_eq!(reason, WithheldReason::Refused);

    core.send(CoreCommand::DumpFileHistory).await.unwrap();
    let history = loop {
        let event = timeout(HANG_GUARD, core.next_event())
            .await
            .expect("core answered the history")
            .expect("core event stream stayed open");
        if let CoreEvent::FileHistory { history } = event {
            break history;
        }
    };
    let fact = history
        .shared
        .iter()
        .find(|fact| fact.identity.file_hash == link.file_hash)
        .expect("the completed file is recorded in the registry");
    assert_eq!(
        fact.withheld.map(|held| held.reason),
        Some(WithheldReason::Refused),
        "recorded, but withheld: never offered"
    );
    core.shutdown().await;
}

/// The refusal is judged where a path leads, not how it is spelt: a
/// download whose output reaches the refused download directory through a
/// link, or completes into it by its real path while the directory is named
/// through a link, is withheld all the same.
#[cfg(unix)]
#[tokio::test]
async fn a_download_completing_into_a_refused_directory_by_another_spelling_is_withheld() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let root = std::fs::canonicalize(tmp.path()).expect("canonical root");
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let alias = root.join("alias");
    std::os::unix::fs::symlink(&home, &alias).unwrap();

    for (download_dir, output) in [
        (&home, alias.join("through-the-link.bin")),
        (&alias, home.join("by-the-real-path.bin")),
    ] {
        let bytes = output.to_str().unwrap().as_bytes().to_vec();
        let name = output.file_name().unwrap().to_str().unwrap();
        let link = file_link_without_part_hash_set(name, &bytes);
        let (core, reason) =
            complete_withheld(download_dir, &home, &link, output.clone(), &bytes).await;
        assert_eq!(reason, WithheldReason::Refused, "{}", output.display());
        core.shutdown().await;
    }
}

/// The Registry Check leaves a row withheld as refused alone, so the lift
/// is the actor's to say: once the download directory moves off the refused
/// one, the file finished there lies under no refused entry and is offered
/// at once, not at the next start.
#[tokio::test]
async fn a_refused_completed_download_is_offered_once_the_download_directory_moves_away() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let root = std::fs::canonicalize(tmp.path()).expect("canonical root");
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let bytes = b"finished before the move".to_vec();
    let link = file_link_without_part_hash_set("moved.bin", &bytes);
    let (mut core, _) =
        complete_withheld(&home, &home, &link, home.join("moved.bin"), &bytes).await;

    core.settings()
        .set(rmule_core::Setting::DownloadDir {
            dir: root.join("downloads"),
            share_confirmed: true,
        })
        .expect("a passing download directory is set");
    timeout(HANG_GUARD, async {
        loop {
            if let CoreEvent::Serve(ServeEvent::FileOffered { file_hash }) =
                core.next_event().await.expect("stream open")
                && file_hash == link.file_hash
            {
                return;
            }
        }
    })
    .await
    .expect("offered once the refusal lifted, well before a recheck");
    core.shutdown().await;
}
