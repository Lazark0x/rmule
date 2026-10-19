//! Picking a download back up from durable state: a resume asks only for the
//! parts the repository has not already recorded verified, a fresh process
//! recovers that same progress — as `Paused`, before any source lookup runs —
//! and the finished download promotes its `.part` file to `final_path`.

use rmule_core::DownloadRepository;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use crate::fixture::next_matching;
use rmule_core::{
    ContentFileStore, Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent,
    DownloadFailure, DownloadLifecycle, DownloadPaths, DownloadedPart, DurableDownloadRepository,
    PeerDownloadOutcome, SourceLookupOutcome, SourceLookupService, VerifiedPartRecord,
    open_durable_store,
};
use rmule_primitives::{
    ClientId, ED2K_PART_SIZE, Informant, PeerSource, ServerEndpoint, SourceLookupTarget,
    SourceSighting,
};
use rmule_testkit::{
    PendingPeerTransfer, PlanAssertingPeerTransfer, StaticPeerTransfer, file_link,
    file_link_without_part_hash_set, next_event, source_with_high_id,
};

#[tokio::test]
async fn resume_skips_verified_parts() {
    let mut bytes = vec![0xAB; ED2K_PART_SIZE as usize];
    bytes.extend_from_slice(b"tail");
    let link = file_link("example.bin", &bytes);
    let hashes = link.part_hash_set.as_ref().unwrap().hashes().to_vec();
    let first = bytes[..ED2K_PART_SIZE as usize].to_vec();
    let second = bytes[ED2K_PART_SIZE as usize..].to_vec();
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let output_path = dir.path().join("download.bin");
    let paths = DownloadPaths::from_final_path(output_path);
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let record = repo
        .create_download(
            &link,
            Some(&ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
            &paths,
            None,
        )
        .unwrap();
    repo.record_verified_part(
        record.id(),
        VerifiedPartRecord {
            part_index: 0,
            offset: 0,
            len: first.len() as u64,
            part_hash: hashes[0],
        },
    )
    .unwrap();
    repo.set_lifecycle(record.id(), DownloadLifecycle::Paused)
        .unwrap();
    ContentFileStore::write_verified_part(&paths, 0, &first)
        .await
        .unwrap();

    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .settings(rmule_core::CoreSettings::default())
        .source_lookup(source_with_high_id())
        .peer_transfer(PlanAssertingPeerTransfer {
            expected_plan_indexes: vec![1],
            outcome: PeerDownloadOutcome {
                peer_hashes: hashes,
                parts: vec![DownloadedPart {
                    part_index: 1,
                    offset: ED2K_PART_SIZE,
                    bytes: second,
                }],
            },
        })
        .build();
    core.send(CoreCommand::Download(DownloadCommand::ResumeDownload {
        download_id: record.id(),
    }))
    .await
    .unwrap();

    let mut events = Vec::new();
    loop {
        let event = next_event(&mut core).await;
        let terminal = matches!(
            event,
            CoreEvent::Download(
                DownloadEvent::DownloadCompleted { .. } | DownloadEvent::DownloadFailed { .. }
            )
        );
        events.push(event);
        if terminal {
            break;
        }
    }

    assert!(events.iter().any(|event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadProgressRestored {
                verified_parts: 1,
                verified_bytes: ED2K_PART_SIZE,
                ..
            })
        )
    }));
    assert!(events.iter().any(|event| matches!(
        event,
        CoreEvent::Download(DownloadEvent::PartVerified { part_index: 1, .. })
    )));
}

#[tokio::test]
async fn completes_to_final_path() {
    let bytes = b"durable complete".to_vec();
    let link = file_link_without_part_hash_set("example.bin", &bytes);
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let output_path = dir.path().join("download.bin");
    let paths = DownloadPaths::from_final_path(output_path.clone());
    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            dir.path(),
        ))
        .source_lookup(source_with_high_id())
        .peer_transfer(StaticPeerTransfer {
            expected_plan_count: 1,
            outcome: PeerDownloadOutcome {
                peer_hashes: Vec::new(),
                parts: vec![DownloadedPart {
                    part_index: 0,
                    offset: 0,
                    bytes: bytes.clone(),
                }],
            },
        })
        .build();

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: link,
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_testkit::file_name("download.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
        kad_aich_root: None,
    }))
    .await
    .unwrap();

    let mut download_id = None;
    loop {
        let event = next_event(&mut core).await;
        match event {
            CoreEvent::Download(DownloadEvent::DownloadQueued {
                download_id: id, ..
            }) => download_id = Some(id),
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    }

    let download_id = download_id.unwrap();
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    assert_eq!(
        repo.load_download(download_id).unwrap().lifecycle(),
        DownloadLifecycle::Completed
    );
    assert_eq!(repo.verified_parts(download_id).unwrap().len(), 1);
    assert_eq!(std::fs::read(&output_path).unwrap(), bytes);
    assert!(!paths.part_path().exists());
}

#[tokio::test]
async fn restart_resume_completes_from_verified_parts() {
    let mut bytes = vec![0xAB; rmule_primitives::ED2K_PART_SIZE as usize];
    bytes.extend_from_slice(b"tail");
    let file = file_link("loopback.bin", &bytes);
    let hashes = file.part_hash_set.as_ref().unwrap().hashes().to_vec();
    let first = bytes[..rmule_primitives::ED2K_PART_SIZE as usize].to_vec();
    let second = bytes[rmule_primitives::ED2K_PART_SIZE as usize..].to_vec();
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let output_path = dir.path().join("restart.bin");
    let paths = DownloadPaths::from_final_path(output_path.clone());
    let lookup_calls = Arc::new(StdMutex::new(Vec::new()));

    let mut first_core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            dir.path(),
        ))
        .source_lookup(RecordingSourceLookup::new(Arc::clone(&lookup_calls)))
        .peer_transfer(PendingPeerTransfer)
        .build();
    first_core
        .send(CoreCommand::Download(DownloadCommand::StartDownload {
            file: file.clone(),
            source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
            name: rmule_testkit::file_name("restart.bin"),
            if_taken: rmule_core::NameTaken::Refuse,
            kad_aich_root: None,
        }))
        .await
        .unwrap();
    let download_id = next_queued_id(&mut first_core).await;
    let _ = next_matching(&mut first_core, |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::PeerSelected { .. })
        )
    })
    .await;

    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    repo.record_verified_part(
        download_id,
        VerifiedPartRecord {
            part_index: 0,
            offset: 0,
            len: first.len() as u64,
            part_hash: hashes[0],
        },
    )
    .unwrap();
    ContentFileStore::write_verified_part(&paths, 0, &first)
        .await
        .unwrap();
    drop(first_core);

    lookup_calls.lock().unwrap().clear();
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    assert_eq!(
        repo.load_download(download_id).unwrap().lifecycle(),
        DownloadLifecycle::Active
    );
    let mut restarted = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .settings(rmule_core::CoreSettings::default())
        .source_lookup(RecordingSourceLookup::new(Arc::clone(&lookup_calls)))
        .peer_transfer(PlanAssertingPeerTransfer {
            expected_plan_indexes: vec![1],
            outcome: PeerDownloadOutcome {
                peer_hashes: hashes,
                parts: vec![DownloadedPart {
                    part_index: 1,
                    offset: rmule_primitives::ED2K_PART_SIZE,
                    bytes: second,
                }],
            },
        })
        .build();

    let recovered = next_matching(&mut restarted, |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadRecovered { .. })
        )
    })
    .await;
    assert!(
        matches!(
            recovered,
            CoreEvent::Download(DownloadEvent::DownloadRecovered {
                download_id: id,
                state: DownloadLifecycle::Active,
                ..
            }) if id == download_id,
        ),
        "expected DownloadRecovered(Active) for {download_id:?} but saw {recovered:?}",
    );
    let restored = next_matching(&mut restarted, |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadProgressRestored { .. })
        )
    })
    .await;
    let expected_bytes = rmule_primitives::ED2K_PART_SIZE;
    assert!(
        matches!(
            restored,
            CoreEvent::Download(DownloadEvent::DownloadProgressRestored {
                download_id: id,
                verified_parts: 1,
                verified_bytes,
            }) if id == download_id && verified_bytes == expected_bytes,
        ),
        "expected DownloadProgressRestored(verified_parts=1, verified_bytes={expected_bytes}) but saw {restored:?}",
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(lookup_calls.lock().unwrap().is_empty());

    restarted
        .send(CoreCommand::Download(DownloadCommand::ResumeDownload {
            download_id,
        }))
        .await
        .unwrap();
    loop {
        let event = next_matching(&mut restarted, |_| true).await;
        match event {
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("resume failed: {reason:?}")
            }
            _ => {}
        }
    }

    assert_eq!(std::fs::read(&output_path).unwrap(), bytes);
    assert!(!paths.part_path().exists());
}

/// Records every lookup so the restart scenario can assert the
/// *absence* of one: recovery must not re-ask a server before a resume asks.
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
            sources: vec![SourceSighting::plain(
                PeerSource::new(ClientId::from_u32(0x0100_007F), 4663),
                Informant::Own,
            )],
        })
    }
}

async fn next_queued_id(core: &mut Core) -> rmule_core::DownloadId {
    match next_matching(core, |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadQueued { .. })
        )
    })
    .await
    {
        CoreEvent::Download(DownloadEvent::DownloadQueued { download_id, .. }) => download_id,
        _ => unreachable!("matcher only returns queued events"),
    }
}
