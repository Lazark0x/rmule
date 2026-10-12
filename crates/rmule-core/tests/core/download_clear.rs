//! Clearing a completed download (ADR-0094, "Clearing a completed download"):
//! the download's record goes, the file it finished stays — on disk and
//! in the Shared File Registry — and a download that has not completed cannot
//! be cleared.

use std::sync::Arc;

use rmule_core::{
    Core, CoreCommand, CoreCommandRejectReason, CoreConfig, CoreError, CoreEvent, DownloadCommand,
    DownloadEvent, DownloadId, DownloadRepository, DownloadedPart, DurableDownloadRepository,
    DurableSharedFileRegistry, PeerDownloadOutcome, ServeEvent, SharedFileRegistry,
    open_durable_store,
};
use rmule_primitives::{Ed2kFileLink, ServerEndpoint};
use rmule_testkit::{
    PendingPeerTransfer, StaticPeerTransfer, file_link_without_part_hash_set, source_with_high_id,
};

use crate::fixture::next_expected;

async fn start(core: &mut Core, file: Ed2kFileLink, name: &str) -> DownloadId {
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_testkit::file_name(name),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();
    match next_expected(core, "the download queued", |event| {
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

async fn clear(core: &mut Core, command: DownloadCommand) -> CoreEvent {
    core.send(CoreCommand::Download(command)).await.unwrap();
    next_expected(core, "the clear's answer", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadCleared { .. })
                | CoreEvent::CommandRejected { .. }
        )
    })
    .await
}

#[tokio::test]
async fn a_cleared_download_leaves_its_file_on_disk_and_in_the_registry() {
    let bytes = b"cleared but kept".to_vec();
    let link = file_link_without_part_hash_set("kept.bin", &bytes);
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let output = dir.path().join("kept.bin");
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
    let id = start(&mut core, link.clone(), "kept.bin").await;
    next_expected(&mut core, "the completed download shared", |event| {
        matches!(event, CoreEvent::Serve(ServeEvent::FileShared { .. }))
    })
    .await;

    let answer = clear(
        &mut core,
        DownloadCommand::ClearDownload { download_id: id },
    )
    .await;
    assert!(
        matches!(answer, CoreEvent::Download(DownloadEvent::DownloadCleared { download_id }) if download_id == id),
        "{answer:?}"
    );

    let downloads = DurableDownloadRepository::new(Arc::clone(&store));
    assert!(matches!(
        downloads.load_download(id),
        Err(CoreError::UnknownDownload)
    ));
    assert_eq!(std::fs::read(&output).unwrap(), bytes, "the file stays");
    let registry = DurableSharedFileRegistry::new(Arc::clone(&store));
    let entry = registry
        .get(link.file_hash)
        .unwrap()
        .expect("the registry keeps the file, so its mark stays Have");
    assert_eq!(entry.path, output);

    // Gone is gone: a second clear names nothing.
    let answer = clear(
        &mut core,
        DownloadCommand::ClearDownload { download_id: id },
    )
    .await;
    assert!(
        matches!(
            answer,
            CoreEvent::CommandRejected {
                reason: CoreCommandRejectReason::UnknownDownload
            }
        ),
        "{answer:?}"
    );
}

/// A download that has not completed still holds its file's place, so
/// neither clear touches it: the one-row clear is refused, and "clear all"
/// passes it by.
#[tokio::test]
async fn a_download_not_completed_is_never_cleared() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            dir.path(),
        ))
        .source_lookup(source_with_high_id())
        .peer_transfer(PendingPeerTransfer)
        .build();
    let link = file_link_without_part_hash_set("running.bin", b"still running");
    let id = start(&mut core, link, "running.bin").await;

    let answer = clear(
        &mut core,
        DownloadCommand::ClearDownload { download_id: id },
    )
    .await;
    assert!(
        matches!(
            answer,
            CoreEvent::CommandRejected {
                reason: CoreCommandRejectReason::DownloadNotCompleted
            }
        ),
        "{answer:?}"
    );

    core.send(CoreCommand::Download(
        DownloadCommand::ClearCompletedDownloads,
    ))
    .await
    .unwrap();
    // The pause after it is answered in order, so a clear it raced would
    // have been seen first.
    core.send(CoreCommand::Download(DownloadCommand::PauseDownload {
        download_id: id,
    }))
    .await
    .unwrap();
    let answer = next_expected(&mut core, "the pause", |event| {
        matches!(
            event,
            CoreEvent::Download(
                DownloadEvent::DownloadPaused { .. } | DownloadEvent::DownloadCleared { .. }
            )
        )
    })
    .await;
    assert!(
        matches!(
            answer,
            CoreEvent::Download(DownloadEvent::DownloadPaused { .. })
        ),
        "{answer:?}"
    );
    let downloads = DurableDownloadRepository::new(Arc::clone(&store));
    assert!(downloads.load_download(id).is_ok());
}

/// A download completed in an earlier run is listed at attach until it
/// is cleared, so "clear completed" never clears a row the operator was not
/// shown.
#[tokio::test]
async fn a_download_completed_in_an_earlier_run_is_listed_at_attach_until_cleared() {
    let bytes = b"finished last time".to_vec();
    let link = file_link_without_part_hash_set("earlier.bin", &bytes);
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
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
    let id = start(&mut core, link, "earlier.bin").await;
    next_expected(&mut core, "the completed download shared", |event| {
        matches!(event, CoreEvent::Serve(ServeEvent::FileShared { .. }))
    })
    .await;
    core.shutdown().await;
    drop(store);

    let store = open_durable_store(dir.path()).expect("shutdown released the store");
    let mut core = Core::builder(CoreConfig::default(), store)
        .settings(rmule_core::CoreSettings::default())
        .source_lookup(source_with_high_id())
        .peer_transfer(PendingPeerTransfer)
        .build();
    let recovered = next_expected(&mut core, "the completed download listed", |event| {
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
                download_id,
                state: rmule_core::DownloadLifecycle::Completed,
                ..
            }) if download_id == id
        ),
        "{recovered:?}"
    );

    let answer = clear(&mut core, DownloadCommand::ClearCompletedDownloads).await;
    assert!(
        matches!(answer, CoreEvent::Download(DownloadEvent::DownloadCleared { download_id }) if download_id == id),
        "{answer:?}"
    );
    core.shutdown().await;
}
