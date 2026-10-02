//! A download's state across Quit and attach (ADR-0094):
//! what the operator left running runs again with no command from a front
//! end, what they paused stays paused, a download with no run keeps its part
//! picture — held and missing parts, nothing in flight — and a failed one holds
//! its file's place and restarts in place.

use std::sync::Arc;
use std::time::Duration;

use rmule_core::diagnostics::PartState;
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent, DownloadFailure,
    DownloadId, DownloadLifecycle, DownloadPaths, DownloadRepository, DurableDownloadRepository,
    VerifiedPartRecord, open_durable_store,
};
use rmule_primitives::{ED2K_PART_SIZE, Ed2kFileLink, ServerEndpoint};
use rmule_testkit::{PendingPeerTransfer, file_link, two_high_id_sources};

use crate::fixture::{identity, next_expected};

/// A two-part file: one full part and a one-byte tail.
fn two_part_link(name: &str, fill: u8) -> Ed2kFileLink {
    let mut bytes = vec![fill; ED2K_PART_SIZE as usize];
    bytes.push(fill);
    file_link(name, &bytes)
}

async fn start(core: &mut Core, file: Ed2kFileLink, dir: &std::path::Path) -> DownloadId {
    let output_path = dir.join(file.name.to_display_string());
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        credentials: identity().into(),
        output_path,
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

async fn part_assigned(core: &mut Core, id: DownloadId) {
    next_expected(core, "a part assigned", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::PartAssigned { download_id, .. }) if *download_id == id
        )
    })
    .await;
}

async fn pause(core: &mut Core, id: DownloadId) {
    core.send(CoreCommand::Download(DownloadCommand::PauseDownload {
        download_id: id,
    }))
    .await
    .unwrap();
    next_expected(core, "the download paused", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadPaused { download_id }) if *download_id == id
        )
    })
    .await;
}

/// Quit with one running and one paused download, then a new core's attach
/// on the same store — the running one runs again and the paused one stays
/// paused, with no command from a front end.
#[tokio::test]
async fn attach_runs_what_quit_left_running_and_leaves_paused_paused() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .source_lookup(two_high_id_sources())
        .peer_transfer(PendingPeerTransfer)
        .build();
    let running = start(&mut core, two_part_link("running.bin", 0xA1), dir.path()).await;
    part_assigned(&mut core, running).await;
    let paused = start(&mut core, two_part_link("paused.bin", 0xB2), dir.path()).await;
    part_assigned(&mut core, paused).await;
    pause(&mut core, paused).await;
    core.shutdown().await;

    // The next process's attach, on the store the Quit left, opened afresh:
    // once shutdown returns nothing of the old core holds the file lock.
    drop(store);
    let store = open_durable_store(dir.path()).expect("shutdown released the store");
    let mut core = Core::builder(
        CoreConfig {
            download_restore_pace: Duration::from_millis(10),
            ..CoreConfig::default()
        },
        Arc::clone(&store),
    )
    .source_lookup(two_high_id_sources())
    .peer_transfer(PendingPeerTransfer)
    .restore_credentials(crate::fixture::connect_credentials().await)
    .build();

    let mut recovered = Vec::new();
    while recovered.len() < 2 {
        if let CoreEvent::Download(DownloadEvent::DownloadRecovered {
            download_id, state, ..
        }) = next_expected(&mut core, "both downloads recovered", |event| {
            matches!(
                event,
                CoreEvent::Download(DownloadEvent::DownloadRecovered { .. })
            )
        })
        .await
        {
            recovered.push((download_id, state));
        }
    }
    recovered.sort_by_key(|(id, _)| id.as_u64());
    let mut expected = vec![
        (running, DownloadLifecycle::Active),
        (paused, DownloadLifecycle::Paused),
    ];
    expected.sort_by_key(|(id, _)| id.as_u64());
    assert_eq!(recovered, expected);

    // The running one resumes and works without anyone asking…
    let resumed = next_expected(&mut core, "a download resumed", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadResumed { .. })
        )
    })
    .await;
    assert!(
        matches!(resumed, CoreEvent::Download(DownloadEvent::DownloadResumed { download_id }) if download_id == running),
        "only the running download resumes, saw {resumed:?}",
    );
    part_assigned(&mut core, running).await;

    // …and nothing ever starts the paused one.
    let late = tokio::time::timeout(Duration::from_millis(200), async {
        loop {
            if let Some(CoreEvent::Download(DownloadEvent::DownloadResumed { download_id })) =
                core.next_event().await
            {
                return download_id;
            }
        }
    })
    .await;
    assert!(late.is_err(), "a second download resumed: {late:?}");
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    assert_eq!(
        repo.load_download(running).unwrap().lifecycle(),
        DownloadLifecycle::Active
    );
    assert_eq!(
        repo.load_download(paused).unwrap().lifecycle(),
        DownloadLifecycle::Paused
    );
}

/// A paused download's diagnostics keep its part picture — every part
/// it has, none in flight — rather than losing the row with the run.
#[tokio::test]
async fn a_paused_download_keeps_its_part_picture_with_nothing_in_flight() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .source_lookup(two_high_id_sources())
        .peer_transfer(PendingPeerTransfer)
        .build();
    let id = start(&mut core, two_part_link("paused.bin", 0xC3), dir.path()).await;
    part_assigned(&mut core, id).await;
    pause(&mut core, id).await;

    let snapshot = core.diagnostics_snapshot();
    let row = snapshot
        .downloads
        .get(&id)
        .expect("the paused download keeps its row");
    assert_eq!(row.parts, vec![PartState::Missing, PartState::Missing]);
    assert!(row.workers.is_empty());
}

/// Attach restores a paused download's part picture from the durable
/// verified parts, before any run exists.
#[tokio::test]
async fn attach_restores_a_paused_downloads_part_picture() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let link = two_part_link("held.bin", 0xD4);
    let hash = link.part_hash_set.as_ref().unwrap().hashes()[0];
    let record = repo
        .create_download(
            &link,
            Some(&ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
            &DownloadPaths::from_final_path(dir.path().join("held.bin")),
        )
        .unwrap();
    repo.set_lifecycle(record.id(), DownloadLifecycle::Paused)
        .unwrap();
    repo.record_verified_part(
        record.id(),
        VerifiedPartRecord {
            part_index: 0,
            offset: 0,
            len: ED2K_PART_SIZE,
            part_hash: hash,
        },
    )
    .unwrap();

    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .source_lookup(two_high_id_sources())
        .peer_transfer(PendingPeerTransfer)
        .restore_credentials(crate::fixture::connect_credentials().await)
        .build();
    next_expected(&mut core, "the download recovered", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadRecovered { .. })
        )
    })
    .await;

    let snapshot = core.diagnostics_snapshot();
    let row = snapshot
        .downloads
        .get(&record.id())
        .expect("a restored download has a row at rest");
    assert_eq!(row.parts, vec![PartState::Verified, PartState::Missing]);
    assert!(row.workers.is_empty());
}

/// A failed download holds its file's place — a second start of the
/// file is refused — and a resume restarts that same row, which runs again
/// without a new download id.
#[tokio::test]
async fn a_failed_download_holds_its_place_and_restarts_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let link = two_part_link("failed.bin", 0xE5);
    let record = repo
        .create_download(
            &link,
            Some(&ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
            &DownloadPaths::from_final_path(dir.path().join("failed.bin")),
        )
        .unwrap();
    repo.set_lifecycle(record.id(), DownloadLifecycle::Failed)
        .unwrap();
    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .source_lookup(two_high_id_sources())
        .peer_transfer(PendingPeerTransfer)
        .restore_credentials(crate::fixture::connect_credentials().await)
        .build();

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: link,
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        credentials: identity().into(),
        output_path: dir.path().join("failed (1).bin"),
    }))
    .await
    .unwrap();
    next_expected(&mut core, "the second start refused", |event| {
        matches!(
            event,
            CoreEvent::CommandRejected {
                reason: rmule_core::CoreCommandRejectReason::DuplicateDownload
            }
        )
    })
    .await;

    core.send(CoreCommand::Download(DownloadCommand::ResumeDownload {
        download_id: record.id(),
        credentials: identity().into(),
    }))
    .await
    .unwrap();
    part_assigned(&mut core, record.id()).await;
    assert_eq!(
        repo.load_download(record.id()).unwrap().lifecycle(),
        DownloadLifecycle::Active
    );
}

/// A failed download keeps why across a restart (ADR-0094, "Failed"): the run
/// fails with no usable source, the process ends, and the next attach reports
/// the row failed with its reason — which a resume then clears.
#[tokio::test]
async fn a_failed_downloads_reason_survives_the_restart() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let sourceless = || rmule_testkit::StaticSourceLookup {
        outcome: rmule_core::SourceLookupOutcome {
            client_id: rmule_primitives::ClientId::from_u32(0x0100_007F),
            sources: Vec::new(),
        },
    };
    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .source_lookup(sourceless())
        .peer_transfer(PendingPeerTransfer)
        .build();
    let id = start(&mut core, two_part_link("lonely.bin", 0xC3), dir.path()).await;
    next_expected(&mut core, "the run failed", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadFailed {
                reason: DownloadFailure::NoUsableSources,
                ..
            })
        )
    })
    .await;
    core.shutdown().await;

    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .source_lookup(sourceless())
        .peer_transfer(PendingPeerTransfer)
        .build();
    let recovered = next_expected(&mut core, "the failed row recovered", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadRecovered { .. })
        )
    })
    .await;
    assert!(
        matches!(
            &recovered,
            CoreEvent::Download(DownloadEvent::DownloadRecovered {
                download_id,
                state: DownloadLifecycle::Failed,
                failure: Some(DownloadFailure::NoUsableSources),
                ..
            }) if *download_id == id
        ),
        "{recovered:?}"
    );

    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    repo.set_lifecycle(id, DownloadLifecycle::Active).unwrap();
    assert_eq!(repo.load_download(id).unwrap().failure(), None);
}

/// A download attach found running that cannot be started is not left to
/// look like it runs: the store refuses its Active mark, and the refusal is
/// told as the download's failure, by its cause.
#[tokio::test]
async fn a_download_attach_cannot_start_is_told_as_failed() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let link = two_part_link("stuck.bin", 0x3E);
    let id = repo
        .create_download(
            &link,
            Some(&ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
            &DownloadPaths::from_final_path(dir.path().join("stuck.bin")),
        )
        .unwrap()
        .id();
    repo.set_lifecycle(id, DownloadLifecycle::Active).unwrap();

    let mut core = Core::builder(
        CoreConfig {
            download_restore_pace: Duration::from_millis(300),
            ..CoreConfig::default()
        },
        Arc::clone(&store),
    )
    .peer_transfer(PendingPeerTransfer)
    .restore_credentials(crate::fixture::connect_credentials().await)
    .build();
    next_expected(&mut core, "the download recovered as running", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadRecovered {
                state: DownloadLifecycle::Active,
                ..
            })
        )
    })
    .await;
    // Between attach and its start, the row leaves every lifecycle a run
    // may take up, so the store refuses the start's Active mark.
    repo.set_lifecycle(id, DownloadLifecycle::Cancelled)
        .unwrap();

    let told = next_expected(&mut core, "the start's refusal told", |event| {
        matches!(
            event,
            CoreEvent::Download(
                DownloadEvent::DownloadFailed { .. } | DownloadEvent::DownloadResumed { .. }
            )
        )
    })
    .await;
    assert!(
        matches!(
            told,
            CoreEvent::Download(DownloadEvent::DownloadFailed {
                download_id,
                reason: DownloadFailure::StoreFailed,
            }) if download_id == id
        ),
        "{told:?}"
    );
}
