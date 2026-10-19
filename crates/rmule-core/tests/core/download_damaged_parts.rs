//! A resume that finds its verified parts damaged on disk (ADR-0093, "Damaged
//! parts"): the parts that no longer hold are dropped and fetched again
//! and the download runs; it fails only when nothing recorded can be trusted,
//! and then its failure names the check, the part, and what was expected and
//! found. The operator's Restart of a failed download (ADR-0094, "Restart")
//! says which it did: continued from what holds, or — with nothing on disk to
//! continue from — started over.

use std::sync::Arc;

use rmule_core::diagnostics::PartState;
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent, DownloadFailure,
    DownloadId, DownloadLifecycle, DownloadPaths, DownloadRepository, DurableDownloadRepository,
    PartFault, RestartOutcome, StorageIntegrityFault, VerifiedPartRecord, open_durable_store,
};
use rmule_primitives::{ED2K_PART_SIZE, Ed2kFileLink, ServerEndpoint};
use rmule_testkit::{PendingPeerTransfer, file_link, two_high_id_sources};

use crate::fixture::next_expected;

const PART: usize = ED2K_PART_SIZE as usize;

/// A three-part file: two full parts and a one-byte tail, every byte `fill`.
fn three_part_link(fill: u8) -> (Ed2kFileLink, Vec<u8>) {
    let mut bytes = vec![fill; 2 * PART];
    bytes.push(fill);
    (file_link("damaged.bin", &bytes), bytes)
}

/// A row at rest in `lifecycle` — a failed one as store version 7 leaves one
/// that failed before the fault was kept (no reason) — with all three parts
/// recorded verified.
fn row_with_three_verified(
    repo: &DurableDownloadRepository,
    link: &Ed2kFileLink,
    paths: &DownloadPaths,
    lifecycle: DownloadLifecycle,
) -> DownloadId {
    let hashes = link.part_hash_set.as_ref().unwrap().hashes().to_vec();
    let id = repo
        .create_download(
            link,
            Some(&ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
            paths,
            None,
        )
        .unwrap()
        .id();
    for (index, len) in [(0u32, ED2K_PART_SIZE), (1, ED2K_PART_SIZE), (2, 1)] {
        repo.record_verified_part(
            id,
            VerifiedPartRecord {
                part_index: index,
                offset: u64::from(index) * ED2K_PART_SIZE,
                len,
                part_hash: hashes[index as usize],
            },
        )
        .unwrap();
    }
    if lifecycle == DownloadLifecycle::Failed {
        repo.set_lifecycle(id, lifecycle).unwrap();
    } else {
        repo.set_lifecycle(id, DownloadLifecycle::Active).unwrap();
        repo.set_lifecycle(id, lifecycle).unwrap();
    }
    id
}

fn core_on(store: &Arc<rmule_core::DurableStore>) -> Core {
    Core::builder(CoreConfig::default(), Arc::clone(store))
        .settings(rmule_core::CoreSettings::default())
        .source_lookup(two_high_id_sources())
        .peer_transfer(PendingPeerTransfer)
        .build()
}

async fn resume(core: &mut Core, id: DownloadId) {
    core.send(CoreCommand::Download(DownloadCommand::ResumeDownload {
        download_id: id,
    }))
    .await
    .unwrap();
}

/// The part file was removed under a run and recreated by its
/// next write, so it is shorter than the file, the first recorded part reads
/// back as zeros and the tail lies past its end — while the second part
/// holds. The Restart continues: the two damaged parts are dropped, the one
/// that holds is kept, and the download runs.
#[tokio::test]
async fn a_restart_continues_from_the_parts_that_hold_and_drops_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let (link, bytes) = three_part_link(0x6D);
    let hashes = link.part_hash_set.as_ref().unwrap().hashes().to_vec();
    let paths = DownloadPaths::from_final_path(dir.path().join("damaged.bin"));
    let id = row_with_three_verified(&repo, &link, &paths, DownloadLifecycle::Failed);
    // Only the second part survives: a hole where the first was, no tail.
    let mut on_disk = vec![0u8; 2 * PART];
    on_disk[PART..].copy_from_slice(&bytes[PART..2 * PART]);
    std::fs::write(paths.part_path(), &on_disk).unwrap();

    let mut core = core_on(&store);
    resume(&mut core, id).await;

    let dropped = next_expected(&mut core, "the damaged parts dropped", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DamagedPartsDropped { .. })
                | CoreEvent::Download(DownloadEvent::DownloadFailed { .. })
        )
    })
    .await;
    let CoreEvent::Download(DownloadEvent::DamagedPartsDropped { damaged, .. }) = dropped else {
        panic!("the resume failed instead of repairing: {dropped:?}");
    };
    assert!(
        matches!(
            damaged.as_slice(),
            [
                PartFault::HashMismatch { part_index: 0, expected, found },
                PartFault::Short { part_index: 2, expected_end, found_len },
            ] if *expected == hashes[0]
                && found != expected
                && *expected_end == 2 * ED2K_PART_SIZE + 1
                && *found_len == 2 * ED2K_PART_SIZE
        ),
        "{damaged:?}"
    );
    next_expected(&mut core, "one part restored", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadProgressRestored {
                verified_parts: 1,
                verified_bytes,
                ..
            }) if *verified_bytes == ED2K_PART_SIZE
        )
    })
    .await;
    next_expected(&mut core, "the restart continued", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadRestarted {
                download_id,
                outcome: RestartOutcome::Continued {
                    kept_parts: 1,
                    kept_bytes,
                    dropped_parts: 2,
                    dropped_bytes,
                },
            }) if *download_id == id
                && *kept_bytes == ED2K_PART_SIZE
                && *dropped_bytes == ED2K_PART_SIZE + 1
        )
    })
    .await;
    next_expected(&mut core, "a part assigned", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::PartAssigned { download_id, .. }) if *download_id == id
        )
    })
    .await;

    let held: Vec<u32> = repo
        .verified_parts(id)
        .unwrap()
        .iter()
        .map(|part| part.part_index)
        .collect();
    assert_eq!(held, vec![1]);
    assert_eq!(
        repo.load_download(id).unwrap().lifecycle(),
        DownloadLifecycle::Active
    );
    let snapshot = core.diagnostics_snapshot();
    let row = snapshot
        .downloads
        .get(&id)
        .expect("the running download's row");
    assert_eq!(row.parts[1], PartState::Verified);
    assert_ne!(row.parts[0], PartState::Verified);
    assert_ne!(row.parts[2], PartState::Verified);
}

/// Resume and wait for the one failure it ends in.
async fn resume_fails(store: &Arc<rmule_core::DurableStore>, id: DownloadId) -> DownloadFailure {
    let mut core = core_on(store);
    resume(&mut core, id).await;
    let failed = next_expected(&mut core, "the resume failed", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadFailed { .. })
        )
    })
    .await;
    core.shutdown().await;
    match failed {
        CoreEvent::Download(DownloadEvent::DownloadFailed {
            download_id,
            reason,
        }) => {
            assert_eq!(download_id, id);
            reason
        }
        _ => unreachable!("matcher only returns failures"),
    }
}

/// With nothing recorded left to trust, a resume of a download that has not
/// failed — a paused one, or attach's restore — fails, the failure names the
/// check and what it found, and the store keeps that detail.
#[tokio::test]
async fn a_part_file_that_backs_nothing_fails_a_resume_with_its_fault() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let (link, _) = three_part_link(0x2B);
    let hashes = link.part_hash_set.as_ref().unwrap().hashes().to_vec();
    let paths = DownloadPaths::from_final_path(dir.path().join("damaged.bin"));

    // No part file at all.
    let id = row_with_three_verified(&repo, &link, &paths, DownloadLifecycle::Paused);
    let missing = DownloadFailure::StorageIntegrityFailed(StorageIntegrityFault::PartFileMissing);
    assert_eq!(resume_fails(&store, id).await, missing);
    assert_eq!(repo.load_download(id).unwrap().failure(), Some(&missing));

    // A part file of zeros, long enough for every part: none holds.
    let other = DownloadPaths::from_final_path(dir.path().join("zeros.bin"));
    let id = row_with_three_verified(
        &repo,
        &three_part_link(0x2C).0,
        &other,
        DownloadLifecycle::Paused,
    );
    let hashes_other = three_part_link(0x2C)
        .0
        .part_hash_set
        .unwrap()
        .hashes()
        .to_vec();
    std::fs::write(other.part_path(), vec![0u8; 2 * PART + 1]).unwrap();
    let reason = resume_fails(&store, id).await;
    assert!(
        matches!(
            &reason,
            DownloadFailure::StorageIntegrityFailed(StorageIntegrityFault::NoPartHolds {
                recorded: 3,
                first: PartFault::HashMismatch { part_index: 0, expected, .. },
            }) if *expected == hashes_other[0]
        ),
        "{reason:?}"
    );
    assert_ne!(hashes_other[0], hashes[0]);
    assert_eq!(repo.verified_parts(id).unwrap().len(), 3);
    assert_eq!(repo.load_download(id).unwrap().failure(), Some(&reason));
}

/// Restart a failed download and wait for what it did.
async fn restart(store: &Arc<rmule_core::DurableStore>, id: DownloadId) -> (Core, RestartOutcome) {
    let mut core = core_on(store);
    resume(&mut core, id).await;
    let restarted = next_expected(&mut core, "the restart", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadRestarted { .. })
                | CoreEvent::Download(DownloadEvent::DownloadFailed { .. })
        )
    })
    .await;
    let CoreEvent::Download(DownloadEvent::DownloadRestarted {
        download_id,
        outcome,
    }) = restarted
    else {
        panic!("the restart failed again: {restarted:?}");
    };
    assert_eq!(download_id, id);
    (core, outcome)
}

/// A Restart with nothing on disk to continue from — the part file gone, or
/// none of what it recorded matching — starts over in the download's place:
/// what was recorded is discarded and said, the old part file is removed, and
/// a fresh run holds a new, empty one.
#[tokio::test]
async fn a_restart_with_nothing_on_disk_to_continue_from_starts_over() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let recorded_bytes = 2 * ED2K_PART_SIZE + 1;

    // The part file is gone.
    let (link, _) = three_part_link(0x3C);
    let gone = DownloadPaths::from_final_path(dir.path().join("gone.bin"));
    let id = row_with_three_verified(&repo, &link, &gone, DownloadLifecycle::Failed);
    let (core, outcome) = restart(&store, id).await;
    core.shutdown().await;
    assert_eq!(
        outcome,
        RestartOutcome::StartedOver {
            fault: StorageIntegrityFault::PartFileMissing,
            dropped_parts: 3,
            dropped_bytes: recorded_bytes,
        }
    );

    // No recorded part matches the part file.
    let (link, _) = three_part_link(0x3D);
    let zeros = DownloadPaths::from_final_path(dir.path().join("zeros.bin"));
    let id = row_with_three_verified(&repo, &link, &zeros, DownloadLifecycle::Failed);
    std::fs::write(zeros.part_path(), vec![0u8; 2 * PART + 1]).unwrap();
    let (mut core, outcome) = restart(&store, id).await;
    assert!(
        matches!(
            outcome,
            RestartOutcome::StartedOver {
                fault: StorageIntegrityFault::NoPartHolds { recorded: 3, .. },
                dropped_parts: 3,
                dropped_bytes,
            } if dropped_bytes == recorded_bytes
        ),
        "{outcome:?}"
    );
    next_expected(&mut core, "a fresh run", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::PartAssigned { download_id, .. }) if *download_id == id
        )
    })
    .await;
    let record = repo.load_download(id).unwrap();
    assert_eq!(record.lifecycle(), DownloadLifecycle::Active);
    assert!(record.failure().is_none(), "the old reason is gone");
    assert_eq!(record.paths(), &zeros, "the same place");
    assert!(repo.verified_parts(id).unwrap().is_empty());
    assert_eq!(
        std::fs::metadata(zeros.part_path()).unwrap().len(),
        0,
        "the old part file is removed; the new run holds a fresh one"
    );
}
