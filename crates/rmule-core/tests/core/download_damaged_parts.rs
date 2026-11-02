//! A resume that finds its verified parts damaged on disk (ADR-0094, "Damaged parts"): the parts
//! that no longer hold are dropped and fetched again
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
use rmule_primitives::{ED2K_PART_SIZE, Ed2kFileLink, Ed2kLink, ServerEndpoint};
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

/// A moved part file is not a lost one: while a file of its name stands in
/// the current Temp Directory, Restart refuses rather than throw it away.
#[tokio::test]
async fn a_restart_refuses_to_start_over_a_file_that_stands_in_temp() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(&dir.path().join("data")).unwrap();
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let (link, _) = three_part_link(0x3E);
    let paths = DownloadPaths::from_final_path(dir.path().join("away/moved.bin"));
    let id = row_with_three_verified(&repo, &link, &paths, DownloadLifecycle::Failed);
    let temp = dir.path().join("Temp");
    std::fs::create_dir(&temp).unwrap();
    let moved = temp.join(paths.part_path().file_name().unwrap());
    std::fs::write(&moved, b"what it held").unwrap();

    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .settings(rmule_core::CoreSettings {
            temp_dir: Some(temp),
            ..rmule_core::CoreSettings::default()
        })
        .source_lookup(two_high_id_sources())
        .peer_transfer(PendingPeerTransfer)
        .build();
    resume(&mut core, id).await;
    let refused = next_expected(&mut core, "the refusal", |event| {
        matches!(event, CoreEvent::CommandRejected { .. })
    })
    .await;
    core.shutdown().await;
    assert!(
        matches!(
            refused,
            CoreEvent::CommandRejected {
                reason: rmule_core::CoreCommandRejectReason::PartFileMoved
            }
        ),
        "{refused:?}"
    );
    assert_eq!(repo.verified_parts(id).unwrap().len(), 3);
    assert_eq!(std::fs::read(&moved).unwrap(), b"what it held");
}

/// A delete the system refused is told, and the row says Cancelled with the
/// path still held, so the next attach finishes the job.
#[cfg(unix)]
#[tokio::test]
async fn a_cancel_stores_first_tells_a_refused_delete_and_attach_tries_again() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(&dir.path().join("data")).unwrap();
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let (link, bytes) = three_part_link(0x3F);
    let locked = dir.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    let paths = DownloadPaths::from_final_path(locked.join("held.bin"));
    let id = row_with_three_verified(&repo, &link, &paths, DownloadLifecycle::Paused);
    std::fs::write(paths.part_path(), &bytes).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();

    let mut core = core_on(&store);
    core.send(CoreCommand::Download(DownloadCommand::CancelDownload {
        download_id: id,
    }))
    .await
    .unwrap();
    let left = next_expected(&mut core, "the refused delete", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::CancelledFileLeft { .. })
        )
    })
    .await;
    core.shutdown().await;
    assert!(
        matches!(
            &left,
            CoreEvent::Download(DownloadEvent::CancelledFileLeft { download_id, part_path })
                if *download_id == id && part_path == paths.part_path()
        ),
        "{left:?}"
    );
    assert_eq!(
        repo.load_download(id).unwrap().lifecycle(),
        DownloadLifecycle::Cancelled
    );
    assert!(paths.part_path().exists());

    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
    core_on(&store).shutdown().await;
    assert!(!paths.part_path().exists(), "swept at attach");
    assert_eq!(repo.cancelled_part_files().unwrap().len(), 0);
}

/// The store is gone and the part file stands: the line beside it brings the
/// download back paused, and the resume's re-hash proves what holds, as it
/// does for any record.
#[tokio::test]
async fn a_part_file_the_store_lost_comes_back_and_a_resume_proves_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(&dir.path().join("data")).unwrap();
    let temp = dir.path().join("Temp");
    std::fs::create_dir(&temp).unwrap();
    let (link, mut bytes) = three_part_link(0x40);
    bytes[PART] ^= 0xFF;
    let part_path = temp.join("lost.bin.part");
    std::fs::write(&part_path, &bytes).unwrap();
    let line = temp.join(".lost.bin.part.link");
    std::fs::write(&line, format!("{}\n", Ed2kLink::File(link))).unwrap();

    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .settings(rmule_core::CoreSettings {
            temp_dir: Some(temp),
            ..rmule_testkit::in_download_dir(
                rmule_core::CoreSettings::default(),
                &dir.path().join("downloads"),
            )
        })
        .source_lookup(two_high_id_sources())
        .peer_transfer(PendingPeerTransfer)
        .restore_at_attach()
        .build();
    next_expected(&mut core, "the part file taken back", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::PartFilesAdopted { parts: 1 })
        )
    })
    .await;
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let id = repo.listed_downloads().unwrap()[0].id();
    let record = repo.load_download(id).unwrap();
    assert_eq!(record.lifecycle(), DownloadLifecycle::Paused);
    assert_eq!(record.paths().part_path(), part_path);
    assert_eq!(repo.verified_parts(id).unwrap().len(), 3);

    resume(&mut core, id).await;
    next_expected(&mut core, "the part that did not hold", |event| {
        matches!(
            event,
            CoreEvent::Download(DownloadEvent::DamagedPartsDropped { .. })
        )
    })
    .await;
    core.shutdown().await;
    let held: Vec<u32> = repo
        .verified_parts(id)
        .unwrap()
        .iter()
        .map(|part| part.part_index)
        .collect();
    assert_eq!(held, [0, 2]);
}
