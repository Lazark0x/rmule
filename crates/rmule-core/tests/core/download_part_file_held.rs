//! The part file under a running download (ADR-0094):
//! the part file is the operator's to delete. The run holds it from its first
//! act, and at the next part it notices that the file at its path is gone,
//! replaced or cut short. It says what that cost, drops the parts it lost,
//! never writes into a file nobody can reach, and never recreates one behind
//! the operator's back. Finalize repairs a file that does not hash.
//!
//! Each leg restores a two-part download with part 0 verified. It waits for a
//! connection while already holding its part file; the leg changes the file,
//! then connects, and part 1 arriving is the run's next part boundary.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rmule_core::{
    ContentFileStore, Core, CoreConfig, CoreEvent, DownloadEvent, DownloadFailure, DownloadId,
    DownloadLifecycle, DownloadPaths, DownloadRepository, DurableDownloadRepository,
    PartFileChange, PartsLost, StorageIntegrityFault, VerifiedPartRecord, open_durable_store,
};
use rmule_primitives::ED2K_PART_SIZE;
use rmule_testkit::{FakeEd2kServer, ServingCore, file_link};
use tokio::time::timeout;

use crate::fixture::{connect_credentials, next_expected};

const PART: usize = ED2K_PART_SIZE as usize;

/// One running two-part download with part 0 verified, a live server whose
/// only source is a real core serving the whole file, and the core that will
/// resume it — waiting for a connection, its part file held.
struct Leg {
    core: Core,
    id: DownloadId,
    repo: DurableDownloadRepository,
    paths: DownloadPaths,
    bytes: Vec<u8>,
    server: FakeEd2kServer,
    _serving: ServingCore,
    _dir: tempfile::TempDir,
}

impl Leg {
    async fn waiting_with_part_zero() -> Self {
        let mut bytes = vec![0x5A; PART];
        bytes.push(0xA5);
        let link = file_link("held.bin", &bytes);
        let hashes = link.part_hash_set.as_ref().unwrap().hashes().to_vec();
        let server = FakeEd2kServer::start_scripted().await;
        let serving = ServingCore::spawn(0x77, "held.bin", &bytes).await;
        server.set_sources(vec![serving.source()]).await;

        let dir = tempfile::tempdir().unwrap();
        let store = open_durable_store(dir.path()).unwrap();
        let repo = DurableDownloadRepository::new(Arc::clone(&store));
        let paths = DownloadPaths::from_final_path(dir.path().join("held.bin"));
        let id = repo
            .create_download(&link, Some(&server.endpoint()), &paths)
            .unwrap()
            .id();
        ContentFileStore::write_verified_part(&paths, 0, &bytes[..PART])
            .await
            .unwrap();
        repo.record_verified_part(
            id,
            VerifiedPartRecord {
                part_index: 0,
                offset: 0,
                len: ED2K_PART_SIZE,
                part_hash: hashes[0],
            },
        )
        .unwrap();
        repo.set_lifecycle(id, DownloadLifecycle::Active).unwrap();

        let mut core = Core::builder(
            CoreConfig {
                download_restore_pace: Duration::from_millis(10),
                ..CoreConfig::default()
            },
            store,
        )
        .restore_credentials(connect_credentials().await)
        .build();
        next_expected(
            &mut core,
            "the restored run waiting, its file held",
            |event| {
                matches!(
                    event,
                    CoreEvent::Download(DownloadEvent::WaitingForConnection { .. })
                )
            },
        )
        .await;
        Self {
            core,
            id,
            repo,
            paths,
            bytes,
            server,
            _serving: serving,
            _dir: dir,
        }
    }

    fn part_path(&self) -> &Path {
        self.paths.part_path()
    }

    async fn connect(&self) {
        rmule_testkit::connect_to(
            &self.core,
            &self.server.endpoint(),
            connect_credentials().await,
        )
        .await;
    }

    /// Every download event until the run ends, completed or failed.
    async fn events_until_the_run_ends(&mut self) -> Vec<DownloadEvent> {
        let mut seen = Vec::new();
        timeout(Duration::from_secs(30), async {
            loop {
                let Some(CoreEvent::Download(event)) = self.core.next_event().await else {
                    continue;
                };
                let ended = matches!(
                    event,
                    DownloadEvent::DownloadCompleted { .. } | DownloadEvent::DownloadFailed { .. }
                );
                seen.push(event);
                if ended {
                    return;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the run never ended; saw {seen:#?}"));
        seen
    }
}

fn lost(events: &[DownloadEvent]) -> Option<(PartFileChange, u32, u64)> {
    events.iter().find_map(|event| match event {
        DownloadEvent::PartFileLost {
            found,
            lost: PartsLost::Counted { parts, bytes },
            ..
        } => Some((*found, *parts, *bytes)),
        _ => None,
    })
}

fn failed_part_file_missing(events: &[DownloadEvent]) -> bool {
    events.iter().any(|event| {
        matches!(
            event,
            DownloadEvent::DownloadFailed {
                reason: DownloadFailure::StorageIntegrityFailed(
                    StorageIntegrityFault::PartFileMissing
                ),
                ..
            }
        )
    })
}

#[tokio::test]
async fn a_part_file_removed_under_the_run_is_told_and_never_recreated() {
    let mut leg = Leg::waiting_with_part_zero().await;
    std::fs::remove_file(leg.part_path()).unwrap();
    leg.connect().await;

    let events = leg.events_until_the_run_ends().await;
    assert_eq!(
        lost(&events),
        Some((PartFileChange::Gone, 1, ED2K_PART_SIZE)),
        "the operator is told what the delete cost: {events:#?}"
    );
    assert!(failed_part_file_missing(&events), "{events:#?}");
    assert!(
        !leg.part_path().exists(),
        "the part file the operator removed is not recreated"
    );
    assert!(
        leg.repo.verified_parts(leg.id).unwrap().is_empty(),
        "nothing is recorded as held that the disk does not hold"
    );
}

/// The run that waits for a connection looks at its part file each
/// second, so a delete is told while it waits — no connect, no next part.
#[tokio::test]
async fn a_part_file_removed_while_the_run_waits_is_told_without_a_connect() {
    let mut leg = Leg::waiting_with_part_zero().await;
    std::fs::remove_file(leg.part_path()).unwrap();

    let events = leg.events_until_the_run_ends().await;
    assert_eq!(
        lost(&events),
        Some((PartFileChange::Gone, 1, ED2K_PART_SIZE)),
        "{events:#?}"
    );
    assert!(failed_part_file_missing(&events), "{events:#?}");
    assert!(
        leg.server.assigned_ids().await.is_empty(),
        "told while it waited: nothing connected"
    );
}

#[tokio::test]
async fn a_part_file_replaced_under_the_run_is_not_written_into() {
    let mut leg = Leg::waiting_with_part_zero().await;
    let other: PathBuf = leg.part_path().with_extension("theirs");
    std::fs::write(&other, b"a file that is not the part file").unwrap();
    std::fs::rename(&other, leg.part_path()).unwrap();
    leg.connect().await;

    let events = leg.events_until_the_run_ends().await;
    assert_eq!(
        lost(&events),
        Some((PartFileChange::Replaced, 1, ED2K_PART_SIZE))
    );
    assert!(failed_part_file_missing(&events), "{events:#?}");
    assert_eq!(
        std::fs::read(leg.part_path()).unwrap(),
        b"a file that is not the part file",
        "the file now at the path is left as it was"
    );
}

#[tokio::test]
async fn a_part_file_cut_short_under_the_run_keeps_going_and_completes() {
    let mut leg = Leg::waiting_with_part_zero().await;
    std::fs::OpenOptions::new()
        .write(true)
        .open(leg.part_path())
        .unwrap()
        .set_len(10)
        .unwrap();
    leg.connect().await;

    let events = leg.events_until_the_run_ends().await;
    assert_eq!(
        lost(&events),
        Some((PartFileChange::Truncated { len: 10 }, 1, ED2K_PART_SIZE))
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, DownloadEvent::DownloadCompleted { .. })),
        "the lost part is fetched again and the download completes: {events:#?}"
    );
    assert_eq!(
        std::fs::read(leg.paths.final_path()).unwrap(),
        leg.bytes,
        "the finished file is whole"
    );
}

#[tokio::test]
async fn a_finished_file_with_a_lost_part_is_repaired_not_condemned() {
    let mut leg = Leg::waiting_with_part_zero().await;
    // Part 0's bytes change in place — same file, same length — so only the
    // whole file's hash at finalize can tell.
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(leg.part_path())
            .unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&vec![0u8; PART]).unwrap();
    }
    leg.connect().await;

    let events = leg.events_until_the_run_ends().await;
    assert!(
        events.iter().any(|event| matches!(
            event,
            DownloadEvent::DamagedPartsDropped { damaged, .. }
                if damaged.len() == 1 && damaged[0].part_index() == 0
        )),
        "finalize names the lost part and drops it: {events:#?}"
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, DownloadEvent::DownloadCompleted { .. })),
        "the download is repaired, not failed: {events:#?}"
    );
    assert_eq!(std::fs::read(leg.paths.final_path()).unwrap(), leg.bytes);
}

/// Every event until the run ends, or what was seen when it runs on past
/// `limit`: a run that loops on its own finalize never ends by itself.
async fn events_within(
    leg: &mut Leg,
    limit: Duration,
) -> Result<Vec<DownloadEvent>, Vec<DownloadEvent>> {
    let mut seen = Vec::new();
    let ended = timeout(limit, async {
        loop {
            let Some(CoreEvent::Download(event)) = leg.core.next_event().await else {
                continue;
            };
            let ended = matches!(
                event,
                DownloadEvent::DownloadCompleted { .. } | DownloadEvent::DownloadFailed { .. }
            );
            seen.push(event);
            if ended {
                return;
            }
        }
    })
    .await;
    match ended {
        Ok(()) => Ok(seen),
        Err(_) => Err(seen),
    }
}

fn failure(events: &[DownloadEvent]) -> Option<&DownloadFailure> {
    events.iter().find_map(|event| match event {
        DownloadEvent::DownloadFailed { reason, .. } => Some(reason),
        _ => None,
    })
}

fn nothing_dropped(events: &[DownloadEvent]) -> bool {
    !events.iter().any(|event| {
        matches!(
            event,
            DownloadEvent::FinishedFileRejected { .. }
                | DownloadEvent::DamagedPartsDropped { .. }
                | DownloadEvent::PartFileLost { .. }
        )
    })
}

#[tokio::test]
async fn a_verified_file_whose_final_path_is_taken_keeps_its_parts_and_fails_by_that_cause() {
    let mut leg = Leg::waiting_with_part_zero().await;
    std::fs::write(leg.paths.final_path(), b"the operator's own file").unwrap();
    leg.connect().await;

    let events = events_within(&mut leg, Duration::from_secs(20))
        .await
        .unwrap_or_else(|seen| panic!("the run never ended; saw {seen:#?}"));
    assert_eq!(failure(&events), Some(&DownloadFailure::FinalPathTaken));
    assert!(nothing_dropped(&events), "{events:#?}");
    assert_eq!(
        leg.repo.verified_parts(leg.id).unwrap().len(),
        2,
        "every verified part is kept"
    );
    assert_eq!(
        std::fs::read(leg.paths.final_path()).unwrap(),
        b"the operator's own file"
    );
    assert_eq!(std::fs::read(leg.part_path()).unwrap(), leg.bytes);
}

#[cfg(unix)]
#[tokio::test]
async fn a_verified_file_whose_rename_is_refused_keeps_its_parts_and_fails_by_that_cause() {
    use std::os::unix::fs::PermissionsExt;
    let mut leg = Leg::waiting_with_part_zero().await;
    let dir = leg.part_path().parent().unwrap().to_path_buf();
    let writable = std::fs::metadata(&dir).unwrap().permissions();
    // The held handle writes on; only the rename needs the directory.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    leg.connect().await;

    let events = events_within(&mut leg, Duration::from_secs(20)).await;
    std::fs::set_permissions(&dir, writable).unwrap();
    let events = events.unwrap_or_else(|seen| panic!("the run never ended; saw {seen:#?}"));
    assert_eq!(
        failure(&events),
        Some(&DownloadFailure::CompletedFileNotMoved { os_code: Some(13) })
    );
    assert!(nothing_dropped(&events), "{events:#?}");
    assert_eq!(leg.repo.verified_parts(leg.id).unwrap().len(), 2);
    assert_eq!(std::fs::read(leg.part_path()).unwrap(), leg.bytes);
}
