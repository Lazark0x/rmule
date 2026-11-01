//! A Durable Store that fails inside a run is told as a store failure, never
//! as a part that failed its check, and no count is told that the store did
//! not give. Each leg names a download the store holds no row for, so every
//! store call it makes is refused.

use rmule_peer::PartIndex;
use rmule_primitives::{Ed2kFileLink, Ed2kText, FileHash};

use super::{
    PersistError, check_held_part_file, distrusted_at_start, hold_part_file, part_file_changed,
    persist_streamed_part, record_failure, write_blocks,
};
use crate::DownloadPaths;
use crate::content::{HeldPartFile, PartFileChange};
use crate::diagnostics::DiagnosticsState;
use crate::download::runner::RunnerContext;
use crate::download::runner::test_context::{Held, runner_context};
use crate::error::DownloadFailure;
use crate::planning::PartPlan;
use crate::service::{CoreEvent, DownloadEvent, DownloadId, PartsLost, VolumeStop};
use crate::storage::DownloadRepository;
use crate::store::download::DurableDownloadRepository;

const UNKNOWN: DownloadId = DownloadId::from_u64(9);

fn context() -> (RunnerContext<(), ()>, Held) {
    runner_context((), (), DiagnosticsState::default())
}

async fn held_part_file(dir: &tempfile::TempDir) -> HeldPartFile {
    HeldPartFile::hold(&dir.path().join("file.part"), 0)
        .await
        .expect("a new part file is held")
        .0
}

#[tokio::test]
async fn a_download_the_store_cannot_read_is_not_held_and_fails_as_a_store_failure() {
    let (runner, _held) = context();
    assert_eq!(
        hold_part_file(&runner, UNKNOWN).await,
        Err(DownloadFailure::StoreFailed)
    );
}

#[test]
fn a_download_whose_distrusted_peers_the_store_cannot_read_does_not_start() {
    let (runner, _held) = context();
    assert_eq!(
        distrusted_at_start(&runner, UNKNOWN),
        Err(DownloadFailure::StoreFailed),
        "a run that forgot its distrust would dial the peers that served it bad data"
    );
}

#[tokio::test]
async fn a_part_the_store_cannot_record_ends_the_run_as_a_store_failure() {
    let (runner, _held) = context();
    let dir = tempfile::tempdir().unwrap();
    *runner.part_file.lock().await = Some(held_part_file(&dir).await);
    let bytes = b"abcd";
    let digest = crate::hashing::part_hash_of(bytes);
    let file = Ed2kFileLink::new(
        Ed2kText::from_utf8("file"),
        bytes.len() as u64,
        FileHash::from_bytes(*digest.as_bytes()),
    )
    .unwrap();
    write_blocks(&runner, UNKNOWN, vec![(0, bytes.to_vec())])
        .await
        .unwrap();
    let plan = PartPlan {
        part_index: PartIndex::new(0),
        offset: 0,
        len: bytes.len() as u64,
    };
    let resolved = crate::hashing::resolve_hash_set_authority(None, None).unwrap();

    let checked = persist_streamed_part(&runner, UNKNOWN, &file, &resolved, plan, false).await;
    assert!(
        matches!(
            checked.result,
            Err(PersistError::Ended(DownloadFailure::StoreFailed))
        ),
        "not a part that failed its check"
    );
}

#[tokio::test]
async fn a_write_the_volume_refuses_is_a_volume_stop_and_no_failed_part() {
    let (runner, _held) = context();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.part");
    std::fs::write(&path, b"").unwrap();
    *runner.part_file.lock().await = Some(HeldPartFile::refusing_writes(&path));

    let result = write_blocks(&runner, UNKNOWN, vec![(0, b"abcd".to_vec())]).await;
    assert_eq!(
        result,
        Err(DownloadFailure::Paused),
        "a refused write must not reach the brain as a part that failed its check"
    );
    assert!(matches!(
        runner.take_volume_stop(),
        Some(VolumeStop::WriteRefused { os_code: Some(_) })
    ));
}

#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "Windows refuses to rename a directory holding an open file"
)]
async fn an_absent_path_over_a_whole_file_drops_no_record() {
    let (runner, mut held) = context();
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("mounted");
    std::fs::create_dir(&parent).unwrap();
    let path = parent.join("file.part");
    let (file, _) = HeldPartFile::hold(&path, 0).await.unwrap();
    *runner.part_file.lock().await = Some(file);
    std::fs::rename(&parent, dir.path().join("elsewhere")).unwrap();

    let ended = check_held_part_file(&runner, UNKNOWN).await;
    assert_eq!(ended, Err(DownloadFailure::Paused));
    assert_eq!(
        runner.take_volume_stop(),
        Some(VolumeStop::PartFileOutOfReach)
    );
    assert!(
        held.evt_rx.try_recv().is_err(),
        "no part is told lost, and so none is dropped"
    );
}

#[tokio::test]
async fn a_changed_part_file_the_store_cannot_count_is_told_without_a_count() {
    let (runner, mut held) = context();
    let dir = tempfile::tempdir().unwrap();
    let mut file = held_part_file(&dir).await;
    std::fs::remove_file(dir.path().join("file.part")).unwrap();

    let failure = part_file_changed(&runner, UNKNOWN, &mut file, PartFileChange::Gone).await;
    assert_eq!(failure, DownloadFailure::StoreFailed);
    assert!(
        matches!(
            held.evt_rx.try_recv(),
            Ok(CoreEvent::Download(DownloadEvent::PartFileLost {
                download_id: UNKNOWN,
                found: PartFileChange::Gone,
                lost: PartsLost::NotCounted,
            }))
        ),
        "the change on disk is told, and no loss of zero parts with it"
    );
}

#[tokio::test]
async fn a_failure_the_store_cannot_record_is_told_after_the_failure() {
    let store = DurableDownloadRepository::new(rmule_testkit::memory_store());
    let (evt_tx, mut evt_rx) = crate::service::outbox(Default::default());

    record_failure(&store, &evt_tx, UNKNOWN, DownloadFailure::PeerDisconnected).await;
    assert!(matches!(
        evt_rx.try_recv(),
        Ok(CoreEvent::Download(DownloadEvent::DownloadFailed {
            download_id: UNKNOWN,
            reason: DownloadFailure::PeerDisconnected,
        }))
    ));
    assert!(matches!(
        evt_rx.try_recv(),
        Ok(CoreEvent::Download(DownloadEvent::FailureNotRecorded {
            download_id: UNKNOWN
        }))
    ));
}

/// The line is what lets a part file outlive the store, so a run that holds
/// its file has written it.
#[tokio::test]
async fn a_held_part_file_has_its_link_beside_it() {
    let (runner, _held) = context();
    let dir = tempfile::tempdir().unwrap();
    let link = rmule_testkit::file_link("beside.bin", &[0x6D; 64]);
    let paths = DownloadPaths::from_final_path(dir.path().join("beside.bin"));
    let id = runner
        .rt
        .store
        .create_download(&link, None, &paths, None)
        .unwrap()
        .id();
    hold_part_file(&runner, id).await.unwrap();

    let line = crate::content::part_link::beside(paths.part_path()).unwrap();
    for _ in 0..500 {
        if line.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    let linked = crate::content::part_link::linked_parts(dir.path());
    assert_eq!(linked[0].link, link);
    assert_eq!(linked[0].part_path, paths.part_path());
}

/// A run that starts again keeps what an earlier one learned: a line without
/// the set could prove none of the parts verified under it.
#[tokio::test]
async fn a_run_start_writes_the_set_a_peer_gave_an_earlier_run() {
    let (runner, _held) = context();
    let dir = tempfile::tempdir().unwrap();
    let bytes = vec![0x6D; rmule_primitives::ED2K_PART_SIZE as usize + 1];
    let proven = rmule_testkit::file_link("set.bin", &bytes);
    let hashes = proven.part_hash_set.as_ref().unwrap().hashes().to_vec();
    let bare = proven.clone().with_part_hash_set(None);
    let paths = DownloadPaths::from_final_path(dir.path().join("set.bin"));
    let store = &runner.rt.store;
    let id = store
        .create_download(&bare, None, &paths, None)
        .unwrap()
        .id();
    store.record_provisional_part_hashes(id, &hashes).unwrap();
    hold_part_file(&runner, id).await.unwrap();

    let line = crate::content::part_link::beside(paths.part_path()).unwrap();
    for _ in 0..500 {
        if line.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    let linked = crate::content::part_link::linked_parts(dir.path());
    assert_eq!(linked[0].link.part_hash_set, proven.part_hash_set);
}
