//! A Durable Store that fails inside a run is told as a store failure, never
//! as a part that failed its check, and no count is told that the store did
//! not give. Each leg names a download the store holds no row for, so every
//! store call it makes is refused.

use rmule_primitives::PartHash;
use tokio::sync::mpsc;

use super::{
    PersistError, distrusted_at_start, hold_part_file, part_file_changed, record_failure,
    write_through_held,
};
use crate::content::{HeldPartFile, PartFileChange};
use crate::diagnostics::DiagnosticsState;
use crate::download::runner::RunnerContext;
use crate::download::runner::test_context::{Held, runner_context};
use crate::durable::VerifiedPartRecord;
use crate::error::DownloadFailure;
use crate::service::{CoreEvent, DownloadEvent, DownloadId, PartsLost};
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
    let record = VerifiedPartRecord {
        part_index: 0,
        offset: 0,
        len: 4,
        part_hash: PartHash::from_bytes([0x11; 16]),
    };

    let result = write_through_held(&runner, UNKNOWN, record, b"abcd").await;
    assert!(
        matches!(
            result,
            Err(PersistError::Ended(DownloadFailure::StoreFailed))
        ),
        "not a part that failed its check"
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
    let (evt_tx, mut evt_rx) = mpsc::channel(4);

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
