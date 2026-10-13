//! The Offer Check's worker on real files: it reads nothing while a scan
//! holds the hashing turn, and a check stopped before its turn reports
//! nothing while the next one is still checked.

use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::timeout;

use super::*;
use crate::file_key::FileKey;
use crate::hashing::part_hash_of;
use crate::served_downloads::PartFileIdentity;

/// Download `seed`, waiting for its check, its part file holding `bytes`, all
/// of it recorded as one part.
fn waiting(dir: &std::path::Path, seed: u8, bytes: &[u8]) -> Waiting {
    let paths = DownloadPaths::from_final_path(dir.join(format!("{seed}.bin")));
    std::fs::write(paths.part_path(), bytes).unwrap();
    Waiting {
        download_id: DownloadId::from_u64(u64::from(seed)),
        file_hash: FileHash::from_bytes([seed; FileHash::BYTE_LEN]),
        paths,
        parts: vec![VerifiedPartRecord {
            part_index: 0,
            offset: 0,
            len: bytes.len() as u64,
            part_hash: part_hash_of(bytes),
        }],
        stop: Arc::default(),
    }
}

async fn next_report(
    reports: &mut mpsc::UnboundedReceiver<RegistryMessage>,
) -> Option<OfferChecked> {
    match timeout(Duration::from_secs(5), reports.recv()).await {
        Ok(Some(RegistryMessage::OfferChecked(report))) => Some(report),
        Ok(None) => None,
        other => panic!("a check's report, not {other:?}"),
    }
}

#[tokio::test]
async fn a_check_reads_nothing_while_a_scan_holds_the_hashing_turn() {
    let dir = tempfile::tempdir().unwrap();
    let check = waiting(dir.path(), 1, b"verified");
    let part = check.paths.part_path().to_path_buf();
    let turn = HashTurn::default();
    let (tx, mut reports) = mpsc::unbounded_channel();
    let scan = turn.take(&AtomicBool::new(false)).unwrap();
    tokio::spawn(run_checks(vec![check], turn.clone(), tx));

    assert!(
        timeout(Duration::from_millis(300), reports.recv())
            .await
            .is_err(),
        "no check runs beside a scan's hashing"
    );
    drop(scan);
    let report = next_report(&mut reports).await.unwrap();
    let Revalidation::Restored { progress, damaged } = report.revalidation else {
        panic!("the part holds");
    };
    assert!(damaged.is_empty());
    assert_eq!(progress.verified_parts(), 1);
    let file = std::fs::File::open(&part).unwrap();
    assert_eq!(
        progress.read_through(),
        PartFileIdentity::read(
            FileKey::of_open(&file).unwrap(),
            &file.metadata().unwrap(),
            true
        ),
        "the identity of the handle it read through"
    );
}

#[tokio::test]
async fn a_check_stopped_while_it_waits_reports_nothing_and_the_next_is_checked() {
    let dir = tempfile::tempdir().unwrap();
    let (resumed, paused) = (
        waiting(dir.path(), 1, b"resumed"),
        waiting(dir.path(), 2, b"paused"),
    );
    let mut checks = OfferChecks::default();
    for check in [&resumed, &paused] {
        checks
            .checking
            .insert(check.download_id, Arc::clone(&check.stop));
    }
    let turn = HashTurn::default();
    let (tx, mut reports) = mpsc::unbounded_channel();
    let scan = turn.take(&AtomicBool::new(false)).unwrap();
    tokio::spawn(run_checks(vec![resumed, paused], turn.clone(), tx));

    checks.stop(DownloadId::from_u64(1));
    drop(scan);
    let report = next_report(&mut reports).await.unwrap();
    assert_eq!(report.download_id, DownloadId::from_u64(2));
    assert!(
        next_report(&mut reports).await.is_none(),
        "the stopped check said nothing"
    );
    assert!(!checks.checking.contains_key(&DownloadId::from_u64(1)));
}
