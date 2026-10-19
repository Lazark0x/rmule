//! CLI behavioral coverage for `rmule-tools ed2k download status` and
//! `... pause`. Seeds the Durable Store directly through the public
//! `DurableDownloadRepository` API — releasing the store's file lock before the
//! binary runs, since one process owns `rmule.redb` (ADR-0083) — then drives
//! the binary to verify the read/update paths actually open that store and
//! produce the documented output. The hermetic `start` / `resume` coverage
//! lives in `download_hermetic.rs` on the testkit counterparties (ADR-0040).

use assert_cmd::Command;
use predicates::prelude::*;
use rmule_core::DownloadRepository;
use rmule_core::{DownloadLifecycle, DownloadPaths, DurableDownloadRepository, open_durable_store};
use rmule_primitives::{Ed2kFileLink, Ed2kText, FileHash, ServerEndpoint};

/// Seed one download row into the Durable Store in `data_dir` and give the
/// file lock back: the store handle dies with this call, so the binary under
/// test can open the same file.
fn seed_one(data_dir: &std::path::Path, name: &str) -> u64 {
    let repo = DurableDownloadRepository::new(open_durable_store(data_dir).unwrap());
    let file = Ed2kFileLink {
        name: Ed2kText::from_utf8(name),
        size: 11,
        file_hash: FileHash::from_bytes([0x55; 16]),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    };
    let server = ServerEndpoint::new("example.invalid", 4661).unwrap();
    let paths = DownloadPaths::from_final_path(data_dir.join(name));
    let record = repo
        .create_download(&file, Some(&server), &paths, None)
        .unwrap();
    record.id().as_u64()
}

#[test]
fn download_status_on_an_empty_store_emits_no_records_marker() {
    let dir = tempfile::tempdir().unwrap();

    Command::cargo_bin("rmule-tools")
        .unwrap()
        .args([
            "ed2k",
            "download",
            "status",
            "--data-dir",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("# no resumable downloads"));
}

#[test]
fn download_status_lists_seeded_records() {
    let dir = tempfile::tempdir().unwrap();
    let download_id = seed_one(dir.path(), "status-rec.bin");

    Command::cargo_bin("rmule-tools")
        .unwrap()
        .args([
            "ed2k",
            "download",
            "status",
            "--data-dir",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "download id={download_id}"
        )))
        .stdout(predicate::str::contains("file_hash=55555555"))
        .stdout(predicate::str::contains("size=11"))
        .stdout(predicate::str::contains("verified_parts=0"));
}

#[test]
fn download_pause_marks_record_paused_when_id_exists() {
    let dir = tempfile::tempdir().unwrap();
    let download_id = seed_one(dir.path(), "pause-rec.bin");

    Command::cargo_bin("rmule-tools")
        .unwrap()
        .args([
            "ed2k",
            "download",
            "pause",
            "--data-dir",
            dir.path().to_str().unwrap(),
            "--download-id",
            &download_id.to_string(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "download paused id={download_id}"
        )));

    let repo = DurableDownloadRepository::new(open_durable_store(dir.path()).unwrap());
    let record = repo
        .list_resumable()
        .unwrap()
        .into_iter()
        .find(|r| r.id().as_u64() == download_id)
        .expect("seeded record still listed after pause");
    assert!(
        matches!(record.lifecycle(), DownloadLifecycle::Paused),
        "lifecycle = {:?}",
        record.lifecycle()
    );
}
