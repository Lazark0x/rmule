//! The content-file store's side of a download: bytes land at the part
//! offset the plan declares, and a part belongs to exactly one download.
use rmule_core::DownloadRepository;
use std::fs;

use crate::fixture::stub_server;
use rmule_core::{ContentFileStore, CoreError, DownloadPaths, DurableDownloadRepository};
use rmule_primitives::{Ed2kFileLink, Ed2kLink};

#[tokio::test]
async fn writes_verified_bytes_at_declared_part_offset() {
    let dir = tempfile::tempdir().unwrap();
    let paths = DownloadPaths::from_final_path(dir.path().join("download.bin"));

    ContentFileStore::write_verified_part(&paths, 4, b"abc")
        .await
        .unwrap();

    assert_eq!(
        ContentFileStore::read_range(paths.part_path(), 4, 3)
            .await
            .unwrap(),
        b"abc"
    );
    assert_eq!(fs::metadata(paths.part_path()).unwrap().len(), 7);
}

#[tokio::test]
async fn read_range_reads_a_completed_file_at_its_final_path() {
    let dir = tempfile::tempdir().unwrap();
    let paths = DownloadPaths::from_final_path(dir.path().join("shared.bin"));
    // A completed share lives at `final_path`, not the `.part` file; the
    // serve side reads its bytes through the same primitive.
    fs::write(paths.final_path(), b"0123456789").unwrap();

    let slice = ContentFileStore::read_range(paths.final_path(), 3, 4)
        .await
        .unwrap();

    assert_eq!(slice, b"3456");
}

#[tokio::test]
async fn read_range_refuses_a_length_over_three_blocks_before_reading() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shared.bin");
    let cap = rmule_peer::MAX_REQUESTED_RANGE;
    fs::File::create(&path).unwrap().set_len(2 * cap).unwrap();

    let read = ContentFileStore::read_range(&path, 0, cap).await.unwrap();
    assert_eq!(read.len() as u64, cap, "three blocks are read");
    assert!(
        ContentFileStore::read_range(&path, 0, cap + 1)
            .await
            .is_err(),
        "a byte more is refused, though the file holds it"
    );
}

#[test]
fn repository_rejects_foreign_part_path_owner() {
    let dir = tempfile::tempdir().unwrap();
    let repo = DurableDownloadRepository::new(rmule_testkit::memory_store());
    let paths = DownloadPaths::from_final_path(dir.path().join("download.bin"));
    repo.create_download(
        &file_link(),
        Some(&stub_server("example.org")),
        &paths,
        None,
    )
    .unwrap();

    let err = repo
        .create_download(
            &other_file_link(),
            Some(&stub_server("example.org")),
            &paths,
            None,
        )
        .unwrap_err();

    assert_eq!(err, CoreError::PathConflict);
}

#[tokio::test]
async fn delete_part_is_idempotent_when_file_missing() {
    let dir = tempfile::tempdir().unwrap();
    let paths = DownloadPaths::from_final_path(dir.path().join("download.bin"));
    assert!(!paths.part_path().exists());

    ContentFileStore::delete_part(&paths).await.unwrap();
    ContentFileStore::write_verified_part(&paths, 0, b"bytes")
        .await
        .unwrap();
    assert!(paths.part_path().exists());

    ContentFileStore::delete_part(&paths).await.unwrap();
    assert!(!paths.part_path().exists());
    ContentFileStore::delete_part(&paths).await.unwrap();
}

fn file_link() -> Ed2kFileLink {
    parse_file_link("download.bin", "0102030405060708090A0B0C0D0E0F10")
}

fn other_file_link() -> Ed2kFileLink {
    parse_file_link("other.bin", "1112131415161718191A1B1C1D1E1F20")
}

fn parse_file_link(name: &str, hash: &str) -> Ed2kFileLink {
    match Ed2kLink::parse(&format!("ed2k://|file|{name}|1234|{hash}|/")).unwrap() {
        Ed2kLink::File(file) => file,
        _ => unreachable!("fixture is a file link"),
    }
}
