//! The version-5 row's evidence: its frozen shape reads the bytes store
//! versions 9 to 14 hold, and such a store climbs to rows that carry their
//! Download Name.

use rmule_primitives::{Ed2kLink, Ed2kText, FileHash};
use rmule_store::{Ladder, Schema};

use super::super::declared_v5;
use super::super::row_enums::{
    DownloadLifecycleV5, DownloadMetadataOriginV1, VerificationAuthorityV1,
};
use super::{DOWNLOADS_V5, DownloadFailureV5, DownloadRowV5, PartFaultV3, StorageIntegrityFaultV4};
use crate::storage::DownloadRepository;
use crate::store::download::DurableDownloadRepository;
use crate::store::download::row::tests::{HELD_ROW_V5, RELEASED_ROW_V5, hex};
use crate::store::{DURABLE_STORE_FILE, DurableStore, open_durable_store};
use crate::{
    DownloadFailure, DownloadId, DownloadLifecycle, DownloadPaths, PartFault, StorageIntegrityFault,
};

fn row_v5(part_path: &str) -> DownloadRowV5 {
    let file = rmule_primitives::Ed2kFileLink::new(
        Ed2kText::from_utf8("a.bin"),
        10,
        FileHash::from_bytes([0xA1; FileHash::BYTE_LEN]),
    )
    .expect("a size eD2k addresses");
    DownloadRowV5 {
        file_hash: file.file_hash,
        file_size: file.size(),
        canonical_link: Ed2kLink::File(file.clone()).to_string(),
        source_hint: None,
        final_path: "/dl/a.bin".into(),
        part_path: part_path.into(),
        lifecycle: DownloadLifecycleV5::Queued,
        verification_authority: None,
        file_name: file.name,
        metadata_origin: DownloadMetadataOriginV1::Link,
        failure: None,
    }
}

/// The frozen version-5 row encodes to the bytes a version-14 store holds,
/// held and released, so the rung reads every row as it was written.
#[test]
fn the_frozen_version_five_row_encodes_as_versions_nine_to_fourteen_wrote_it() {
    for (part_path, stored) in [
        ("/dl/a.bin.part", HELD_ROW_V5),
        ("\0released:7", RELEASED_ROW_V5),
    ] {
        let bytes = postcard::to_allocvec(&row_v5(part_path)).unwrap();
        assert_eq!(hex(&bytes), stored);
        let read: DownloadRowV5 = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(read.part_path, part_path);
    }
}

/// The version-5 lifecycle and failure are read by variant position: every
/// variant of each frozen copy encodes to the bytes those stores hold.
#[test]
fn every_frozen_version_five_lifecycle_and_failure_encodes_as_written() {
    let lifecycles = [
        (DownloadLifecycleV5::Queued, 0),
        (DownloadLifecycleV5::Active, 1),
        (DownloadLifecycleV5::Paused, 2),
        (DownloadLifecycleV5::Failed, 3),
        (DownloadLifecycleV5::Completed, 4),
        (DownloadLifecycleV5::Cancelled, 5),
        (DownloadLifecycleV5::Completing, 6),
    ];
    for (lifecycle, byte) in lifecycles {
        assert_eq!(postcard::to_allocvec(&lifecycle).unwrap(), [byte]);
        assert_eq!(
            postcard::from_bytes::<DownloadLifecycleV5>(&[byte]).unwrap(),
            lifecycle
        );
    }
    let failures: [(DownloadFailureV5, &[u8]); 15] = [
        (DownloadFailureV5::NoUsableSources, &[0]),
        (DownloadFailureV5::HashSetMismatch, &[1]),
        (DownloadFailureV5::Cancelled, &[2]),
        (DownloadFailureV5::Paused, &[3]),
        (DownloadFailureV5::ServerDisconnected, &[4]),
        (DownloadFailureV5::ServerFiltered, &[5]),
        (DownloadFailureV5::SourceLookupTimedOut, &[6]),
        (DownloadFailureV5::PeerDisconnected, &[7]),
        (DownloadFailureV5::PartVerificationFailed, &[8]),
        (
            DownloadFailureV5::StorageIntegrityFailed(StorageIntegrityFaultV4::PartFileMissing),
            &[9, 0],
        ),
        (
            DownloadFailureV5::StorageIntegrityFailed(StorageIntegrityFaultV4::NoPartHolds {
                recorded: 3,
                first: PartFaultV3::Short {
                    part_index: 2,
                    expected_end: 300,
                    found_len: 5,
                },
            }),
            &[9, 2, 3, 0, 2, 0xAC, 0x02, 5],
        ),
        (DownloadFailureV5::FinalPathTaken, &[10]),
        (
            DownloadFailureV5::CompletedFileNotMoved { os_code: Some(18) },
            &[11, 1, 36],
        ),
        (DownloadFailureV5::StoreFailed, &[12]),
        (
            DownloadFailureV5::CompletionCopyFailed { os_code: Some(28) },
            &[13, 1, 56],
        ),
    ];
    for (failure, encoded) in failures {
        assert_eq!(postcard::to_allocvec(&failure).unwrap(), encoded);
        assert_eq!(
            postcard::from_bytes::<DownloadFailureV5>(encoded).unwrap(),
            failure
        );
    }
}

/// A version-14 store's rows climb to version 15 with the name each was
/// placed under: the part file's name less `.part`, whatever destination a
/// completion move stored since.
#[test]
fn a_version_fourteen_row_climbs_with_the_name_it_was_placed_under() {
    let dir = tempfile::tempdir().unwrap();
    let numbered = DownloadPaths::new(
        dir.path().join("dl/have (1).bin"),
        dir.path().join("temp/have (1).bin.part"),
    );
    let moved = DownloadPaths::new(
        dir.path().join("dl/film (2).mkv"),
        dir.path().join("temp/film.mkv.part"),
    );
    let (numbered_key, moved_key) = {
        let v14 = DurableStore::open(
            dir.path().join(DURABLE_STORE_FILE),
            &declared_v5::schema_v5_rows(),
            &Ladder::new(14, 14, &[]),
        )
        .unwrap();
        v14.write(|txn| {
            let have = rmule_testkit::file_link("have.bin", b"have");
            let film = rmule_testkit::file_link("film.mkv", b"film");
            Ok::<_, rmule_store::StoreError>((
                declared_v5::seed_v5(txn, &have, &numbered)?,
                declared_v5::seed_v5(txn, &film, &moved)?,
            ))
        })
        .unwrap()
    };

    let repo = DurableDownloadRepository::new(open_durable_store(dir.path()).unwrap());
    let numbered_row = repo
        .load_download(DownloadId::from_u64(numbered_key))
        .unwrap();
    assert_eq!(numbered_row.paths().name(), "have (1).bin");
    assert_eq!(numbered_row.paths().final_path(), numbered.final_path());
    assert_eq!(numbered_row.lifecycle(), DownloadLifecycle::Queued);
    let moved_row = repo.load_download(DownloadId::from_u64(moved_key)).unwrap();
    assert_eq!(moved_row.paths().name(), "film.mkv");
    assert_eq!(moved_row.paths().final_path(), moved.final_path());
    assert_eq!(
        repo.part_files().unwrap().len(),
        2,
        "both rows still hold their part files"
    );
}

/// A row's link is typed from the climb on: text that no longer parses costs
/// the row its hints and its `p=`, never the row, since the row's own hash and
/// size name the file.
#[test]
fn a_version_fourteen_row_with_damaged_link_text_keeps_its_file() {
    let dir = tempfile::tempdir().unwrap();
    let paths = DownloadPaths::new(
        dir.path().join("dl/have.bin"),
        dir.path().join("temp/have.bin.part"),
    );
    let have = rmule_testkit::file_link("have.bin", b"have");
    let key = {
        let v14 = DurableStore::open(
            dir.path().join(DURABLE_STORE_FILE),
            &declared_v5::schema_v5_rows(),
            &Ladder::new(14, 14, &[]),
        )
        .unwrap();
        v14.write(|txn| {
            let key = declared_v5::seed_v5(txn, &have, &paths)?;
            let (_, mut row) = DOWNLOADS_V5.iter(txn)?.remove(0);
            row.canonical_link = "not a link".into();
            DOWNLOADS_V5.set(txn, &key, &row)?;
            Ok::<_, rmule_store::StoreError>(key)
        })
        .unwrap()
    };

    let repo = DurableDownloadRepository::new(open_durable_store(dir.path()).unwrap());
    let record = repo.load_download(DownloadId::from_u64(key)).unwrap();
    assert_eq!(record.file_link().file_hash, have.file_hash);
    assert_eq!(record.file_link().size(), have.size());
    assert_eq!(repo.unreadable_rows().unwrap(), 0);
}

/// A row failed with a part fault climbs to the live reason it stood for.
#[test]
fn a_version_fourteen_part_fault_climbs_to_the_live_fault() {
    let (expected, found) = ([0x11; 16], [0x22; 16]);
    let dir = tempfile::tempdir().unwrap();
    {
        let v14 = DurableStore::open(
            dir.path().join(DURABLE_STORE_FILE),
            &Schema::new().indexed(&DOWNLOADS_V5),
            &Ladder::new(14, 14, &[]),
        )
        .unwrap();
        let mut row = row_v5("/dl/a.bin.part");
        row.lifecycle = DownloadLifecycleV5::Failed;
        row.failure = Some(DownloadFailureV5::StorageIntegrityFailed(
            StorageIntegrityFaultV4::NoPartHolds {
                recorded: 1,
                first: PartFaultV3::HashMismatch {
                    part_index: 1,
                    expected: rmule_primitives::PartHash::from_bytes(expected),
                    found: rmule_primitives::PartHash::from_bytes(found),
                },
            },
        ));
        v14.write(|txn| DOWNLOADS_V5.insert(txn, &3, &row)).unwrap();
    }
    let repo = DurableDownloadRepository::new(open_durable_store(dir.path()).unwrap());
    assert_eq!(
        repo.load_download(DownloadId::from_u64(3))
            .unwrap()
            .failure(),
        Some(&DownloadFailure::StorageIntegrityFailed(
            StorageIntegrityFault::NoPartHolds {
                recorded: 1,
                first: PartFault::HashMismatch {
                    part_index: 1,
                    expected: rmule_primitives::PartHash::from_bytes(expected),
                    found: rmule_primitives::PartHash::from_bytes(found),
                },
            }
        ))
    );
}

/// The authority and origin of a version-5 row are read by variant position:
/// every variant of each frozen copy encodes to the byte those stores hold.
#[test]
fn every_frozen_authority_and_origin_encodes_as_written() {
    let authorities = [
        (Some(VerificationAuthorityV1::LinkPartHashSet), vec![1, 0]),
        (Some(VerificationAuthorityV1::PeerHashSet), vec![1, 1]),
        (Some(VerificationAuthorityV1::FileHashOnly), vec![1, 2]),
        (None, vec![0]),
    ];
    for (authority, encoded) in authorities {
        assert_eq!(postcard::to_allocvec(&authority).unwrap(), encoded);
        assert_eq!(
            postcard::from_bytes::<Option<VerificationAuthorityV1>>(&encoded).unwrap(),
            authority
        );
    }
    let origins = [
        (DownloadMetadataOriginV1::Link, 0),
        (DownloadMetadataOriginV1::RecoveredLink, 1),
        (DownloadMetadataOriginV1::Unknown, 2),
    ];
    for (origin, byte) in origins {
        assert_eq!(postcard::to_allocvec(&origin).unwrap(), [byte]);
        assert_eq!(
            postcard::from_bytes::<DownloadMetadataOriginV1>(&[byte]).unwrap(),
            origin
        );
    }
}
