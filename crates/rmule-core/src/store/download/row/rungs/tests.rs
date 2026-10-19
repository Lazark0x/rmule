//! The rungs' evidence: an older store climbs to today's rows.

use rmule_primitives::{Ed2kText, FileHash, ServerEndpoint};
use rmule_store::{Ladder, Schema};

use super::row_enums::{DownloadLifecycleV1, DownloadMetadataOriginV1, VerificationAuthorityV1};
use super::{
    DOWNLOADS_V1, DOWNLOADS_V2, DOWNLOADS_V3, DOWNLOADS_V4, DownloadFailureV2, DownloadFailureV3,
    DownloadFailureV4, DownloadRowV1, DownloadRowV2, DownloadRowV3, DownloadRowV4, PartFaultV3,
    StorageIntegrityFaultV3, StorageIntegrityFaultV4,
};
use crate::storage::DownloadRepository;
use crate::store::download::DurableDownloadRepository;
use crate::store::{DurableStore, open_durable_store};
use crate::{DownloadFailure, DownloadId, DownloadLifecycle, PartFault, StorageIntegrityFault};

/// A version-5 store's failed row climbs to version 6 with no reason — it
/// failed before reasons were kept — and stays a live row that holds its
/// file's place.
#[test]
fn a_version_five_download_row_climbs_to_no_failure_reason() {
    let dir = tempfile::tempdir().unwrap();
    {
        let v5 = DurableStore::open(
            dir.path().join(crate::store::DURABLE_STORE_FILE),
            &Schema::new().indexed(&DOWNLOADS_V1),
            &Ladder::new(5, &[]),
        )
        .unwrap();
        v5.write(|txn| {
            DOWNLOADS_V1.insert(
                txn,
                &7,
                &DownloadRowV1 {
                    file_hash: FileHash::from_bytes([0x5A; FileHash::BYTE_LEN]),
                    file_size: 10,
                    canonical_link: "ed2k://|file|old.bin|10|5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A|/"
                        .into(),
                    server: ServerEndpoint::new("127.0.0.1", 4661).unwrap(),
                    final_path: "/dl/old.bin".into(),
                    part_path: "/dl/old.bin.part".into(),
                    lifecycle: DownloadLifecycleV1::Failed,
                    verification_authority: None,
                    file_name: Ed2kText::from_utf8("old.bin"),
                    metadata_origin: DownloadMetadataOriginV1::Link,
                },
            )
        })
        .unwrap();
    }
    let repo = DurableDownloadRepository::new(open_durable_store(dir.path()).unwrap());
    let id = DownloadId::from_u64(7);
    let record = repo.load_download(id).unwrap();
    assert_eq!(record.lifecycle(), DownloadLifecycle::Failed);
    assert_eq!(record.failure(), None);
    assert_eq!(repo.live_downloads().unwrap().len(), 1);
    assert_eq!(
        repo.part_files().unwrap(),
        vec![("/dl/old.bin.part".into(), true)]
    );
}

fn v2_row(name: &str, byte: u8, failure: DownloadFailureV2) -> DownloadRowV2 {
    let hash = format!("{byte:02X}").repeat(FileHash::BYTE_LEN);
    DownloadRowV2 {
        file_hash: FileHash::from_bytes([byte; FileHash::BYTE_LEN]),
        file_size: 10,
        canonical_link: format!("ed2k://|file|{name}|10|{hash}|/"),
        server: ServerEndpoint::new("127.0.0.1", 4661).unwrap(),
        final_path: format!("/dl/{name}"),
        part_path: format!("/dl/{name}.part"),
        lifecycle: DownloadLifecycleV1::Failed,
        verification_authority: None,
        file_name: Ed2kText::from_utf8(name),
        metadata_origin: DownloadMetadataOriginV1::Link,
        failure: Some(failure),
    }
}

/// A version-6 store's failed rows climb to version 7: the bare
/// storage-integrity code, which has no fault to carry, reads no reason
/// and stays Failed; every other reason is kept.
#[test]
fn a_version_six_storage_integrity_failure_climbs_to_no_reason() {
    let dir = tempfile::tempdir().unwrap();
    {
        let v6 = DurableStore::open(
            dir.path().join(crate::store::DURABLE_STORE_FILE),
            &Schema::new().indexed(&DOWNLOADS_V2),
            &Ladder::new(6, &[]),
        )
        .unwrap();
        v6.write(|txn| {
            DOWNLOADS_V2.insert(
                txn,
                &4,
                &v2_row("a.bin", 0xA1, DownloadFailureV2::StorageIntegrityFailed),
            )?;
            DOWNLOADS_V2.insert(
                txn,
                &5,
                &v2_row("b.bin", 0xB2, DownloadFailureV2::ServerFiltered),
            )
        })
        .unwrap();
    }
    let repo = DurableDownloadRepository::new(open_durable_store(dir.path()).unwrap());
    let integrity = repo.load_download(DownloadId::from_u64(4)).unwrap();
    assert_eq!(integrity.lifecycle(), DownloadLifecycle::Failed);
    assert_eq!(integrity.failure(), None);
    let filtered = repo.load_download(DownloadId::from_u64(5)).unwrap();
    assert_eq!(filtered.failure(), Some(&DownloadFailure::ServerFiltered));
    assert_eq!(repo.live_downloads().unwrap().len(), 2);
}

/// A version-7 store's unreadable part file climbs to version 8 keeping
/// the OS's error number its message named, and nothing else of the text;
/// a message that names none keeps none.
#[test]
fn a_version_seven_unreadable_part_file_keeps_its_os_error_number() {
    let v3_row = |name: &str, byte: u8, failure: DownloadFailureV3| {
        let v2 = v2_row(name, byte, DownloadFailureV2::ServerFiltered);
        DownloadRowV3 {
            file_hash: v2.file_hash,
            file_size: v2.file_size,
            canonical_link: v2.canonical_link,
            server: v2.server,
            final_path: v2.final_path,
            part_path: v2.part_path,
            lifecycle: v2.lifecycle,
            verification_authority: v2.verification_authority,
            file_name: v2.file_name,
            metadata_origin: v2.metadata_origin,
            failure: Some(failure),
        }
    };
    let unreadable = |message: &str| {
        DownloadFailureV3::StorageIntegrityFailed(StorageIntegrityFaultV3::PartFileUnreadable(
            message.to_owned(),
        ))
    };
    let dir = tempfile::tempdir().unwrap();
    {
        let v7 = DurableStore::open(
            dir.path().join(crate::store::DURABLE_STORE_FILE),
            &Schema::new().indexed(&DOWNLOADS_V3),
            &Ladder::new(7, &[]),
        )
        .unwrap();
        v7.write(|txn| {
            DOWNLOADS_V3.insert(
                txn,
                &4,
                &v3_row("a.bin", 0xA1, unreadable("Permission denied (os error 13)")),
            )?;
            DOWNLOADS_V3.insert(txn, &5, &v3_row("b.bin", 0xB2, unreadable("stream ended")))?;
            DOWNLOADS_V3.insert(
                txn,
                &6,
                &v3_row("c.bin", 0xC3, DownloadFailureV3::ServerFiltered),
            )
        })
        .unwrap();
    }
    let repo = DurableDownloadRepository::new(open_durable_store(dir.path()).unwrap());
    let failure = |id| {
        repo.load_download(DownloadId::from_u64(id))
            .unwrap()
            .failure()
            .cloned()
    };
    assert_eq!(
        failure(4),
        Some(DownloadFailure::StorageIntegrityFailed(
            StorageIntegrityFault::PartFileUnreadable { os_code: Some(13) }
        ))
    );
    assert_eq!(
        failure(5),
        Some(DownloadFailure::StorageIntegrityFailed(
            StorageIntegrityFault::PartFileUnreadable { os_code: None }
        ))
    );
    assert_eq!(failure(6), Some(DownloadFailure::ServerFiltered));
    assert_eq!(repo.live_downloads().unwrap().len(), 3);
}

/// A version-8 store's download row climbs to version 9: the server
/// it named becomes its source hint, and a row created after the rung may
/// name none.
#[test]
fn a_version_eight_download_row_keeps_its_server_as_a_source_hint() {
    let v2 = v2_row("hinted.bin", 0xD4, DownloadFailureV2::ServerFiltered);
    let server = v2.server.clone();
    let dir = tempfile::tempdir().unwrap();
    {
        let v8 = DurableStore::open(
            dir.path().join(crate::store::DURABLE_STORE_FILE),
            &Schema::new().indexed(&DOWNLOADS_V4),
            &Ladder::new(8, &[]),
        )
        .unwrap();
        v8.write(|txn| {
            DOWNLOADS_V4.insert(
                txn,
                &9,
                &DownloadRowV4 {
                    file_hash: v2.file_hash,
                    file_size: v2.file_size,
                    canonical_link: v2.canonical_link,
                    server: v2.server,
                    final_path: v2.final_path,
                    part_path: v2.part_path,
                    lifecycle: DownloadLifecycleV1::Paused,
                    verification_authority: Some(VerificationAuthorityV1::PeerHashSet),
                    file_name: v2.file_name,
                    metadata_origin: v2.metadata_origin,
                    failure: None,
                },
            )
        })
        .unwrap();
    }
    let repo = DurableDownloadRepository::new(open_durable_store(dir.path()).unwrap());
    let record = repo.load_download(DownloadId::from_u64(9)).unwrap();
    assert_eq!(record.source_hint(), Some(&server));
    assert_eq!(record.lifecycle(), DownloadLifecycle::Paused);
    assert_eq!(
        record.verification_authority(),
        Some(crate::VerificationAuthority::PeerHashSet)
    );

    let unhinted = repo
        .create_download(
            &rmule_testkit::file_link("kad-only.bin", b"kad only"),
            None,
            &crate::DownloadPaths::from_final_path(dir.path().join("kad-only.bin")),
            None,
        )
        .unwrap();
    assert_eq!(
        repo.load_download(unhinted.id()).unwrap().source_hint(),
        None
    );
}

const EXPECTED: [u8; 16] = [0x11; 16];
const FOUND: [u8; 16] = [0x22; 16];

fn mismatch() -> PartFaultV3 {
    PartFaultV3::HashMismatch {
        part_index: 1,
        expected: rmule_primitives::PartHash::from_bytes(EXPECTED),
        found: rmule_primitives::PartHash::from_bytes(FOUND),
    }
}

fn bytes(prefix: &[u8], tail: &[&[u8]]) -> Vec<u8> {
    let mut all = prefix.to_vec();
    for part in tail {
        all.extend_from_slice(part);
    }
    all
}

/// The version-8 failure reason is read by variant position: every variant
/// of the frozen shape encodes to the bytes a version-8 store holds, so a
/// live enum that changes can never change what they mean.
#[test]
fn every_frozen_version_eight_failure_encodes_as_version_eight_wrote_it() {
    let integrity = DownloadFailureV4::StorageIntegrityFailed;
    let cases: Vec<(DownloadFailureV4, Vec<u8>)> = vec![
        (DownloadFailureV4::NoUsableSources, vec![0]),
        (DownloadFailureV4::HashSetMismatch, vec![1]),
        (DownloadFailureV4::Cancelled, vec![2]),
        (DownloadFailureV4::Paused, vec![3]),
        (DownloadFailureV4::ServerDisconnected, vec![4]),
        (DownloadFailureV4::ServerFiltered, vec![5]),
        (DownloadFailureV4::SourceLookupTimedOut, vec![6]),
        (DownloadFailureV4::PeerDisconnected, vec![7]),
        (DownloadFailureV4::PartVerificationFailed, vec![8]),
        (
            integrity(StorageIntegrityFaultV4::PartFileMissing),
            vec![9, 0],
        ),
        (
            integrity(StorageIntegrityFaultV4::PartFileUnreadable { os_code: Some(13) }),
            vec![9, 1, 1, 26],
        ),
        (
            integrity(StorageIntegrityFaultV4::PartFileUnreadable { os_code: None }),
            vec![9, 1, 0],
        ),
        (
            integrity(StorageIntegrityFaultV4::NoPartHolds {
                recorded: 3,
                first: PartFaultV3::Short {
                    part_index: 2,
                    expected_end: 300,
                    found_len: 5,
                },
            }),
            vec![9, 2, 3, 0, 2, 0xAC, 0x02, 5],
        ),
        (
            integrity(StorageIntegrityFaultV4::NoPartHolds {
                recorded: 1,
                first: mismatch(),
            }),
            bytes(&[9, 2, 1, 1, 1], &[&EXPECTED, &FOUND]),
        ),
    ];
    for (failure, encoded) in cases {
        assert_eq!(
            postcard::to_allocvec(&failure).unwrap(),
            encoded,
            "{failure:?}"
        );
        assert_eq!(
            postcard::from_bytes::<DownloadFailureV4>(&encoded).unwrap(),
            failure
        );
    }
}

/// The version-7 fault's part is the same frozen shape.
#[test]
fn the_frozen_version_seven_fault_encodes_as_version_seven_wrote_it() {
    let fault = StorageIntegrityFaultV3::NoPartHolds {
        recorded: 1,
        first: mismatch(),
    };
    assert_eq!(
        postcard::to_allocvec(&DownloadFailureV3::StorageIntegrityFailed(fault)).unwrap(),
        bytes(&[9, 2, 1, 1, 1], &[&EXPECTED, &FOUND])
    );
    assert_eq!(
        postcard::to_allocvec(&DownloadFailureV3::StorageIntegrityFailed(
            StorageIntegrityFaultV3::PartFileUnreadable("x".into())
        ))
        .unwrap(),
        vec![9, 1, 1, b'x']
    );
}

/// A version-8 row failed with a part fault climbs to the live reason it
/// stood for.
#[test]
fn a_version_eight_part_fault_climbs_to_the_live_fault() {
    let v2 = v2_row("faulted.bin", 0xE5, DownloadFailureV2::ServerFiltered);
    let dir = tempfile::tempdir().unwrap();
    {
        let v8 = DurableStore::open(
            dir.path().join(crate::store::DURABLE_STORE_FILE),
            &Schema::new().indexed(&DOWNLOADS_V4),
            &Ladder::new(8, &[]),
        )
        .unwrap();
        v8.write(|txn| {
            DOWNLOADS_V4.insert(
                txn,
                &3,
                &DownloadRowV4 {
                    file_hash: v2.file_hash,
                    file_size: v2.file_size,
                    canonical_link: v2.canonical_link,
                    server: v2.server,
                    final_path: v2.final_path,
                    part_path: v2.part_path,
                    lifecycle: DownloadLifecycleV1::Failed,
                    verification_authority: None,
                    file_name: v2.file_name,
                    metadata_origin: v2.metadata_origin,
                    failure: Some(DownloadFailureV4::StorageIntegrityFailed(
                        StorageIntegrityFaultV4::NoPartHolds {
                            recorded: 1,
                            first: mismatch(),
                        },
                    )),
                },
            )
        })
        .unwrap();
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
                    expected: rmule_primitives::PartHash::from_bytes(EXPECTED),
                    found: rmule_primitives::PartHash::from_bytes(FOUND),
                },
            }
        ))
    );
}

/// The lifecycle, authority and origin of a version-1 to version-8 row are
/// read by variant position: every variant of each frozen copy encodes to the
/// byte those stores hold.
#[test]
fn every_frozen_row_enum_encodes_as_versions_one_to_eight_wrote_it() {
    let lifecycles = [
        (DownloadLifecycleV1::Queued, 0),
        (DownloadLifecycleV1::Active, 1),
        (DownloadLifecycleV1::Paused, 2),
        (DownloadLifecycleV1::Failed, 3),
        (DownloadLifecycleV1::Completed, 4),
        (DownloadLifecycleV1::Cancelled, 5),
    ];
    for (lifecycle, byte) in lifecycles {
        assert_eq!(postcard::to_allocvec(&lifecycle).unwrap(), [byte]);
        assert_eq!(
            postcard::from_bytes::<DownloadLifecycleV1>(&[byte]).unwrap(),
            lifecycle
        );
    }
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
