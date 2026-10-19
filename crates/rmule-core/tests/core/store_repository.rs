//! The durable download repository on `rmule-store`: what a reopen recovers
//! (name, exact size, canonical link, verified and provisional part hashes),
//! the two creation guards — identity keyed on hash and size rather than
//! filename, and the `.part` path no second row may claim — and the lifecycle
//! transitions the store admits.
use rmule_core::DownloadRepository;
use rmule_core::open_durable_store;
use std::fs;
use std::path::Path;

use crate::fixture::{stub_link, stub_server};
use rmule_core::{
    CoreError, DownloadId, DownloadLifecycle, DownloadMetadataOrigin, DownloadPaths,
    DurableDownloadRecord, DurableDownloadRepository, VerificationAuthority, VerifiedPartRecord,
};
use rmule_primitives::{ED2K_PART_SIZE, Ed2kFileLink, Ed2kLink, Ed2kText, FileHash, PartHash};

/// Open (creating if absent) the store in data directory `dir` and hand back
/// a repository over it. Dropping the repository closes the file, which is
/// what a "reopen" needs — the engine holds an exclusive lock.
fn repository(dir: &Path) -> DurableDownloadRepository {
    DurableDownloadRepository::new(open_durable_store(dir).unwrap())
}

fn create(repo: &DurableDownloadRepository, dir: &Path, name: &str) -> DurableDownloadRecord {
    repo.create_download(
        &stub_link(name, 1234, 0x01),
        Some(&stub_server("example.org")),
        &DownloadPaths::from_final_path(dir.join(name)),
        None,
    )
    .unwrap()
}

#[test]
fn download_name_and_exact_size_survive_a_store_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let store_path = dir.path();
    // A real-world ED2K name: spaces plus a Windows-1252 byte that is not
    // valid UTF-8 (ADR-0019), and a size no part count could approximate.
    let name = Ed2kText::from_bytes(b"caf\xE9 clip.avi".to_vec());
    let file = Ed2kFileLink {
        name: name.clone(),
        size: 9_663_676_416,
        file_hash: FileHash::from_bytes([0x5A; FileHash::BYTE_LEN]),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    };

    let repo = repository(store_path);
    let created = repo
        .create_download(
            &file,
            Some(&stub_server("example.org")),
            &DownloadPaths::from_final_path(dir.path().join("download.bin")),
            None,
        )
        .unwrap();
    drop(repo);

    let repo = repository(store_path);
    let loaded = repo.load_download(created.id()).unwrap();
    assert_eq!(loaded.metadata().name, name);
    assert_eq!(loaded.metadata().size, file.size);
    assert_eq!(loaded.metadata().origin, DownloadMetadataOrigin::Link);
    assert_eq!(loaded.file_size(), file.size);
    // The restart projection is a second read — it must carry the same facts.
    let recovered = repo.live_downloads().unwrap();
    assert_eq!(
        recovered
            .iter()
            .map(DurableDownloadRecord::metadata)
            .collect::<Vec<_>>(),
        vec![loaded.metadata()]
    );
}

#[test]
fn duplicate_live_download_uses_file_hash_and_size_not_filename() {
    let dir = tempfile::tempdir().unwrap();
    let repo = repository(dir.path());
    let server = stub_server("example.org");

    repo.create_download(
        &stub_link("first.bin", 1234, 0x01),
        Some(&server),
        &DownloadPaths::from_final_path(dir.path().join("first.bin")),
        None,
    )
    .unwrap();

    let err = repo
        .create_download(
            &stub_link("renamed.bin", 1234, 0x01),
            Some(&server),
            &DownloadPaths::from_final_path(dir.path().join("renamed.bin")),
            None,
        )
        .unwrap_err();

    assert_eq!(err, CoreError::DuplicateDownloadIdentity);
}

#[test]
fn a_part_path_another_row_already_writes_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let repo = repository(dir.path());
    let paths = DownloadPaths::from_final_path(dir.path().join("shared.bin"));

    repo.create_download(
        &stub_link("first.bin", 1234, 0x01),
        Some(&stub_server("a.org")),
        &paths,
        None,
    )
    .unwrap();

    // A different file entirely, so the identity guard does not fire — the
    // two rows would still write the same `.part`.
    let err = repo
        .create_download(
            &stub_link("other.bin", 5678, 0x02),
            Some(&stub_server("a.org")),
            &paths,
            None,
        )
        .unwrap_err();

    assert_eq!(err, CoreError::PathConflict);
}

#[test]
fn created_download_persists_canonical_file_link() {
    let dir = tempfile::tempdir().unwrap();
    let repo = repository(dir.path());
    let canonical = "ed2k://|file|name%20with%20spaces.bin|1234|0102030405060708090A0B0C0D0E0F10|/";
    let Ok(Ed2kLink::File(file)) = Ed2kLink::parse(canonical) else {
        unreachable!("fixture is a file link")
    };

    let created = repo
        .create_download(
            &file,
            Some(&stub_server("example.org")),
            &DownloadPaths::from_final_path(dir.path().join("download.bin")),
            None,
        )
        .unwrap();

    assert_eq!(
        repo.load_download(created.id()).unwrap().canonical_link(),
        canonical
    );
}

#[test]
fn existing_final_output_path_is_rejected_before_creating_record() {
    let dir = tempfile::tempdir().unwrap();
    let repo = repository(dir.path());
    let final_path = dir.path().join("already-there.bin");
    fs::write(&final_path, b"existing").unwrap();

    let err = repo
        .create_download(
            &stub_link("already-there.bin", 1234, 0x01),
            Some(&stub_server("example.org")),
            &DownloadPaths::from_final_path(final_path.clone()),
            None,
        )
        .unwrap_err();
    assert_eq!(err, CoreError::PathConflict);

    fs::remove_file(&final_path).unwrap();
    let created = repo
        .create_download(
            &stub_link("already-there.bin", 1234, 0x01),
            Some(&stub_server("example.org")),
            &DownloadPaths::from_final_path(final_path),
            None,
        )
        .unwrap();
    // The refused create consumed no id: the counter only moves on success.
    assert_eq!(created.id(), DownloadId::from_u64(1));
}

#[test]
fn lifecycle_allows_pause_resume_and_completion_path() {
    let dir = tempfile::tempdir().unwrap();
    let repo = repository(dir.path());
    let created = create(&repo, dir.path(), "download.bin");

    for state in [
        DownloadLifecycle::Active,
        DownloadLifecycle::Paused,
        DownloadLifecycle::Active,
        DownloadLifecycle::Completing,
        // A Pause before the file is in place, and the repair of a copy whose
        // bytes changed, both leave the move (ADR-0115).
        DownloadLifecycle::Paused,
        DownloadLifecycle::Active,
        DownloadLifecycle::Completing,
        DownloadLifecycle::Active,
        DownloadLifecycle::Completing,
        DownloadLifecycle::Completed,
    ] {
        repo.set_lifecycle(created.id(), state).unwrap();
    }

    assert_eq!(
        repo.load_download(created.id()).unwrap().lifecycle(),
        DownloadLifecycle::Completed
    );
}

/// A completing row stores its destination with its lifecycle, and names it
/// beside its part file as the download's own until it is completed: the
/// scan never reads the file the move puts there first (ADR-0115).
#[test]
fn a_completing_row_names_its_destination_as_its_own_until_it_completes() {
    let dir = tempfile::tempdir().unwrap();
    let repo = repository(dir.path());
    let created = create(&repo, dir.path(), "download.bin");
    let part = created.paths().part_path().to_path_buf();
    repo.set_lifecycle(created.id(), DownloadLifecycle::Active)
        .unwrap();
    let destination = dir.path().join("download (1).bin");

    repo.set_completing(created.id(), &destination).unwrap();

    let record = repo.load_download(created.id()).unwrap();
    assert_eq!(record.lifecycle(), DownloadLifecycle::Completing);
    assert_eq!(record.paths().final_path(), destination);
    let mut parts = repo.part_files().unwrap();
    parts.sort();
    assert_eq!(parts, vec![(destination, true), (part.clone(), true)]);

    repo.set_lifecycle(created.id(), DownloadLifecycle::Completed)
        .unwrap();
    assert_eq!(repo.part_files().unwrap(), vec![(part, false)]);
    assert_eq!(
        repo.set_completing(created.id(), dir.path()).unwrap_err(),
        CoreError::InvalidLifecycleTransition
    );
}

/// Every completion goes through `Completing`, which names the destination
/// before anything moves (ADR-0115).
#[test]
fn a_running_download_completes_only_through_completing() {
    let dir = tempfile::tempdir().unwrap();
    let repo = repository(dir.path());
    let created = create(&repo, dir.path(), "download.bin");
    repo.set_lifecycle(created.id(), DownloadLifecycle::Active)
        .unwrap();

    let err = repo
        .set_lifecycle(created.id(), DownloadLifecycle::Completed)
        .unwrap_err();

    assert_eq!(err, CoreError::InvalidLifecycleTransition);
}

#[test]
fn cancelled_lifecycle_is_terminal() {
    let dir = tempfile::tempdir().unwrap();
    let repo = repository(dir.path());
    let created = create(&repo, dir.path(), "download.bin");

    repo.set_lifecycle(created.id(), DownloadLifecycle::Cancelled)
        .unwrap();
    let err = repo
        .set_lifecycle(created.id(), DownloadLifecycle::Active)
        .unwrap_err();

    assert_eq!(err, CoreError::InvalidLifecycleTransition);
}

/// A restart reads a download the operator left running as running —
/// the read at attach rewrites nothing.
#[test]
fn a_restart_reads_a_running_download_as_running() {
    let dir = tempfile::tempdir().unwrap();
    let repo = repository(dir.path());
    let created = create(&repo, dir.path(), "download.bin");
    repo.set_lifecycle(created.id(), DownloadLifecycle::Active)
        .unwrap();

    let live = repo.live_downloads().unwrap();

    assert_eq!(live.len(), 1);
    assert_eq!(live[0].id(), created.id());
    assert_eq!(live[0].lifecycle(), DownloadLifecycle::Active);
    assert_eq!(
        repo.load_download(created.id()).unwrap().lifecycle(),
        DownloadLifecycle::Active
    );
}

#[test]
fn the_restart_read_keeps_each_row_as_the_last_process_left_it() {
    let dir = tempfile::tempdir().unwrap();
    let repo = repository(dir.path());
    let active = create(&repo, dir.path(), "active.bin");
    repo.set_lifecycle(active.id(), DownloadLifecycle::Active)
        .unwrap();
    let paused = repo
        .create_download(
            &stub_link("paused.bin", 5678, 0x02),
            Some(&stub_server("example.org")),
            &DownloadPaths::from_final_path(dir.path().join("paused.bin")),
            None,
        )
        .unwrap();
    repo.set_lifecycle(paused.id(), DownloadLifecycle::Paused)
        .unwrap();

    let recovered = repo.live_downloads().unwrap();
    let resumable = repo.list_resumable().unwrap();

    assert_eq!(
        recovered
            .iter()
            .map(|record| (record.id(), record.lifecycle()))
            .collect::<Vec<_>>(),
        vec![
            (active.id(), DownloadLifecycle::Active),
            (paused.id(), DownloadLifecycle::Paused)
        ]
    );
    assert_eq!(
        resumable
            .iter()
            .map(|record| (record.id(), record.lifecycle()))
            .collect::<Vec<_>>(),
        vec![(paused.id(), DownloadLifecycle::Paused)]
    );
}

#[test]
fn verified_part_records_persist_for_resume_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let store_path = dir.path();
    let repo = repository(store_path);
    let created = create(&repo, dir.path(), "download.bin");
    // Out of part order on the way in: the child key range reads them back in
    // part order regardless.
    let parts = [
        VerifiedPartRecord {
            part_index: 3,
            offset: 3 * ED2K_PART_SIZE,
            len: 1024,
            part_hash: PartHash::from_bytes([0x3a; PartHash::BYTE_LEN]),
        },
        VerifiedPartRecord {
            part_index: 1,
            offset: ED2K_PART_SIZE,
            len: ED2K_PART_SIZE,
            part_hash: PartHash::from_bytes([0x1a; PartHash::BYTE_LEN]),
        },
    ];

    for part in parts {
        repo.record_verified_part(created.id(), part).unwrap();
    }
    drop(repo);

    let repo = repository(store_path);
    assert_eq!(
        repo.verified_parts(created.id()).unwrap(),
        vec![parts[1], parts[0]]
    );
}

#[test]
fn re_verifying_a_part_replaces_its_child_rather_than_duplicating_it() {
    let dir = tempfile::tempdir().unwrap();
    let repo = repository(dir.path());
    let created = create(&repo, dir.path(), "download.bin");
    let repaired = VerifiedPartRecord {
        part_index: 0,
        offset: 0,
        len: 2048,
        part_hash: PartHash::from_bytes([0xBB; PartHash::BYTE_LEN]),
    };

    repo.record_verified_part(
        created.id(),
        VerifiedPartRecord {
            len: 1024,
            part_hash: PartHash::from_bytes([0xAA; PartHash::BYTE_LEN]),
            ..repaired
        },
    )
    .unwrap();
    repo.record_verified_part(created.id(), repaired).unwrap();

    assert_eq!(repo.verified_parts(created.id()).unwrap(), vec![repaired]);
}

#[test]
fn provisional_part_hashes_survive_a_store_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let store_path = dir.path();
    let repo = repository(store_path);
    let created = create(&repo, dir.path(), "download.bin");
    let hashes = vec![
        PartHash::from_bytes([0x11; PartHash::BYTE_LEN]),
        PartHash::from_bytes([0x22; PartHash::BYTE_LEN]),
    ];

    repo.record_provisional_part_hashes(created.id(), &hashes)
        .unwrap();
    drop(repo);

    let repo = repository(store_path);
    assert_eq!(repo.provisional_part_hashes(created.id()).unwrap(), hashes);
    assert_eq!(
        repo.load_download(created.id())
            .unwrap()
            .verification_authority(),
        Some(VerificationAuthority::PeerHashSet)
    );
}

#[test]
fn replacing_provisional_part_hashes_is_rejected_unless_identical() {
    let dir = tempfile::tempdir().unwrap();
    let repo = repository(dir.path());
    let created = create(&repo, dir.path(), "download.bin");
    let hashes = vec![PartHash::from_bytes([0x11; PartHash::BYTE_LEN])];

    repo.record_provisional_part_hashes(created.id(), &hashes)
        .unwrap();
    repo.record_provisional_part_hashes(created.id(), &hashes)
        .unwrap();

    let err = repo
        .record_provisional_part_hashes(
            created.id(),
            &[PartHash::from_bytes([0x22; PartHash::BYTE_LEN])],
        )
        .unwrap_err();

    assert_eq!(err, CoreError::ProvisionalAuthorityConflict);
}

#[test]
fn a_set_drops_the_parts_recorded_before_it_that_it_disproves() {
    let dir = tempfile::tempdir().unwrap();
    let repo = repository(dir.path());
    let created = create(&repo, dir.path(), "download.bin");
    let hashes: Vec<PartHash> = [0x11, 0x22, 0x33]
        .map(|byte| PartHash::from_bytes([byte; PartHash::BYTE_LEN]))
        .to_vec();
    let part = |part_index: u32, part_hash| VerifiedPartRecord {
        part_index,
        offset: u64::from(part_index) * ED2K_PART_SIZE,
        len: ED2K_PART_SIZE,
        part_hash,
    };
    let held = part(0, hashes[0]);
    let refuted = part(1, PartHash::from_bytes([0xEE; PartHash::BYTE_LEN]));
    repo.record_verified_part(created.id(), held).unwrap();
    repo.record_verified_part(created.id(), refuted).unwrap();

    assert_eq!(
        repo.record_provisional_part_hashes(created.id(), &hashes)
            .unwrap(),
        vec![refuted]
    );
    assert_eq!(repo.verified_parts(created.id()).unwrap(), vec![held]);
    assert!(
        repo.record_provisional_part_hashes(created.id(), &hashes)
            .unwrap()
            .is_empty(),
        "the set in force refutes nothing it already checked"
    );
}

#[test]
fn link_part_hash_authority_does_not_duplicate_hashes_as_child_rows() {
    let dir = tempfile::tempdir().unwrap();
    let repo = repository(dir.path());
    let bytes = vec![0xAB; ED2K_PART_SIZE as usize + 1];
    let file = rmule_testkit::file_link("with-p.bin", &bytes);

    let created = repo
        .create_download(
            &file,
            Some(&stub_server("example.org")),
            &DownloadPaths::from_final_path(dir.path().join("download.bin")),
            None,
        )
        .unwrap();

    assert_eq!(
        repo.load_download(created.id())
            .unwrap()
            .verification_authority(),
        Some(VerificationAuthority::LinkPartHashSet)
    );
    assert!(
        repo.provisional_part_hashes(created.id())
            .unwrap()
            .is_empty()
    );
    // Peer hashes cannot displace the link's own set.
    assert_eq!(
        repo.record_provisional_part_hashes(
            created.id(),
            &[PartHash::from_bytes([0x11; PartHash::BYTE_LEN])]
        )
        .unwrap_err(),
        CoreError::ProvisionalAuthorityConflict
    );
}

#[test]
fn an_unknown_download_is_refused_by_every_read() {
    let dir = tempfile::tempdir().unwrap();
    let repo = repository(dir.path());
    let ghost = DownloadId::from_u64(404);

    assert_eq!(
        repo.load_download(ghost).unwrap_err(),
        CoreError::UnknownDownload
    );
    assert_eq!(
        repo.verified_parts(ghost).unwrap_err(),
        CoreError::UnknownDownload
    );
    assert_eq!(
        repo.provisional_part_hashes(ghost).unwrap_err(),
        CoreError::UnknownDownload
    );
    assert_eq!(
        repo.set_lifecycle(ghost, DownloadLifecycle::Active)
            .unwrap_err(),
        CoreError::UnknownDownload
    );
}
