//! Seam-level contract for `DownloadRepository`: the same persist → finalize →
//! revalidate sequence behaves identically against the Durable Store
//! repository on a file and on the engine's in-memory backend, so no caller
//! can tell which of the two answers behind the seam.

use rmule_core::open_durable_store;
use std::path::Path;

use crate::fixture::stub_server;
use rmule_core::{
    ContentFileStore, DownloadLifecycle, DownloadPaths, DownloadRepository,
    DurableDownloadRepository, PartFault, ResolvedAuthority, Revalidation, VerifiedPartRecord,
};
use rmule_primitives::{ED2K_PART_SIZE, Ed2kFileLink, Ed2kText, FileHash, PartHash, UserHash};
use rmule_testkit::file_link;

/// The durable repository on the engine's in-memory backend — one
/// implementation, no twin (ADR-0083).
fn store_in_memory() -> DurableDownloadRepository {
    DurableDownloadRepository::new(rmule_testkit::memory_store())
}

/// The same repository on a real file in `dir`.
fn store_on_file(dir: &Path) -> DurableDownloadRepository {
    DurableDownloadRepository::new(open_durable_store(dir).unwrap())
}

/// One full part plus a tail, so assembly order and per-part hashes both
/// matter.
fn fixture_bytes() -> Vec<u8> {
    let mut bytes = vec![0xAB; ED2K_PART_SIZE as usize];
    bytes.extend_from_slice(b"tail");
    bytes
}

fn part_record(part_index: u32, offset: u64, len: u64, part_hash: PartHash) -> VerifiedPartRecord {
    VerifiedPartRecord {
        part_index,
        offset,
        len,
        part_hash,
    }
}

/// A part as a run leaves it: its bytes in the part file, then its record.
async fn persist(
    repo: &DurableDownloadRepository,
    paths: &DownloadPaths,
    id: rmule_core::DownloadId,
    part: VerifiedPartRecord,
    bytes: &[u8],
) {
    ContentFileStore::write_verified_part(paths, part.offset, bytes)
        .await
        .unwrap();
    repo.record_verified_part(id, part).unwrap();
}

/// The happy sequence: parts persisted out of order (assembly is the
/// repository's business), revalidation restores the full progress, and
/// finalize verifies the assembled content and promotes to `Completed`.
async fn persists_and_revalidates(repo: DurableDownloadRepository, paths: &DownloadPaths) {
    let bytes = fixture_bytes();
    let link = file_link("contract.bin", &bytes);
    let hashes = link.part_hash_set.as_ref().unwrap().hashes().to_vec();
    let id = repo
        .create_download(&link, Some(&stub_server("127.0.0.1")), paths, None)
        .unwrap()
        .id();
    repo.set_lifecycle(id, DownloadLifecycle::Active).unwrap();
    let (first, tail) = bytes.split_at(ED2K_PART_SIZE as usize);

    persist(
        &repo,
        paths,
        id,
        part_record(1, ED2K_PART_SIZE, tail.len() as u64, hashes[1]),
        tail,
    )
    .await;
    persist(
        &repo,
        paths,
        id,
        part_record(0, 0, first.len() as u64, hashes[0]),
        first,
    )
    .await;

    let Revalidation::Restored { progress, damaged } = repo.revalidate(id).await.unwrap() else {
        panic!("an intact part file is not condemned");
    };
    assert!(damaged.is_empty());
    assert_eq!(progress.verified_parts(), 2);
    assert_eq!(progress.verified_bytes(), bytes.len() as u64);
}

/// Corrupted bytes behind a genuine-looking record: revalidation drops the
/// damaged part and keeps the other, and re-persisting the genuine part
/// repairs the download.
async fn corrupted_bytes_fail_revalidation(repo: DurableDownloadRepository, paths: &DownloadPaths) {
    let bytes = fixture_bytes();
    let link = file_link("contract.bin", &bytes);
    let hashes = link.part_hash_set.as_ref().unwrap().hashes().to_vec();
    let id = repo
        .create_download(&link, Some(&stub_server("127.0.0.1")), paths, None)
        .unwrap()
        .id();
    repo.set_lifecycle(id, DownloadLifecycle::Active).unwrap();
    let (first, tail) = bytes.split_at(ED2K_PART_SIZE as usize);

    persist(
        &repo,
        paths,
        id,
        part_record(1, ED2K_PART_SIZE, tail.len() as u64, hashes[1]),
        tail,
    )
    .await;
    // Part 0's stored bytes are corrupted: the record claims the genuine part
    // hash, but different bytes went through the seam.
    let corrupt = vec![0xEE; first.len()];
    persist(
        &repo,
        paths,
        id,
        part_record(0, 0, first.len() as u64, hashes[0]),
        &corrupt,
    )
    .await;

    // Resume-time revalidation drops the damaged part alone: its record
    // goes, the other part's stays, so a resume fetches only part 0.
    let Revalidation::Restored { progress, damaged } = repo.revalidate(id).await.unwrap() else {
        panic!("one intact part keeps the part file");
    };
    assert!(
        matches!(
            damaged.as_slice(),
            [PartFault::HashMismatch { part_index: 0, expected, found }]
                if *expected == hashes[0] && found != expected
        ),
        "{damaged:?}"
    );
    assert_eq!(progress.verified_parts(), 1);
    let held: Vec<u32> = repo
        .verified_parts(id)
        .unwrap()
        .iter()
        .map(|part| part.part_index)
        .collect();
    assert_eq!(held, vec![1]);

    // Re-persisting the genuine part repairs the download: both hold again.
    persist(
        &repo,
        paths,
        id,
        part_record(0, 0, first.len() as u64, hashes[0]),
        first,
    )
    .await;
    let Revalidation::Restored { progress, damaged } = repo.revalidate(id).await.unwrap() else {
        panic!("a repaired part file is not condemned");
    };
    assert!(damaged.is_empty(), "{damaged:?}");
    assert_eq!(progress.verified_parts(), 2);
}

/// The three verification-authority outcomes resolve identically behind the
/// seam. A link carrying a `p=` set answers `Link` even though its provisional
/// child rows stay empty by design (recording them is refused); a link without
/// one but with recorded peer hashes answers `Provisional`; a file with neither
/// answers `FileHashOnly`.
async fn hash_authority_resolves_link_provisional_and_none<R: DownloadRepository>(
    repo: R,
    dir: &Path,
) {
    // Link authority: the canonical link's `p=` set wins, and the provisional
    // child rows are empty by design (the seam refuses to record them).
    let bytes = fixture_bytes();
    let link = file_link("contract.bin", &bytes);
    let link_hashes = link.part_hash_set.as_ref().unwrap().hashes().to_vec();
    let link_paths = DownloadPaths::from_final_path(dir.join("link.bin"));
    let link_id = repo
        .create_download(&link, Some(&stub_server("127.0.0.1")), &link_paths, None)
        .unwrap()
        .id();
    assert!(repo.provisional_part_hashes(link_id).unwrap().is_empty());
    assert_eq!(
        repo.hash_authority(link_id).unwrap(),
        ResolvedAuthority::Link(link_hashes),
    );

    // Provisional authority: the canonical link carried no `p=` set (a hashless
    // magnet), so peer hashes recorded after the fact are what answers.
    let peer_hashes = vec![
        PartHash::from_bytes([0x11; PartHash::BYTE_LEN]),
        PartHash::from_bytes([0x22; PartHash::BYTE_LEN]),
    ];
    let hashless = Ed2kFileLink {
        name: Ed2kText::from_utf8("provisional.bin"),
        size: ED2K_PART_SIZE + 4,
        file_hash: FileHash::from_bytes([0x33; FileHash::BYTE_LEN]),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    };
    let prov_paths = DownloadPaths::from_final_path(dir.join("provisional.bin"));
    let prov_id = repo
        .create_download(
            &hashless,
            Some(&stub_server("127.0.0.1")),
            &prov_paths,
            None,
        )
        .unwrap()
        .id();
    repo.record_provisional_part_hashes(prov_id, &peer_hashes)
        .unwrap();
    assert_eq!(
        repo.hash_authority(prov_id).unwrap(),
        ResolvedAuthority::Provisional(peer_hashes),
    );

    // No authority: neither a link `p=` set nor recorded peer hashes.
    let hashless_small = Ed2kFileLink {
        name: Ed2kText::from_utf8("none.bin"),
        size: 128,
        file_hash: FileHash::from_bytes([0x44; FileHash::BYTE_LEN]),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    };
    let none_paths = DownloadPaths::from_final_path(dir.join("none.bin"));
    let none_id = repo
        .create_download(
            &hashless_small,
            Some(&stub_server("127.0.0.1")),
            &none_paths,
            None,
        )
        .unwrap()
        .id();
    assert_eq!(
        repo.hash_authority(none_id).unwrap(),
        ResolvedAuthority::FileHashOnly,
    );
}

#[tokio::test]
async fn store_in_memory_persists_and_revalidates() {
    let dir = tempfile::tempdir().unwrap();
    let paths = DownloadPaths::from_final_path(dir.path().join("contract.bin"));
    persists_and_revalidates(store_in_memory(), &paths).await;
}

#[tokio::test]
async fn store_on_file_persists_and_revalidates() {
    let dir = tempfile::tempdir().unwrap();
    let paths = DownloadPaths::from_final_path(dir.path().join("contract.bin"));
    persists_and_revalidates(store_on_file(dir.path()), &paths).await;
}

#[tokio::test]
async fn store_in_memory_corrupted_bytes_fail_revalidation() {
    let dir = tempfile::tempdir().unwrap();
    let paths = DownloadPaths::from_final_path(dir.path().join("contract.bin"));
    corrupted_bytes_fail_revalidation(store_in_memory(), &paths).await;
}

#[tokio::test]
async fn store_on_file_corrupted_bytes_fail_revalidation() {
    let dir = tempfile::tempdir().unwrap();
    let paths = DownloadPaths::from_final_path(dir.path().join("contract.bin"));
    corrupted_bytes_fail_revalidation(store_on_file(dir.path()), &paths).await;
}

#[tokio::test]
async fn store_in_memory_hash_authority_resolves_link_provisional_and_none() {
    let dir = tempfile::tempdir().unwrap();
    hash_authority_resolves_link_provisional_and_none(store_in_memory(), dir.path()).await;
}

#[tokio::test]
async fn store_on_file_hash_authority_resolves_link_provisional_and_none() {
    let dir = tempfile::tempdir().unwrap();
    hash_authority_resolves_link_provisional_and_none(store_on_file(dir.path()), dir.path()).await;
}

/// A peer a download distrusts is held by the download's durable
/// record: it survives a restart, and distrusting it twice keeps one entry.
#[test]
fn a_distrusted_peer_survives_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let paths = DownloadPaths::from_final_path(dir.path().join("contract.bin"));
    let link = file_link("contract.bin", &fixture_bytes());
    let peer = UserHash::from_bytes([0xBA; UserHash::BYTE_LEN]);

    let repo = store_on_file(dir.path());
    let id = repo
        .create_download(&link, Some(&stub_server("127.0.0.1")), &paths, None)
        .unwrap()
        .id();
    repo.distrust_peer(id, peer).unwrap();
    repo.distrust_peer(id, peer).unwrap();
    drop(repo);

    assert_eq!(
        store_on_file(dir.path()).distrusted_peers(id).unwrap(),
        vec![peer]
    );
}

/// A download keeps the Kad AICH root it was started from, and the contest
/// that ends it, across a restart (ADR-0038).
#[test]
fn a_kad_aich_root_and_its_contest_survive_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let paths = DownloadPaths::from_final_path(dir.path().join("rooted.bin"));
    let link = file_link("rooted.bin", &fixture_bytes());
    let root = rmule_primitives::AichRootHash::from_bytes([0xA1; 20]);

    let repo = store_on_file(dir.path());
    let id = repo
        .create_download(&link, None, &paths, Some(root))
        .unwrap()
        .id();
    drop(repo);
    let repo = store_on_file(dir.path());
    assert_eq!(
        repo.load_download(id).unwrap().kad_aich_root(),
        Some(rmule_core::KadAichRoot::Trusted(root))
    );

    repo.contest_kad_aich_root(id).unwrap();
    drop(repo);
    assert_eq!(
        store_on_file(dir.path())
            .load_download(id)
            .unwrap()
            .kad_aich_root(),
        Some(rmule_core::KadAichRoot::Contested)
    );
}
