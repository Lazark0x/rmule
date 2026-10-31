//! The whole ladder from the store an operator's disk holds: every seam's
//! tables as store version 1 declared them — indexes included — a row in
//! each table a rung touches, climbed to today's version in one open, then
//! read back through the seams, their indexes and their counters.

use std::path::Path;
use std::sync::Arc;

use rmule_primitives::{PartHash, ServerEndpoint, UserHash};
use rmule_store::{Ladder, Schema, Store};

use super::{
    DURABLE_STORE_FILE, DurableStore, OpenRefusal, open_durable_store, open_durable_store_in_memory,
};
use crate::credit::CreditStore;
use crate::registry::{ShareSource, SharedFileEntry, SharedFileRegistry};
use crate::server_list::{ManagedServer, ServerListStore, ServerMerge};
use crate::storage::{DownloadRepository, ResolvedAuthority};
use crate::store::app_config::DurableAppConfig;
use crate::store::credit::DurableCreditStore;
use crate::store::download::DurableDownloadRepository;
use crate::store::registry::DurableSharedFileRegistry;
use crate::{
    CoreError, DownloadId, DownloadLifecycle, DownloadPaths, VerificationAuthority,
    VerifiedPartRecord,
};

/// Every table the version-1 store declared, as it declared it.
fn schema_v1() -> Schema {
    super::credit::schema_v1()
        .merge(super::download::schema_v1())
        .merge(super::registry::schema_v1())
        .merge(super::app_config::schema_v1())
}

#[test]
fn a_version_one_store_with_every_index_climbs_to_today_and_reads_back_whole() {
    let dir = tempfile::tempdir().unwrap();
    let downloads = dir.path().join("downloads");
    let file = rmule_testkit::file_link("kept.bin", &[0x6D; 64]);
    let paths = DownloadPaths::from_final_path(downloads.join("kept.bin"));
    let server = ServerEndpoint::new("10.9.8.7", 4661).unwrap();
    let part = VerifiedPartRecord {
        part_index: 0,
        offset: 0,
        len: 64,
        part_hash: PartHash::from_bytes([0x31; 16]),
    };
    let peer_hashes = vec![PartHash::from_bytes([0x41; 16])];
    let distrusted = UserHash::from_bytes([0x51; UserHash::BYTE_LEN]);
    let credited = UserHash::from_bytes([0x52; UserHash::BYTE_LEN]);
    let shared = SharedFileEntry {
        file_hash: rmule_primitives::FileHash::from_bytes([0x61; 16]),
        file_size: 2_000,
        path: "/share/shared.bin".into(),
        name: "shared.bin".into(),
        part_hashes: vec![PartHash::from_bytes([0x71; 16])],
        source: ShareSource::Explicit,
        modified: None,
    };
    let key = {
        let v1 = DurableStore::open(
            dir.path().join(DURABLE_STORE_FILE),
            &schema_v1(),
            &Ladder::new(1, &[]),
        )
        .unwrap();
        v1.write(|txn| {
            let key = super::download::seed_v1(
                txn,
                &file,
                &server,
                &paths,
                part,
                &peer_hashes,
                distrusted,
            )?;
            super::registry::share_v1(txn, &shared)?;
            super::credit::row_v1(txn, credited, 5_000_000)?;
            super::app_config::add_server_v1(txn, &server, "kept server")?;
            Ok::<_, rmule_store::StoreError>(key)
        })
        .unwrap()
    };

    let store = open_durable_store(dir.path()).unwrap();
    let credit = DurableCreditStore::new(Arc::clone(&store));
    assert_eq!(credit.totals(credited).unwrap().downloaded, 5_000_000);
    assert_ne!(
        credit.snapshot().unwrap()[0].last_seen,
        0,
        "it ages from the climb"
    );
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let id = DownloadId::from_u64(key);
    let record = repo.load_download(id).unwrap();
    assert_eq!(record.lifecycle(), DownloadLifecycle::Active);
    assert_eq!(record.source_hint(), Some(&server));
    assert_eq!(record.failure(), None);
    assert_eq!(
        record.verification_authority(),
        Some(VerificationAuthority::PeerHashSet)
    );
    assert_eq!(repo.verified_parts(id).unwrap(), vec![part]);
    assert_eq!(
        repo.hash_authority(id).unwrap(),
        ResolvedAuthority::Provisional(peer_hashes)
    );
    assert_eq!(repo.distrusted_peers(id).unwrap(), vec![distrusted]);

    // The part-path index still names the row.
    assert_eq!(
        repo.part_files().unwrap(),
        vec![(paths.part_path().to_path_buf(), true)]
    );
    let other = rmule_testkit::file_link("other.bin", &[0x7E; 64]);
    assert_eq!(
        repo.create_download(&other, None, &paths, None)
            .unwrap_err(),
        CoreError::PathConflict
    );
    // The identity index still names the row.
    let elsewhere = DownloadPaths::from_final_path(downloads.join("again.bin"));
    assert_eq!(
        repo.create_download(&file, None, &elsewhere, None)
            .unwrap_err(),
        CoreError::DuplicateDownloadIdentity
    );
    // The id counter goes on from the row it minted.
    let next = repo
        .create_download(&other, None, &elsewhere, None)
        .unwrap();
    assert_eq!(next.id(), DownloadId::from_u64(key + 1));

    let registry = DurableSharedFileRegistry::new(Arc::clone(&store));
    assert_eq!(registry.list().unwrap(), vec![shared]);

    let list = DurableAppConfig::new(store);
    let servers = list.servers().unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(
        (
            servers[0].endpoint.clone(),
            servers[0].name.to_display_string(),
            servers[0].fail_count,
            servers[0].figures.clone()
        ),
        (server.clone(), "kept server".to_string(), 2, None)
    );
    // The endpoint index still finds the row: the same endpoint folds in.
    assert_eq!(
        list.merge_server(ManagedServer::listed(server.clone()))
            .unwrap(),
        ServerMerge::Updated
    );
    assert_eq!(list.servers().unwrap().len(), 1);
    assert!(list.remove_server(&server).unwrap());
    assert!(list.servers().unwrap().is_empty());
}

/// The refusal is typed through to the front end: only a held file asks
/// about a second process.
#[test]
fn a_held_store_is_refused_as_busy_not_as_a_string() {
    let dir = tempfile::tempdir().unwrap();
    let held = open_durable_store(dir.path()).unwrap();
    assert!(matches!(
        open_durable_store(dir.path()).unwrap_err(),
        CoreError::StoreRefused {
            refusal: OpenRefusal::Busy,
            ..
        }
    ));
    drop(held);
}

#[cfg(unix)]
#[test]
fn a_new_store_is_born_private_and_an_old_one_is_repaired() {
    use std::os::unix::fs::PermissionsExt;

    let mode = |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode();
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    drop(open_durable_store(&data_dir).unwrap());
    let file = data_dir.join(DURABLE_STORE_FILE);
    assert_eq!(mode(&data_dir) & 0o777, 0o700);
    assert_eq!(mode(&file) & 0o777, 0o600);

    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    drop(open_durable_store(&data_dir).unwrap());
    assert_eq!(mode(&data_dir) & 0o777, 0o700);
    assert_eq!(mode(&file) & 0o777, 0o600);
}

fn a_download(repo: &DurableDownloadRepository, part: &Path) -> DownloadId {
    let link = rmule_testkit::file_link("moved.bin", &[0x6D; 64]);
    let paths = DownloadPaths::new(part.with_extension("bin"), part.to_path_buf());
    repo.create_download(&link, None, &paths, None)
        .unwrap()
        .id()
}

/// The migration the review names: a new disk, a renamed home. Every row
/// follows the directory, and nothing has to rewrite it.
#[test]
fn a_moved_data_directory_carries_its_part_paths() {
    let dir = tempfile::tempdir().unwrap();
    let (old, new) = (dir.path().join("old"), dir.path().join("new"));
    let store = open_durable_store(&old).unwrap();
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let id = a_download(&repo, &old.join("Temp/film.part"));
    assert_eq!(
        repo.load_download(id).unwrap().paths().part_path(),
        old.join("Temp/film.part")
    );
    drop((repo, store));

    std::fs::rename(&old, &new).unwrap();
    let repo = DurableDownloadRepository::new(open_durable_store(&new).unwrap());
    assert_eq!(
        repo.load_download(id).unwrap().paths().part_path(),
        new.join("Temp/film.part")
    );
    assert_eq!(
        repo.part_files().unwrap(),
        vec![(new.join("Temp/film.part"), true)]
    );
}

#[test]
fn a_part_path_outside_the_data_directory_stays_where_it_was_placed() {
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = dir.path().join("elsewhere/film.part");
    let repo =
        DurableDownloadRepository::new(open_durable_store(&dir.path().join("data")).unwrap());
    let id = a_download(&repo, &elsewhere);
    assert_eq!(
        repo.load_download(id).unwrap().paths().part_path(),
        elsewhere
    );
}

/// A row version 16 wrote names its part file absolutely; the climb makes it
/// relative, so the first move after the upgrade already carries it.
#[test]
fn the_climb_to_seventeen_roots_a_stored_absolute_part_path() {
    let dir = tempfile::tempdir().unwrap();
    let (seeded, home, moved) = (
        dir.path().join("seeded"),
        dir.path().join("home"),
        dir.path().join("moved"),
    );
    std::fs::create_dir(&seeded).unwrap();
    // Written from another directory, so the row keeps the absolute text a
    // version-16 build wrote for a part inside `home`.
    let store = Store::open(
        seeded.join(DURABLE_STORE_FILE),
        &super::durable_schema(),
        &Ladder::new(16, &[]),
    )
    .unwrap();
    let repo = DurableDownloadRepository::new(Arc::new(store));
    let id = a_download(&repo, &home.join("Temp/film.part"));
    drop(repo);

    std::fs::rename(&seeded, &home).unwrap();
    let store = open_durable_store(&home).unwrap();
    assert_eq!(store.version().unwrap(), super::LADDER.current);
    assert!(home.join(format!("{DURABLE_STORE_FILE}.v16")).exists());
    drop(store);

    std::fs::rename(&home, &moved).unwrap();
    let repo = DurableDownloadRepository::new(open_durable_store(&moved).unwrap());
    assert_eq!(
        repo.load_download(id).unwrap().paths().part_path(),
        moved.join("Temp/film.part")
    );
}

#[test]
fn a_cancelled_row_keeps_no_children_and_its_path_can_be_given_up() {
    let repo = DurableDownloadRepository::new(open_durable_store_in_memory().unwrap());
    let id = a_download(&repo, Path::new("/temp/film.part"));
    repo.record_verified_part(
        id,
        VerifiedPartRecord {
            part_index: 0,
            offset: 0,
            len: 64,
            part_hash: PartHash::from_bytes([1; 16]),
        },
    )
    .unwrap();
    repo.set_lifecycle(id, DownloadLifecycle::Cancelled)
        .unwrap();
    assert_eq!(repo.verified_parts(id).unwrap(), Vec::new());

    assert_eq!(repo.cancelled_part_files().unwrap().len(), 1);
    repo.part_file_gone(id).unwrap();
    assert_eq!(repo.cancelled_part_files().unwrap().len(), 0);
}

/// One flipped row reads as one lost row: the rest stay listed and startable,
/// and the operator hears a count rather than an empty tab.
#[test]
fn one_download_row_that_will_not_decode_costs_that_row() {
    let store = open_durable_store_in_memory().unwrap();
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let id = a_download(&repo, Path::new("/temp/film.part"));
    super::download::write_undecodable_row(&store, 99);

    let listed: Vec<_> = repo
        .listed_downloads()
        .unwrap()
        .iter()
        .map(|record| record.id())
        .collect();
    assert_eq!(listed, [id]);
    assert_eq!(repo.list_resumable().unwrap().len(), 1);
    assert_eq!(repo.unreadable_rows().unwrap(), 1);
}
