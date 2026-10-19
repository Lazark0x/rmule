//! The whole ladder from the store an operator's disk holds: every seam's
//! tables as store version 1 declared them — indexes included — a row in
//! each table a rung touches, climbed to today's version in one open, then
//! read back through the seams, their indexes and their counters.

use std::sync::Arc;

use rmule_primitives::{PartHash, ServerEndpoint, UserHash};
use rmule_store::{Ladder, Schema};

use super::{DURABLE_STORE_FILE, DurableStore, open_durable_store};
use crate::registry::{ShareSource, SharedFileEntry, SharedFileRegistry};
use crate::server_list::{ManagedServer, ServerListStore, ServerMerge};
use crate::storage::{DownloadRepository, ResolvedAuthority};
use crate::store::app_config::DurableAppConfig;
use crate::store::download::DurableDownloadRepository;
use crate::store::registry::DurableSharedFileRegistry;
use crate::{
    CoreError, DownloadId, DownloadLifecycle, DownloadPaths, VerificationAuthority,
    VerifiedPartRecord,
};

/// Every table the version-1 store declared, as it declared it.
fn schema_v1() -> Schema {
    super::credit::schema()
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
            super::app_config::add_server_v1(txn, &server, "kept server")?;
            Ok::<_, rmule_store::StoreError>(key)
        })
        .unwrap()
    };

    let store = open_durable_store(dir.path()).unwrap();
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
