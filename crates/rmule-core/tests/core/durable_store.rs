//! The Durable Store's composition (ADR-0083): core merges the four seams'
//! schemas and opens one store, so every seam reads through the same handle.
//! A seam whose tables the merge dropped would fail its first read here, and a
//! data directory that did not carry `rmule.redb` would strand the legacy
//! import and both front-ends, which name the file through core.

use rmule_core::DownloadRepository;
use std::sync::Arc;

use rmule_core::{
    AppConfigStore, CreditStore, DURABLE_STORE_FILE, DurableAppConfig, DurableCreditStore,
    DurableDownloadRepository, DurableSharedFileRegistry, ServerListStore, SharedFileRegistry,
    open_durable_store, open_durable_store_in_memory,
};

/// The merged schema carries every seam's tables: each seam's first read on
/// the shared handle succeeds instead of failing on a table the open never
/// created.
#[test]
fn one_store_serves_every_durable_seam() {
    let store = open_durable_store_in_memory().expect("in-memory store opens");
    let config = DurableAppConfig::new(Arc::clone(&store));
    let downloads = DurableDownloadRepository::new(Arc::clone(&store));
    let registry = DurableSharedFileRegistry::new(Arc::clone(&store));
    let credit = DurableCreditStore::new(Arc::clone(&store));

    assert!(config.servers().expect("server list readable").is_empty());
    assert!(
        downloads
            .list_resumable()
            .expect("download rows readable")
            .is_empty()
    );
    assert!(registry.list().expect("share set readable").is_empty());
    assert!(credit.snapshot().expect("credit ring readable").is_empty());
}

/// `open_durable_store` creates the directory and `rmule.redb` inside it, and
/// what one process wrote through the composed open is what the next reads —
/// the identity a front-end mints on first run survives a restart.
#[test]
fn a_data_dir_opens_as_one_rmule_redb_that_persists_across_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("fresh");

    let minted = {
        let store = open_durable_store(&data_dir).expect("first open creates the store");
        DurableAppConfig::new(store)
            .ensure_identity()
            .expect("identity minted")
    };
    assert!(data_dir.join(DURABLE_STORE_FILE).is_file());

    let store = open_durable_store(&data_dir).expect("reopen");
    let reloaded = DurableAppConfig::new(store)
        .ensure_identity()
        .expect("identity reloaded");
    assert_eq!(reloaded.user_hash(), minted.user_hash());
}
