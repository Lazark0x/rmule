//! The version ladder at open: a fresh store is stamped at the ladder's
//! current version with no step run; an older store climbs every rung in
//! order, each step's rewrite landing before the next starts, and the tables
//! it rewrites open under the new record version afterwards; a newer store
//! and a rung without a step are refused.

use rmule_store::{
    Ladder, Packed, Schema, StoreError, TableDefinition, UpgradeStep, WriteTransaction,
};

use crate::fixture::{
    DOWNLOADS, DOWNLOADS_V2, Download, DownloadV2, V1, download, on_each_backend, schema_v1,
};

/// v1 -> v2: `Download` grows a `trail`, rewritten in place under the same
/// table name.
fn grow_trail(txn: &WriteTransaction) -> Result<(), StoreError> {
    let old = DOWNLOADS.iter(txn)?;
    // The old primary goes by its definition; the wrapper never exposes it.
    txn.delete_table(TableDefinition::<u64, Packed<Download>>::new("download"))?;
    DOWNLOADS_V2.create(txn)?;
    for (key, record) in old {
        let grown = DownloadV2 {
            name: record.name,
            size: record.size,
            part_path: record.part_path,
            file_hash: record.file_hash,
            trail: "1".into(),
        };
        DOWNLOADS_V2.insert(txn, &key, &grown)?;
    }
    Ok(())
}

/// v2 -> v3: every trail is extended, proving step order.
fn extend_trail(txn: &WriteTransaction) -> Result<(), StoreError> {
    for (key, mut record) in DOWNLOADS_V2.iter(txn)? {
        record.trail.push('2');
        DOWNLOADS_V2.update(txn, &key, &record)?;
    }
    Ok(())
}

static V3_STEPS: [UpgradeStep; 2] = [
    UpgradeStep {
        from: 2,
        run: extend_trail,
    },
    UpgradeStep {
        from: 1,
        run: grow_trail,
    },
];

const V3: Ladder = Ladder::new(3, &V3_STEPS);

fn schema_v3() -> Schema {
    Schema::new().indexed(&DOWNLOADS_V2)
}

#[test]
fn a_fresh_store_is_stamped_at_current_without_running_steps() {
    on_each_backend(|backend| {
        let store = backend.open(&schema_v3(), &V3).unwrap();
        assert_eq!(store.version().unwrap(), 3);
        assert!(DOWNLOADS_V2.is_empty(&store.begin_read().unwrap()).unwrap());
    });
}

#[test]
fn an_older_store_climbs_every_rung_in_order_and_opens_under_the_new_record() {
    on_each_backend(|backend| {
        let store = backend.open(&schema_v1(), &V1).unwrap();
        let txn = store.begin_write().unwrap();
        DOWNLOADS.insert(&txn, &4, &download(4)).unwrap();
        DOWNLOADS.insert(&txn, &8, &download(8)).unwrap();
        txn.commit().unwrap();
        drop(store);

        let store = backend.open(&schema_v3(), &V3).unwrap();
        assert_eq!(store.version().unwrap(), 3);
        let read = store.begin_read().unwrap();
        let rows = DOWNLOADS_V2.iter(&read).unwrap();
        assert_eq!(rows.len(), 2);
        for (key, record) in rows {
            assert_eq!(record.name, format!("file-{key}"));
            assert_eq!(record.trail, "12");
        }
    });
}

#[test]
fn a_store_newer_than_the_ladder_is_refused() {
    on_each_backend(|backend| {
        drop(backend.open(&schema_v3(), &V3).unwrap());
        let error = backend.open(&schema_v1(), &V1).unwrap_err();
        assert!(
            matches!(
                error,
                StoreError::FutureVersion {
                    found: 3,
                    current: 1
                }
            ),
            "{error:?}"
        );
    });
}

#[test]
fn a_rung_without_a_step_is_refused_and_the_stamp_stays() {
    on_each_backend(|backend| {
        drop(backend.open(&schema_v1(), &V1).unwrap());
        let gapped = Ladder::new(3, &V3_STEPS[..1]);
        let error = backend.open(&schema_v3(), &gapped).unwrap_err();
        assert!(
            matches!(error, StoreError::MissingStep { from: 1 }),
            "{error:?}"
        );

        let store = backend.open(&schema_v1(), &V1).unwrap();
        assert_eq!(store.version().unwrap(), 1);
    });
}
