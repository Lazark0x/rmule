//! Index maintenance is the store's, not the caller's: every write moves the
//! unique and multimap entries with the record, a refused write leaves the
//! transaction untouched, reads through an index work on a write transaction
//! before commit, and a key range comes back in key order.

use rmule_store::StoreError;

use crate::fixture::{DOWNLOADS, IDENTITY, PART_PATH, V1, download, on_each_backend, schema_v1};

#[test]
fn insert_populates_both_indexes_and_update_moves_the_changed_entry() {
    on_each_backend(|backend| {
        let store = backend.open(&schema_v1(), &V1).unwrap();
        let txn = store.begin_write().unwrap();
        let mut first = download(1);
        DOWNLOADS.insert(&txn, &1, &first).unwrap();
        // Visible on the write transaction before commit.
        assert_eq!(
            DOWNLOADS
                .by_unique(&txn, &PART_PATH, "/tmp/1.part")
                .unwrap(),
            Some(1)
        );
        txn.commit().unwrap();

        let txn = store.begin_write().unwrap();
        first.part_path = "/tmp/moved.part".into();
        first.size = 42;
        let replaced = DOWNLOADS.update(&txn, &1, &first).unwrap();
        assert_eq!(replaced, download(1));
        txn.commit().unwrap();

        let read = store.begin_read().unwrap();
        assert_eq!(DOWNLOADS.get(&read, &1).unwrap(), Some(first.clone()));
        assert_eq!(
            DOWNLOADS
                .by_unique(&read, &PART_PATH, "/tmp/1.part")
                .unwrap(),
            None
        );
        assert_eq!(
            DOWNLOADS
                .by_unique(&read, &PART_PATH, "/tmp/moved.part")
                .unwrap(),
            Some(1)
        );
        assert!(
            DOWNLOADS
                .by_multi(&read, &IDENTITY, ([1; 16], 1001))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            DOWNLOADS.by_multi(&read, &IDENTITY, ([1; 16], 42)).unwrap(),
            vec![1]
        );
    });
}

#[test]
fn remove_returns_the_record_and_clears_its_index_entries() {
    on_each_backend(|backend| {
        let store = backend.open(&schema_v1(), &V1).unwrap();
        let txn = store.begin_write().unwrap();
        DOWNLOADS.insert(&txn, &7, &download(7)).unwrap();
        assert_eq!(DOWNLOADS.remove(&txn, &7).unwrap(), Some(download(7)));
        assert_eq!(DOWNLOADS.remove(&txn, &7).unwrap(), None);
        txn.commit().unwrap();

        let read = store.begin_read().unwrap();
        assert!(DOWNLOADS.is_empty(&read).unwrap());
        assert_eq!(
            DOWNLOADS
                .by_unique(&read, &PART_PATH, "/tmp/7.part")
                .unwrap(),
            None
        );
        assert!(
            DOWNLOADS
                .by_multi(&read, &IDENTITY, ([7; 16], 1007))
                .unwrap()
                .is_empty()
        );
    });
}

#[test]
fn multimap_index_holds_every_record_sharing_an_identity() {
    on_each_backend(|backend| {
        let store = backend.open(&schema_v1(), &V1).unwrap();
        let txn = store.begin_write().unwrap();
        let mut twin = download(3);
        twin.part_path = "/tmp/3-again.part".into();
        DOWNLOADS.insert(&txn, &3, &download(3)).unwrap();
        DOWNLOADS.insert(&txn, &30, &twin).unwrap();
        txn.commit().unwrap();

        let read = store.begin_read().unwrap();
        assert_eq!(
            DOWNLOADS
                .by_multi(&read, &IDENTITY, ([3; 16], 1003))
                .unwrap(),
            vec![3, 30]
        );
    });
}

#[test]
fn a_unique_violation_is_refused_before_anything_is_written() {
    on_each_backend(|backend| {
        let store = backend.open(&schema_v1(), &V1).unwrap();
        let txn = store.begin_write().unwrap();
        DOWNLOADS.insert(&txn, &1, &download(1)).unwrap();
        let mut clash = download(2);
        clash.part_path = "/tmp/1.part".into();

        let error = DOWNLOADS.insert(&txn, &2, &clash).unwrap_err();
        assert!(
            matches!(
                error,
                StoreError::UniqueViolation {
                    index: "download.part_path"
                }
            ),
            "{error:?}"
        );
        assert_eq!(DOWNLOADS.get(&txn, &2).unwrap(), None);
        assert!(
            DOWNLOADS
                .by_multi(&txn, &IDENTITY, ([2; 16], 1002))
                .unwrap()
                .is_empty()
        );

        // Keeping a key's own unique value is not a clash.
        let mut renamed = download(1);
        renamed.name = "renamed".into();
        DOWNLOADS.update(&txn, &1, &renamed).unwrap();
        txn.commit().unwrap();
    });
}

#[test]
fn insert_and_update_check_key_presence_and_put_does_not() {
    on_each_backend(|backend| {
        let store = backend.open(&schema_v1(), &V1).unwrap();
        let txn = store.begin_write().unwrap();
        assert!(matches!(
            DOWNLOADS.update(&txn, &5, &download(5)).unwrap_err(),
            StoreError::KeyMissing { record: "download" }
        ));
        assert_eq!(DOWNLOADS.put(&txn, &5, &download(5)).unwrap(), None);
        assert!(matches!(
            DOWNLOADS.insert(&txn, &5, &download(5)).unwrap_err(),
            StoreError::KeyExists { record: "download" }
        ));
        let mut moved = download(5);
        moved.part_path = "/tmp/5b.part".into();
        assert_eq!(DOWNLOADS.put(&txn, &5, &moved).unwrap(), Some(download(5)));
        assert_eq!(
            DOWNLOADS
                .by_unique(&txn, &PART_PATH, "/tmp/5.part")
                .unwrap(),
            None
        );
        txn.commit().unwrap();
    });
}

#[test]
fn range_and_iter_come_back_in_key_order() {
    on_each_backend(|backend| {
        let store = backend.open(&schema_v1(), &V1).unwrap();
        let txn = store.begin_write().unwrap();
        for id in [9, 2, 300, 40] {
            DOWNLOADS.insert(&txn, &id, &download(id)).unwrap();
        }
        txn.commit().unwrap();

        let read = store.begin_read().unwrap();
        let keys: Vec<u64> = DOWNLOADS
            .iter(&read)
            .unwrap()
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        assert_eq!(keys, vec![2, 9, 40, 300]);
        let window: Vec<(u64, String)> = DOWNLOADS
            .range(&read, 9..=40)
            .unwrap()
            .into_iter()
            .map(|(key, record)| (key, record.name))
            .collect();
        assert_eq!(window, vec![(9, "file-9".into()), (40, "file-40".into())]);
        assert_eq!(DOWNLOADS.len(&read).unwrap(), 4);
    });
}
