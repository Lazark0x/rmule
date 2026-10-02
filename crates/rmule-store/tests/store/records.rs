//! The version tag on a packed record is what the engine matches tables on:
//! a table written under `download@v1` refuses to open as `download@v2`,
//! with a typed error naming both.

use rmule_store::{Ladder, Packed, Schema, StoreError};

use crate::fixture::{
    DOWNLOADS, DOWNLOADS_V2, Download, DownloadV2, V1, download, on_each_backend,
};

#[test]
fn a_table_written_under_one_record_version_refuses_the_next() {
    on_each_backend(|backend| {
        let store = backend
            .open(&Schema::new().indexed(&DOWNLOADS), &V1)
            .unwrap();
        let txn = store.begin_write().unwrap();
        DOWNLOADS.insert(&txn, &1, &download(1)).unwrap();
        txn.commit().unwrap();
        drop(store);

        let error = backend
            .open(&Schema::new().indexed(&DOWNLOADS_V2), &Ladder::new(1, &[]))
            .expect_err("v2 schema must be refused on a v1 table");
        match error {
            StoreError::TableTypeMismatch {
                table,
                stored_value,
                ..
            } => {
                assert_eq!(table, "download");
                assert_eq!(stored_value, Packed::<Download>::tag());
                assert_ne!(stored_value, Packed::<DownloadV2>::tag());
            }
            other => panic!("expected TableTypeMismatch, got {other:?}"),
        }
    });
}
