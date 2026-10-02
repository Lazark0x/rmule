//! Unit tests for the durable Shared File Registry: an old row climbing the schema ladder, and a directory answer kept durably.

use super::{SHARED_FILES_V1, SharedFileV1};
use crate::registry::{ShareSource, SharedFileRegistry};
use crate::store::{DurableStore, open_durable_store};
use rmule_primitives::FileHash;
use rmule_store::{Ladder, Schema};
use std::path::Path;

use super::DurableSharedFileRegistry;

#[test]
fn a_version_one_row_climbs_to_an_untrusted_modification_time() {
    let dir = tempfile::tempdir().unwrap();
    {
        // A store as version 1 left it: the old row shape, stamped 1.
        let v1 = DurableStore::open(
            dir.path().join(crate::store::DURABLE_STORE_FILE),
            &Schema::new().indexed(&SHARED_FILES_V1),
            &Ladder::new(1, &[]),
        )
        .unwrap();
        v1.write(|txn| {
            SHARED_FILES_V1.insert(
                txn,
                &[0x5A; FileHash::BYTE_LEN],
                &SharedFileV1 {
                    file_size: 7,
                    path: "/dl/old.bin".into(),
                    name: "old.bin".into(),
                    source: ShareSource::CompletedDownload,
                },
            )
        })
        .unwrap();
    }
    let registry = DurableSharedFileRegistry::new(open_durable_store(dir.path()).unwrap());
    let rows = registry.list().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].path, Path::new("/dl/old.bin"));
    assert_eq!(rows[0].source, ShareSource::CompletedDownload);
    assert_eq!(rows[0].modified, None, "an unknown time is never trusted");
}

#[test]
fn a_directory_answer_is_durable_and_a_later_one_replaces_it() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (Path::new("/dl/a"), Path::new("/dl/b"));
    {
        let registry = DurableSharedFileRegistry::new(open_durable_store(dir.path()).unwrap());
        assert_eq!(registry.directory_answer(a).unwrap(), None);
        registry.record_directory_answer(a, false).unwrap();
        registry.record_directory_answer(b, true).unwrap();
        registry.record_directory_answer(a, true).unwrap();
    }
    let registry = DurableSharedFileRegistry::new(open_durable_store(dir.path()).unwrap());
    assert_eq!(registry.directory_answer(a).unwrap(), Some(true));
    assert_eq!(registry.directory_answer(b).unwrap(), Some(true));
    assert_eq!(registry.directory_answer(Path::new("/dl")).unwrap(), None);
}
