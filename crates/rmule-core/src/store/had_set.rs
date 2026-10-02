//! The **Had Set** on the Durable Store (ADR-0105, "The Had Set"): one row
//! per file hash that was in the **Shared File Registry** and whose file has
//! since left the disk, with the size, the name it last had and when it left.
//!
//! The set is read through [`DurableHadSet`]. It is written only inside the
//! registry's own transactions — a row found gone joins it in the write that
//! removes the row, and every share takes its hash out in the write that
//! stores the row — so the two never disagree about a file between writes.

use std::sync::Arc;
use std::time::SystemTime;

use rmule_primitives::FileHash;
use rmule_store::{Indexed, Record, Store, StoreError, UpgradeStep, WriteTransaction};
use serde::{Deserialize, Serialize};

use crate::CoreError;
use crate::file_history::{Ed2kIdentity, HadFile};
use crate::store::Schema;

/// A had file's key: its ED2K File Hash's bytes, as the registry keys its
/// rows.
type FileKey = [u8; FileHash::BYTE_LEN];

/// One had file, less its hash.
#[derive(Debug, Serialize, Deserialize)]
struct HadRow {
    /// [`Ed2kIdentity::file_size`].
    file_size: u64,
    /// [`HadFile::name`].
    name: String,
    /// [`HadFile::found_gone`].
    found_gone: SystemTime,
}

impl Record for HadRow {
    const NAME: &'static str = "had_file";
    const VERSION: u32 = 1;
}

static HAD_FILES: Indexed<FileKey, HadRow> = Indexed::new(HadRow::NAME, &[]);

/// The table this seam owns, merged into the store's schema.
#[must_use]
pub(crate) fn schema() -> Schema {
    Schema::new().indexed(&HAD_FILES)
}

/// Store version 2 → 3: the Had Set's table appears, empty. A version-2
/// build must refuse the file afterwards, because its shares would not take
/// a hash out of the set.
pub(crate) const UPGRADE_FROM_V2: UpgradeStep = UpgradeStep {
    from: 2,
    run: |txn| HAD_FILES.create(txn),
};

/// The file `key` left the disk, last named `name` and `file_size` long: it
/// joins the set, replacing an older leaving of the same content. Runs on
/// the registry's transaction that removes the row.
pub(super) fn join(
    txn: &WriteTransaction,
    key: &FileKey,
    file_size: u64,
    name: String,
    found_gone: SystemTime,
) -> Result<(), StoreError> {
    HAD_FILES.set(
        txn,
        key,
        &HadRow {
            file_size,
            name,
            found_gone,
        },
    )
}

/// The content `key` is shared again: it is on disk, so not Had. Runs on the
/// registry's transaction that stores the row.
pub(super) fn forget(txn: &WriteTransaction, key: &FileKey) -> Result<(), StoreError> {
    HAD_FILES.remove(txn, key).map(drop)
}

/// The **Had Set**'s read side. A clone shares the store; every read is one
/// transaction.
#[derive(Clone, Debug)]
pub struct DurableHadSet {
    store: Arc<Store>,
}

impl DurableHadSet {
    /// Bind the seam to the store all seams share.
    #[must_use]
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    /// Every file in the set.
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the store read fails.
    pub fn list(&self) -> Result<Vec<HadFile>, CoreError> {
        self.store.read(|txn| {
            Ok(HAD_FILES
                .iter(txn)?
                .into_iter()
                .map(|(key, row)| HadFile {
                    identity: Ed2kIdentity::new(FileHash::from_bytes(key), row.file_size),
                    name: row.name,
                    found_gone: row.found_gone,
                })
                .collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use rmule_primitives::FileHash;
    use rmule_store::{Ladder, Schema};

    use crate::registry::{ShareSource, SharedFileEntry, SharedFileRegistry};
    use crate::store::registry::DurableSharedFileRegistry;
    use crate::store::{DURABLE_STORE_FILE, DurableStore, open_durable_store};

    fn entry(byte: u8, path: &str) -> SharedFileEntry {
        SharedFileEntry {
            file_hash: FileHash::from_bytes([byte; FileHash::BYTE_LEN]),
            file_size: 4_000 + u64::from(byte),
            path: PathBuf::from(path),
            name: Path::new(path)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into(),
            source: ShareSource::DownloadDirectory,
            part_hashes: Vec::new(),
            modified: None,
        }
    }

    fn had(registry: &DurableSharedFileRegistry) -> Vec<(FileHash, u64, String)> {
        registry
            .had_set()
            .list()
            .unwrap()
            .into_iter()
            .map(|file| (file.identity.file_hash, file.identity.file_size, file.name))
            .collect()
    }

    #[test]
    fn a_gone_row_leaves_and_joins_and_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let film = entry(1, "/dl/film.mkv");
        {
            let registry = DurableSharedFileRegistry::new(open_durable_store(dir.path()).unwrap());
            registry.share(film.clone()).unwrap();
            assert!(registry.gone(film.file_hash, &film.path).unwrap());
            assert_eq!(registry.get(film.file_hash).unwrap(), None);
        }
        let registry = DurableSharedFileRegistry::new(open_durable_store(dir.path()).unwrap());
        assert_eq!(
            had(&registry),
            [(film.file_hash, film.file_size, "film.mkv".to_string())]
        );
    }

    #[test]
    fn an_unshare_does_not_join() {
        let registry = DurableSharedFileRegistry::new(rmule_testkit::memory_store());
        let kept = entry(2, "/dl/kept.bin");
        registry.share(kept.clone()).unwrap();
        assert!(registry.unshare(kept.file_hash).unwrap());
        assert!(had(&registry).is_empty());
    }

    #[test]
    fn a_row_that_moved_is_not_gone_from_its_old_path() {
        let registry = DurableSharedFileRegistry::new(rmule_testkit::memory_store());
        let old = entry(3, "/dl/draft.txt");
        registry.share(old.clone()).unwrap();
        registry
            .share(SharedFileEntry {
                path: "/dl/final.txt".into(),
                ..old.clone()
            })
            .unwrap();
        assert!(!registry.gone(old.file_hash, &old.path).unwrap());
        assert!(registry.get(old.file_hash).unwrap().is_some());
        assert!(had(&registry).is_empty());
    }

    #[test]
    fn a_share_of_had_content_takes_it_out_of_the_set() {
        let registry = DurableSharedFileRegistry::new(rmule_testkit::memory_store());
        let film = entry(4, "/dl/film.mkv");
        let other = entry(5, "/dl/other.mkv");
        for row in [&film, &other] {
            registry.share(row.clone()).unwrap();
            registry.gone(row.file_hash, &row.path).unwrap();
        }
        registry
            .share(SharedFileEntry {
                path: "/dl/again/film (1).mkv".into(),
                ..film.clone()
            })
            .unwrap();
        assert_eq!(
            had(&registry)
                .into_iter()
                .map(|(hash, ..)| hash)
                .collect::<Vec<_>>(),
            [other.file_hash]
        );
    }

    #[test]
    fn a_version_two_store_climbs_to_an_empty_set() {
        let dir = tempfile::tempdir().unwrap();
        let film = entry(6, "/dl/film.mkv");
        // A store as version 2 left it: every table but the set's, stamped 2.
        let schema = Schema::new()
            .merge(crate::store::registry::schema_v2())
            .merge(crate::store::download::schema_v1());
        drop(
            DurableStore::open(
                dir.path().join(DURABLE_STORE_FILE),
                &schema,
                &Ladder::new(2, &[crate::store::registry::UPGRADE_FROM_V1]),
            )
            .unwrap(),
        );
        let registry = DurableSharedFileRegistry::new(open_durable_store(dir.path()).unwrap());
        assert!(had(&registry).is_empty());
        registry.share(film.clone()).unwrap();
        assert!(registry.gone(film.file_hash, &film.path).unwrap());
        assert_eq!(had(&registry).len(), 1);
    }
}
