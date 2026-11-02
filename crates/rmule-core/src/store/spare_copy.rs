//! The **Spare Copy** records on the Durable Store (ADR-0100): one row per path under the download
//! directory whose
//! content is already shared from another path, with the stamp and identity
//! the **Hash Trust Rule** compares, keyed to the content's hash.
//!
//! Written only inside the registry's own transactions, so a spare never
//! outlives its content's row: a share deletes the spare at its path, and a
//! row that leaves takes its content's spares with it.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use rmule_primitives::FileHash;
use rmule_store::{Indexed, MultimapIndex, Readable, Record, StoreError, WriteTransaction};
use serde::{Deserialize, Serialize};

use crate::directory_scan::{FileIdentity, FileStamp, SpareCopy};
use crate::store::Schema;

/// The content key the registry uses: the ED2K File Hash's bytes.
type FileKey = [u8; FileHash::BYTE_LEN];

/// One spare copy, less its path, which is the key.
#[derive(Debug, Serialize, Deserialize)]
struct SpareRow {
    /// The content, which has a registry row at another path.
    file_hash: FileHash,
    /// [`FileStamp::size`].
    size: u64,
    /// [`FileStamp::modified`].
    modified: SystemTime,
    /// The file's identity when it was recorded, if its filesystem gives one.
    identity: Option<FileIdentity>,
}

impl Record for SpareRow {
    const NAME: &'static str = "spare_copy";
    const VERSION: u32 = 1;
}

/// The spares of one content, so a row that leaves takes them with it.
static BY_CONTENT: MultimapIndex<FileKey, String, SpareRow> =
    MultimapIndex::new("spare_copy.content", |row| *row.file_hash.as_bytes());

/// Keyed by the path's text: a path that is not valid UTF-8 is never
/// recorded, so two such paths can never share a key.
static SPARES: Indexed<String, SpareRow> = Indexed::new(SpareRow::NAME, &[&BY_CONTENT]);

/// The table this seam owns, merged into the store's schema.
#[must_use]
pub(crate) fn schema() -> Schema {
    Schema::new().indexed(&SPARES)
}

/// Record `spare`, replacing whatever was recorded at its path. A path that is
/// not valid UTF-8 is not recorded; the file is hashed again at each start.
pub(super) fn record(txn: &WriteTransaction, spare: &SpareCopy) -> Result<(), StoreError> {
    let Some(key) = spare.path.to_str() else {
        return Ok(());
    };
    SPARES.set(
        txn,
        &key.to_owned(),
        &SpareRow {
            file_hash: spare.file_hash,
            size: spare.stamp.size,
            modified: spare.stamp.modified,
            identity: spare.identity,
        },
    )
}

/// Nothing is a spare at `path` any more.
pub(super) fn forget_at(txn: &WriteTransaction, path: &Path) -> Result<(), StoreError> {
    match path.to_str() {
        Some(key) => SPARES.remove(txn, &key.to_owned()).map(drop),
        None => Ok(()),
    }
}

/// The content `key`'s row left: its spares go with it, since the part hash
/// set that would let one be offered unread went with the row.
pub(super) fn forget_content(txn: &WriteTransaction, key: &FileKey) -> Result<(), StoreError> {
    for path in SPARES.by_multi(txn, &BY_CONTENT, key)? {
        SPARES.remove(txn, &path)?;
    }
    Ok(())
}

/// Every recorded spare.
pub(super) fn list(txn: &impl Readable) -> Result<Vec<SpareCopy>, StoreError> {
    Ok(crate::store::readable(&SPARES, txn)?
        .into_iter()
        .map(|(path, row)| SpareCopy {
            path: PathBuf::from(path),
            file_hash: row.file_hash,
            stamp: FileStamp {
                size: row.size,
                modified: row.modified,
            },
            identity: row.identity,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    use rmule_primitives::FileHash;

    use crate::directory_scan::{FileIdentity, FileStamp, SpareCopy};
    use crate::registry::{ShareSource, SharedFileEntry, SharedFileRegistry};
    use crate::store::open_durable_store;
    use crate::store::registry::{DurableSharedFileRegistry, ScanWrite};

    const CONTENT: FileHash = FileHash::from_bytes([7; FileHash::BYTE_LEN]);

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn row(path: &str) -> SharedFileEntry {
        SharedFileEntry {
            file_hash: CONTENT,
            file_size: 9,
            path: PathBuf::from(path),
            name: String::new(),
            source: ShareSource::DownloadDirectory,
            part_hashes: Vec::new(),
            modified: Some(at(1)),
        }
    }

    fn spare(path: &str) -> SpareCopy {
        SpareCopy {
            path: PathBuf::from(path),
            file_hash: CONTENT,
            stamp: FileStamp {
                size: 9,
                modified: at(2),
            },
            identity: Some(FileIdentity {
                device: 1,
                inode: 42,
                born: at(2),
            }),
        }
    }

    fn open(dir: &Path) -> DurableSharedFileRegistry {
        DurableSharedFileRegistry::new(open_durable_store(dir).unwrap())
    }

    fn record(registry: &DurableSharedFileRegistry, path: &str) {
        registry
            .write_scanned(&[ScanWrite::Spare(spare(path))])
            .unwrap();
    }

    /// The rows a commit moving the row of [`CONTENT`] says it moved.
    fn relocate(
        registry: &DurableSharedFileRegistry,
        from: &str,
        to: &str,
    ) -> Vec<rmule_primitives::FileHash> {
        registry
            .write_scanned(&[ScanWrite::Moved {
                file_hash: CONTENT,
                from: from.into(),
                to: spare(to),
            }])
            .unwrap()
    }

    #[test]
    fn a_spare_is_durable_only_beside_its_contents_row() {
        let dir = tempfile::tempdir().unwrap();
        {
            let registry = open(dir.path());
            record(&registry, "/dl/copy.bin");
            assert!(registry.spares().unwrap().is_empty(), "no row yet");
            registry.share(row("/dl/film.bin")).unwrap();
            record(&registry, "/dl/film.bin");
            assert!(
                registry.spares().unwrap().is_empty(),
                "the row's own path is no spare"
            );
            record(&registry, "/dl/copy.bin");
        }
        let registry = open(dir.path());
        assert_eq!(registry.spares().unwrap(), [spare("/dl/copy.bin")]);
    }

    #[test]
    fn every_exit_of_the_row_takes_its_spares_and_a_share_at_the_path_takes_that_one() {
        let dir = tempfile::tempdir().unwrap();
        let registry = open(dir.path());
        registry.share(row("/dl/film.bin")).unwrap();
        record(&registry, "/dl/a.bin");
        record(&registry, "/dl/b.bin");
        registry.share(row("/dl/a.bin")).unwrap();
        assert_eq!(registry.spares().unwrap(), [spare("/dl/b.bin")]);
        registry.unshare(CONTENT).unwrap();
        assert!(registry.spares().unwrap().is_empty());

        registry.share(row("/dl/film.bin")).unwrap();
        record(&registry, "/dl/b.bin");
        assert!(registry.gone(CONTENT, Path::new("/dl/film.bin")).unwrap());
        assert!(registry.spares().unwrap().is_empty());
    }

    #[test]
    fn a_relocated_row_takes_the_spares_path_stamp_and_identity_unread() {
        let dir = tempfile::tempdir().unwrap();
        let registry = open(dir.path());
        let mut shared = row("/dl/film.bin");
        shared.part_hashes = vec![rmule_primitives::PartHash::from_bytes([3; 16])];
        registry.share(shared.clone()).unwrap();
        record(&registry, "/dl/copy.bin");
        assert!(
            relocate(&registry, "/dl/elsewhere.bin", "/dl/copy.bin").is_empty(),
            "only from the path the row names"
        );
        assert_eq!(
            relocate(&registry, "/dl/film.bin", "/dl/copy.bin"),
            [CONTENT]
        );
        let moved = registry.get(CONTENT).unwrap().unwrap();
        assert_eq!(moved.path, Path::new("/dl/copy.bin"));
        assert_eq!(moved.name, "copy.bin");
        assert_eq!(moved.modified, Some(at(2)));
        assert_eq!(moved.part_hashes, shared.part_hashes);
        assert!(registry.spares().unwrap().is_empty());
        assert_eq!(
            registry.identities().unwrap().get(&CONTENT),
            spare("/dl/copy.bin").identity.as_ref()
        );
    }

    #[test]
    fn a_spare_row_keeps_its_bytes() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        let row = super::SpareRow {
            file_hash: FileHash::from_bytes([7; 16]),
            size: 300,
            modified: at,
            identity: Some(FileIdentity {
                device: 1,
                inode: 2,
                born: at,
            }),
        };
        crate::store::assert_pinned(
            &row,
            "07070707070707070707070707070707ac028094ebdc03000101028094ebdc0300",
        );
    }
}
