//! The durable **Shared File Registry** on the Durable Store (ADR-0083): one
//! record per shared file, keyed by the file's content identity, and one
//! record per part hash beside it, keyed by file and part index. The split is
//! a storage shape, not a seam boundary: a share writes the row and its part
//! hashes in one transaction, so a re-share can never leave a hash from the
//! old set behind, and every read rejoins the two in the transaction that
//! read the row. So an entry from [`SharedFileRegistry::get`] or
//! [`SharedFileRegistry::list`] carries the file's whole part hash set, and a
//! serve state seeded from `list` after a restart answers a hash-set probe
//! for a file shared before it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use rmule_primitives::{FileHash, PartHash};
use rmule_store::{
    Children, Indexed, Packed, Readable, Record, Store, StoreError, TableDefinition, UpgradeStep,
    WriteTransaction,
};
use serde::{Deserialize, Serialize};

use crate::CoreError;
use crate::directory_scan::{FileIdentity, SpareCopy};
use crate::registry::{ShareSource, SharedFileEntry, SharedFileRegistry};
use crate::store::Schema;
use crate::store::had_set::{self, DurableHadSet};
use crate::store::spare_copy;

mod shared_directory;

pub(crate) use shared_directory::{SetAsideRuling, UPGRADE_FROM_V10};

/// A shared file's key: its ED2K File Hash's bytes. Content identity is the
/// seam's key (ADR-0031), so sharing the same file twice upserts one row.
type FileKey = [u8; FileHash::BYTE_LEN];

/// One shared file, less its part hash set — the set lives in its own record
/// kind, keyed by this record's key.
#[derive(Debug, Serialize, Deserialize)]
struct SharedFile {
    /// [`SharedFileEntry::file_size`].
    file_size: u64,
    /// [`SharedFileEntry::path`].
    path: PathBuf,
    /// [`SharedFileEntry::name`].
    name: String,
    /// [`SharedFileEntry::source`].
    source: ShareSource,
    /// [`SharedFileEntry::modified`].
    modified: Option<SystemTime>,
    /// The file's **File Identity**, when the scan read one: what lets a
    /// rename carry the row unread (ADR-0104, "What the scan remembers").
    identity: Option<FileIdentity>,
}

impl Record for SharedFile {
    const NAME: &'static str = "shared_file";
    const VERSION: u32 = 3;
}

/// The row as store versions 2 to 4 wrote it, before it carried the file's
/// identity. Compiled only for the upgrades that pass through it.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct SharedFileV2 {
    pub(super) file_size: u64,
    pub(super) path: PathBuf,
    pub(super) name: String,
    pub(super) source: ShareSource,
    pub(super) modified: Option<SystemTime>,
}

impl Record for SharedFileV2 {
    const NAME: &'static str = "shared_file";
    const VERSION: u32 = 2;
}

pub(super) static SHARED_FILES_V2: Indexed<FileKey, SharedFileV2> =
    Indexed::new("shared_file", &[]);

/// The row as store version 1 wrote it, before the Hash Trust Rule needed the
/// modification time (ADR-0102). Compiled only for [`UPGRADE_FROM_V1`].
#[derive(Debug, Serialize, Deserialize)]
struct SharedFileV1 {
    file_size: u64,
    path: PathBuf,
    name: String,
    source: ShareSource,
}

impl Record for SharedFileV1 {
    const NAME: &'static str = "shared_file";
    const VERSION: u32 = 1;
}

static SHARED_FILES_V1: Indexed<FileKey, SharedFileV1> = Indexed::new("shared_file", &[]);

/// Store version 1 → 2: every shared row gains an unknown modification time.
/// `None` never satisfies the Hash Trust Rule, so the first scan re-hashes
/// such a file once and stamps it (ADR-0102 "Building the scan").
pub(crate) const UPGRADE_FROM_V1: UpgradeStep = UpgradeStep {
    from: 1,
    run: stamp_unknown_modified_time,
};

fn stamp_unknown_modified_time(txn: &WriteTransaction) -> Result<(), StoreError> {
    let old = SHARED_FILES_V1.iter(txn)?;
    // The old primary goes by its definition; the wrapper never exposes it.
    txn.delete_table(TableDefinition::<FileKey, Packed<SharedFileV1>>::new(
        "shared_file",
    ))?;
    // Written in version 2's shape, so the rung from version 4 finds what it
    // reads whichever version a store climbs from.
    SHARED_FILES_V2.create(txn)?;
    for (key, row) in old {
        let grown = SharedFileV2 {
            file_size: row.file_size,
            path: row.path,
            name: row.name,
            source: row.source,
            modified: None,
        };
        SHARED_FILES_V2.insert(txn, &key, &grown)?;
    }
    Ok(())
}

/// Store version 4 → 5 (ADR-0104, "What the scan remembers"): every shared
/// row gains an unknown identity, which carries nothing until the scan reads
/// one, and the spare-copy table appears, empty. A version-4 build refuses the
/// store: its shares would not delete a spare recorded at the shared path.
pub(crate) const UPGRADE_FROM_V4: UpgradeStep = UpgradeStep {
    from: 4,
    run: identify_nothing_and_record_no_spare,
};

fn identify_nothing_and_record_no_spare(txn: &WriteTransaction) -> Result<(), StoreError> {
    let old = SHARED_FILES_V2.iter(txn)?;
    txn.delete_table(TableDefinition::<FileKey, Packed<SharedFileV2>>::new(
        "shared_file",
    ))?;
    SHARED_FILES.create(txn)?;
    for (key, row) in old {
        let grown = SharedFile {
            file_size: row.file_size,
            path: row.path,
            name: row.name,
            source: row.source,
            modified: row.modified,
            identity: None,
        };
        SHARED_FILES.insert(txn, &key, &grown)?;
    }
    spare_copy::create(txn)
}

/// The operator's answer to the disclosure guard, one per directory ever
/// asked about (ADR-0101): whether what lies under it may be offered.
#[derive(Debug, Default, Serialize, Deserialize)]
struct DirectoryAnswers(Vec<(PathBuf, bool)>);

impl Record for DirectoryAnswers {
    const NAME: &'static str = "shared_directory_answer";
    const VERSION: u32 = 1;
}

/// The answers, held as one row: a handful of directories, never a table's
/// worth, read whole whenever a scan starts.
static DIRECTORY_ANSWERS: Indexed<u8, DirectoryAnswers> = Indexed::new(DirectoryAnswers::NAME, &[]);

/// One hash of one file's ED2K part hash set. A file below one part has no
/// set and therefore no record here, which is not the same as not being
/// shared — presence is decided by the [`SharedFile`] row alone.
#[derive(Debug, Serialize, Deserialize)]
struct SharedFilePartHash(PartHash);

impl SharedFilePartHash {
    const fn of(hash: &PartHash) -> Self {
        Self(*hash)
    }
}

impl Record for SharedFilePartHash {
    const NAME: &'static str = "shared_file_part_hash";
    const VERSION: u32 = 1;
}

/// The share set: one row per file we serve, keyed by file hash.
static SHARED_FILES: Indexed<FileKey, SharedFile> = Indexed::new("shared_file", &[]);

/// The part hash sets of the files in [`SHARED_FILES`], one row per hash,
/// keyed by the file and the part's place in its set.
static PART_HASHES: Children<FileKey, SharedFilePartHash> = Children::new("shared_file_part_hash");

/// The tables this seam owns, for the store the front-end opens: merged with
/// the other seams' pieces and handed to `Store::open` once.
#[must_use]
pub(crate) fn schema() -> Schema {
    Schema::new()
        .indexed(&SHARED_FILES)
        .children(&PART_HASHES)
        .indexed(&DIRECTORY_ANSWERS)
        .merge(shared_directory::schema())
}

/// The registry's tables as store version 1 declared them, for a test that
/// builds an older store.
#[cfg(test)]
pub(crate) fn schema_v1() -> Schema {
    Schema::new()
        .indexed(&SHARED_FILES_V1)
        .children(&PART_HASHES)
}

/// Share `entry` as a store of version 1 would have, on `txn`.
///
/// # Errors
/// The store's.
#[cfg(test)]
pub(crate) fn share_v1(txn: &WriteTransaction, entry: &SharedFileEntry) -> Result<(), StoreError> {
    let key = *entry.file_hash.as_bytes();
    SHARED_FILES_V1.put(
        txn,
        &key,
        &SharedFileV1 {
            file_size: entry.file_size,
            path: entry.path.clone(),
            name: entry.name.clone(),
            source: entry.source,
        },
    )?;
    PART_HASHES.replace(
        txn,
        key,
        entry.part_hashes.iter().map(SharedFilePartHash::of),
    )
}

/// The registry's tables as store versions 2 to 4 declared them, for a test
/// that builds an older store.
#[cfg(test)]
pub(crate) fn schema_v2() -> Schema {
    Schema::new()
        .indexed(&SHARED_FILES_V2)
        .children(&PART_HASHES)
        .indexed(&DIRECTORY_ANSWERS)
}

/// Share `entry` as a store of versions 2 to 4 would have, on `txn`.
///
/// # Errors
/// The store's.
#[cfg(test)]
pub(crate) fn share_v2(txn: &WriteTransaction, entry: &SharedFileEntry) -> Result<(), StoreError> {
    let key = *entry.file_hash.as_bytes();
    SHARED_FILES_V2.put(
        txn,
        &key,
        &SharedFileV2 {
            file_size: entry.file_size,
            path: entry.path.clone(),
            name: entry.name.clone(),
            source: entry.source,
            modified: entry.modified,
        },
    )?;
    PART_HASHES.replace(
        txn,
        key,
        entry.part_hashes.iter().map(SharedFilePartHash::of),
    )
}

/// The registry's tables as store version 10 declared them, before the
/// Shared Directory List, for a test that builds an older store.
#[cfg(test)]
pub(crate) fn schema_v10() -> Schema {
    Schema::new()
        .indexed(&SHARED_FILES)
        .children(&PART_HASHES)
        .indexed(&DIRECTORY_ANSWERS)
        .merge(spare_copy::schema())
}

/// Share `entry` as a store of version 10 would have, on `txn`.
///
/// # Errors
/// The store's.
#[cfg(test)]
pub(crate) fn share_v10(txn: &WriteTransaction, entry: &SharedFileEntry) -> Result<(), StoreError> {
    let key = *entry.file_hash.as_bytes();
    SHARED_FILES.put(txn, &key, &SharedFile::of(entry))?;
    PART_HASHES.replace(
        txn,
        key,
        entry.part_hashes.iter().map(SharedFilePartHash::of),
    )
}

/// The durable [`SharedFileRegistry`] (ADR-0083): the share set in the
/// Durable Store, each row carrying how the file came to
/// be shared, so a restart re-offers the same files without re-hashing them.
///
/// Every operation takes `&self` and commits durably before it returns; the
/// handle is `Send + Sync` and clones share one store, so no mutex wraps it.
#[derive(Clone, Debug)]
pub struct DurableSharedFileRegistry {
    store: Arc<Store>,
}

impl DurableSharedFileRegistry {
    /// Bind the seam to the store all seams share.
    #[must_use]
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

impl DurableSharedFileRegistry {
    /// The **Had Set** over the same store: its writes are this registry's
    /// transitions, so it reads where they write.
    #[must_use]
    pub fn had_set(&self) -> DurableHadSet {
        DurableHadSet::new(Arc::clone(&self.store))
    }

    /// The **Share Totals** over the same store, keyed as these rows are.
    #[must_use]
    pub fn share_totals(&self) -> crate::store::share_totals::DurableShareTotals {
        crate::store::share_totals::DurableShareTotals::new(Arc::clone(&self.store))
    }

    /// The recorded answer for `dir` — `Some(true)` to share what lies under
    /// it, `Some(false)` declined — or `None` when it was never asked.
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the store read fails.
    pub fn directory_answer(&self, dir: &Path) -> Result<Option<bool>, CoreError> {
        self.store.read(|txn| {
            Ok(DIRECTORY_ANSWERS
                .get(txn, &0)?
                .unwrap_or_default()
                .0
                .into_iter()
                .find_map(|(asked, share)| (asked == dir).then_some(share)))
        })
    }

    /// Every recorded **Spare Copy** (ADR-0104, "Spare copies are recorded").
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the store read fails.
    pub(crate) fn spares(&self) -> Result<Vec<SpareCopy>, CoreError> {
        self.store.read(|txn| Ok(spare_copy::list(txn)?))
    }

    /// Each row's recorded **File Identity**, by content.
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the store read fails.
    pub(crate) fn identities(&self) -> Result<HashMap<FileHash, FileIdentity>, CoreError> {
        self.store.read(|txn| {
            Ok(SHARED_FILES
                .iter(txn)?
                .into_iter()
                .filter_map(|(key, row)| Some((FileHash::from_bytes(key), row.identity?)))
                .collect())
        })
    }

    /// Record `spare`, if its content still has a row at another path; a spare
    /// never outlives its content's row. True when recorded.
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the store write fails.
    pub(crate) fn record_spare(&self, spare: &SpareCopy) -> Result<bool, CoreError> {
        self.store.write(
            |txn| match SHARED_FILES.get(txn, spare.file_hash.as_bytes())? {
                Some(row) if row.path != spare.path => {
                    spare_copy::record(txn, spare)?;
                    Ok(true)
                }
                _ => Ok(false),
            },
        )
    }

    /// Nothing is a spare at `path` any more: it vanished or changed.
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the store write fails.
    pub(crate) fn forget_spare(&self, path: &Path) -> Result<(), CoreError> {
        self.store
            .write(|txn| Ok(spare_copy::forget_at(txn, path)?))
    }

    /// Move the row of `file_hash` from `from` to the file `to` names, unread:
    /// its path, name, time and identity change, its part hash set and source
    /// stay, and a spare recorded at `to` is gone (ADR-0100, "What the scan
    /// remembers"). Only if the row still names `from`; true when it moved.
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the store write fails.
    pub(crate) fn relocate(
        &self,
        file_hash: FileHash,
        from: &Path,
        to: &SpareCopy,
    ) -> Result<bool, CoreError> {
        self.store.write(|txn| {
            let key = *file_hash.as_bytes();
            match SHARED_FILES.get(txn, &key)? {
                Some(mut row) if row.path == from => {
                    row.path.clone_from(&to.path);
                    row.name = SharedFileEntry::name_of(&to.path);
                    row.modified = Some(to.stamp.modified);
                    row.identity = to.identity;
                    SHARED_FILES.set(txn, &key, &row)?;
                    spare_copy::forget_at(txn, &to.path)?;
                    Ok(true)
                }
                _ => Ok(false),
            }
        })
    }

    /// Record the identity of the file behind the row of `file_hash`, if the
    /// row still names `path`.
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the store write fails.
    pub(crate) fn identify(
        &self,
        file_hash: FileHash,
        path: &Path,
        identity: FileIdentity,
    ) -> Result<(), CoreError> {
        self.store.write(|txn| {
            let key = *file_hash.as_bytes();
            if let Some(mut row) = SHARED_FILES.get(txn, &key)?
                && row.path == path
            {
                row.identity = Some(identity);
                SHARED_FILES.set(txn, &key, &row)?;
            }
            Ok(())
        })
    }

    /// Record the answer for `dir`, replacing an earlier one.
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the store write fails.
    pub fn record_directory_answer(&self, dir: &Path, share: bool) -> Result<(), CoreError> {
        self.store.write(|txn| {
            let mut answers = DIRECTORY_ANSWERS.get(txn, &0)?.unwrap_or_default();
            answers.0.retain(|(asked, _)| asked != dir);
            answers.0.push((dir.to_path_buf(), share));
            Ok(DIRECTORY_ANSWERS.set(txn, &0, &answers)?)
        })
    }
}

impl SharedFileRegistry for DurableSharedFileRegistry {
    fn share(&self, entry: SharedFileEntry) -> Result<(), CoreError> {
        self.store.write(|txn| {
            let key = *entry.file_hash.as_bytes();
            // The row and the whole replacement set go in one transaction, so
            // a re-share with a shorter set leaves no hash of the old one
            // behind. An error here aborts the transaction, which leaves the
            // share set as it was.
            SHARED_FILES.put(txn, &key, &SharedFile::of(&entry))?;
            had_set::forget(txn, &key)?;
            // A path that holds the row is no spare, and nothing set aside.
            spare_copy::forget_at(txn, &entry.path)?;
            shared_directory::forget_set_aside_at(txn, &entry.path)?;
            Ok(PART_HASHES.replace(
                txn,
                key,
                entry.part_hashes.iter().map(SharedFilePartHash::of),
            )?)
        })
    }

    fn gone(&self, file_hash: FileHash, path: &Path) -> Result<bool, CoreError> {
        self.store.write(|txn| {
            let key = *file_hash.as_bytes();
            match SHARED_FILES.get(txn, &key)? {
                Some(row) if row.path == path => {
                    SHARED_FILES.remove(txn, &key)?;
                    PART_HASHES.clear(txn, key)?;
                    spare_copy::forget_content(txn, &key)?;
                    had_set::join(txn, &key, row.file_size, row.name, SystemTime::now())?;
                    Ok(true)
                }
                _ => Ok(false),
            }
        })
    }

    fn unshare(&self, file_hash: FileHash) -> Result<bool, CoreError> {
        self.store.write(|txn| {
            let key = *file_hash.as_bytes();
            let removed = SHARED_FILES.remove(txn, &key)?;
            PART_HASHES.clear(txn, key)?;
            spare_copy::forget_content(txn, &key)?;
            Ok(removed.is_some())
        })
    }

    fn get(&self, file_hash: FileHash) -> Result<Option<SharedFileEntry>, CoreError> {
        self.store.read(|txn| {
            let key = *file_hash.as_bytes();
            let Some(row) = SHARED_FILES.get(txn, &key)? else {
                return Ok(None);
            };
            // Row and set are read on one transaction, so the entry is never
            // half a concurrent re-share.
            Ok(Some(row.into_entry(file_hash, part_hashes_of(txn, key)?)))
        })
    }

    fn list(&self) -> Result<Vec<SharedFileEntry>, CoreError> {
        self.store.read(|txn| {
            // One range per row, all on the transaction that read the rows, so
            // the serve side can seed its snapshot from here and answer a
            // hash-set probe out of it rather than with a second trip.
            SHARED_FILES
                .iter(txn)?
                .into_iter()
                .map(|(key, row)| {
                    Ok(row.into_entry(FileHash::from_bytes(key), part_hashes_of(txn, key)?))
                })
                .collect()
        })
    }

    fn hash_set(&self, file_hash: FileHash) -> Result<Option<Vec<PartHash>>, CoreError> {
        self.store.read(|txn| {
            let key = *file_hash.as_bytes();
            if !SHARED_FILES.contains(txn, &key)? {
                return Ok(None);
            }
            Ok(Some(part_hashes_of(txn, key)?))
        })
    }
}

impl SharedFile {
    fn of(entry: &SharedFileEntry) -> Self {
        Self {
            file_size: entry.file_size,
            path: entry.path.clone(),
            name: entry.name.clone(),
            source: entry.source,
            modified: entry.modified,
            identity: None,
        }
    }

    /// The entry a read answers with: the row's fields rejoined with the part
    /// hash set read beside it.
    fn into_entry(self, file_hash: FileHash, part_hashes: Vec<PartHash>) -> SharedFileEntry {
        SharedFileEntry {
            file_hash,
            file_size: self.file_size,
            path: self.path,
            name: self.name,
            source: self.source,
            part_hashes,
            modified: self.modified,
        }
    }
}

/// One file's stored part hash set in part order, read on `txn` — the read
/// side of the row/set split, so the caller that holds the row holds its set
/// from the same transaction. Empty for a file below one part, which has no
/// set to store.
fn part_hashes_of(txn: &impl Readable, key: FileKey) -> Result<Vec<PartHash>, CoreError> {
    Ok(PART_HASHES
        .list(txn, key)?
        .into_iter()
        .map(|(_, hash)| hash.0)
        .collect())
}

#[cfg(test)]
mod tests;
