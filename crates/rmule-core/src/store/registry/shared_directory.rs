//! The **Shared Directory List** and the **Set-Aside Rows** on the Durable
//! Store (ADR-0101, "Shared Directories"): the directories the operator added,
//! keyed by the canonical path's text, and the rows a removed directory took
//! out of the registry, keyed by path, with everything a pass needs to share
//! the file again without reading it. Both are written inside the registry's
//! own transactions, so a remove leaves no row behind that its set-aside copy
//! would contradict, and a share at a path takes the set-aside row there.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use rmule_primitives::{FileHash, PartHash};
use rmule_store::{Indexed, Readable, Record, StoreError, UpgradeStep, WriteTransaction};
use serde::{Deserialize, Serialize};

use super::{DurableSharedFileRegistry, PART_HASHES, SHARED_FILES, part_hashes_of};
use crate::CoreError;
use crate::directory_scan::{FileIdentity, SetAside, SpareCopy};
use crate::registry::{ShareSource, SharedFileEntry};
use crate::store::{Schema, spare_copy};

/// One directory the operator added, less its path, which is the key.
#[derive(Debug, Serialize, Deserialize)]
struct SharedDirectory {
    /// When the operator's yes stored it: the list's order.
    added: SystemTime,
}

impl Record for SharedDirectory {
    const NAME: &'static str = "shared_directory";
    const VERSION: u32 = 1;
}

/// Keyed by the canonical path's text; a path that is not valid UTF-8 is
/// refused at the add, so two such paths can never share a key.
static SHARED_DIRECTORIES: Indexed<String, SharedDirectory> =
    Indexed::new(SharedDirectory::NAME, &[]);

/// One **Set-Aside Row**, less its path, which is the key.
#[derive(Debug, Serialize, Deserialize)]
struct SetAsideRow {
    file_hash: FileHash,
    size: u64,
    modified: SystemTime,
    identity: Option<FileIdentity>,
    part_hashes: Vec<PartHash>,
}

impl Record for SetAsideRow {
    const NAME: &'static str = "set_aside_row";
    const VERSION: u32 = 1;
}

static SET_ASIDE: Indexed<String, SetAsideRow> = Indexed::new(SetAsideRow::NAME, &[]);

/// The tables this module owns, merged into the registry's schema.
pub(super) fn schema() -> Schema {
    Schema::new()
        .indexed(&SHARED_DIRECTORIES)
        .indexed(&SET_ASIDE)
}

/// Store version 10 → 11 (ADR-0101, "Shared Directories"): the list and the
/// set-aside rows appear, empty. A version-10 build refuses the store: it
/// would share a path without deleting that path's set-aside row, and it
/// would not scan the listed directories.
pub(crate) const UPGRADE_FROM_V10: UpgradeStep = UpgradeStep {
    from: 10,
    run: |txn| {
        SHARED_DIRECTORIES.create(txn)?;
        SET_ASIDE.create(txn)
    },
};

/// A share at `path` takes the set-aside row there: the path holds a row now.
pub(super) fn forget_set_aside_at(txn: &WriteTransaction, path: &Path) -> Result<(), StoreError> {
    match path.to_str() {
        Some(key) => SET_ASIDE.remove(txn, &key.to_owned()).map(drop),
        None => Ok(()),
    }
}

/// How one registry row left a removed directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SetAsideRuling {
    /// The row left the registry; its file is still on disk, so it is not Had.
    Left(FileHash),
    /// The row moved to a spare copy of its content under another shared
    /// directory: the content is still offered.
    Moved(FileHash),
}

impl DurableSharedFileRegistry {
    /// The directories the operator added, in the order added.
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the store read fails.
    pub(crate) fn shared_directories(&self) -> Result<Vec<PathBuf>, CoreError> {
        self.store.read(|txn| {
            let mut dirs = SHARED_DIRECTORIES.iter(txn)?;
            dirs.sort_by(|a, b| a.1.added.cmp(&b.1.added).then_with(|| a.0.cmp(&b.0)));
            Ok(dirs
                .into_iter()
                .map(|(path, _)| PathBuf::from(path))
                .collect())
        })
    }

    /// Store `dir` in the list and take `replaces` out of it, in one step:
    /// the operator's yes to a parent that replaces its children.
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the path is not valid UTF-8 or the
    /// store write fails.
    pub(crate) fn add_shared_directory(
        &self,
        dir: &Path,
        replaces: &[PathBuf],
    ) -> Result<(), CoreError> {
        let key = utf8(dir)?;
        self.store.write(|txn| {
            for child in replaces {
                if let Some(child) = child.to_str() {
                    SHARED_DIRECTORIES.remove(txn, &child.to_owned())?;
                }
            }
            Ok(SHARED_DIRECTORIES.set(
                txn,
                &key,
                &SharedDirectory {
                    added: SystemTime::now(),
                },
            )?)
        })
    }

    /// Take `dir` out of the list and every registry row under it, and not
    /// under one of `kept`, out of the registry, in one step (ADR-0101,
    /// "Shared Directories"): each row, and each spare copy under `dir`,
    /// becomes a **Set-Aside Row**; a row whose content has a spare copy
    /// outside `dir` moves to it. None of them joins the Had Set. `None` when
    /// `dir` was not listed.
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the store write fails.
    pub(crate) fn remove_shared_directory(
        &self,
        dir: &Path,
        kept: &[PathBuf],
    ) -> Result<Option<Vec<SetAsideRuling>>, CoreError> {
        let key = utf8(dir)?;
        let under =
            |path: &Path| path.starts_with(dir) && !kept.iter().any(|k| path.starts_with(k));
        self.store.write(|txn| {
            if SHARED_DIRECTORIES.remove(txn, &key)?.is_none() {
                return Ok(None);
            }
            let spares = spare_copy::list(txn)?;
            // Spares under the directory are set aside with their content's
            // part hash set, read while the row is still there.
            for spare in spares.iter().filter(|spare| under(&spare.path)) {
                let content = *spare.file_hash.as_bytes();
                if SHARED_FILES.contains(txn, &content)? {
                    set_aside_spare(txn, spare, part_hashes_of(txn, content)?)?;
                }
                spare_copy::forget_at(txn, &spare.path)?;
            }
            let mut rulings = Vec::new();
            for (content, row) in SHARED_FILES.iter(txn)? {
                if !under(&row.path) {
                    continue;
                }
                let file_hash = FileHash::from_bytes(content);
                let part_hashes = part_hashes_of(txn, content)?;
                if let (Some(key), Some(modified)) = (row.path.to_str(), row.modified) {
                    SET_ASIDE.set(
                        txn,
                        &key.to_owned(),
                        &SetAsideRow {
                            file_hash,
                            size: row.file_size,
                            modified,
                            identity: row.identity,
                            part_hashes,
                        },
                    )?;
                }
                let elsewhere = spares
                    .iter()
                    .find(|spare| spare.file_hash == file_hash && !under(&spare.path));
                if let Some(spare) = elsewhere {
                    let mut moved = row;
                    moved.path.clone_from(&spare.path);
                    moved.name = SharedFileEntry::name_of(&spare.path);
                    moved.modified = Some(spare.stamp.modified);
                    moved.identity = spare.identity;
                    SHARED_FILES.set(txn, &content, &moved)?;
                    spare_copy::forget_at(txn, &spare.path)?;
                    rulings.push(SetAsideRuling::Moved(file_hash));
                } else {
                    SHARED_FILES.remove(txn, &content)?;
                    PART_HASHES.clear(txn, content)?;
                    spare_copy::forget_content(txn, &content)?;
                    rulings.push(SetAsideRuling::Left(file_hash));
                }
            }
            Ok(Some(rulings))
        })
    }

    /// Every **Set-Aside Row**, as the entry a pass would share for it.
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the store read fails.
    pub(crate) fn set_asides(&self) -> Result<Vec<SetAside>, CoreError> {
        self.store.read(list)
    }

    /// The set-aside row at `path` no longer describes the file there.
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the store write fails.
    pub(crate) fn forget_set_aside(&self, path: &Path) -> Result<(), CoreError> {
        self.store.write(|txn| Ok(forget_set_aside_at(txn, path)?))
    }
}

fn set_aside_spare(
    txn: &WriteTransaction,
    spare: &SpareCopy,
    part_hashes: Vec<PartHash>,
) -> Result<(), StoreError> {
    let Some(key) = spare.path.to_str() else {
        return Ok(());
    };
    SET_ASIDE.set(
        txn,
        &key.to_owned(),
        &SetAsideRow {
            file_hash: spare.file_hash,
            size: spare.stamp.size,
            modified: spare.stamp.modified,
            identity: spare.identity,
            part_hashes,
        },
    )
}

fn list(txn: &impl Readable) -> Result<Vec<SetAside>, CoreError> {
    Ok(SET_ASIDE
        .iter(txn)?
        .into_iter()
        .map(|(path, row)| {
            let path = PathBuf::from(path);
            SetAside {
                entry: SharedFileEntry {
                    file_hash: row.file_hash,
                    file_size: row.size,
                    name: SharedFileEntry::name_of(&path),
                    path,
                    source: ShareSource::DownloadDirectory,
                    part_hashes: row.part_hashes,
                    modified: Some(row.modified),
                },
                identity: row.identity,
            }
        })
        .collect())
}

fn utf8(dir: &Path) -> Result<String, CoreError> {
    dir.to_str()
        .map(str::to_owned)
        .ok_or_else(|| CoreError::Repository(format!("{} is not valid UTF-8", dir.display())))
}

#[cfg(test)]
mod tests;
