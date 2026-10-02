//! The **File History**: what rmule's own records say about files the
//! operator has already met — every **Shared File Registry** entry with where
//! it lies, every file of the **Had Set**, and every download cancelled before
//! it completed — read in one go for a front end that marks search results
//! (ADR-0100, Known-File Marks).
//!
//! A read over the owners, never a seam of its own: the registry, the Had Set
//! and the download store stay the only places these facts are kept. Live downloads
//! are not here; a front end already holds them from the download edges.

use std::path::PathBuf;
use std::time::SystemTime;

use rmule_primitives::FileHash;

use crate::CoreError;
use crate::registry::{SharedFileEntry, SharedFileRegistry};
use crate::registry_check::{Withheld, WithheldRows};
use crate::storage::DownloadRepository;
use crate::store::had_set::DurableHadSet;

/// An eD2k file's identity: its hash and its exact size. The hash alone does
/// not decide a file — two sizes may share one — so the pair is what a file
/// is known by. Not the **File Identity** of a file on disk (device, inode).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ed2kIdentity {
    /// The file's ED2K hash.
    pub file_hash: FileHash,
    /// Its exact size in bytes.
    pub file_size: u64,
}

impl Ed2kIdentity {
    /// The identity of the file `file_hash` of `file_size` bytes.
    #[must_use]
    pub const fn new(file_hash: FileHash, file_size: u64) -> Self {
        Self {
            file_hash,
            file_size,
        }
    }
}

/// The operator's history with files, as rmule's records hold it now.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileHistory {
    /// Every file the **Shared File Registry** holds: offered, or withheld
    /// while its file is not readable now.
    pub shared: Vec<SharedFileFact>,
    /// Every file of the **Had Set** — once shared, since gone from the disk.
    pub had: Vec<HadFile>,
    /// Every download cancelled before it completed, by identity. A file
    /// cancelled twice is listed twice.
    pub cancelled: Vec<Ed2kIdentity>,
    /// The parts that could not be read this time. Each holds nothing, and
    /// its marks are missing, not absent.
    pub unread: Vec<HistoryPart>,
}

/// One of the three parts of the **File History**, each read from its own
/// owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryPart {
    /// The **Shared File Registry**: the `Have` and `Withheld` marks.
    Shared,
    /// The **Had Set**: the `Had` marks.
    Had,
    /// The cancelled downloads: the `Cancelled` marks.
    Cancelled,
}

/// One registry entry, as far as a front end needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedFileFact {
    /// The file's hash and exact size.
    pub identity: Ed2kIdentity,
    /// Where the shared bytes lie.
    pub path: PathBuf,
    /// Why nothing is offered for it now, and since when rmule noticed;
    /// `None` while it is offered (ADR-0100, "The registry against the
    /// disk").
    pub withheld: Option<Withheld>,
}

/// One file of the **Had Set**: it was in the registry and has left the disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HadFile {
    /// The file's hash and exact size.
    pub identity: Ed2kIdentity,
    /// The name it had when it left — the operator's own name for it, which a
    /// search result's name need not be.
    pub name: String,
    /// When rmule found it gone, which is not when it was deleted: a file
    /// deleted while rmule was not running is found at the next start.
    pub found_gone: SystemTime,
}

/// Read the history from its owners. A part that cannot be read holds
/// nothing and is named in [`FileHistory::unread`], so a front end can say
/// its marks are missing rather than draw none as if there were none.
pub(crate) fn read(
    registry: &impl SharedFileRegistry,
    withheld: &WithheldRows,
    had: &DurableHadSet,
    downloads: &impl DownloadRepository,
) -> FileHistory {
    assemble(
        registry.list(),
        withheld,
        had.list(),
        downloads.list_cancelled(),
    )
}

/// The history from its three reads, each failed one named in `unread`.
fn assemble(
    shared: Result<Vec<SharedFileEntry>, CoreError>,
    withheld: &WithheldRows,
    had: Result<Vec<HadFile>, CoreError>,
    cancelled: Result<Vec<Ed2kIdentity>, CoreError>,
) -> FileHistory {
    let mut unread = Vec::new();
    let shared = match shared {
        Ok(entries) => entries
            .into_iter()
            .map(|entry| SharedFileFact {
                identity: Ed2kIdentity::new(entry.file_hash, entry.file_size),
                path: entry.path,
                withheld: withheld.get(entry.file_hash),
            })
            .collect(),
        Err(error) => unread_part(&mut unread, HistoryPart::Shared, &error),
    };
    let had = had.unwrap_or_else(|error| unread_part(&mut unread, HistoryPart::Had, &error));
    let cancelled =
        cancelled.unwrap_or_else(|error| unread_part(&mut unread, HistoryPart::Cancelled, &error));
    FileHistory {
        shared,
        had,
        cancelled,
        unread,
    }
}

/// Name `part` unread, with its error in the Run Log; it holds nothing.
fn unread_part<T>(unread: &mut Vec<HistoryPart>, part: HistoryPart, error: &CoreError) -> Vec<T> {
    tracing::warn!(?part, %error, "file history: a part could not be read");
    unread.push(part);
    Vec::new()
}

#[cfg(test)]
mod tests {
    use rmule_primitives::FileHash;

    use super::{Ed2kIdentity, HistoryPart, assemble};
    use crate::CoreError;
    use crate::registry_check::WithheldRows;

    fn failed<T>() -> Result<T, CoreError> {
        Err(CoreError::Repository("disk".into()))
    }

    #[test]
    fn a_part_that_could_not_be_read_is_named_not_shown_as_empty() {
        let cancelled = vec![Ed2kIdentity::new(FileHash::from_bytes([1; 16]), 10)];
        let history = assemble(
            failed(),
            &WithheldRows::before_start_look(),
            failed(),
            Ok(cancelled),
        );
        assert_eq!(history.unread, [HistoryPart::Shared, HistoryPart::Had]);
        assert_eq!(history.cancelled.len(), 1, "the part that was read stands");
        let whole = assemble(
            Ok(Vec::new()),
            &WithheldRows::before_start_look(),
            Ok(Vec::new()),
            Ok(Vec::new()),
        );
        assert!(whole.unread.is_empty(), "an empty part read is not a gap");
    }
}
