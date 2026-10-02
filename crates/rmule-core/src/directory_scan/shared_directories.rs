//! The **Shared Directory List**'s rules that need no scan (ADR-0101,
//! "Shared Directories"): the guards an added directory must pass, and which
//! entries are scanned and which are covered by another. Pure but for the
//! looks the guards take at the path itself: its canonical form, whether it
//! is a directory, and whether it is a mount point.

use std::io;
use std::path::{Path, PathBuf};

use crate::file_key::FileKey;

/// What the front end tells core about the operator's machine, so the guards
/// can refuse it: core never reads the environment itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShareGuards {
    /// The operator's home directory.
    pub home: Option<PathBuf>,
    /// rmule's own data directory: the store, the identity keys, the credit
    /// file.
    pub data_dir: Option<PathBuf>,
}

/// Why a directory was not added to, or removed from, the list. A code: the
/// front end words it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectoryRefusal {
    /// Nothing is there, or it is not a directory.
    NotADirectory,
    /// The path could not be looked at, for an OS error of this kind.
    Unreachable(io::ErrorKind),
    /// The path is not valid UTF-8; the list keys on its text.
    NotUtf8,
    /// The operator's home directory itself.
    HomeDirectory,
    /// A filesystem root: `/`, or a mount point.
    FilesystemRoot,
    /// rmule's own data directory, or a directory inside it.
    DataDirectory,
    /// A directory that holds rmule's own data directory.
    HoldsDataDirectory,
    /// Already in the list, or being added.
    AlreadyShared,
    /// Inside a directory already in the list.
    InsideShared {
        /// The listed directory it lies in.
        parent: PathBuf,
    },
    /// The download directory is shared while it is the download directory;
    /// it is changed in Settings, not removed.
    DownloadDirectory,
    /// Not in the list.
    NotShared,
    /// The store would not record the change.
    StoreFailed,
}

/// Check `path` for the add against `listed` — every entry's canonical path,
/// the download directory's and those being added included — and answer its
/// canonical path, the list's key.
///
/// # Errors
/// The first guard it fails, in the order ADR-0101 lists them.
pub(crate) fn admit(
    path: &Path,
    listed: &[PathBuf],
    guards: &ShareGuards,
) -> Result<PathBuf, DirectoryRefusal> {
    let dir = match std::fs::canonicalize(path) {
        Ok(dir) => dir,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(DirectoryRefusal::NotADirectory);
        }
        Err(error) => return Err(DirectoryRefusal::Unreachable(error.kind())),
    };
    match std::fs::metadata(&dir) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Err(DirectoryRefusal::NotADirectory),
        Err(error) => return Err(DirectoryRefusal::Unreachable(error.kind())),
    }
    if dir.to_str().is_none() {
        return Err(DirectoryRefusal::NotUtf8);
    }
    if guards.home.as_deref().map(canonical).as_deref() == Some(dir.as_path()) {
        return Err(DirectoryRefusal::HomeDirectory);
    }
    if mount_point(&dir) {
        return Err(DirectoryRefusal::FilesystemRoot);
    }
    if let Some(data) = guards.data_dir.as_deref().map(canonical) {
        if dir.starts_with(&data) {
            return Err(DirectoryRefusal::DataDirectory);
        }
        if data.starts_with(&dir) {
            return Err(DirectoryRefusal::HoldsDataDirectory);
        }
    }
    if listed.contains(&dir) {
        return Err(DirectoryRefusal::AlreadyShared);
    }
    if let Some(parent) = listed.iter().find(|entry| dir.starts_with(entry)) {
        return Err(DirectoryRefusal::InsideShared {
            parent: parent.clone(),
        });
    }
    Ok(dir)
}

/// `path` resolved, or as given when it cannot be: a guard over a path that
/// does not exist still compares its spelling.
pub(crate) fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Whether `dir` is a filesystem root: it has no parent, or its parent lies
/// on another volume — the device on Unix, the volume serial number on
/// Windows, where a volume mounted in a folder is opened through the folder.
/// Two Windows volumes with one serial number (a cloned disk) read as one,
/// and then only a drive root is refused.
fn mount_point(dir: &Path) -> bool {
    let Some(parent) = dir.parent() else {
        return true;
    };
    volume(dir).zip(volume(parent)).is_some_and(|(a, b)| a != b)
}

fn volume(path: &Path) -> Option<u64> {
    FileKey::at(path).ok().map(|key| key.volume)
}

/// Each entry of `entries`, with the entry it lies under when it is covered:
/// the outermost entries are scanned, every other is its parent's.
pub(crate) fn covering(entries: &[PathBuf]) -> Vec<(PathBuf, Option<PathBuf>)> {
    entries
        .iter()
        .map(|entry| {
            let by = entries
                .iter()
                .filter(|other| *other != entry && entry.starts_with(other))
                .min_by_key(|other| other.components().count())
                .cloned();
            (entry.clone(), by)
        })
        .collect()
}

#[cfg(test)]
mod tests;
