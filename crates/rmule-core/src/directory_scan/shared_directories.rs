//! The **Shared Directory List**'s rules that need no scan (ADR-0101,
//! "Shared Directories"): the guards an added directory and the download
//! directory must pass, the ones the **Temp Directory** must pass apart from
//! every shared directory (ADR-0115), and which entries are scanned and which
//! are covered by another. Pure but for the looks the guards take at the path
//! itself: its canonical form, whether it is a directory, and whether it is a
//! mount point.

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

/// Why a directory was not added to, or removed from, the list, or not
/// taken as the Temp Directory. A code: the front end words it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DirectoryRefusal {
    /// Nothing is there, or it is not a directory.
    NotADirectory,
    /// The path could not be looked at, or made, for an OS error of this kind.
    Unreachable(io::ErrorKind),
    /// The path is not valid UTF-8; the list keys on its text.
    NotUtf8,
    /// A relative path, which would move with the working directory.
    NotAbsolute,
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
    /// A Temp Directory holding a directory in the list, the download
    /// directory included.
    HoldsShared {
        /// The listed directory it holds.
        child: PathBuf,
    },
    /// The Temp Directory, or a directory holding it: rmule's unfinished part
    /// files lie there.
    HoldsTempDirectory,
    /// A directory inside the Temp Directory: no shared directory and the
    /// Temp Directory overlap, either way (ADR-0115).
    InsideTempDirectory,
    /// The download directory is shared while it is the download directory;
    /// it is changed in Settings, not removed.
    DownloadDirectory,
    /// Not in the list.
    NotShared,
    /// The store would not record the change.
    StoreFailed,
}

/// Check `path` for the add against `listed` — every entry's canonical path,
/// the download directory's and those being added included — and the Temp
/// Directory `temp_dir`, and answer its canonical path, the list's key.
///
/// # Errors
/// The first guard it fails, in the order ADR-0101 lists them.
pub(crate) fn admit(
    path: &Path,
    listed: &[PathBuf],
    guards: &ShareGuards,
    temp_dir: Option<&Path>,
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
    guard(&dir, guards, temp_dir)?;
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

/// Check a directory where it is now with the add's guards on what a
/// directory is: valid UTF-8, not the home, not a filesystem root, not rmule's
/// data directory, inside it or holding it, and neither the Temp Directory
/// `temp_dir`, holding it nor inside it. The download directory is judged
/// so at its set and before each of its scans, and every listed entry when its
/// scan starts and again when it appears after missing, since what a path
/// leads to can change after the add. Unlike an add it need not be there
/// yet — aMule makes its incoming directory, a download makes rmule's, and a
/// listed directory can be missing — so a directory not there is judged where
/// it would be, and its scan judges it again when it appears.
///
/// # Errors
/// The first guard it fails, in the order ADR-0101 lists them.
pub(crate) fn guard_in_place(
    dir: &Path,
    guards: &ShareGuards,
    temp_dir: Option<&Path>,
) -> Result<(), DirectoryRefusal> {
    guard(&resolved(dir), guards, temp_dir)
}

/// The guards on what the canonical directory `dir` is, whatever the list
/// holds.
fn guard(
    dir: &Path,
    guards: &ShareGuards,
    temp_dir: Option<&Path>,
) -> Result<(), DirectoryRefusal> {
    guard_any(dir, guards)?;
    if let Some(data) = guards.data_dir.as_deref().map(canonical) {
        if dir.starts_with(&data) {
            return Err(DirectoryRefusal::DataDirectory);
        }
        if data.starts_with(dir) {
            return Err(DirectoryRefusal::HoldsDataDirectory);
        }
    }
    if let Some(temp) = temp_dir.map(resolved) {
        if temp.starts_with(dir) {
            return Err(DirectoryRefusal::HoldsTempDirectory);
        }
        if dir.starts_with(&temp) {
            return Err(DirectoryRefusal::InsideTempDirectory);
        }
    }
    Ok(())
}

/// The guards every directory rmule keeps files in passes, on its canonical
/// path `dir`: valid UTF-8, not the home, not a filesystem root.
fn guard_any(dir: &Path, guards: &ShareGuards) -> Result<(), DirectoryRefusal> {
    if dir.to_str().is_none() {
        return Err(DirectoryRefusal::NotUtf8);
    }
    if guards.home.as_deref().map(canonical).as_deref() == Some(dir) {
        return Err(DirectoryRefusal::HomeDirectory);
    }
    if mount_point(dir) {
        return Err(DirectoryRefusal::FilesystemRoot);
    }
    Ok(())
}

/// Check `dir` for the Temp Directory where it is now, or would be made
/// (ADR-0115): an absolute path, not an existing file, then the guards every
/// directory passes ([`guard_any`]), and apart from the Shared Directory
/// List — not the download directory `download_dir`, nor one of `shared`
/// (canonical, as the list keys them), inside one or holding one. rmule's
/// data directory is no bar: the default lies inside it.
///
/// # Errors
/// The first guard it fails, in that order.
pub(crate) fn guard_temp_dir(
    dir: &Path,
    guards: &ShareGuards,
    download_dir: Option<&Path>,
    shared: &[PathBuf],
) -> Result<(), DirectoryRefusal> {
    if !dir.is_absolute() {
        return Err(DirectoryRefusal::NotAbsolute);
    }
    if dir.exists() && !dir.is_dir() {
        return Err(DirectoryRefusal::NotADirectory);
    }
    let dir = resolved(dir);
    guard_any(&dir, guards)?;
    let download = download_dir.map(resolved);
    if download.as_ref() == Some(&dir) {
        return Err(DirectoryRefusal::DownloadDirectory);
    }
    let listed: Vec<&PathBuf> = download.iter().chain(shared).collect();
    if listed.contains(&&dir) {
        return Err(DirectoryRefusal::AlreadyShared);
    }
    if let Some(parent) = listed.iter().find(|entry| dir.starts_with(entry)) {
        return Err(DirectoryRefusal::InsideShared {
            parent: (*parent).clone(),
        });
    }
    if let Some(child) = listed.iter().find(|entry| entry.starts_with(&dir)) {
        return Err(DirectoryRefusal::HoldsShared {
            child: (*child).clone(),
        });
    }
    Ok(())
}

/// The list's entries as the refused-folder rule reads them: each as the
/// list names it and where it leads now, symlinks resolved, with whether the
/// guards refuse it. Resolved once, when read, so one reading rules on every
/// row a pass looks at.
pub(crate) struct RefusedFolders {
    entries: Vec<RefusalEntry>,
}

struct RefusalEntry {
    named: PathBuf,
    real: PathBuf,
    refused: bool,
}

impl RefusedFolders {
    /// Read `listed`: each entry's path with whether the guards refuse it.
    pub(crate) fn read<'a>(listed: impl IntoIterator<Item = (&'a Path, bool)>) -> Self {
        let entries = listed
            .into_iter()
            .map(|(dir, refused)| RefusalEntry {
                named: dir.to_path_buf(),
                real: resolved(dir),
                refused,
            })
            .collect();
        Self { entries }
    }

    /// Whether a file at `path` lies under a refused entry. The entry nearest
    /// to it decides, so a passing entry inside a refused one shares its own
    /// files; of two entries equally near, a refused one decides. The rule is
    /// read twice, by the paths as spelt and by where they lead now, and
    /// either reading refusing the file refuses it: no other spelling of a
    /// refused folder — a link into it, or the folder named through a link —
    /// lets a file out.
    pub(crate) fn refuses(&self, path: &Path) -> bool {
        let real = resolved(path);
        nearest_refuses(path, self.entries.iter().map(|e| (&e.named, e.refused)))
            || nearest_refuses(&real, self.entries.iter().map(|e| (&e.real, e.refused)))
    }
}

/// Whether the entry of `entries` nearest to `path` — the deepest one it lies
/// under, a refused one on a tie — is refused.
fn nearest_refuses<'a>(path: &Path, entries: impl Iterator<Item = (&'a PathBuf, bool)>) -> bool {
    entries
        .filter(|(dir, _)| path.starts_with(dir))
        .max_by_key(|(dir, refused)| (dir.components().count(), *refused))
        .is_some_and(|(_, refused)| refused)
}

/// `path` with its longest existing ancestor resolved and the rest appended:
/// where a directory not made yet would be. As given when no ancestor
/// resolves, or a component is `..`.
fn resolved(path: &Path) -> PathBuf {
    let mut rest = Vec::new();
    let mut head = path;
    loop {
        if let Ok(real) = std::fs::canonicalize(head) {
            return rest.iter().rev().fold(real, |dir, name| dir.join(name));
        }
        match (head.parent(), head.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name);
                head = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
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
