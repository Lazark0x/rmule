//! The walk and the diff: which files lie under the download directory, and
//! against the registry and the spare copies, which the **Hash Trust Rule**
//! keeps, which leave, and which files are hashed. No byte of any file is
//! read here.

use std::collections::{BTreeSet, HashMap};
use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};

use rmule_primitives::FileHash;

use super::{DirectorySource, EntryKind, FileStamp, Known, SpareCopy};
use crate::registry::SharedFileEntry;

/// Whether the scan passes over a name, wherever it stands in a path: a
/// dot-prefixed name. rmule's own part files are skipped by their paths
/// ([`PartFiles`](super::PartFiles)), never by a suffix.
pub(crate) fn skipped_name(name: &OsStr) -> bool {
    name.to_string_lossy().starts_with('.')
}

/// A file the walk found, with its stamp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FoundFile {
    pub(crate) path: PathBuf,
    pub(crate) stamp: FileStamp,
}

/// What a walk found: every file it listed, and every known path under a
/// subfolder it could not list that could not be looked at on its own
/// either, with the error's kind.
#[derive(Debug, Default)]
pub(crate) struct Walked {
    pub(crate) found: Vec<FoundFile>,
    pub(crate) unreadable: Vec<(PathBuf, io::ErrorKind)>,
}

/// A registry row whose file is no longer at its path as recorded: gone, or
/// changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GoneRow {
    /// The row's content.
    pub(crate) file_hash: FileHash,
    /// Where the row says the file lies.
    pub(crate) path: PathBuf,
    /// The file's size, which a rename keeps.
    pub(crate) size: u64,
}

impl GoneRow {
    pub(crate) fn of(row: &SharedFileEntry) -> Self {
        Self {
            file_hash: row.file_hash,
            path: row.path.clone(),
            size: row.file_size,
        }
    }
}

/// What the pass does, decided before any read.
#[derive(Debug, Default)]
pub(crate) struct Plan {
    /// Rows and spare copies kept unread.
    pub(crate) trusted: usize,
    /// Rows whose file changed: their content is no longer on disk as shared,
    /// but nothing was removed, so they never join the Had Set.
    pub(crate) changed: Vec<GoneRow>,
    /// Spare copies whose file vanished or changed: their records go.
    pub(crate) spares_left: Vec<PathBuf>,
    /// Rows whose file is gone.
    pub(crate) gone: Vec<GoneRow>,
    /// Files to hash, in name order.
    pub(crate) hash: Vec<FoundFile>,
    /// Part files left by cancelled or completed downloads: never hashed.
    pub(crate) leftovers: Vec<PathBuf>,
    /// Trusted rows with no recorded identity, and their paths.
    pub(crate) unidentified: Vec<(FileHash, PathBuf)>,
    /// Rows under a subfolder that could not be listed whose file could not
    /// be looked at either: withheld as unreadable, never gone.
    pub(crate) unreadable: Vec<(FileHash, PathBuf, io::ErrorKind)>,
}

/// Every file under `root`, recursively, in name order. Skipped names
/// ([`skipped_name`]), symlinks and anything not a regular file are
/// skipped. A subfolder gone before it is listed hides nothing. One that
/// cannot be listed for another error hides what is under it, so each
/// known path under it is looked at on its own ([`look_under`]). Only
/// `root` itself failing is an error.
pub(crate) fn walk(source: &dyn DirectorySource, root: &Path, known: &Known) -> io::Result<Walked> {
    let mut walked = Walked::default();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = match source.list(&dir) {
            Ok(entries) => entries,
            Err(error) if dir == root => return Err(error),
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                tracing::warn!(dir = %dir.display(), %error, "could not list; each known file under it looked at alone");
                look_under(source, &dir, known, &mut walked);
                continue;
            }
        };
        for entry in entries {
            if skipped_name(&entry.name) {
                continue;
            }
            let path = dir.join(&entry.name);
            match entry.kind {
                EntryKind::Directory => pending.push(path),
                EntryKind::File(stamp) => walked.found.push(FoundFile { path, stamp }),
                EntryKind::Symlink | EntryKind::Other => {}
            }
        }
    }
    walked.found.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(walked)
}

/// Look at each registry row's and spare copy's path under `dir`, a folder
/// that cannot be listed: a file is found as a listing would have found it;
/// nothing, or something other than a file, is not there; any other error
/// makes the path unreadable, never gone.
fn look_under(source: &dyn DirectorySource, dir: &Path, known: &Known, walked: &mut Walked) {
    let paths: BTreeSet<&PathBuf> = known
        .rows
        .iter()
        .map(|row| &row.path)
        .chain(known.spares.iter().map(|spare| &spare.path))
        .filter(|path| path.starts_with(dir))
        .collect();
    for path in paths {
        match source.kind(path) {
            Ok(EntryKind::File(stamp)) => walked.found.push(FoundFile {
                path: path.clone(),
                stamp,
            }),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => walked.unreadable.push((path.clone(), error.kind())),
        }
    }
}

/// Diff what lies under `root` against what is `known`. A row or spare copy
/// under `root` whose path, size and modification time match a found file is
/// trusted; one that differs is dropped and its file hashed as new; one whose
/// file is gone is dropped. A found file with neither is hashed, unless it is
/// one of rmule's own part files. A row or spare copy the walk could not
/// look at is left as it is, the row withheld as unreadable. Rows outside
/// `root` are not the scan's.
pub(crate) fn plan(root: &Path, walked: Walked, known: &Known) -> Plan {
    let Walked { found, unreadable } = walked;
    let mut under: HashMap<&Path, &SharedFileEntry> = known
        .rows
        .iter()
        .filter(|row| row.path.starts_with(root))
        .map(|row| (row.path.as_path(), row))
        .collect();
    let mut spares: HashMap<&Path, &SpareCopy> = known
        .spares
        .iter()
        .filter(|spare| spare.path.starts_with(root))
        .map(|spare| (spare.path.as_path(), spare))
        .collect();
    let mut plan = Plan::default();
    for (path, kind) in unreadable {
        spares.remove(path.as_path());
        if let Some(row) = under.remove(path.as_path()) {
            plan.unreadable.push((row.file_hash, path, kind));
        }
    }
    for file in found {
        if known.parts.left.contains(&file.path) {
            plan.leftovers.push(file.path);
            continue;
        }
        if known.parts.live.contains(&file.path) {
            continue;
        }
        let spare = spares.remove(file.path.as_path());
        match under.remove(file.path.as_path()) {
            Some(row) if trusted(row, file.stamp) => {
                plan.trusted += 1;
                if !known.identities.contains_key(&row.file_hash) {
                    plan.unidentified.push((row.file_hash, row.path.clone()));
                }
            }
            Some(row) => {
                plan.changed.push(GoneRow::of(row));
                plan.hash.push(file);
            }
            None => match spare {
                Some(spare) if spare.stamp == file.stamp => plan.trusted += 1,
                Some(spare) => {
                    plan.spares_left.push(spare.path.clone());
                    plan.hash.push(file);
                }
                None => plan.hash.push(file),
            },
        }
    }
    // What is left names files that are no longer there.
    plan.gone.extend(under.into_values().map(GoneRow::of));
    plan.gone.sort_by(|a, b| a.path.cmp(&b.path));
    plan.spares_left
        .extend(spares.into_keys().map(Path::to_path_buf));
    plan.spares_left.sort();
    plan
}

/// The **Hash Trust Rule**: the row's size and time are the file's.
pub(crate) fn trusted(row: &SharedFileEntry, stamp: FileStamp) -> bool {
    row.file_size == stamp.size && row.modified == Some(stamp.modified)
}
