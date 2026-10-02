//! A rename carries its hash when the file's identity proves it (ADR-0104,
//! "What the scan remembers"): a file at a path no record vouches for is
//! matched, by its **File Identity**, size and modification time, against the
//! rows and spare copies under the directory, and taken over unread. Nothing
//! here reads a byte; a file is looked at (its identity) only when some record
//! has its exact size and modification time.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use rmule_primitives::FileHash;

use super::plan::FoundFile;
use super::{DirectorySource, FileIdentity, FileStamp, Known, ScanReport, SpareCopy};

/// What a carried file becomes.
#[derive(Debug)]
pub(crate) enum Carry {
    /// The row of `file_hash`, whose file is no longer at `from`, moves to it.
    Row {
        /// The row's content.
        file_hash: FileHash,
        /// Where the row said the file lay.
        from: PathBuf,
        /// The file, with its stamp and identity.
        to: SpareCopy,
    },
    /// Its content is shared from another path: it is a spare copy.
    Spare(SpareCopy),
}

impl Carry {
    /// Report it, and say which row moved where, if one did.
    pub(crate) fn report(self, report: &mut dyn FnMut(ScanReport)) -> Option<(FileHash, PathBuf)> {
        match self {
            Self::Row {
                file_hash,
                from,
                to,
            } => {
                let path = to.path.clone();
                report(ScanReport::Moved {
                    file_hash,
                    from,
                    to,
                });
                Some((file_hash, path))
            }
            Self::Spare(spare) => {
                report(ScanReport::Spare(spare));
                None
            }
        }
    }
}

/// A record under the directory that can vouch for a file at a new path.
struct Voucher {
    file_hash: FileHash,
    identity: FileIdentity,
    /// The row's path; `None` for a spare copy, which never moves a row.
    row_at: Option<PathBuf>,
}

/// Split `files` — found at paths no record vouches for — into those carried
/// and those still to be read. `lost` holds the rows under `root` whose file
/// is no longer at their path as recorded (gone or changed): such a row moves
/// to the file its identity finds, at most once. A file whose identity
/// matches a row still in place (a hard link), or a spare copy, becomes a
/// spare copy.
pub(crate) fn carry(
    source: &dyn DirectorySource,
    root: &Path,
    files: Vec<FoundFile>,
    known: &Known,
    lost: &HashSet<FileHash>,
) -> (Vec<Carry>, Vec<FoundFile>) {
    let mut vouchers: HashMap<FileStamp, Vec<Voucher>> = HashMap::new();
    for row in known.rows.iter().filter(|row| row.path.starts_with(root)) {
        let (Some(identity), Some(modified)) = (known.identities.get(&row.file_hash), row.modified)
        else {
            continue;
        };
        let stamp = FileStamp {
            size: row.file_size,
            modified,
        };
        vouchers.entry(stamp).or_default().push(Voucher {
            file_hash: row.file_hash,
            identity: *identity,
            row_at: Some(row.path.clone()),
        });
    }
    for spare in known
        .spares
        .iter()
        .filter(|spare| spare.path.starts_with(root))
    {
        if let Some(identity) = spare.identity {
            vouchers.entry(spare.stamp).or_default().push(Voucher {
                file_hash: spare.file_hash,
                identity,
                row_at: None,
            });
        }
    }
    let mut moved: HashSet<FileHash> = HashSet::new();
    let (mut carried, mut still) = (Vec::new(), Vec::new());
    for file in files {
        let Some(candidates) = vouchers.get(&file.stamp) else {
            still.push(file);
            continue;
        };
        // Looked at only now: some record has this exact size and time.
        let Some(identity) = source.identity(&file.path) else {
            still.push(file);
            continue;
        };
        let Some(voucher) = candidates.iter().find(|v| v.identity == identity) else {
            still.push(file);
            continue;
        };
        let to = SpareCopy {
            path: file.path,
            file_hash: voucher.file_hash,
            stamp: file.stamp,
            identity: Some(identity),
        };
        carried.push(match &voucher.row_at {
            Some(from) if lost.contains(&voucher.file_hash) && moved.insert(voucher.file_hash) => {
                Carry::Row {
                    file_hash: voucher.file_hash,
                    from: from.clone(),
                    to,
                }
            }
            _ => Carry::Spare(to),
        });
    }
    (carried, still)
}
