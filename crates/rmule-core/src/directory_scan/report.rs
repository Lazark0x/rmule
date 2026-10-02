//! What the scan tells the actor on the report lane: each registry change it
//! asks for, and how a pass ended. The scan decides and reports; the actor
//! owns the registry and writes.

use std::io;
use std::path::PathBuf;

use rmule_primitives::FileHash;

use super::{FileIdentity, ScanSummary, SpareCopy, WatchFault};
use crate::registry::SharedFileEntry;

/// A registry change the scan asks the actor to make, or the end of its
/// first pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ScanReport {
    /// The file behind this row changed; its old hash is not Had.
    Unshare(FileHash),
    /// The file behind this row is gone from `path`, and its content was not
    /// found elsewhere: the row leaves and its hash joins the Had Set.
    Gone {
        /// The row's content.
        file_hash: FileHash,
        /// Where the row said the file lay.
        path: PathBuf,
    },
    /// The row's file is not at `path`, and a file of its size may be it at
    /// a new path: the row stays while the scan finds out, and nothing is
    /// offered for it meanwhile.
    Held {
        /// The row's content.
        file_hash: FileHash,
        /// Where the row said the file lay.
        path: PathBuf,
    },
    /// The row's file lies under a folder that cannot be listed, and could
    /// not be looked at on its own for an error of this kind: nothing is
    /// offered for it, and it is never Had.
    Unreadable {
        /// The row's content.
        file_hash: FileHash,
        /// Where the row says the file lies.
        path: PathBuf,
        /// The kind of the look's error.
        kind: io::ErrorKind,
    },
    /// The watch could not read the file at `path`, for an OS error of this
    /// kind and number: it is not shared. Told once until it is hashed; a
    /// later change notice for it tries again.
    NotHashed {
        /// The file.
        path: PathBuf,
        /// The kind of the OS error.
        kind: io::ErrorKind,
        /// The OS's error number, when there is one.
        os_code: Option<i32>,
    },
    /// A file hashed and ready to share.
    Share(SharedFileEntry),
    /// The row of `file_hash` moves, unread, from `from` to the file `to`
    /// describes: a spare copy, or the same file renamed. Its part hash set
    /// stays; a spare recorded at the new path is gone.
    Moved {
        /// The row's content.
        file_hash: FileHash,
        /// Where the row said the file lay.
        from: PathBuf,
        /// The file it moves to, with its stamp and identity.
        to: SpareCopy,
    },
    /// A file whose content is shared from another path: recorded, never
    /// offered.
    Spare(SpareCopy),
    /// The spare copy recorded at this path vanished or changed.
    SpareLeft(PathBuf),
    /// The file behind the row of `file_hash`, at `path`, has this identity.
    Identified {
        /// The row's content.
        file_hash: FileHash,
        /// The row's path.
        path: PathBuf,
        /// The file's identity.
        identity: FileIdentity,
    },
    /// The watch was lost while running, for this reason; it is being
    /// re-established.
    WatchInterrupted(WatchFault),
    /// A lost watch runs again, and the whole directory is examined.
    WatchRestored,
    /// This path is no longer watched, for this reason; the rest is.
    PathUnwatched {
        /// The path.
        path: PathBuf,
        /// Why.
        reason: WatchFault,
    },
    /// Part files left by cancelled or completed downloads lie at these
    /// paths: skipped, never shared, and left on disk. Each is reported once
    /// per scan.
    LeftoverParts(Vec<PathBuf>),
    /// The first pass hashed or skipped every planned file; the watch starts.
    Finished(ScanSummary),
    /// The directory itself is not there, noticed at `since`: every row
    /// under it is withheld, never Had, until it is back.
    RootMissing {
        /// When rmule noticed.
        since: std::time::SystemTime,
    },
    /// The missing directory is back; a fresh pass runs.
    RootReturned,
    /// The set-aside row at this path no longer describes the file there.
    SetAsideLeft(PathBuf),
}

/// How a pass ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PassEnd {
    /// Every planned file was hashed or skipped.
    Finished(ScanSummary),
    /// The operator declined; nothing moved.
    Declined,
    /// The stop flag was raised; what was reported before it stands.
    Stopped,
    /// The directory itself could not be listed.
    Unlistable,
}
