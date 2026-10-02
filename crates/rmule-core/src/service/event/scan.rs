//! The **Shared Directory List**'s and its scans' event vocabulary
//! (ADR-0100): the disclosure guard's question, an entry added, refused,
//! removed, missing or back, how a pass ended, and a watch that could not be
//! kept. What the scan shares or unshares arrives as the ordinary
//! `ServeEvent::FileShared` / `FileUnshared`, as any share-set change does.

use std::fmt;
use std::path::PathBuf;

use crate::{DirectoryOffer, DirectoryRefusal, ScanSummary, WatchFault};

use super::CoreEvent;

/// A **Download Directory Scan** fact. Wrapped by [`CoreEvent::Scan`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanEvent {
    /// The first scan of `dir` found files it would offer, or `dir` is
    /// being added. Nothing under it is hashed or shared until a
    /// `ScanCommand::Answer` for `dir` arrives.
    ConsentRequested {
        /// The directory asked about.
        dir: PathBuf,
        /// What it would offer.
        offer: DirectoryOffer,
        /// Whether the operator is adding it (else it is the download
        /// directory's first share).
        adding: bool,
        /// The listed directories a yes replaces: they lie under `dir`.
        replaces: Vec<PathBuf>,
    },
    /// `dir` is in the list now, and `replaced` are not.
    DirectoryAdded {
        /// The directory, by its canonical path.
        dir: PathBuf,
        /// The listed directories it replaced.
        replaced: Vec<PathBuf>,
    },
    /// `dir` was not added or removed, for `reason`.
    DirectoryRefused {
        /// The directory, as the command named it.
        dir: PathBuf,
        /// Why.
        reason: DirectoryRefusal,
    },
    /// `dir` left the list: `files` left the registry at once, not Had, and
    /// are set aside.
    DirectoryRemoved {
        /// The directory.
        dir: PathBuf,
        /// How many shared files it took with it.
        files: usize,
    },
    /// The listed directory `dir` is not there, noticed at `since`: its
    /// files are withheld, never Had, and it stays listed. Said once until
    /// it is back.
    DirectoryMissing {
        /// The directory.
        dir: PathBuf,
        /// When rmule noticed.
        since: std::time::SystemTime,
    },
    /// The missing directory `dir` is back: its files are looked at again,
    /// unread, and offered.
    DirectoryReturned {
        /// The directory.
        dir: PathBuf,
    },
    /// The pass over `dir` ended; what it kept, shared and dropped.
    Finished {
        /// The directory scanned.
        dir: PathBuf,
        /// What the pass came to.
        summary: ScanSummary,
    },
    /// The operator declined to share `dir`, now or before; nothing under it
    /// is offered.
    Declined {
        /// The directory declined.
        dir: PathBuf,
    },
    /// The first pass over `dir` holds, but the directory is not watched:
    /// files that appear or change under it are not noticed until the next
    /// start. Said once per start.
    WatchUnavailable {
        /// The directory not watched.
        dir: PathBuf,
        /// Why.
        reason: WatchFault,
    },
    /// The watch over `dir` was lost while running and is being
    /// re-established; what changes meanwhile is examined once it is back.
    /// Said once per outage.
    WatchInterrupted {
        /// The directory.
        dir: PathBuf,
        /// Why.
        reason: WatchFault,
    },
    /// A lost watch over `dir` runs again, and the whole directory is
    /// examined for what changed meanwhile. Ends the outage.
    WatchRestored {
        /// The directory.
        dir: PathBuf,
    },
    /// `path` under `dir` is no longer watched; the rest of `dir` is. Said
    /// once per path while the watch lives; the next watch covers it again.
    PathUnwatched {
        /// The directory.
        dir: PathBuf,
        /// The path not watched.
        path: PathBuf,
        /// Why.
        reason: WatchFault,
    },
    /// Part files left by cancelled or completed downloads lie under `dir`.
    /// They are rmule's own partial work, so they are not shared, and they
    /// are left where they are. Each path is told once per scan.
    LeftoverParts {
        /// The directory scanned.
        dir: PathBuf,
        /// The leftover part files.
        paths: Vec<PathBuf>,
    },
    /// The watch could not read the file at `path` under `dir`, for an OS
    /// error of this kind and number, so it is not shared. Said once per
    /// file until it is hashed; a later change to it tries again.
    FileNotHashed {
        /// The directory.
        dir: PathBuf,
        /// The file not read.
        path: PathBuf,
        /// The kind of the OS error.
        kind: std::io::ErrorKind,
        /// The OS's error number, when there is one.
        os_code: Option<i32>,
    },
    /// `dir` itself could not be listed — missing, unmounted or unreadable.
    /// Nothing was unshared: a disk that is gone for now is not a deletion.
    Unlistable {
        /// The directory that could not be listed.
        dir: PathBuf,
    },
}

impl From<ScanEvent> for CoreEvent {
    fn from(event: ScanEvent) -> Self {
        Self::Scan(event)
    }
}

impl fmt::Display for ScanEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConsentRequested {
                dir,
                offer,
                adding,
                replaces,
            } => {
                write!(
                    f,
                    "scan_consent_requested dir={} files={} bytes={} unread={} adding={adding} replaces={}",
                    dir.display(),
                    offer.files,
                    offer.bytes,
                    offer.unread,
                    replaces.len(),
                )
            }
            Self::DirectoryAdded { dir, replaced } => write!(
                f,
                "shared_directory_added dir={} replaced={}",
                dir.display(),
                replaced.len()
            ),
            Self::DirectoryRefused { dir, reason } => write!(
                f,
                "shared_directory_refused dir={} reason={reason:?}",
                dir.display()
            ),
            Self::DirectoryRemoved { dir, files } => write!(
                f,
                "shared_directory_removed dir={} files={files}",
                dir.display()
            ),
            Self::DirectoryMissing { dir, .. } => {
                write!(f, "shared_directory_missing dir={}", dir.display())
            }
            Self::DirectoryReturned { dir } => {
                write!(f, "shared_directory_returned dir={}", dir.display())
            }
            Self::Finished { dir, summary } => write!(
                f,
                "scan_finished dir={} trusted={} hashed={} carried={} dropped={} skipped={}",
                dir.display(),
                summary.trusted,
                summary.hashed,
                summary.carried,
                summary.dropped,
                summary.skipped,
            ),
            Self::Declined { dir } => write!(f, "scan_declined dir={}", dir.display()),
            Self::Unlistable { dir } => write!(f, "scan_unlistable dir={}", dir.display()),
            Self::WatchInterrupted { dir, reason } => write!(
                f,
                "scan_watch_interrupted dir={} reason={reason:?}",
                dir.display()
            ),
            Self::WatchRestored { dir } => {
                write!(f, "scan_watch_restored dir={}", dir.display())
            }
            Self::PathUnwatched { dir, path, reason } => write!(
                f,
                "scan_path_unwatched dir={} path={} reason={reason:?}",
                dir.display(),
                path.display()
            ),
            Self::FileNotHashed {
                dir,
                path,
                kind,
                os_code,
            } => write!(
                f,
                "scan_file_not_hashed dir={} path={} kind={kind:?} os_code={}",
                dir.display(),
                path.display(),
                os_code.map_or_else(|| "none".to_string(), |code| code.to_string()),
            ),
            Self::LeftoverParts { dir, paths } => write!(
                f,
                "scan_leftover_parts dir={} count={}",
                dir.display(),
                paths.len()
            ),
            Self::WatchUnavailable { dir, reason } => write!(
                f,
                "scan_watch_unavailable dir={} reason={reason:?}",
                dir.display()
            ),
        }
    }
}
