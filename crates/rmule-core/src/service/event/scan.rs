//! The **Shared Directory List**'s and its scans' event vocabulary
//! (ADR-0100): the disclosure guard's question, an entry added, refused,
//! removed, missing or back, how a pass ended, and a watch that could not be
//! kept. What the scan shares or unshares arrives as the ordinary
//! `ServeEvent::FileShared` / `FileUnshared`, as any share-set change does.

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
    /// `dir` was not added or removed, for `reason` — or an added `dir`
    /// fails a guard where its path leads now, at attach or as it appears
    /// after missing: it stays in the list, listed as refused, and is not
    /// scanned until a later start finds it passes.
    DirectoryRefused {
        /// The directory, as the command or the list named it.
        dir: PathBuf,
        /// Why.
        reason: DirectoryRefusal,
    },
    /// The download directory the Core Settings name, `dir`, fails the
    /// guards for `reason`, at attach, when it moves, or when it appears: it
    /// is not scanned, and nothing under it is offered. The setting stands;
    /// downloads still finish there.
    DownloadDirectoryRefused {
        /// The directory, as the setting names it.
        dir: PathBuf,
        /// The guard it failed.
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
