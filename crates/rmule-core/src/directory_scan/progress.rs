//! A scan's progress as core reports it: the diagnostics level a front end
//! reads while a scan runs, the phase it names, and what a finished pass came
//! to.

use std::path::PathBuf;
use std::time::SystemTime;

/// One entry of the **Shared Directory List** as the diagnostics snapshot
/// shows it, in list order (ADR-0101, "Shared Directories"): the directory,
/// what kind of entry it is, and its state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedDirectoryDiagnostics {
    /// The directory: the download directory as the preference names it,
    /// an added one by its canonical path.
    pub dir: PathBuf,
    /// What kind of entry it is.
    pub role: DirectoryRole,
    /// Its state.
    pub state: DirectoryState,
}

/// What kind of entry a listed directory is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DirectoryRole {
    /// Entry 0, the download directory: follows the preference, never
    /// removed.
    DownloadDirectory,
    /// A directory the operator added and confirmed.
    Added,
    /// A directory being added: its scan waits for the operator's confirm,
    /// and it is not in the list yet.
    Adding,
}

/// Where a listed directory stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectoryState {
    /// Its scan runs; the phase says where.
    Scan(ScanPhase),
    /// Its scan is starting and has not yet said where it stands.
    Starting,
    /// It lies under another listed directory, whose scan covers its files.
    Covered {
        /// The listed directory it lies under.
        by: PathBuf,
    },
    /// The operator declined to share it; nothing under it is offered.
    Declined,
    /// It could not be listed for a reason other than being missing; nothing
    /// under it is scanned until the next start.
    Unlistable,
    /// The guards refuse it (ADR-0101): the download directory the Core
    /// Settings name, or where an added directory's path leads now, is the
    /// home, a filesystem root, or rmule's data directory, inside it or
    /// holding it. It is not scanned, and it covers no other entry.
    Refused(crate::DirectoryRefusal),
}

/// A scan's progress: which directory, and where the pass stands. One per
/// running scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryScanDiagnostics {
    /// The directory being scanned.
    pub dir: PathBuf,
    /// Where the pass stands.
    pub phase: ScanPhase,
}

/// Where one pass stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanPhase {
    /// Walking the tree and comparing it with the registry; nothing read yet.
    Walking,
    /// The disclosure guard is waiting for the operator: what the directory
    /// would offer.
    AwaitingConsent {
        /// What would be offered.
        offer: DirectoryOffer,
    },
    /// The directory itself is not there: its files are withheld, and it is
    /// looked for once a minute.
    Missing {
        /// When rmule noticed.
        since: SystemTime,
    },
    /// Hashing: `done` of `total` files finished, `current` in hand.
    Hashing {
        /// Files finished, hashed or skipped.
        done: usize,
        /// Files the pass hashes in all.
        total: usize,
        /// The file being read now.
        current: PathBuf,
    },
    /// The first pass is done and reported, and the operating system's
    /// watch is being started: it ends in `Watching`, or in `Unwatched`
    /// with its reason.
    StartingWatch,
    /// The first pass is done and the directory is watched; `settling`
    /// files wait for five seconds of stillness before they are hashed.
    Watching {
        /// Files seen but not yet still.
        settling: usize,
    },
    /// The watch was lost while running and a new one is being started:
    /// what changed meanwhile is examined once it is back.
    Rewatching {
        /// Why the watch was lost, or why the last attempt failed.
        reason: super::WatchFault,
        /// Which of the bounded attempts is next, from 1.
        attempt: u32,
    },
    /// The first pass is done but the directory could not be watched: what
    /// it found holds, and nothing later is noticed until the next start.
    Unwatched {
        /// Why.
        reason: super::WatchFault,
    },
}

/// What a directory would offer, as the disclosure guard asks it: the
/// operator's confirm names these numbers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirectoryOffer {
    /// Files that would be offered.
    pub files: usize,
    /// Their size in bytes.
    pub bytes: u64,
    /// How many of them need no read: already hashed, or set aside.
    pub unread: usize,
}

/// What one pass came to, reported at its end.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScanSummary {
    /// Rows and spare copies the trust rule kept without a read.
    pub trusted: usize,
    /// Files hashed and shared.
    pub hashed: usize,
    /// Files at a new path whose hash their **File Identity** carried,
    /// unread: a row moved to them, or they became spare copies.
    pub carried: usize,
    /// Rows whose file changed or vanished: they left the registry, or
    /// moved to the same content at another path.
    pub dropped: usize,
    /// Files not shared: moved while hashed, or a second copy of content
    /// already shared from another path.
    pub skipped: usize,
    /// Files the pass could not read: each is also reported by path and
    /// reason as [`ScanEvent::FileNotHashed`](crate::ScanEvent::FileNotHashed).
    pub unreadable: usize,
}

/// One entry of the **Shared Directory List** as the actor installs it: a
/// running scan's state is read from its progress cell at the snapshot.
#[derive(Clone, Debug)]
pub(crate) struct InstalledDirectory {
    pub(crate) dir: std::path::PathBuf,
    pub(crate) role: crate::DirectoryRole,
    pub(crate) state: InstalledState,
}

/// Where an installed entry's state comes from.
#[derive(Clone, Debug)]
pub(crate) enum InstalledState {
    /// Its scan's progress cell.
    Scan(super::ProgressCell),
    /// A state the actor decided.
    Fixed(crate::DirectoryState),
}

impl InstalledDirectory {
    pub(crate) fn read(&self) -> crate::SharedDirectoryDiagnostics {
        let state = match &self.state {
            InstalledState::Scan(cell) => cell
                .lock()
                .expect("scan progress")
                .as_ref()
                .map_or(crate::DirectoryState::Starting, |progress| {
                    crate::DirectoryState::Scan(progress.phase.clone())
                }),
            InstalledState::Fixed(state) => state.clone(),
        };
        crate::SharedDirectoryDiagnostics {
            dir: self.dir.clone(),
            role: self.role,
            state,
        }
    }
}
