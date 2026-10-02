//! The **file-known predicate**: whether this session would dial
//! for a file hash — one we share, or one we are downloading. aMule's
//! `GetFileByID` answers the same question across the same two tables
//! (`CKnownFileList` and `CDownloadQueue`,
//! [`ClientTCPSocket.cpp#L1630`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L1630)).
//!
//! A mirrored membership cell, not a query. The firewalled front's `0x99`
//! consume must never await the actor — the front is a `select!` loop nobody
//! else drains, and a round trip through it would be one more consumer it
//! could stall (the front's standing rule, `SharedTunnelAdmit`'s
//! shape). So the two tables' *writers* — the serve command arm and the
//! download command arm, both actor-owned — push every change here inline,
//! on the events that already mutate the tables (a shared directory's scan,
//! `UnshareFile`, an auto-share on download completion, a download starting or ending), and the
//! front reads the mirror synchronously off its own thread.
//!
//! The downloading half mirrors the **Download Set**'s files. A file is at
//! most one live download (the store refuses a duplicate), so a plain set of
//! hashes balances: each start inserts its hash, its retire removes that hash.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use rmule_primitives::FileHash;

/// The mirrored state: the Shared File Registry's key set, and the Download
/// Set's file hashes.
#[derive(Default)]
struct Known {
    shared: HashSet<FileHash>,
    downloading: HashSet<FileHash>,
}

/// The cell itself — cloned into `FirewalledWiring` (the one reader) and the
/// actor's `CoreWiring` (the writers). A plain `std::sync::Mutex`: every
/// section below is a map update that never crosses an `.await`.
#[derive(Clone, Default)]
pub(crate) struct SharedFileKnown(Arc<Mutex<Known>>);

impl SharedFileKnown {
    fn lock(&self) -> std::sync::MutexGuard<'_, Known> {
        self.0.lock().expect("file-known mutex")
    }

    /// A file joined the share set — a shared directory's scan, or a
    /// completed download's auto-share (ADR-0031).
    pub(crate) fn share(&self, file_hash: FileHash) {
        self.lock().shared.insert(file_hash);
    }

    /// A file left the share set (`UnshareFile`).
    pub(crate) fn unshare(&self, file_hash: FileHash) {
        self.lock().shared.remove(&file_hash);
    }

    /// A download of `file_hash` joined the Download Set
    /// (`StartDownload`/`ResumeDownload`).
    pub(crate) fn download_started(&self, file_hash: FileHash) {
        self.lock().downloading.insert(file_hash);
    }

    /// The download of `file_hash` was retired, however it ended —
    /// cancelled, paused, completed or failed (ADR-0093): its retire is the
    /// one caller, so one removal per start always balances, and it removes
    /// only its own file, never a download still running beside it.
    pub(crate) fn download_ended(&self, file_hash: FileHash) {
        self.lock().downloading.remove(&file_hash);
    }

    /// aMule's `GetFileByID`: shared, or the file we are downloading.
    pub(crate) fn contains(&self, file_hash: FileHash) -> bool {
        let known = self.lock();
        known.shared.contains(&file_hash) || known.downloading.contains(&file_hash)
    }
}
