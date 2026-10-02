//! The **Withheld Row**s (ADR-0106, "The registry against the disk"): the
//! registry rows kept while nothing is offered for them, each with its reason
//! and when rmule noticed. One cell, written by the actor alone and read by
//! everything that offers: the serve snapshot, the Kad publisher and the file
//! history. Until the Registry Check's start look is done nothing is offered.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use rmule_primitives::FileHash;

use crate::registry::SharedFileEntry;

/// Why a registry row is not offered now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WithheldReason {
    /// Its file is not at its path; the scan is looking for it elsewhere under
    /// the download directory, or the start look found it gone and the first
    /// recheck rules on it.
    Missing,
    /// Its file changed on disk; the scan hashes it again, or the first
    /// recheck rules on it.
    Changed,
    /// Its folder is missing too, as an unmounted volume's is. It stays until
    /// the folder returns or the operator unshares it.
    FolderMissing,
    /// Its file is there but cannot be opened or read, for this kind of
    /// error.
    Unreadable(std::io::ErrorKind),
}

/// One withheld row's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Withheld {
    /// Why nothing is offered for it.
    pub reason: WithheldReason,
    /// When rmule noticed — not when the file changed on disk.
    pub since: SystemTime,
}

#[derive(Default)]
struct State {
    /// The start look is not done: nothing is offered yet.
    before_look: bool,
    rows: HashMap<FileHash, Withheld>,
}

/// The withheld rows, shared by the actor (the one writer) and every reader
/// of the offer. A plain mutex: no section crosses an `.await`.
#[derive(Clone, Default)]
pub(crate) struct WithheldRows(Arc<Mutex<State>>);

impl WithheldRows {
    /// A cell for a core whose start look has not run: nothing is offered
    /// until [`looked`](Self::looked).
    pub(crate) fn before_start_look() -> Self {
        Self(Arc::new(Mutex::new(State {
            before_look: true,
            rows: HashMap::new(),
        })))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().expect("withheld rows")
    }

    /// The start look is done: every row not withheld is offered.
    pub(crate) fn looked(&self) {
        self.lock().before_look = false;
    }

    /// Whether the start look is done, so the offer is known.
    pub(crate) fn is_looked(&self) -> bool {
        !self.lock().before_look
    }

    /// Withhold `file_hash` for `reason`. True when this changed what is
    /// withheld: the row was offered, or held for another reason.
    pub(crate) fn withhold(
        &self,
        file_hash: FileHash,
        reason: WithheldReason,
        now: SystemTime,
    ) -> bool {
        let mut state = self.lock();
        if state
            .rows
            .get(&file_hash)
            .is_some_and(|held| held.reason == reason)
        {
            return false;
        }
        state
            .rows
            .insert(file_hash, Withheld { reason, since: now });
        true
    }

    /// Offer `file_hash` again, or forget it as its row leaves. True when it
    /// was withheld.
    pub(crate) fn lift(&self, file_hash: FileHash) -> bool {
        self.lock().rows.remove(&file_hash).is_some()
    }

    /// Why `file_hash` is withheld, if it is.
    pub(crate) fn get(&self, file_hash: FileHash) -> Option<Withheld> {
        self.lock().rows.get(&file_hash).copied()
    }

    /// Every withheld row's hash.
    pub(crate) fn hashes(&self) -> Vec<FileHash> {
        self.lock().rows.keys().copied().collect()
    }

    /// The rows of `rows` that are offered: none before the start look, and
    /// never a withheld one.
    pub(crate) fn offered(&self, rows: Vec<SharedFileEntry>) -> Vec<SharedFileEntry> {
        let state = self.lock();
        if state.before_look {
            return Vec::new();
        }
        rows.into_iter()
            .filter(|row| !state.rows.contains_key(&row.file_hash))
            .collect()
    }
}
