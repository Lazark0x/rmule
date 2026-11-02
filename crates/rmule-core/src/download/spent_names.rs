//! The node's **Spent Names** (ADR-0090): the **Ask Names** a source is not
//! pooled under for a while, on stock's dead-source windows
//! (`DeadSourceList.cpp:34-35`), one registry for the **Download Set**. A dead
//! peer is dead for every file, as stock's global list has it
//! (`ClientList.cpp:87`); a peer that lacks the file is spent for that file
//! alone, as its per-file list has it. A Pause, a Resume, a Cancel and a
//! re-add of one hash each keep them (ADR-0107 invariant 15), and a process
//! restart loses them, as stock's. Time is an argument, and a name past its
//! window simply reads unspent: no timer runs.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rmule_primitives::FileHash;

use crate::download::source_book::AskName;

/// How often expired names are dropped, so the registry stays bounded by what
/// its longest window can hold.
const SWEEP_SPACING: Duration = Duration::from_secs(60);

/// What spends a name, which picks its window and its reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Spend {
    /// A High ID that did not answer, or hung up before its file answer:
    /// stock's global `BLOCKTIME`, 30 minutes.
    DeadHighId,
    /// The same of a Low ID, a lapsed callback among it: stock's global
    /// `BLOCKTIMEFW`, 45 minutes.
    DeadLowId,
    /// It lacks this file: stock's per-file window, 45 minutes, 60 for a
    /// Low ID.
    NoFile {
        /// Whether it is a Low ID.
        low_id: bool,
    },
}

impl Spend {
    const fn window(self) -> Duration {
        Duration::from_secs(match self {
            Self::DeadHighId => 30 * 60,
            Self::DeadLowId | Self::NoFile { low_id: false } => 45 * 60,
            Self::NoFile { low_id: true } => 60 * 60,
        })
    }
}

/// The registry: each spent name, for one file or for all (`None`), and the
/// instant it is free again.
#[derive(Debug, Default)]
pub(crate) struct SpentNames {
    until: HashMap<(Option<FileHash>, AskName), Instant>,
    swept_at: Option<Instant>,
}

/// The core's one registry, shared by every run of the **Download Set**. Held
/// only for one read or write, never across an await.
pub(crate) type SharedSpentNames = Arc<Mutex<SpentNames>>;

impl SpentNames {
    /// An empty registry, shared.
    pub(crate) fn shared() -> SharedSpentNames {
        Arc::new(Mutex::new(Self::default()))
    }

    fn is_spent(&self, file: FileHash, name: AskName, now: Instant) -> bool {
        [None, Some(file)]
            .into_iter()
            .filter_map(|reach| self.until.get(&(reach, name)))
            .any(|&until| now < until)
    }

    fn sweep(&mut self, now: Instant) {
        if self
            .swept_at
            .is_none_or(|at| now.saturating_duration_since(at) >= SWEEP_SPACING)
        {
            self.swept_at = Some(now);
            self.until.retain(|_, until| now < *until);
        }
    }
}

/// One run's view of the registry, as a run of `file`.
#[derive(Debug)]
pub(crate) struct SpentSeat {
    names: SharedSpentNames,
    file: FileHash,
}

impl SpentSeat {
    /// A run of `file`'s view of `names`.
    pub(crate) const fn new(names: SharedSpentNames, file: FileHash) -> Self {
        Self { names, file }
    }

    /// A view of a registry of its own: one book no other shares a peer with.
    pub(crate) fn alone() -> Self {
        Self::new(SpentNames::shared(), FileHash::from_bytes([0; 16]))
    }

    fn lock(&self) -> parking_lot::MutexGuard<'_, SpentNames> {
        self.names.lock()
    }

    /// Spend `name` from `now`; a window already running longer stays.
    pub(crate) fn spend(&self, name: AskName, spend: Spend, now: Instant) {
        let reach = matches!(spend, Spend::NoFile { .. }).then_some(self.file);
        let until = now + spend.window();
        self.lock()
            .until
            .entry((reach, name))
            .and_modify(|held| *held = (*held).max(until))
            .or_insert(until);
    }

    /// Whether `name` is spent at `now`, for this file or for all.
    pub(crate) fn is_spent(&self, name: AskName, now: Instant) -> bool {
        self.lock().is_spent(self.file, name, now)
    }

    /// Drop what has expired, at most once in [`SWEEP_SPACING`].
    pub(crate) fn sweep(&self, now: Instant) {
        self.lock().sweep(now);
    }
}
