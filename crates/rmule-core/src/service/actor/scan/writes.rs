//! The scan's registry writes on their way to one commit (ADR-0102). A pass
//! reports two writes per file it hashes, and each commit is an fsync, so the
//! actor gathers them and commits many at once: every commit stays durable,
//! and nothing is offered or told before its commit returned, so a crash
//! costs the files of the open batch a second hash and claims nothing that is
//! not on the disk.

use std::time::Duration;

use tokio::time::Instant;

use crate::store::registry::ScanWrite;

/// The most writes one commit takes.
const MOST: usize = 256;

/// How long a write waits for others: what a file shared alone waits to be
/// offered.
const LONGEST: Duration = Duration::from_millis(250);

/// The writes no commit took yet, oldest first.
#[derive(Debug, Default)]
pub(in crate::service::actor) struct ScanWrites {
    pending: Vec<ScanWrite>,
    oldest: Option<Instant>,
}

impl ScanWrites {
    /// Gather `write`; `true` when the batch is full and wants its commit now.
    pub(super) fn push(&mut self, write: ScanWrite) -> bool {
        self.oldest.get_or_insert_with(Instant::now);
        self.pending.push(write);
        self.pending.len() >= MOST
    }

    /// Whether anything waits for a commit.
    pub(in crate::service::actor) const fn waiting(&self) -> bool {
        self.oldest.is_some()
    }

    /// When the oldest write has waited long enough. Asked with nothing
    /// waiting, the answer is now, and nobody waits on it.
    pub(in crate::service::actor) fn due(&self) -> Instant {
        self.oldest
            .map_or_else(Instant::now, |oldest| oldest + LONGEST)
    }

    /// Everything gathered, for one commit.
    pub(super) fn take(&mut self) -> Vec<ScanWrite> {
        self.oldest = None;
        std::mem::take(&mut self.pending)
    }
}
