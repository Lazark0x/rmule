//! What the serve activity did for each shared file: aMule's per-file
//! statistic (`CFileStatistic`, `amule-2.3.3/src/KnownFile.cpp:76-98`) — upload
//! requests drawn, slots granted, bytes served — both for this run and all
//! time, the two figures aMule's Shared Files list shows side by side.
//!
//! This run's figures start at zero when core starts and are never retired,
//! so a file's row outlives the peers that fed it. The all-time figures are
//! the **Share Totals** the Durable Store held at start plus this run's; the
//! [`ShareLedger`] hands the files that moved to the actor's periodic flush,
//! which writes them back (`crate::store::share_totals`).

use std::collections::{BTreeMap, BTreeSet};

use rmule_primitives::FileHash;

/// One file's serve figures over some span — a run, or all time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShareTotals {
    /// Upload requests (`OP_STARTUPLOADREQ`) the file drew from peers not
    /// already waiting for it — aMule's `AddRequest`
    /// (`amule-2.3.3/src/UploadQueue.cpp:483`): counted once past the
    /// per-address cap, whether the peer then got a slot, a place, or found the
    /// wait list full. A waiting peer asking again is not a new request.
    pub requests: u64,
    /// Upload slots granted for the file — aMule's `AddAccepted`
    /// (`UploadQueue.cpp:229`).
    pub accepted: u64,
    /// Payload bytes of this file handed to peers' connection writers —
    /// aMule's `AddTransferred`. Monotonic.
    pub transferred: u64,
}

impl ShareTotals {
    fn plus(self, other: Self) -> Self {
        Self {
            requests: self.requests.saturating_add(other.requests),
            accepted: self.accepted.saturating_add(other.accepted),
            transferred: self.transferred.saturating_add(other.transferred),
        }
    }
}

/// One shared file's serve counters. Keyed by the file's hash in
/// [`DiagnosticsSnapshot::shared_files`](super::DiagnosticsSnapshot::shared_files);
/// a file with neither this run's activity nor stored totals has no entry,
/// which reads as zero of each.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SharedFileCounters {
    /// Upload requests this run ([`ShareTotals::requests`]).
    pub requests: u64,
    /// Slots granted this run ([`ShareTotals::accepted`]).
    pub accepted: u64,
    /// Bytes served this run; the same bytes
    /// [`SessionCounters::up_bytes_total`](super::SessionCounters::up_bytes_total)
    /// sums over every file.
    pub transferred: u64,
    /// Every run's, this one included — up to date to the byte, whatever
    /// the store has been flushed with so far.
    pub all_time: ShareTotals,
}

/// The per-file figures behind [`SharedFileCounters`], and which files moved
/// since the last flush.
#[derive(Debug, Default)]
pub(super) struct ShareLedger {
    /// What the store held when core started. Set once; never flushed into,
    /// so the all-time figure is always `stored + run`.
    stored: BTreeMap<FileHash, ShareTotals>,
    run: BTreeMap<FileHash, ShareTotals>,
    moved: BTreeSet<FileHash>,
}

impl ShareLedger {
    pub(super) fn seed(&mut self, stored: BTreeMap<FileHash, ShareTotals>) {
        self.stored = stored;
    }

    /// Fold one event's worth of `delta` into `file_hash`'s run figures.
    pub(super) fn add(&mut self, file_hash: FileHash, delta: ShareTotals) {
        let run = self.run.entry(file_hash).or_default();
        *run = run.plus(delta);
        self.moved.insert(file_hash);
    }

    fn all_time(&self, file_hash: &FileHash) -> ShareTotals {
        let stored = self.stored.get(file_hash).copied().unwrap_or_default();
        stored.plus(self.run.get(file_hash).copied().unwrap_or_default())
    }

    pub(super) fn counters(&self) -> BTreeMap<FileHash, SharedFileCounters> {
        self.stored
            .keys()
            .chain(self.run.keys())
            .map(|file_hash| {
                let run = self.run.get(file_hash).copied().unwrap_or_default();
                let counters = SharedFileCounters {
                    requests: run.requests,
                    accepted: run.accepted,
                    transferred: run.transferred,
                    all_time: self.all_time(file_hash),
                };
                (*file_hash, counters)
            })
            .collect()
    }

    /// The all-time figures of every file that moved since the last take,
    /// forgetting that they moved.
    pub(super) fn take_moved(&mut self) -> Vec<(FileHash, ShareTotals)> {
        std::mem::take(&mut self.moved)
            .into_iter()
            .map(|file_hash| (file_hash, self.all_time(&file_hash)))
            .collect()
    }

    /// A flush that failed: its files moved still.
    pub(super) fn restore_moved(&mut self, files: impl IntoIterator<Item = FileHash>) {
        self.moved.extend(files);
    }
}
