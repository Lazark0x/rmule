//! The run's source membership (ADR-0057): the sources the runner's
//! **Remote-Queued Pool** holds a standing for, handed between that pool and the
//! candidate pool, and the counts of every source the run knows.

use rmule_primitives::PeerEndpoint;

use super::{Decision, DownloadState};
use crate::download::source_ask_clock::SourceCounts;

impl DownloadState {
    /// Re-admit a source the runner's Remote-Queued Pool is driving a **TCP full
    /// ask** at (ADR-0057): its `FILEREASKTIME` heartbeat reconnects and re-asks.
    /// The source leaves the standing and joins the candidate pool — one owner
    /// handing it to the next (unless it is already a live worker or still
    /// pooled) — and any free slot fills, the same rejoin a peer-exchanged
    /// High-ID source takes. Returns the resulting spawn decisions.
    pub(crate) fn readd_source(&mut self, peer: PeerEndpoint) -> Vec<Decision> {
        let mut out = Vec::new();
        self.remote_queued.remove(&peer);
        if !self.holds(peer) {
            self.pool.push_back(peer);
        }
        self.fill(&mut out);
        out
    }

    /// The runner's Remote-Queued Pool took `peer` (ADR-0057): it queued us and
    /// hung up. From here a sighting of it merges into the standing rather than
    /// pooling it a second time.
    pub(crate) fn enter_remote_queue(&mut self, peer: PeerEndpoint) {
        self.remote_queued.insert(peer);
    }

    /// `peer` left the runner's Remote-Queued Pool without a TCP full ask — a
    /// slot grant or transfer on a live worker, or a `0x92` drop. A fact a
    /// sighting attached to its standing (another family's half) goes with it.
    pub(crate) fn leave_remote_queue(&mut self, peer: PeerEndpoint) {
        if self.remote_queued.remove(&peer) && !self.workers.contains_key(&peer) {
            self.dual_stack_fallbacks.remove(&peer);
        }
    }

    /// Sources this run knows now: the peers in a worker slot, the Low-ID
    /// callbacks awaited, every dial pool not yet drawn from, and each source
    /// that queued us and hung up — aMule's source count, republished beside
    /// the part map. A queued source still ending its worker counts once.
    pub(crate) fn known_sources(&self) -> u32 {
        let queued_only = self
            .remote_queued
            .iter()
            .filter(|peer| !self.workers.contains_key(peer) && !self.pool.contains(peer))
            .count();
        let known = self.workers.len()
            + self.pending_callbacks.len()
            + self.pool.len()
            + self.low_id_pool.len()
            + self.low_id_global_pool.len()
            + queued_only;
        u32::try_from(known).unwrap_or(u32::MAX)
    }

    /// Sources on queue, downloading or connected — aMule's
    /// `GetValidSourcesCount` (stock 2.3.3 `PartFile.cpp:3467-3496`): the peers in a worker
    /// slot and each source that queued us and hung up, counted once.
    fn valid_sources(&self) -> u32 {
        let queued_only = self
            .remote_queued
            .iter()
            .filter(|peer| !self.workers.contains_key(peer))
            .count();
        u32::try_from(self.workers.len() + queued_only).unwrap_or(u32::MAX)
    }

    /// The counts the source-ask rule reads: [`Self::known_sources`] and
    /// [`Self::valid_sources`].
    pub(crate) fn source_counts(&self) -> SourceCounts {
        SourceCounts {
            known: self.known_sources(),
            valid: self.valid_sources(),
        }
    }
}
