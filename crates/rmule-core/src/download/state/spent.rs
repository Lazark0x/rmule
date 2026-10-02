//! **Spent Endpoints** of a download (ADR-0090): an
//! endpoint — a High-ID single-address source, either half of a dual-stack
//! one, or a Low-ID candidate's rung-0 IPv6 half — whose dial ended short of
//! a completed handshake is not dialed again until it has sat out a re-ask
//! period. One set carries both kinds: whichever road dialed it, an endpoint
//! nothing answered at is equally dead, and each road reads only its own
//! kind back (a High-ID half at pooling, a Low-ID half at the route choice).
//!
//! Why the dial ended does not matter: no route, refused, timed out, closed
//! before the hello answer, or a worker that could not even start all read
//! the same from here — nothing answers at that endpoint now. A worker that
//! did complete its handshake reached a live peer, so its end — queue full,
//! slot refused or timed out, a disconnect, a failed part — never spends it;
//! a queued source returns on ADR-0057's re-ask cadence instead. A
//! `CryptIncompatible` retirement was never dialed, so it spends nothing.
//!
//! The block lasts one to two `FILEREASKTIME` periods: the set is two
//! generations, turned once a period ([`DownloadState::on_reask_period`]), so
//! an endpoint spent in the current one stays spent through the next. That
//! brackets aMule's 30/45-minute dead-source block (`DeadSourceList.cpp:34`),
//! costs a dead source at most one failed dial per re-ask period, and lets a
//! source that was only momentarily down back in on its next sighting — with
//! no per-endpoint clock, so the brain stays clock-free.

use std::collections::HashSet;

use rmule_primitives::PeerEndpoint;

use super::DownloadState;

/// The two generations of spent endpoints (see the module docs).
#[derive(Debug, Default)]
pub(super) struct SpentEndpoints {
    current: HashSet<PeerEndpoint>,
    previous: HashSet<PeerEndpoint>,
}

impl SpentEndpoints {
    /// Spend `peer`: its dial ended short of a completed handshake.
    pub(super) fn spend(&mut self, peer: PeerEndpoint) {
        self.current.insert(peer);
    }

    /// Whether `peer` is spent — in either generation.
    pub(super) fn contains(&self, peer: &PeerEndpoint) -> bool {
        self.current.contains(peer) || self.previous.contains(peer)
    }

    /// A re-ask period passed: the older generation's endpoints are free to be
    /// dialed again.
    fn turn(&mut self) {
        self.previous = std::mem::take(&mut self.current);
    }
}

impl DownloadState {
    /// One `FILEREASKTIME` period passed (the runner's clock): endpoints spent
    /// two periods ago may be dialed again when next sighted. Nothing is
    /// re-pooled here — a spent endpoint left the pool when it was spent, and
    /// comes back only as a sighting brings it.
    pub(crate) fn on_reask_period(&mut self) {
        self.spent.turn();
    }
}
