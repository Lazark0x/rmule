//! The **Source Book**'s blocks: what stops a source from being pooled, held
//! apart from the records because each outlives them (ADR-0090).
//!
//! **Spent names** — the **Ask Names** a source is not pooled under for a
//! while, held in the node's one registry (`spent_names`), so they outlive
//! the run. An endpoint whose dial ended short of a completed handshake is
//! spent: a High-ID single-address source, either half of a dual-stack one, a
//! Low-ID candidate's rung-0 IPv6 half. Why the dial ended does not matter: no
//! route, refused, timed out, closed before the hello answer, or a worker that
//! could not even start all read the same — nothing answers at that endpoint
//! now. A peer that answered the hello and closed before its file answer is
//! spent the same way (`BaseClient.cpp:1288-1293`), and so is a callback that
//! lapsed unanswered with its invitation out, under its Low-ID key: that is the
//! source's re-ask clock past its record. A worker whose file request was
//! answered reached a live peer and never spends, save one that said it lacks
//! the file: its record is spent under every name it holds — endpoints, Low-ID
//! key, User Hashes — as aMule dead-lists it (ADR-0090). A `CryptIncompatible`
//! retirement dialed nothing.
//!
//! **Distrusted peers** — a peer proven to have served this file bad data
//! (invariant 4). *Proven* is the rule's whole weight: the AICH recovery pins
//! corrupt blocks on their senders, a part with one contributor has nobody
//! else to blame, a hash set that is not the file's own convicts its sender,
//! and a refetch proves a cell's old copy or a writer's two copies of one cell
//! (ADR-0117 §1); a writer named only by elimination is not. Keyed by User Hash,
//! so the distrust follows the peer to a new address, and held for the
//! download's life, seeded from its durable record.

use std::collections::HashSet;
use std::time::Instant;

use rmule_primitives::UserHash;

use super::asks::AskName;
use crate::download::spent_names::{Spend, SpentSeat};

/// The run's seat in the **Spent Names**, the book's clock, and the distrusted
/// User Hashes.
#[derive(Debug)]
pub(super) struct Blocks {
    spent: SpentSeat,
    /// The brain's last instant: `None` before its first reached the book,
    /// when no worker has ended and nothing can be spent.
    now: Option<Instant>,
    distrusted: HashSet<UserHash>,
}

impl Blocks {
    /// Blocks that start from the distrust the download's record holds.
    pub(super) fn new(distrusted: HashSet<UserHash>) -> Self {
        Self {
            spent: SpentSeat::alone(),
            now: None,
            distrusted,
        }
    }

    /// Read and write spent names in `spent` from here on.
    pub(super) fn share_spent(&mut self, spent: SpentSeat) {
        self.spent = spent;
    }

    /// Spend `name`, as `spend` says.
    pub(super) fn spend(&mut self, name: impl Into<AskName>, spend: Spend) {
        if let Some(now) = self.now {
            self.spent.spend(name.into(), spend, now);
        }
    }

    /// Whether `name` is spent.
    pub(super) fn is_spent(&self, name: impl Into<AskName>) -> bool {
        self.now
            .is_some_and(|now| self.spent.is_spent(name.into(), now))
    }

    /// The brain reached the book at `now`.
    pub(super) fn clock(&mut self, now: Instant) {
        self.now = self.now.max(Some(now));
        self.spent.sweep(now);
    }

    /// Whether a source named by `user_hash` is distrusted.
    pub(super) fn distrusts(&self, user_hash: Option<UserHash>) -> bool {
        user_hash.is_some_and(|hash| self.distrusted.contains(&hash))
    }

    /// Distrust `user_hash`; `true` when it was not distrusted yet.
    pub(super) fn distrust(&mut self, user_hash: UserHash) -> bool {
        self.distrusted.insert(user_hash)
    }
}
