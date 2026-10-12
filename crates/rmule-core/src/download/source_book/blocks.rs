//! The **Source Book**'s blocks: what stops a source from being pooled, held
//! apart from the records because each outlives them (ADR-0090).
//!
//! **Spent endpoints** — an endpoint whose dial ended short of a completed
//! handshake: a High-ID single-address source, either half of a dual-stack
//! one, a Low-ID candidate's rung-0 IPv6 half. Why the dial ended does not
//! matter: no route, refused, timed out, closed before the hello answer, or a
//! worker that could not even start all read the same — nothing answers at
//! that endpoint now. A worker that did complete its handshake reached a live
//! peer and never spends; a `CryptIncompatible` retirement dialed nothing. The
//! block lasts one to two `FILEREASKTIME` periods: two generations, turned
//! once a period at the brain's tick, so an endpoint spent in the current one
//! stays spent through the next. That brackets aMule's 30/45-minute
//! dead-source block (`DeadSourceList.cpp:34`) with no per-endpoint clock.
//!
//! **Distrusted peers** — a peer proven to have served this file bad data
//! (invariant 4). *Proven* is the rule's whole weight: the AICH recovery pins
//! corrupt blocks on their senders, a part with one contributor has nobody
//! else to blame, a hash set that is not the file's own convicts its sender;
//! a retire-all across several contributors blames none. Keyed by User Hash,
//! so the distrust follows the peer to a new address, and held for the
//! download's life, seeded from its durable record.

use std::collections::HashSet;
use std::time::Instant;

use rmule_primitives::{PeerEndpoint, UserHash};

use super::standing::FILE_REASK_TIME;

/// The two generations of spent endpoints and the distrusted User Hashes.
#[derive(Debug, Default)]
pub(super) struct Blocks {
    spent: HashSet<PeerEndpoint>,
    spent_last_period: HashSet<PeerEndpoint>,
    /// When the generations last turned, or the run started: `None` before
    /// the brain's first instant reached the book.
    turned_at: Option<Instant>,
    distrusted: HashSet<UserHash>,
}

impl Blocks {
    /// Blocks that start from the distrust the download's record holds.
    pub(super) fn new(distrusted: HashSet<UserHash>) -> Self {
        Self {
            distrusted,
            ..Self::default()
        }
    }

    /// Spend `endpoint`: its dial ended short of a completed handshake.
    pub(super) fn spend(&mut self, endpoint: PeerEndpoint) {
        self.spent.insert(endpoint);
    }

    /// Whether `endpoint` is spent, in either generation.
    pub(super) fn is_spent(&self, endpoint: PeerEndpoint) -> bool {
        self.spent.contains(&endpoint) || self.spent_last_period.contains(&endpoint)
    }

    /// Turn the generations at `now` when a re-ask period has passed since
    /// the last turn: the older generation may be dialed again. The first
    /// instant only starts the period.
    pub(super) fn turn_at(&mut self, now: Instant) {
        match self.turned_at {
            None => self.turned_at = Some(now),
            Some(at) if now.saturating_duration_since(at) >= FILE_REASK_TIME => {
                self.spent_last_period = std::mem::take(&mut self.spent);
                self.turned_at = Some(now);
            }
            Some(_) => {}
        }
    }

    /// When the generations next turn.
    pub(super) fn next_turn(&self) -> Option<Instant> {
        self.turned_at.map(|at| at + FILE_REASK_TIME)
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
