//! The per-download part scheduler: which peer works which part, which parts two
//! peers may race (ADR-0026), and which part backfills a worker that retired
//! (ADR-0030). A peer is handed only a part its **Advertised Parts** hold,
//! chosen by one rank (ADR-0112): very rare first, then aMule's head and tail,
//! then a streaming window, then rarest. It is pure bookkeeping over the part
//! plan — the brain that calls it owns every decision that reaches a socket.

mod rank;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use rmule_peer::{PartBitmap, PartIndex};
use rmule_primitives::PeerEndpoint;

use self::rank::{RankInputs, preview_band, rank, very_rare_bound};
use crate::PartPlan;
use crate::diagnostics::PartState;
use crate::planning::{plan_missing_part_ranges, plan_part_ranges};

/// How a download's parts are ordered past rarity (ADR-0112 §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartOrder {
    /// No **Preview Band** and no **Streaming Window**: very rare first, then
    /// the rarest, then the lowest index. Every download outside Streaming
    /// Priority.
    Rarest,
    /// A Streaming Priority download: aMule's preview parts — the first, the
    /// last, and the last-but-one when the last is short — as the Preview
    /// Band, then a Streaming Window of `window_parts` parts from the lowest
    /// unverified one, `0` for none.
    Streaming {
        /// The window's width `N` (`CoreConfig::streaming_window_parts`).
        window_parts: u32,
    },
}

impl PartOrder {
    /// The order a download ranks its parts in: a Streaming Window of
    /// `window_parts` when it is Streaming Priority, else the rarest first.
    #[must_use]
    pub const fn of(streaming_priority: bool, window_parts: u32) -> Self {
        if streaming_priority {
            Self::Streaming { window_parts }
        } else {
            Self::Rarest
        }
    }

    /// The Preview Band of a `file_size`-byte file in this order.
    fn band(self, file_size: u64) -> BTreeSet<u32> {
        match self {
            Self::Rarest => BTreeSet::new(),
            Self::Streaming { .. } => preview_band(file_size),
        }
    }

    /// The Streaming Window's width; `0` for none.
    const fn window_parts(self) -> u32 {
        match self {
            Self::Rarest => 0,
            Self::Streaming { window_parts } => window_parts,
        }
    }
}

/// What [`DownloadScheduler::assign_next`] handed a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Assignment {
    /// A pending part, now the peer's.
    Fresh(PartPlan),
    /// An in-flight part the peer now races (ADR-0026).
    Raced(PartPlan),
    /// The peer already works a part, and is handed nothing beside it.
    Busy,
    /// Nothing to do. `lacked` says whether the peer's Advertised Parts hold
    /// a part the file still lacks — every one in flight, the peer's own
    /// included — or none, aMule's `bPartsNeeded` false.
    Nothing {
        /// Whether the peer holds a part the file still lacks.
        lacked: bool,
    },
}

/// Per-download part scheduler.
///
/// A part is in exactly one of three states: **pending** (not assigned to
/// any peer), **racing** (assigned to one or more peers), or verified (no
/// longer tracked). Each peer works at most one part at a time
/// (ADR-0026's per-worker rule), but per ADR-0026's racing amendment a
/// single part may be assigned to several peers concurrently when there
/// are more idle peers than missing parts — the first peer to deliver a
/// verified copy wins and the others are dropped. This keeps backup peers
/// queued on a busy uploader instead of sitting idle (and being dropped),
/// which is what lets a scarce-part download survive a slow primary.
#[derive(Clone, Debug)]
pub struct DownloadScheduler {
    /// How many parts the file has. Kept so the scheduler can answer for
    /// *every* index — the verified ones left both maps (or never entered
    /// them, on resume), and absence alone cannot name them.
    total_parts: u32,
    pending: BTreeMap<u32, PartPlan>,
    racing: BTreeMap<u32, RacingPart>,
    peer_part: HashMap<PeerEndpoint, u32>,
    completed: HashSet<PeerEndpoint>,
    /// The **Preview Band**, empty outside Streaming Priority. A member that
    /// verifies simply leaves candidacy.
    band: BTreeSet<u32>,
    /// The **Streaming Window**'s width; `0` for none.
    window_parts: u32,
}

#[derive(Clone, Debug)]
struct RacingPart {
    plan: PartPlan,
    racers: HashSet<PeerEndpoint>,
}

impl DownloadScheduler {
    /// Plan every part of `file_size` and mark `verified_parts` as already done,
    /// so a resumed download starts with only what it still needs pending,
    /// its parts ranked in `order`.
    #[must_use]
    pub fn new(
        file_size: u64,
        verified_parts: impl IntoIterator<Item = u32>,
        order: PartOrder,
    ) -> Self {
        let verified_parts = verified_parts.into_iter().collect::<Vec<_>>();
        let plans = if verified_parts.is_empty() {
            plan_part_ranges(file_size)
        } else {
            plan_missing_part_ranges(file_size, &verified_parts)
        };
        let pending = plans
            .into_iter()
            .map(|plan| (plan.part_index, plan))
            .collect();
        Self {
            total_parts: rmule_primitives::part_count(file_size),
            pending,
            racing: BTreeMap::new(),
            peer_part: HashMap::new(),
            completed: HashSet::new(),
            band: order.band(file_size),
            window_parts: order.window_parts(),
        }
    }

    /// Assign `peer` a part its Advertised Parts `parts` hold, by rank
    /// (ADR-0112 §4) over the download's **Part Frequency** `frequency` and
    /// the `known` sources whose parts are known. Prefers a fresh pending
    /// part; when none is left a *backup* peer (one that has not yet
    /// completed a part) races the best-ranked in-flight part it holds and is
    /// not already on, so a surplus peer stays queued on a busy uploader
    /// instead of idling (ADR-0026). A peer that has already delivered a part
    /// idles rather than redundantly racing a healthy in-flight peer. A peer
    /// that already holds a part is [`Assignment::Busy`].
    pub fn assign_next(
        &mut self,
        peer: PeerEndpoint,
        parts: &PartBitmap,
        frequency: &[u32],
        known: u32,
    ) -> Assignment {
        if self.peer_part.contains_key(&peer) {
            return Assignment::Busy;
        }
        let held = |part: &u32| parts.has(PartIndex::new(*part));
        let inputs = RankInputs {
            frequency,
            very_rare_bound: very_rare_bound(known),
            band: &self.band,
            window: self.window(),
        };
        let fresh = self
            .pending
            .keys()
            .filter(|part| held(part))
            .min_by_key(|&&part| rank(part, &inputs))
            .copied();
        if let Some(part_index) = fresh
            && let Some(plan) = self.pending.remove(&part_index)
        {
            let mut racers = HashSet::new();
            racers.insert(peer);
            self.racing.insert(part_index, RacingPart { plan, racers });
            self.peer_part.insert(peer, part_index);
            return Assignment::Fresh(plan);
        }

        let lacked = self.lacks_any_of(parts);
        if self.completed.contains(&peer) {
            return Assignment::Nothing { lacked };
        }
        let raced = self
            .racing
            .iter()
            .filter(|(part, racing)| held(part) && !racing.racers.contains(&peer))
            .map(|(&part, _)| part)
            .min_by_key(|&part| rank(part, &inputs));
        let Some(part) = raced.and_then(|part_index| self.racing.get_mut(&part_index)) else {
            return Assignment::Nothing { lacked };
        };
        part.racers.insert(peer);
        let plan = part.plan;
        self.peer_part.insert(peer, plan.part_index);
        Assignment::Raced(plan)
    }

    /// Whether a source whose Advertised Parts are `parts` holds a part the
    /// file still lacks — aMule's `bPartsNeeded` (stock 2.3.3
    /// `DownloadClient.cpp:397-449`), the one predicate a `0x91` status and an
    /// assignment both read.
    #[must_use]
    pub fn lacks_any_of(&self, parts: &PartBitmap) -> bool {
        parts
            .iter_present()
            .any(|part| !self.is_part_verified(part.value()))
    }

    /// The **Streaming Window**: `window_parts` parts from the lowest
    /// unverified one, so it slides as its anchor verifies.
    fn window(&self) -> std::ops::Range<u32> {
        let anchor = match (self.pending.keys().next(), self.racing.keys().next()) {
            (Some(&pending), Some(&racing)) => pending.min(racing),
            (Some(&lowest), None) | (None, Some(&lowest)) => lowest,
            (None, None) => return 0..0,
        };
        anchor..anchor.saturating_add(self.window_parts)
    }

    /// Mark the part `peer` was working as verified. Removes the part and
    /// drops every other peer that was racing it (they were working an
    /// already-finished part). Returns the completed plan.
    pub fn complete_verified(&mut self, peer: PeerEndpoint) -> Option<PartPlan> {
        let part_index = self.peer_part.remove(&peer)?;
        let part = self.racing.remove(&part_index)?;
        for racer in &part.racers {
            self.peer_part.remove(racer);
        }
        self.completed.insert(peer);
        Some(part.plan)
    }

    /// Release `peer`'s part after a failure. If other peers are still
    /// racing the same part it stays in flight and this returns `None`
    /// (nothing to reassign). Otherwise the part returns to the pending
    /// pool and its plan is returned for reassignment. A peer whose part
    /// was already verified by a winning racer returns `None`.
    pub fn release_for_retry(&mut self, peer: PeerEndpoint) -> Option<PartPlan> {
        let part_index = self.peer_part.remove(&peer)?;
        let part = self.racing.get_mut(&part_index)?;
        part.racers.remove(&peer);
        if part.racers.is_empty() {
            let part = self.racing.remove(&part_index)?;
            self.pending.insert(part_index, part.plan);
            Some(part.plan)
        } else {
            None
        }
    }

    /// Return a racing part to the pending pool for an AICH repair retry
    /// (ADR-0038), clearing every racer's hold so the part is reassigned fresh.
    /// Unlike [`complete_verified`](Self::complete_verified) the part is not
    /// finished, and unlike [`release_for_retry`](Self::release_for_retry) it
    /// re-pends regardless of how many peers were racing it — the repair has
    /// truncated the part's shared assembly to the earliest corrupt block, so
    /// the next assignment resumes from there. Returns the plan, or `None` if
    /// the part is not currently racing.
    pub fn repend_part(&mut self, part_index: u32) -> Option<PartPlan> {
        let part = self.racing.remove(&part_index)?;
        for racer in &part.racers {
            self.peer_part.remove(racer);
        }
        self.pending.insert(part_index, part.plan);
        Some(part.plan)
    }

    /// Return a verified part to the pending pool: its record was disproved,
    /// and it is fetched again. `false` when the part was not verified.
    pub fn repend_verified(&mut self, plan: PartPlan) -> bool {
        if plan.part_index >= self.total_parts || !self.is_part_verified(plan.part_index) {
            return false;
        }
        self.pending.insert(plan.part_index, plan);
        true
    }

    /// Drain every racing assignment and leave the scheduler holding none, for
    /// a teardown that has to release what workers were holding. The parts do
    /// **not** return to pending — the caller owns what happens to them.
    pub fn take_in_flight(&mut self) -> Vec<(PeerEndpoint, PartPlan)> {
        let assignments = self
            .peer_part
            .iter()
            .filter_map(|(&peer, index)| self.racing.get(index).map(|part| (peer, part.plan)))
            .collect();
        self.peer_part.clear();
        self.racing.clear();
        assignments
    }

    /// Whether no part is left to fetch: nothing pending and nothing racing.
    /// Completion is by absence, so this is true exactly when every part has
    /// verified.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.pending.is_empty() && self.racing.is_empty()
    }

    /// Whether part `part_index` is fully verified: neither pending (not started)
    /// nor racing (in flight). Completion is by absence here — a verified part is
    /// removed from both maps — so this is the query for our own availability
    /// bitfield in a source-reask ping (ADR-0057).
    #[must_use]
    pub fn is_part_verified(&self, part_index: u32) -> bool {
        !self.pending.contains_key(&part_index) && !self.racing.contains_key(&part_index)
    }

    /// Whether `peer` currently holds an assigned (in-flight) part. A pure
    /// read used to tell a worker that just finished streaming its range and
    /// was already reassigned (leave its assignment) from one whose part a
    /// co-racer finished (give it the next part).
    #[must_use]
    pub fn is_working(&self, peer: PeerEndpoint) -> bool {
        self.peer_part.contains_key(&peer)
    }

    /// The status of every part, index `0..total_parts` (ADR-0079).
    ///
    /// This is the scheduler's own partition read positionally: racing →
    /// [`PartState::InFlight`], pending → [`PartState::Missing`], tracked by
    /// neither → [`PartState::Verified`] (the same completion-by-absence rule
    /// [`is_part_verified`](Self::is_part_verified) reads). Because the three
    /// come from one walk of one partition, a tally of this vector is the
    /// only part accounting there is — no separate counters to drift from it.
    #[must_use]
    pub fn part_states(&self) -> Vec<PartState> {
        (0..self.total_parts)
            .map(|index| {
                if self.racing.contains_key(&index) {
                    PartState::InFlight
                } else if self.pending.contains_key(&index) {
                    PartState::Missing
                } else {
                    PartState::Verified
                }
            })
            .collect()
    }
}
