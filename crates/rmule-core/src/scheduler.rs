//! The per-download block scheduler (ADR-0117): which blocks of which parts a
//! worker is handed, one worker per block, and the **Duplicate Set** a worker
//! with nothing unclaimed left is handed in the **End Game**. A peer is handed
//! only blocks of parts its **Advertised Parts** hold, the part chosen by one
//! rank (ADR-0112): very rare first, then aMule's head and tail, then a
//! streaming window, then rarest. It is pure bookkeeping over the part plan
//! and the **Arrived Ranges** it is shown — the brain that calls it owns every
//! decision that reaches a socket.

mod claims;
mod end_game;
mod rank;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet, HashSet};

use rmule_peer::{PartBitmap, PartIndex};
use rmule_primitives::PeerEndpoint;

use self::claims::Claim;
use self::rank::{RankInputs, preview_band, very_rare_bound};
use crate::assembly::Attempt;
use crate::byte_ranges::ByteRanges;
use crate::diagnostics::PartState;
use crate::planning::{BlockPlan, PartPlan, part_plan};

/// The most blocks one **Duplicate Set** holds: 3 × `EMBLOCKSIZE` at most
/// (ADR-0117).
pub(crate) const DUPLICATE_SET_BLOCKS: usize = 3;

/// How a download's parts are ordered past rarity (ADR-0112 §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PartOrder {
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
    pub(crate) const fn of(streaming_priority: bool, window_parts: u32) -> Self {
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

/// What the scheduler reads of the download beside its own bookkeeping: each
/// part's **Arrived Ranges** and each worker's **Delivery Rate**, the End
/// Game's input, and a refetched part's **Failed Cells** (ADR-0117). `()`
/// shows nothing arrived and measures nobody.
pub(crate) trait Progress {
    /// `peer`'s Delivery Rate in bytes per second, `None` until measured.
    fn rate(&self, peer: PeerEndpoint) -> Option<u64>;
    /// The Arrived Ranges of `part_index`, relative to the part's start;
    /// `None` when nothing of it arrived.
    fn arrived(&self, part_index: u32) -> Option<&ByteRanges>;
    /// The Failed Cells `part_index` keeps from an attempt that failed with
    /// no root; `None` for a part that has not failed so.
    fn failed_cells(&self, _part_index: u32) -> Option<&Attempt> {
        None
    }
}

impl Progress for () {
    fn rate(&self, _: PeerEndpoint) -> Option<u64> {
        None
    }
    fn arrived(&self, _: u32) -> Option<&ByteRanges> {
        None
    }
}

/// What [`DownloadScheduler::hand`] gave a worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Handout {
    /// Blocks to ask, in order, each now claimed by the worker.
    Blocks {
        /// The blocks.
        blocks: Vec<BlockPlan>,
        /// Whether they are a **Duplicate Set**: blocks a slower worker is
        /// fetching, handed again in the End Game.
        duplicate: bool,
    },
    /// Nothing. `lacked` says whether the worker's Advertised Parts hold a part
    /// the file still lacks — every block of it claimed, the worker's own
    /// included — or none, aMule's `bPartsNeeded` false.
    Nothing {
        /// Whether the worker holds a part the file still lacks.
        lacked: bool,
    },
}

/// Per-download block scheduler.
///
/// A part is missing until it verifies. While missing it is fetched as blocks:
/// each **Claimed Block** is held by one worker until its range has arrived,
/// whoever delivered it, or the worker's end, requeue or a lost block frees
/// it. A part whose bytes have all arrived is verifying until its result.
#[derive(Clone, Debug)]
pub(crate) struct DownloadScheduler {
    file_size: u64,
    /// How many parts the file has, so the scheduler answers for every index.
    total_parts: u32,
    /// Every part not yet verified.
    missing: BTreeSet<u32>,
    /// The missing parts whose bytes have all arrived, awaiting their check.
    verifying: BTreeSet<u32>,
    /// Every Claimed Block, by part.
    claims: BTreeMap<u32, Vec<Claim>>,
    /// The next handout's order stamp: a worker's claims in stamp order are
    /// the order it asks them in.
    next_seq: u64,
    /// The **Preview Band**, empty outside Streaming Priority.
    band: BTreeSet<u32>,
    /// The **Streaming Window**'s width; `0` for none.
    window_parts: u32,
}

impl DownloadScheduler {
    /// Plan every part of `file_size` and mark `verified_parts` as already
    /// done, so a resumed download starts with only what it still needs, its
    /// parts ranked in `order`. Nothing of an unverified part has arrived: a
    /// restart rebuilds the block set from the verified parts (ADR-0117 §4).
    #[must_use]
    pub(crate) fn new(
        file_size: u64,
        verified_parts: impl IntoIterator<Item = u32>,
        order: PartOrder,
    ) -> Self {
        let total_parts = rmule_primitives::part_count(file_size);
        let verified: HashSet<u32> = verified_parts.into_iter().collect();
        Self {
            file_size,
            total_parts,
            missing: (0..total_parts).filter(|p| !verified.contains(p)).collect(),
            verifying: BTreeSet::new(),
            claims: BTreeMap::new(),
            next_seq: 0,
            band: order.band(file_size),
            window_parts: order.window_parts(),
        }
    }

    /// Hand `peer` up to `room` blocks of parts its Advertised Parts `parts`
    /// hold, by rank (ADR-0112 §4) over the download's **Part Frequency**
    /// `frequency` and the `known` sources whose parts are known: unclaimed
    /// blocks first, from the first-ranked part on; with none left, a
    /// **Duplicate Set** of slower workers' blocks (ADR-0117).
    pub(crate) fn hand(
        &mut self,
        peer: PeerEndpoint,
        room: usize,
        parts: &PartBitmap,
        frequency: &[u32],
        known: u32,
        progress: &impl Progress,
    ) -> Handout {
        let inputs = RankInputs {
            frequency,
            very_rare_bound: very_rare_bound(known),
            band: &self.band,
            window: self.window(),
        };
        let held = |part: u32| parts.has(PartIndex::new(part));
        let fresh = self.fresh_blocks(peer, room, &held, &inputs, progress);
        let (blocks, duplicate) = if fresh.is_empty() {
            (
                self.duplicate_set(peer, room, &held, &inputs, progress),
                true,
            )
        } else {
            (fresh, false)
        };
        if blocks.is_empty() {
            return Handout::Nothing {
                lacked: self.lacks_any_of(parts),
            };
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        for block in &blocks {
            self.claims
                .entry(block.part_index)
                .or_default()
                .push(Claim {
                    start: block.start,
                    end: block.end,
                    holder: peer,
                    seq,
                    duplicate,
                });
        }
        Handout::Blocks { blocks, duplicate }
    }

    /// The blocks of `part_index` that have arrived are done: every claim its
    /// Arrived Ranges `arrived` now cover ends, whoever delivered it.
    pub(crate) fn settle(&mut self, part_index: u32, arrived: &ByteRanges) {
        let offset = part_plan(self.file_size, part_index).offset;
        if let Some(claims) = self.claims.get_mut(&part_index) {
            claims.retain(|claim| !arrived.covers(claim.start - offset, claim.end - offset));
            if claims.is_empty() {
                self.claims.remove(&part_index);
            }
        }
    }

    /// Free every block `peer` holds — its worker ended or was requeued — for
    /// the next worker with room. Answers the parts it held blocks of, in
    /// order.
    pub(crate) fn release(&mut self, peer: PeerEndpoint) -> Vec<u32> {
        let mut parts = Vec::new();
        self.claims.retain(|&part, claims| {
            let before = claims.len();
            claims.retain(|claim| claim.holder != peer);
            if claims.len() != before {
                parts.push(part);
            }
            !claims.is_empty()
        });
        parts
    }

    /// `peer`'s asked range `start..end` will never arrive on its slot: free
    /// that much of what it holds (ADR-0117, ADR-0029 "A lost block is
    /// freed").
    pub(crate) fn lose(&mut self, peer: PeerEndpoint, start: u64, end: u64) {
        for claims in self.claims.values_mut() {
            *claims = claims
                .iter()
                .flat_map(|claim| claim.without(peer, start, end))
                .collect();
        }
        self.claims.retain(|_, claims| !claims.is_empty());
    }

    /// Every byte of `part_index` has arrived: it is verifying, and no block
    /// of it is claimed any more.
    pub(crate) fn verifying(&mut self, part_index: u32) {
        if self.missing.contains(&part_index) {
            self.verifying.insert(part_index);
            self.claims.remove(&part_index);
        }
    }

    /// `part_index` verified: it is done. Answers its plan, or `None` when it
    /// was not missing.
    pub(crate) fn complete_verified(&mut self, part_index: u32) -> Option<PartPlan> {
        self.verifying.remove(&part_index);
        self.claims.remove(&part_index);
        self.missing
            .remove(&part_index)
            .then(|| part_plan(self.file_size, part_index))
    }

    /// `part_index` failed its check, or its corrupt blocks were dropped: it
    /// is fetched again, from what its Arrived Ranges still hold.
    pub(crate) fn failed(&mut self, part_index: u32) {
        self.verifying.remove(&part_index);
    }

    /// Return a verified part to the missing set: its record was disproved,
    /// and it is fetched again. `false` when the part was not verified.
    pub(crate) fn repend_verified(&mut self, plan: PartPlan) -> bool {
        if plan.part_index >= self.total_parts || !self.is_part_verified(plan.part_index) {
            return false;
        }
        self.missing.insert(plan.part_index);
        true
    }

    /// Drop every claim for a teardown that has to release what workers were
    /// holding: each worker and a part it held blocks of, by part.
    pub(crate) fn take_in_flight(&mut self) -> Vec<(PeerEndpoint, u32)> {
        let mut held: Vec<(PeerEndpoint, u32)> = Vec::new();
        for (&part, claims) in &self.claims {
            for claim in claims {
                if !held.contains(&(claim.holder, part)) {
                    held.push((claim.holder, part));
                }
            }
        }
        self.claims.clear();
        held
    }

    /// Whether no part is left to fetch: every part has verified.
    #[must_use]
    pub(crate) fn is_complete(&self) -> bool {
        self.missing.is_empty()
    }

    /// Whether part `part_index` is verified — the query for our own
    /// availability bitfield in a source-reask ping (ADR-0057).
    #[must_use]
    pub(crate) fn is_part_verified(&self, part_index: u32) -> bool {
        part_index < self.total_parts && !self.missing.contains(&part_index)
    }

    /// Whether `peer` holds a Claimed Block.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn holds_claims(&self, peer: PeerEndpoint) -> bool {
        self.claims
            .values()
            .flatten()
            .any(|claim| claim.holder == peer)
    }

    /// The parts `peer` holds a Claimed Block of.
    #[must_use]
    pub(crate) fn parts_of(&self, peer: PeerEndpoint) -> BTreeSet<u32> {
        self.claims
            .iter()
            .filter(|(_, claims)| claims.iter().any(|claim| claim.holder == peer))
            .map(|(&part, _)| part)
            .collect()
    }

    /// Whether a source whose Advertised Parts are `parts` holds a part the
    /// file still lacks — aMule's `bPartsNeeded` (stock 2.3.3
    /// `DownloadClient.cpp:397-449`), the one predicate a `0x91` status and a
    /// handout both read.
    #[must_use]
    pub(crate) fn lacks_any_of(&self, parts: &PartBitmap) -> bool {
        parts
            .iter_present()
            .any(|part| !self.is_part_verified(part.value()))
    }

    /// The **Streaming Window**: `window_parts` parts from the lowest
    /// unverified one, so it slides as its anchor verifies.
    fn window(&self) -> std::ops::Range<u32> {
        self.missing.first().map_or(0..0, |&anchor| {
            anchor..anchor.saturating_add(self.window_parts)
        })
    }

    /// The status of every part, index `0..total_parts` (ADR-0079): a block
    /// claimed or its bytes being verified → [`PartState::InFlight`], any other
    /// missing part → [`PartState::Missing`], else [`PartState::Verified`].
    /// One walk over the scheduler's own sets, so a tally of this vector is
    /// the only part accounting there is.
    #[must_use]
    pub(crate) fn part_states(&self) -> Vec<PartState> {
        (0..self.total_parts)
            .map(|index| {
                if !self.missing.contains(&index) {
                    PartState::Verified
                } else if self.verifying.contains(&index) || self.claims.contains_key(&index) {
                    PartState::InFlight
                } else {
                    PartState::Missing
                }
            })
            .collect()
    }
}
