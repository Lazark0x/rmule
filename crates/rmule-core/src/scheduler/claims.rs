//! **Claimed Blocks** (ADR-0117): a part's unarrived, unclaimed bytes cut on
//! its `EMBLOCKSIZE` grid, as aMule's `GetNextEmptyBlockInPart` cuts them
//! (stock 2.3.3 `PartFile.cpp:1246-1311`), so a block leaves the grid exactly
//! where the gap it fills does; and the fresh handout that takes them from the
//! first-ranked part on, a refetched part's cells asked of someone else first.

use std::collections::HashMap;

use rmule_primitives::{EMBLOCKSIZE, PeerEndpoint};

use super::rank::{RankInputs, rank};
use super::{DownloadScheduler, Progress};
use crate::assembly::Attempt;
use crate::planning::{BlockPlan, part_plan};

/// One block asked of one worker and not yet wholly arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Claim {
    /// Its first byte's offset in the file.
    pub(super) start: u64,
    /// The offset just past its last byte.
    pub(super) end: u64,
    /// The worker asking it.
    pub(super) holder: PeerEndpoint,
    /// The handout it came in: a worker asks its claims in this order.
    pub(super) seq: u64,
    /// Whether it is a **Duplicate Set**'s, a second copy of another
    /// worker's block.
    pub(super) duplicate: bool,
}

impl Claim {
    /// What is left of this claim once `peer` lost `start..end`: the claim
    /// itself when another worker holds it or the range misses it, else the
    /// pieces on either side.
    pub(super) fn without(self, peer: PeerEndpoint, start: u64, end: u64) -> Vec<Self> {
        if self.holder != peer || end <= self.start || start >= self.end {
            return vec![self];
        }
        let mut left = Vec::new();
        if self.start < start {
            left.push(Self { end: start, ..self });
        }
        if end < self.end {
            left.push(Self { start: end, ..self });
        }
        left
    }
}

impl DownloadScheduler {
    /// Up to `room` unclaimed blocks of the parts `held` names for `peer`,
    /// the first-ranked part first and each part's blocks in order — a
    /// refetched part's in `refetch_order`.
    pub(super) fn fresh_blocks(
        &self,
        peer: PeerEndpoint,
        room: usize,
        held: &impl Fn(u32) -> bool,
        inputs: &RankInputs<'_>,
        progress: &impl Progress,
    ) -> Vec<BlockPlan> {
        let mut candidates: Vec<u32> = self
            .missing
            .iter()
            .copied()
            .filter(|&part| held(part) && !self.verifying.contains(&part))
            .collect();
        candidates.sort_by_key(|&part| rank(part, inputs));
        let mut blocks = Vec::new();
        for part in candidates {
            if blocks.len() >= room {
                break;
            }
            let wanted = room - blocks.len();
            let unclaimed = self.unclaimed_blocks(part, progress);
            let ordered = match progress.failed_cells(part) {
                Some(failed) => self.refetch_order(peer, unclaimed, failed),
                None => unclaimed,
            };
            blocks.extend(ordered.into_iter().take(wanted));
        }
        blocks
    }

    /// The blocks of a part kept as `failed` Failed Cells, in the order `peer`
    /// asks them (ADR-0117 §1): cells it did not write first, so a refetched
    /// cell's new bytes come from someone else, and each old writer's cells in
    /// turn, so they come from several workers. Each group keeps its order.
    fn refetch_order(
        &self,
        peer: PeerEndpoint,
        blocks: Vec<BlockPlan>,
        failed: &Attempt,
    ) -> Vec<BlockPlan> {
        let mut turns: HashMap<&[PeerEndpoint], usize> = HashMap::new();
        let mut keyed: Vec<((bool, usize), BlockPlan)> = blocks
            .into_iter()
            .map(|block| {
                let offset = part_plan(self.file_size, block.part_index).offset;
                let writers = failed.writers_of((block.start - offset) / EMBLOCKSIZE);
                let turn = turns.entry(writers).or_default();
                let key = (writers.contains(&peer), *turn);
                *turn += 1;
                (key, block)
            })
            .collect();
        keyed.sort_by_key(|&(key, _)| key);
        keyed.into_iter().map(|(_, block)| block).collect()
    }

    /// The unarrived, unclaimed blocks of `part_index`, in order.
    pub(super) fn unclaimed_blocks(
        &self,
        part_index: u32,
        progress: &impl Progress,
    ) -> Vec<BlockPlan> {
        let plan = part_plan(self.file_size, part_index);
        let mut taken = progress.arrived(part_index).cloned().unwrap_or_default();
        for claim in self.claims.get(&part_index).into_iter().flatten() {
            taken.insert(claim.start - plan.offset, claim.end - plan.offset);
        }
        let mut blocks = Vec::new();
        for (start, end) in taken.gaps(0, plan.len) {
            let mut at = start;
            while at < end {
                let stop = ((at / EMBLOCKSIZE + 1) * EMBLOCKSIZE).min(end);
                blocks.push(BlockPlan {
                    part_index,
                    start: plan.offset + at,
                    end: plan.offset + stop,
                });
                at = stop;
            }
        }
        blocks
    }
}
