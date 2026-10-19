//! **Claimed Blocks** (ADR-0117): a part's unarrived, unclaimed bytes cut on
//! its `EMBLOCKSIZE` grid, as aMule's `GetNextEmptyBlockInPart` cuts them
//! (stock 2.3.3 `PartFile.cpp:1246-1311`), so a block leaves the grid exactly
//! where the gap it fills does; and the fresh handout that takes them from the
//! first-ranked part on.

use rmule_primitives::{EMBLOCKSIZE, PeerEndpoint};

use super::rank::{RankInputs, rank};
use super::{DownloadScheduler, Progress};
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
    /// Up to `room` unclaimed blocks of the parts `held` names, the
    /// first-ranked part first and each part's blocks in order.
    pub(super) fn fresh_blocks(
        &self,
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
            blocks.extend(
                self.unclaimed_blocks(part, progress)
                    .into_iter()
                    .take(wanted),
            );
        }
        blocks
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
