//! The **End Game** (ADR-0117): a worker with room and no unclaimed block in a
//! part it advertised is handed a **Duplicate Set** — at most three blocks a
//! slower worker is fetching, asked of nobody else — the latest expected
//! first. A block is asked of at most two workers, and a worker holds one
//! unsettled set at a time, so each set wastes at most 3 × `EMBLOCKSIZE`.

use rmule_primitives::PeerEndpoint;

use super::claims::Claim;
use super::rank::{RankInputs, duplicate_rank};
use super::{DUPLICATE_SET_BLOCKS, DownloadScheduler, Progress};
use crate::planning::{BlockPlan, part_plan};

impl DownloadScheduler {
    /// `peer`'s Duplicate Set of at most `room` blocks, or none: it already
    /// holds an unsettled one, it is unmeasured, or no block of a part `held`
    /// names is held alone by a worker measured slower (an unmeasured holder
    /// counts as zero).
    pub(super) fn duplicate_set(
        &self,
        peer: PeerEndpoint,
        room: usize,
        held: &impl Fn(u32) -> bool,
        inputs: &RankInputs<'_>,
        progress: &impl Progress,
    ) -> Vec<BlockPlan> {
        let holds_a_set = self
            .claims
            .values()
            .flatten()
            .any(|claim| claim.holder == peer && claim.duplicate);
        let Some(own) = progress.rate(peer).filter(|_| !holds_a_set) else {
            return Vec::new();
        };
        let mut candidates = Vec::new();
        for (&part, claims) in &self.claims {
            if !held(part) || self.verifying.contains(&part) {
                continue;
            }
            for claim in claims {
                let doubled = claims.iter().any(|other| {
                    other.duplicate && other.start < claim.end && claim.start < other.end
                });
                if claim.holder == peer || claim.duplicate || doubled {
                    continue;
                }
                let rate = progress.rate(claim.holder).unwrap_or(0);
                if rate >= own {
                    continue;
                }
                let finish = self
                    .bytes_ahead(claim, progress)
                    .checked_div(rate)
                    .unwrap_or(u64::MAX);
                // What of the block is still to come: the holder's arrived
                // bytes are not asked twice.
                let offset = part_plan(self.file_size, part).offset;
                let unarrived = progress.arrived(part).map_or_else(
                    || vec![(claim.start - offset, claim.end - offset)],
                    |ranges| ranges.gaps(claim.start - offset, claim.end - offset),
                );
                for (start, end) in unarrived {
                    candidates.push((
                        duplicate_rank(part, inputs, finish),
                        offset + start,
                        BlockPlan {
                            part_index: part,
                            start: offset + start,
                            end: offset + end,
                        },
                    ));
                }
            }
        }
        candidates.sort_by_key(|&(rank, start, _)| (rank, start));
        candidates
            .into_iter()
            .take(room.min(DUPLICATE_SET_BLOCKS))
            .map(|(_, _, block)| block)
            .collect()
    }

    /// The bytes `claim`'s holder still awaits up to and including it, in the
    /// order it asks them: what stands between it and `claim`'s last byte.
    fn bytes_ahead(&self, claim: &Claim, progress: &impl Progress) -> u64 {
        self.claims
            .iter()
            .flat_map(|(&part, claims)| claims.iter().map(move |other| (part, other)))
            .filter(|(_, other)| {
                other.holder == claim.holder && (other.seq, other.start) <= (claim.seq, claim.start)
            })
            .map(|(part, other)| {
                let offset = part_plan(self.file_size, part).offset;
                let arrived = progress.arrived(part).map_or(0, |ranges| {
                    ranges.covered_within(other.start - offset, other.end - offset)
                });
                (other.end - other.start).saturating_sub(arrived)
            })
            .sum()
    }
}
