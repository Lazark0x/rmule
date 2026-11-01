//! The record of one in-flight ED2K part (ADR-0029, ADR-0117). Bytes arrive
//! from any worker, at any offset, on the 180 KiB grid or off it:
//! [`PartAssembly`] keeps the part's **Arrived Ranges** exact to the byte,
//! answers which bytes are new — so the first copy of a byte wins — and
//! records every worker that wrote into each `EMBLOCKSIZE` cell for AICH
//! repair, and for the **Failed Cells** a part with no trusted root keeps
//! across its refetch ([`Attempt`]). It holds no byte: the new ones go to the
//! `.part`, and the part is read back from there once its ranges cover it. As
//! an [`ArrivedPart`] it is the row the **Arrived Checkpoint** keeps, and every
//! run starts from those rows, so a resumed part is an assembly like any other.

use std::collections::HashMap;

use rmule_peer::PartIndex;
use rmule_primitives::{EMBLOCKSIZE, PeerEndpoint, UserHash};

use crate::byte_ranges::ByteRanges;
use crate::planning::PartPlan;

mod failed_cells;

pub(crate) use failed_cells::{Attempt, Cell, Verdict};

/// What the file held for one cell: the SHA-1 of its bytes, its AICH block
/// hash, as the **Persist Lane** read them.
pub(crate) type CellHash = [u8; 20];

/// One in-flight part, in the file's offsets.
#[derive(Clone, Debug)]
pub(crate) struct PartAssembly {
    /// The part.
    plan: PartPlan,
    /// The **Arrived Ranges**, in the file's offsets.
    arrived: ByteRanges,
    /// Per cell, every worker that wrote a byte into it: the provenance AICH
    /// repair retires by (ADR-0038).
    writers: Vec<Vec<PeerEndpoint>>,
    /// The User Hash each writer's hello named when it wrote, so a writer
    /// proven after its worker ended is still distrusted (ADR-0090).
    user_hashes: HashMap<PeerEndpoint, UserHash>,
    /// Each cell's hash as the lane read it from the file, once a part's check
    /// needed it; empty before that.
    cell_hashes: Vec<CellHash>,
}

/// One writer of a part as a checkpoint holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ArrivedWriter {
    /// Where it wrote from.
    pub(crate) endpoint: PeerEndpoint,
    /// The User Hash its hello named.
    pub(crate) user_hash: Option<UserHash>,
}

/// One part's row of the **Arrived Checkpoint** (ADR-0117 §4). No range left
/// says the part has no row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ArrivedPart {
    /// The part.
    pub(crate) part_index: PartIndex,
    /// The Arrived Ranges, in the file's offsets.
    pub(crate) ranges: Vec<(u64, u64)>,
    /// The part's writers.
    pub(crate) writers: Vec<ArrivedWriter>,
    /// Per cell, the positions in `writers` of those that wrote into it.
    pub(crate) cells: Vec<Vec<u16>>,
}

impl ArrivedPart {
    /// The row of a part with no bytes left.
    pub(crate) const fn none(part_index: PartIndex) -> Self {
        Self {
            part_index,
            ranges: Vec::new(),
            writers: Vec::new(),
            cells: Vec::new(),
        }
    }

    /// This row with its claims cut to `end`, where the file ends: a byte past
    /// it has not reached the file, whatever the row says.
    pub(crate) fn cut_to(mut self, end: u64) -> Self {
        self.ranges = self
            .ranges
            .into_iter()
            .filter_map(|(start, stop)| (start < end).then_some((start, stop.min(end))))
            .collect();
        self
    }
}

impl PartAssembly {
    /// An empty assembly for `plan`.
    pub(crate) fn new(plan: PartPlan) -> Self {
        Self {
            plan,
            arrived: ByteRanges::default(),
            writers: vec![Vec::new(); plan.cells()],
            user_hashes: HashMap::new(),
            cell_hashes: Vec::new(),
        }
    }

    /// The assembly a checkpoint's `row` keeps for `plan`. A claim outside the
    /// part is no claim, and a writer position no row wrote names nobody.
    pub(crate) fn resumed(plan: PartPlan, row: &ArrivedPart) -> Self {
        let mut assembly = Self::new(plan);
        for &(start, end) in &row.ranges {
            assembly
                .arrived
                .insert(start.max(plan.offset), end.min(plan.end()));
        }
        let writer = |at: &u16| row.writers.get(usize::from(*at));
        for (cell, positions) in assembly.writers.iter_mut().zip(&row.cells) {
            *cell = positions
                .iter()
                .filter_map(writer)
                .map(|writer| writer.endpoint)
                .collect();
        }
        assembly.user_hashes = row
            .writers
            .iter()
            .filter_map(|writer| Some((writer.endpoint, writer.user_hash?)))
            .collect();
        assembly
    }

    /// This assembly as its checkpoint row.
    pub(crate) fn arrived_part(&self) -> ArrivedPart {
        let mut writers: Vec<ArrivedWriter> = Vec::new();
        let mut position = |endpoint: PeerEndpoint| {
            let found = writers.iter().position(|w| w.endpoint == endpoint);
            let at = found.unwrap_or_else(|| {
                writers.push(ArrivedWriter {
                    endpoint,
                    user_hash: self.user_hashes.get(&endpoint).copied(),
                });
                writers.len() - 1
            });
            u16::try_from(at).unwrap_or(u16::MAX)
        };
        let cells = self
            .writers
            .iter()
            .map(|cell| cell.iter().map(|&writer| position(writer)).collect())
            .collect();
        ArrivedPart {
            part_index: self.plan.part_index,
            ranges: self.arrived.ranges().collect(),
            writers,
            cells,
        }
    }

    /// Merge the `len` bytes that `peer`, whose hello named `user_hash`,
    /// delivered at file offset `offset`, and answer the ranges of them that
    /// are new, in order: only those are written. Bytes outside the part go
    /// nowhere.
    pub(crate) fn merge(
        &mut self,
        peer: PeerEndpoint,
        user_hash: Option<UserHash>,
        offset: u64,
        len: u64,
    ) -> Vec<(u64, u64)> {
        let start = offset.max(self.plan.offset);
        let end = offset.saturating_add(len).min(self.plan.end());
        if let Some(user_hash) = user_hash {
            self.user_hashes.insert(peer, user_hash);
        }
        let fresh = self.arrived.insert(start, end);
        for &(first, stop) in &fresh {
            let last = self.plan.cell_of(stop - 1);
            for cell in self.plan.cell_of(first)..=last {
                if !self.writers[cell].contains(&peer) {
                    self.writers[cell].push(peer);
                }
            }
        }
        fresh
    }

    /// The **Arrived Ranges**, in the file's offsets.
    pub(crate) fn arrived(&self) -> &ByteRanges {
        &self.arrived
    }

    /// Whether every byte of the part has arrived.
    pub(crate) fn is_complete(&self) -> bool {
        self.arrived.covers(self.plan.offset, self.plan.end())
    }

    /// The workers that wrote into AICH block `block` of the part; empty when
    /// none of it has arrived.
    pub(crate) fn writers_of_block(&self, block: usize) -> &[PeerEndpoint] {
        self.writers.get(block).map_or(&[], Vec::as_slice)
    }

    /// Forget AICH blocks `blocks`: their bytes leave the Arrived Ranges and
    /// are fetched again (ADR-0038).
    pub(crate) fn drop_blocks(&mut self, blocks: &[u16]) {
        for &block in blocks {
            let cell = usize::from(block);
            let start = self.plan.cell_start(cell);
            self.arrived
                .remove(start, (start + EMBLOCKSIZE).min(self.plan.end()));
            if let Some(writers) = self.writers.get_mut(cell) {
                writers.clear();
            }
        }
        self.cell_hashes.clear();
    }

    /// The lane read the part's cells: what [`Self::attempt`] judges by.
    pub(crate) fn read_back(&mut self, cell_hashes: Vec<CellHash>) {
        self.cell_hashes = cell_hashes;
    }

    /// The part's cells as one attempt at it: each cell's AICH block hash and
    /// writers (ADR-0117 §1). `None` before the lane read them.
    pub(crate) fn attempt(&self) -> Option<Attempt> {
        if self.cell_hashes.len() != self.writers.len() {
            return None;
        }
        let cells = self
            .cell_hashes
            .iter()
            .zip(&self.writers)
            .map(|(&hash, writers)| Cell {
                hash,
                writers: writers.clone(),
            })
            .collect();
        Some(Attempt::new(cells, self.user_hashes.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmule_primitives::{ED2K_PART_SIZE, Ipv4Endpoint, PeerEndpoint};
    use std::collections::BTreeSet;
    use std::net::Ipv4Addr;

    fn peer(n: u8) -> PeerEndpoint {
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, n), 4662))
    }

    /// Part 0 of `len` bytes.
    fn part(len: u64) -> PartPlan {
        PartPlan {
            part_index: PartIndex::new(0),
            offset: 0,
            len,
        }
    }

    fn cell_hashes(assembly: &mut PartAssembly) {
        let cells = assembly.writers.len();
        assembly.read_back(vec![[0; 20]; cells]);
    }

    /// Blocks asked a byte shorter around a link's Asked Ranges leave the
    /// grid (ADR-0107): they merge wherever they land, from whichever worker,
    /// and the part completes once the ranges cover it (ADR-0117).
    #[test]
    fn assembly_merges_off_grid_blocks() {
        let len = 3 * EMBLOCKSIZE + 1_000;
        let mut a = PartAssembly::new(part(len));
        let first = EMBLOCKSIZE - 1;
        // Worker 2's off-grid block lands first, across the first cell edge.
        assert_eq!(
            a.merge(peer(2), None, first, EMBLOCKSIZE),
            vec![(first, first + EMBLOCKSIZE)]
        );
        // Worker 1's block a byte short of the grid, then the byte it left.
        assert_eq!(a.merge(peer(1), None, 0, first), vec![(0, first)]);
        assert!(!a.is_complete());
        // A tail block overlapping what arrived writes only what is new.
        let tail = 2 * EMBLOCKSIZE - 10;
        assert_eq!(
            a.merge(peer(3), None, tail, len - tail),
            vec![(2 * EMBLOCKSIZE - 1, len)]
        );
        assert!(a.is_complete());
        // Each cell names every worker that wrote into it: worker 2's block
        // spans cells 0 and 1, and the tail worker wrote only the byte it left.
        assert_eq!(a.writers_of_block(0), &[peer(2), peer(1)]);
        assert_eq!(a.writers_of_block(1), &[peer(2), peer(3)]);
        assert_eq!(a.writers_of_block(2), &[peer(3)]);
    }

    /// The first copy of a byte wins: a duplicate's later bytes, the same or
    /// not, are dropped, and its sender is no contributor.
    #[test]
    fn a_later_copy_of_an_arrived_byte_is_dropped() {
        let mut a = PartAssembly::new(part(10));
        assert_eq!(a.merge(peer(1), None, 2, 3), vec![(2, 5)]);
        assert!(a.merge(peer(2), None, 2, 3).is_empty());
        cell_hashes(&mut a);
        assert!(!a.attempt().unwrap().writers().contains(&peer(2)));
        // Bytes past the part's end go nowhere.
        assert_eq!(a.merge(peer(2), None, 8, 4), vec![(8, 10)]);
        assert_eq!(a.arrived().gaps(0, 10), vec![(0, 2), (5, 8)]);
    }

    /// AICH repair forgets exactly the corrupt cells: the rest of the part
    /// stays, and the dropped cell's bytes are missing again (ADR-0038).
    #[test]
    fn dropping_a_block_forgets_only_its_cell() {
        let len = 2 * EMBLOCKSIZE;
        let mut a = PartAssembly::new(part(len));
        a.merge(peer(1), None, 0, EMBLOCKSIZE);
        a.merge(peer(2), None, EMBLOCKSIZE, EMBLOCKSIZE);
        a.drop_blocks(&[0]);
        assert_eq!(a.arrived().gaps(0, len), vec![(0, EMBLOCKSIZE)]);
        assert!(a.writers_of_block(0).is_empty());
        cell_hashes(&mut a);
        assert_eq!(a.attempt().unwrap().writers(), BTreeSet::from([peer(2)]));
    }

    /// An arrival is in the file's offsets, on any part: bytes before the
    /// part's start or past its end go nowhere, never to its first byte.
    #[test]
    fn an_arrival_outside_its_part_lands_nowhere() {
        let plan = PartPlan {
            part_index: PartIndex::new(2),
            offset: 2 * ED2K_PART_SIZE,
            len: 100,
        };
        let mut a = PartAssembly::new(plan);
        assert!(a.merge(peer(1), None, 0, 50).is_empty());
        assert_eq!(
            a.merge(peer(1), None, plan.offset - 10, 20),
            vec![(plan.offset, plan.offset + 10)]
        );
        assert_eq!(
            a.arrived().gaps(plan.offset, plan.end()),
            vec![(plan.offset + 10, plan.end())]
        );
    }

    /// A resumed assembly is the one its row was taken from: the same ranges,
    /// the same writers in each cell, the same hash under each writer.
    #[test]
    fn a_checkpoint_row_resumes_the_assembly_it_was_taken_from() {
        let plan = PartPlan {
            part_index: PartIndex::new(1),
            offset: ED2K_PART_SIZE,
            len: 2 * EMBLOCKSIZE,
        };
        let hash = UserHash::from_bytes([7; 16]);
        let mut a = PartAssembly::new(plan);
        a.merge(peer(1), Some(hash), plan.offset, EMBLOCKSIZE + 1);
        a.merge(peer(2), None, plan.offset + EMBLOCKSIZE + 1, 9);
        let resumed = PartAssembly::resumed(plan, &a.arrived_part());
        assert_eq!(resumed.arrived(), a.arrived());
        assert_eq!(resumed.writers_of_block(0), &[peer(1)]);
        assert_eq!(resumed.writers_of_block(1), &[peer(1), peer(2)]);
        assert_eq!(resumed.arrived_part(), a.arrived_part());
    }

    /// A claim past the file's end is no claim: the checkpoint is cut to the
    /// file it speaks for.
    #[test]
    fn a_checkpoint_is_cut_to_the_file_it_speaks_for() {
        let mut row = ArrivedPart::none(PartIndex::new(0));
        row.ranges = vec![(0, 10), (20, 30), (40, 50)];
        assert_eq!(row.cut_to(25).ranges, vec![(0, 10), (20, 25)]);
    }
}
