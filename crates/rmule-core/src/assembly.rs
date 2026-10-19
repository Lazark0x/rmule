//! In-memory assembly of one in-flight ED2K part (ADR-0029, ADR-0117). Bytes
//! arrive from any worker, at any offset, on the 180 KiB grid or off it:
//! [`PartAssembly`] keeps the part's **Arrived Ranges** exact to the byte,
//! writes only bytes not yet arrived — so the first copy of a byte wins — and
//! records every worker that wrote into each `EMBLOCKSIZE` cell for AICH
//! repair, and for the **Failed Cells** a part with no trusted root keeps
//! across its refetch ([`Attempt`]). Nothing here touches disk: a part reaches
//! the content store only once it is whole and verified.

use std::collections::HashMap;

use rmule_primitives::{EMBLOCKSIZE, PeerEndpoint, UserHash, aich_block_hash};

use crate::byte_ranges::ByteRanges;

mod failed_cells;

pub(crate) use failed_cells::{Attempt, Cell, Verdict};

/// One in-flight part's arrived bytes, by offset within the part.
#[derive(Clone, Debug)]
pub(crate) struct PartAssembly {
    /// The part's length.
    len: u64,
    /// The **Arrived Ranges**, relative to the part's start.
    arrived: ByteRanges,
    /// The bytes, one `EMBLOCKSIZE` cell each, allocated at its first byte.
    cells: Vec<Option<Box<[u8]>>>,
    /// Per cell, every worker that wrote a byte into it: the provenance AICH
    /// repair retires by (ADR-0038).
    writers: Vec<Vec<PeerEndpoint>>,
    /// The User Hash each writer's hello named when it wrote, so a writer
    /// proven after its worker ended is still distrusted (ADR-0090).
    user_hashes: HashMap<PeerEndpoint, UserHash>,
}

impl PartAssembly {
    /// An empty assembly for a part of `len` bytes.
    pub(crate) fn new(len: u64) -> Self {
        let cells = usize::try_from(len.div_ceil(EMBLOCKSIZE)).unwrap_or(usize::MAX);
        Self {
            len,
            arrived: ByteRanges::default(),
            cells: vec![None; cells],
            writers: vec![Vec::new(); cells],
            user_hashes: HashMap::new(),
        }
    }

    /// Merge `bytes` that `peer`, whose hello named `user_hash`, delivered at
    /// `offset` within the part. Only bytes not yet arrived are written;
    /// bytes past the part's end are dropped. Answers how many bytes were new.
    pub(crate) fn merge(
        &mut self,
        peer: PeerEndpoint,
        user_hash: Option<UserHash>,
        offset: u64,
        bytes: &[u8],
    ) -> u64 {
        let end = offset.saturating_add(bytes.len() as u64).min(self.len);
        let mut written = 0;
        if let Some(user_hash) = user_hash {
            self.user_hashes.insert(peer, user_hash);
        }
        for (start, stop) in self.arrived.insert(offset.min(end), end) {
            self.write(
                peer,
                start,
                &bytes[(start - offset) as usize..(stop - offset) as usize],
            );
            written += stop - start;
        }
        written
    }

    /// Copy `bytes`, new at `start`, into their cells.
    fn write(&mut self, peer: PeerEndpoint, start: u64, bytes: &[u8]) {
        let mut at = start;
        let mut rest = bytes;
        while !rest.is_empty() {
            let cell = (at / EMBLOCKSIZE) as usize;
            let cell_len = self.cell_len(cell);
            let within = (at - cell as u64 * EMBLOCKSIZE) as usize;
            let take = rest.len().min(cell_len - within);
            let buffer =
                self.cells[cell].get_or_insert_with(|| vec![0; cell_len].into_boxed_slice());
            buffer[within..within + take].copy_from_slice(&rest[..take]);
            if !self.writers[cell].contains(&peer) {
                self.writers[cell].push(peer);
            }
            at += take as u64;
            rest = &rest[take..];
        }
    }

    /// The **Arrived Ranges**, relative to the part's start.
    pub(crate) fn arrived(&self) -> &ByteRanges {
        &self.arrived
    }

    /// Whether every byte of the part has arrived.
    pub(crate) fn is_complete(&self) -> bool {
        self.arrived.covers(0, self.len)
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
            let cell = block as usize;
            let start = u64::from(block) * EMBLOCKSIZE;
            self.arrived
                .remove(start, (start + EMBLOCKSIZE).min(self.len));
            if let Some(buffer) = self.cells.get_mut(cell) {
                *buffer = None;
            }
            if let Some(writers) = self.writers.get_mut(cell) {
                writers.clear();
            }
        }
    }

    /// The part's cells as one attempt at it: each cell's AICH block hash and
    /// writers (ADR-0117 §1), a cell not yet arrived hashed as zeros.
    pub(crate) fn attempt(&self) -> Attempt {
        let cells = self
            .cells
            .iter()
            .zip(&self.writers)
            .enumerate()
            .map(|(cell, (buffer, writers))| Cell {
                hash: match buffer {
                    Some(buffer) => aich_block_hash(buffer),
                    None => aich_block_hash(&vec![0; self.cell_len(cell)]),
                },
                writers: writers.clone(),
            })
            .collect();
        Attempt::new(cells, self.user_hashes.clone())
    }

    /// The length of cell `cell`: `EMBLOCKSIZE`, or less for the part's last.
    fn cell_len(&self, cell: usize) -> usize {
        let cell_start = cell as u64 * EMBLOCKSIZE;
        (self.len - cell_start).min(EMBLOCKSIZE) as usize
    }

    /// The part's bytes in order, a cell not yet arrived read as zeros.
    pub(crate) fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(usize::try_from(self.len).unwrap_or(0));
        for (cell, buffer) in self.cells.iter().enumerate() {
            match buffer {
                Some(buffer) => out.extend_from_slice(buffer),
                None => out.resize(out.len() + self.cell_len(cell), 0),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmule_primitives::{Ipv4Endpoint, PeerEndpoint};
    use std::collections::BTreeSet;
    use std::net::Ipv4Addr;

    fn peer(n: u8) -> PeerEndpoint {
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, n), 4662))
    }

    /// The byte at part offset `at` of a recognisable part.
    fn byte(at: u64) -> u8 {
        (at % 251) as u8
    }

    fn slice(start: u64, end: u64) -> Vec<u8> {
        (start..end).map(byte).collect()
    }

    /// Blocks asked a byte shorter around a link's Asked Ranges leave the
    /// grid (ADR-0107): they merge wherever they land, from whichever worker,
    /// and the part completes once the ranges cover it, every byte where it
    /// belongs (ADR-0117).
    #[test]
    fn assembly_merges_off_grid_blocks() {
        let len = 3 * EMBLOCKSIZE + 1_000;
        let mut a = PartAssembly::new(len);
        let first = EMBLOCKSIZE - 1;
        // Worker 2's off-grid block lands first, across the first cell edge.
        assert_eq!(
            a.merge(peer(2), None, first, &slice(first, first + EMBLOCKSIZE)),
            EMBLOCKSIZE
        );
        // Worker 1's block a byte short of the grid, then the byte it left.
        assert_eq!(a.merge(peer(1), None, 0, &slice(0, first)), first);
        assert!(!a.is_complete());
        // A tail block overlapping what arrived writes only what is new.
        let tail = 2 * EMBLOCKSIZE - 10;
        assert_eq!(
            a.merge(peer(3), None, tail, &slice(tail, len)),
            len - (2 * EMBLOCKSIZE - 1)
        );
        assert!(a.is_complete());
        assert_eq!(a.bytes(), slice(0, len));
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
        let mut a = PartAssembly::new(10);
        assert_eq!(a.merge(peer(1), None, 2, &[1, 1, 1]), 3);
        assert_eq!(a.merge(peer(2), None, 2, &[9, 9, 9]), 0);
        assert!(!a.attempt().writers().contains(&peer(2)));
        assert_eq!(&a.bytes()[2..5], &[1, 1, 1]);
        // Bytes past the part's end go nowhere.
        assert_eq!(a.merge(peer(2), None, 8, &[7, 7, 7, 7]), 2);
        assert_eq!(a.arrived().gaps(0, 10), vec![(0, 2), (5, 8)]);
    }

    /// AICH repair forgets exactly the corrupt cells: the rest of the part
    /// stays, and the dropped cell's bytes are missing again (ADR-0038).
    #[test]
    fn dropping_a_block_forgets_only_its_cell() {
        let len = 2 * EMBLOCKSIZE;
        let mut a = PartAssembly::new(len);
        a.merge(peer(1), None, 0, &slice(0, EMBLOCKSIZE));
        a.merge(peer(2), None, EMBLOCKSIZE, &slice(EMBLOCKSIZE, len));
        a.drop_blocks(&[0]);
        assert_eq!(a.arrived().gaps(0, len), vec![(0, EMBLOCKSIZE)]);
        assert!(a.writers_of_block(0).is_empty());
        assert_eq!(a.attempt().writers(), BTreeSet::from([peer(2)]));
    }
}
