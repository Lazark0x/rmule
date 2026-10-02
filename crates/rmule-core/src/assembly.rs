//! In-memory assembly of one in-flight ED2K part (ADR-0029). Workers fetch a
//! part's blocks in order, so what has arrived is always a contiguous prefix —
//! [`PartAssembly`] holds that prefix, absorbs the racers' redundant deliveries,
//! and drops anything that would leave a gap. Nothing here touches disk: a part
//! reaches the content store only once it is whole and verified.

use std::collections::HashSet;

use rmule_primitives::{EMBLOCKSIZE, PeerEndpoint};

/// In-memory assembly of one in-flight ED2K part as a contiguous prefix.
///
/// Workers fetch blocks sequentially, so received bytes always form a
/// contiguous run `[0, bytes.len())` measured from the part's start. A
/// chunk that covers the current prefix end extends it; a chunk wholly
/// behind the prefix (a redundant delivery from a lockstep racer) is
/// dropped; a chunk that starts past the prefix end (a gap) is dropped.
/// Per ADR-0029 this is in-memory and per-session only.
#[derive(Clone, Debug, Default)]
pub(crate) struct PartAssembly {
    bytes: Vec<u8>,
    contributors: HashSet<PeerEndpoint>,
    /// Per-AICH-block (`EMBLOCKSIZE`) contributor, indexed by block index
    /// within the part: the peer that wrote each block's first byte. AICH
    /// recovery uses it to retire exactly the peer that delivered a corrupt
    /// block (ADR-0038). Exact for the one-peer-per-block common case; a
    /// heuristic when a block is split across a mid-block handoff.
    block_contributors: Vec<PeerEndpoint>,
}

impl PartAssembly {
    pub(crate) fn prefix_len(&self) -> u64 {
        self.bytes.len() as u64
    }

    pub(crate) fn contributors(&self) -> &HashSet<PeerEndpoint> {
        &self.contributors
    }

    /// Merge a block delivered by `peer` at byte `offset` within the part
    /// (offset relative to the part start). Returns `true` if the prefix
    /// advanced. Always records `peer` as a contributor when the chunk is
    /// at least partially useful.
    pub(crate) fn merge_block(&mut self, peer: PeerEndpoint, offset: u64, bytes: &[u8]) -> bool {
        let prefix = self.bytes.len() as u64;
        let end = offset + bytes.len() as u64;
        if offset > prefix || end <= prefix {
            // Gap ahead, or wholly-redundant chunk behind the prefix.
            return false;
        }
        let start_in_chunk = (prefix - offset) as usize;
        self.bytes.extend_from_slice(&bytes[start_in_chunk..]);
        self.contributors.insert(peer);
        // Attribute every AICH block this merge started (wrote the first byte
        // of) to `peer`. Blocks start in prefix order, so the vec grows by
        // index; the next unrecorded block is `block_contributors.len()`.
        let new_len = self.bytes.len() as u64;
        let mut block = self.block_contributors.len() as u64;
        while block * EMBLOCKSIZE < new_len {
            self.block_contributors.push(peer);
            block += 1;
        }
        true
    }

    /// The peer that delivered AICH block `block_index` of this part, or
    /// `None` if that block is not yet present. The AICH repair (ADR-0038) reads
    /// it to retire exactly the peer that delivered a corrupt block.
    pub(crate) fn contributor_of_block(&self, block_index: usize) -> Option<PeerEndpoint> {
        self.block_contributors.get(block_index).copied()
    }

    /// Roll the assembled prefix back to `len` bytes, dropping later bytes and
    /// their per-block provenance. AICH repair truncates to the earliest corrupt
    /// block so the re-stream resumes from there, reusing the contiguous-prefix
    /// model (ADR-0038).
    pub(crate) fn truncate(&mut self, len: u64) {
        self.bytes.truncate(len as usize);
        let blocks_kept = self.bytes.len().div_ceil(EMBLOCKSIZE as usize);
        self.block_contributors.truncate(blocks_kept);
    }

    pub(crate) fn is_complete(&self, part_len: u64) -> bool {
        self.bytes.len() as u64 == part_len
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmule_primitives::{Ipv4Endpoint, PeerEndpoint};
    use std::net::Ipv4Addr;

    fn peer(n: u8) -> PeerEndpoint {
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, n), 4662))
    }

    #[test]
    fn sequential_blocks_extend_the_prefix() {
        let mut a = PartAssembly::default();
        assert!(a.merge_block(peer(1), 0, &[1, 2, 3]));
        assert!(a.merge_block(peer(1), 3, &[4, 5]));
        assert_eq!(a.bytes(), &[1, 2, 3, 4, 5]);
        assert_eq!(a.prefix_len(), 5);
    }

    #[test]
    fn a_dropped_peers_prefix_is_continued_by_another_peer() {
        let mut a = PartAssembly::default();
        assert!(a.merge_block(peer(1), 0, &[1, 2, 3])); // peer 1 then drops
        assert!(a.merge_block(peer(2), 3, &[4, 5, 6])); // peer 2 resumes
        assert_eq!(a.bytes(), &[1, 2, 3, 4, 5, 6]);
        assert!(a.contributors().contains(&peer(1)));
        assert!(a.contributors().contains(&peer(2)));
    }

    #[test]
    fn redundant_lockstep_chunk_behind_the_prefix_is_dropped() {
        let mut a = PartAssembly::default();
        a.merge_block(peer(1), 0, &[1, 2, 3, 4]);
        // A slower racer re-delivers an earlier chunk: no advance, not a contributor.
        assert!(!a.merge_block(peer(2), 0, &[1, 2]));
        assert_eq!(a.prefix_len(), 4);
        assert!(!a.contributors().contains(&peer(2)));
    }

    #[test]
    fn overlapping_chunk_extends_only_the_new_tail() {
        let mut a = PartAssembly::default();
        a.merge_block(peer(1), 0, &[1, 2]);
        // Chunk [1,4) overlaps the prefix end at 2; only [2,4) is appended.
        assert!(a.merge_block(peer(2), 1, &[2, 3, 4]));
        assert_eq!(a.bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn gap_chunk_ahead_of_the_prefix_is_dropped() {
        let mut a = PartAssembly::default();
        a.merge_block(peer(1), 0, &[1, 2]);
        assert!(!a.merge_block(peer(1), 5, &[9])); // gap at [2,5)
        assert_eq!(a.prefix_len(), 2);
    }

    #[test]
    fn is_complete_at_part_len() {
        let mut a = PartAssembly::default();
        a.merge_block(peer(1), 0, &[1, 2, 3, 4]);
        assert!(a.is_complete(4));
        assert!(!a.is_complete(5));
    }

    #[test]
    fn block_contributors_attribute_each_aich_block_to_its_deliverer() {
        // Two full EMBLOCKSIZE blocks from different peers: AICH attribution
        // names the exact deliverer of each block so a corrupt block retires
        // only its source (ADR-0038).
        let mut a = PartAssembly::default();
        let emb = EMBLOCKSIZE as usize;
        assert!(a.merge_block(peer(1), 0, &vec![0u8; emb]));
        assert!(a.merge_block(peer(2), EMBLOCKSIZE, &vec![0u8; emb]));
        assert_eq!(a.contributor_of_block(0), Some(peer(1)));
        assert_eq!(a.contributor_of_block(1), Some(peer(2)));
        assert_eq!(a.contributor_of_block(2), None);
    }

    #[test]
    fn block_contributor_follows_a_mid_block_handoff_by_first_byte() {
        // peer 1 writes the first half of block 0 then drops; peer 2 resumes
        // and finishes block 0 and starts block 1. Block 0 is attributed to
        // its first-byte writer (peer 1); block 1 to peer 2.
        let mut a = PartAssembly::default();
        let half = (EMBLOCKSIZE / 2) as usize;
        assert!(a.merge_block(peer(1), 0, &vec![0u8; half]));
        assert!(a.merge_block(peer(2), half as u64, &vec![0u8; EMBLOCKSIZE as usize]));
        assert_eq!(a.contributor_of_block(0), Some(peer(1)));
        assert_eq!(a.contributor_of_block(1), Some(peer(2)));
    }
}
