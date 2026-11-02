//! The **Failed Cells** (ADR-0117 §1): one complete attempt at a part, cell by
//! cell — each cell's AICH block hash and its writers — which a part that
//! failed its check with no Trusted AICH Root keeps across its refetch, and
//! what the next attempt's cells prove about the writers they are compared
//! with. A part keeps at most [`KEPT_ATTEMPTS`], so the evidence is bounded.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rmule_primitives::{PeerEndpoint, UserHash};

/// The failed attempts a part keeps, the latest ones. Narrowing ends a part's
/// failures in a few attempts; one past these goes uncharged.
pub(crate) const KEPT_ATTEMPTS: usize = 4;

/// One cell of an attempt.
#[derive(Clone, Debug)]
pub(crate) struct Cell {
    /// The SHA-1 of its bytes, its AICH block hash.
    pub(crate) hash: [u8; 20],
    /// Every worker that wrote a byte into it.
    pub(crate) writers: Vec<PeerEndpoint>,
}

/// One complete attempt at a part, its cells in order.
#[derive(Clone, Debug)]
pub(crate) struct Attempt {
    cells: Vec<Cell>,
    /// The User Hash each writer's hello named when it wrote.
    user_hashes: HashMap<PeerEndpoint, UserHash>,
}

/// What a comparison shows of a part's writers (ADR-0117 §1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Verdict {
    /// Per writer, the cells proved corrupt that it wrote into, alone or not.
    pub(crate) charged: BTreeMap<PeerEndpoint, u64>,
    /// The writers proven by bytes they alone wrote.
    pub(crate) proven: BTreeSet<PeerEndpoint>,
    /// The writers a repeated failure points to, with nothing proven.
    pub(crate) suspected: BTreeSet<PeerEndpoint>,
}

impl Verdict {
    /// A cell written by `writers` is proved corrupt.
    pub(crate) fn charge(&mut self, writers: &[PeerEndpoint]) {
        for &writer in writers {
            *self.charged.entry(writer).or_default() += 1;
        }
        if let [sole] = writers {
            self.proven.insert(*sole);
        }
    }

    /// How many writers the comparison points to, proven or not.
    pub(crate) fn named(&self) -> usize {
        self.proven.len() + self.suspected.len()
    }
}

impl Attempt {
    /// An attempt of `cells`, its writers' hellos naming `user_hashes`.
    pub(crate) fn new(cells: Vec<Cell>, user_hashes: HashMap<PeerEndpoint, UserHash>) -> Self {
        Self { cells, user_hashes }
    }

    /// Every worker that wrote a byte of the attempt.
    pub(crate) fn writers(&self) -> BTreeSet<PeerEndpoint> {
        self.cells
            .iter()
            .flat_map(|cell| cell.writers.iter().copied())
            .collect()
    }

    /// The User Hash each writer's hello named when it wrote.
    pub(crate) const fn user_hashes(&self) -> &HashMap<PeerEndpoint, UserHash> {
        &self.user_hashes
    }

    /// The one worker that wrote every cell: a cell with no writer on record
    /// leaves that unknown.
    fn sole_writer(&self) -> Option<PeerEndpoint> {
        let (first, rest) = self.cells.split_first()?;
        let [sole] = first.writers[..] else {
            return None;
        };
        rest.iter()
            .all(|cell| cell.writers == [sole])
            .then_some(sole)
    }

    /// The workers that wrote cell `cell`; empty past the part's end.
    pub(crate) fn writers_of(&self, cell: u64) -> &[PeerEndpoint] {
        usize::try_from(cell)
            .ok()
            .and_then(|cell| self.cells.get(cell))
            .map_or(&[], |cell| cell.writers.as_slice())
    }

    /// What this attempt, verified, proves of the `failed` attempts: a cell
    /// whose bytes differ held corrupt bytes, as a root would have named it.
    pub(crate) fn disproves(&self, failed: &[Self]) -> Verdict {
        let mut verdict = Verdict::default();
        for attempt in failed {
            for (good, old) in self.cells.iter().zip(&attempt.cells) {
                if good.hash != old.hash {
                    verdict.charge(&old.writers);
                }
            }
        }
        verdict
    }

    /// What this attempt, failed, shows against `kept`, the attempt that
    /// failed before it.
    ///
    /// - A writer that wrote the whole attempt alone sent at least one bad
    ///   cell.
    /// - With nothing kept, nothing else is shown.
    /// - Otherwise a cell whose bytes match, from writers disjoint from the old
    ///   ones, is corroborated, and both copies are taken as good; one whose
    ///   bytes differ is disputed. A writer that alone sent both differing
    ///   copies of a cell sent at least one bad copy.
    /// - With no proof, the suspects are those that wrote an uncorroborated
    ///   cell in both attempts and a copy of every disputed cell: with one bad
    ///   sender, that sender. If that leaves nobody (two senders lied, or two
    ///   sent one corrupt copy), every writer it cannot clear.
    pub(crate) fn names(&self, kept: Option<&Self>) -> Verdict {
        let mut verdict = Verdict::default();
        if let Some(sole) = self.sole_writer() {
            verdict.charge(&[sole]);
            return verdict;
        }
        let Some(kept) = kept else {
            return verdict;
        };
        let (mut ours, mut theirs) = (BTreeSet::new(), BTreeSet::new());
        let mut disputed: Option<BTreeSet<PeerEndpoint>> = None;
        for (new, old) in self.cells.iter().zip(&kept.cells) {
            let shared = new.writers.iter().any(|w| old.writers.contains(w));
            if new.hash == old.hash && !shared {
                continue;
            }
            ours.extend(new.writers.iter().copied());
            theirs.extend(old.writers.iter().copied());
            if new.hash != old.hash {
                let sides: BTreeSet<PeerEndpoint> =
                    new.writers.iter().chain(&old.writers).copied().collect();
                disputed = Some(match disputed {
                    Some(every) => &every & &sides,
                    None => sides,
                });
                if let ([a], [b]) = (&new.writers[..], &old.writers[..])
                    && a == b
                {
                    verdict.charge(&[*a]);
                }
            }
        }
        if !verdict.proven.is_empty() {
            return verdict;
        }
        let mut pointed = &ours & &theirs;
        if let Some(every) = disputed {
            pointed = &pointed & &every;
        }
        let uncleared = &ours | &theirs;
        verdict.suspected = [pointed, uncleared]
            .into_iter()
            .find(|writers| !writers.is_empty())
            .unwrap_or_else(|| self.writers());
        verdict
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmule_primitives::Ipv4Endpoint;
    use std::net::Ipv4Addr;

    fn peer(n: u8) -> PeerEndpoint {
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, n), 4662))
    }

    /// An attempt whose cells are `(hash byte, writer)` pairs.
    fn attempt(cells: &[(u8, u8)]) -> Attempt {
        Attempt::new(
            cells
                .iter()
                .map(|&(hash, writer)| Cell {
                    hash: [hash; 20],
                    writers: vec![peer(writer)],
                })
                .collect(),
            HashMap::new(),
        )
    }

    /// Two writers alone on a part, each refetching the other's cells: every
    /// cell is disputed between them, and nothing tells them apart, so both
    /// are suspected and neither is proven.
    #[test]
    fn two_writers_disputing_each_others_cells_are_both_suspected() {
        let first = attempt(&[(9, 1), (9, 1), (2, 2), (3, 2)]);
        let second = attempt(&[(0, 2), (1, 2), (8, 1), (8, 1)]);
        let verdict = second.names(Some(&first));
        assert_eq!(verdict.suspected, BTreeSet::from([peer(1), peer(2)]));
        assert!(verdict.proven.is_empty() && verdict.charged.is_empty());
    }

    /// A writer that alone sent two differing copies of one cell sent bad
    /// bytes at least once: it is proven, whoever else shared the part, and
    /// an honest writer corroborated elsewhere is not pointed to.
    #[test]
    fn a_writer_that_alone_sent_two_copies_of_a_cell_that_differ_is_proven() {
        let first = attempt(&[(9, 1), (1, 2), (2, 3)]);
        let second = attempt(&[(7, 1), (1, 3), (2, 2)]);
        let verdict = second.names(Some(&first));
        assert_eq!(verdict.proven, BTreeSet::from([peer(1)]));
        assert!(verdict.suspected.is_empty());
    }

    /// Two seeds holding one corrupt copy agree on every cell, so nothing is
    /// disputed and every cell reads as corroborated, and the part fails
    /// anyway: neither is cleared, and the part narrows.
    #[test]
    fn two_sources_of_one_corrupt_copy_are_both_suspected() {
        let first = attempt(&[(9, 1), (8, 2)]);
        let second = attempt(&[(9, 2), (8, 1)]);
        let verdict = second.names(Some(&first));
        assert_eq!(verdict.suspected, BTreeSet::from([peer(1), peer(2)]));
    }

    /// A resumed cell with no writer on record may hold anyone's bytes, so
    /// the rest of the part's one writer is not its sole writer.
    #[test]
    fn a_cell_with_no_writer_on_record_proves_no_sole_writer() {
        let mut failed = attempt(&[(1, 1), (2, 1)]);
        failed.cells[1].writers.clear();
        assert!(failed.names(None).proven.is_empty());
    }

    /// A verified part charges every kept attempt that held a bad copy, each
    /// writer of a differing cell, and proves only a sole writer.
    #[test]
    fn a_verified_part_charges_each_attempt_and_proves_only_sole_writers() {
        let mut first = attempt(&[(9, 1), (2, 2), (3, 3)]);
        first.cells[1].hash = [7; 20];
        first.cells[1].writers.push(peer(1));
        let second = attempt(&[(1, 2), (9, 1), (3, 3)]);
        let good = attempt(&[(1, 2), (2, 3), (3, 3)]);
        let verdict = good.disproves(&[first, second]);
        assert_eq!(verdict.charged[&peer(1)], 3);
        assert_eq!(verdict.charged[&peer(2)], 1);
        assert_eq!(verdict.proven, BTreeSet::from([peer(1)]));
        assert!(!verdict.charged.contains_key(&peer(3)));
    }
}
