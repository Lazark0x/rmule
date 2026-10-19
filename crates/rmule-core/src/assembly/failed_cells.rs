//! The **Failed Cells** (ADR-0117 §1): one complete attempt at a part, cell by
//! cell — each cell's AICH block hash and its writers — which a part that
//! failed its check with no Trusted AICH Root keeps across its refetch, and
//! what the next attempt's cells prove about the writers they are compared
//! with. A part keeps one attempt, so the evidence is at most one hash and one
//! writer list per cell.

use std::collections::{BTreeSet, HashMap};

use rmule_primitives::{PeerEndpoint, UserHash};

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

/// The writers a comparison names, and those of them it proves (ADR-0090
/// invariant 4): every named writer is retired, a proven one distrusted too.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Verdict {
    /// Every writer named.
    pub(crate) named: BTreeSet<PeerEndpoint>,
    /// The named writers proven to have sent bad bytes.
    pub(crate) proven: BTreeSet<PeerEndpoint>,
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

    /// The User Hash `writer`'s hello named when it wrote, if it named one.
    pub(crate) fn user_hash(&self, writer: PeerEndpoint) -> Option<UserHash> {
        self.user_hashes.get(&writer).copied()
    }

    /// The workers that wrote cell `cell`; empty past the part's end.
    pub(crate) fn writers_of(&self, cell: u64) -> &[PeerEndpoint] {
        usize::try_from(cell)
            .ok()
            .and_then(|cell| self.cells.get(cell))
            .map_or(&[], |cell| cell.writers.as_slice())
    }

    /// What this attempt, verified, proves of the failed attempt `failed`: a
    /// cell whose bytes differ held corrupt bytes, as a root would have named
    /// it. Its writers are named, and its sole writer proven.
    pub(crate) fn disproves(&self, failed: &Self) -> Verdict {
        let mut verdict = Verdict::default();
        for (good, old) in self.cells.iter().zip(&failed.cells) {
            if good.hash == old.hash {
                continue;
            }
            verdict.named.extend(old.writers.iter().copied());
            if let [sole] = old.writers[..] {
                verdict.proven.insert(sole);
            }
        }
        verdict
    }

    /// What this attempt, failed, names against the part's Failed Cells
    /// `kept`, the attempt that failed before it.
    ///
    /// - A writer that wrote the whole attempt alone sent its bad bytes:
    ///   named and proven.
    /// - With nothing kept, nobody else is named.
    /// - Otherwise a cell whose bytes match, from writers disjoint from the old
    ///   ones, is corroborated, and both copies are good; one whose bytes
    ///   differ is disputed. The writers named are those that wrote an
    ///   uncorroborated cell in both attempts and a copy of every disputed
    ///   cell: with one bad sender, that sender. A writer that alone sent
    ///   both differing copies of a cell is proven.
    pub(crate) fn names(&self, kept: Option<&Self>) -> Verdict {
        let writers = self.writers();
        if writers.len() == 1 {
            return Verdict {
                named: writers.clone(),
                proven: writers,
            };
        }
        let Some(kept) = kept else {
            return Verdict::default();
        };
        let mut proven = BTreeSet::new();
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
                    proven.insert(*a);
                }
            }
        }
        let mut named = &ours & &theirs;
        if let Some(every) = disputed {
            named = &named & &every;
        }
        Verdict {
            named: &named | &proven,
            proven,
        }
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
    /// are named and neither is proven.
    #[test]
    fn two_writers_disputing_each_others_cells_are_both_named() {
        let first = attempt(&[(9, 1), (9, 1), (2, 2), (3, 2)]);
        let second = attempt(&[(0, 2), (1, 2), (8, 1), (8, 1)]);
        let verdict = second.names(Some(&first));
        assert_eq!(verdict.named, BTreeSet::from([peer(1), peer(2)]));
        assert!(verdict.proven.is_empty());
    }

    /// A writer that alone sent two differing copies of one cell sent bad
    /// bytes at least once: it is proven, whoever else shared the part, and
    /// an honest writer corroborated elsewhere is not named.
    #[test]
    fn a_writer_that_alone_sent_two_copies_of_a_cell_that_differ_is_proven() {
        let first = attempt(&[(9, 1), (1, 2), (2, 3)]);
        let second = attempt(&[(7, 1), (1, 3), (2, 2)]);
        let verdict = second.names(Some(&first));
        assert_eq!(verdict.named, BTreeSet::from([peer(1)]));
        assert_eq!(verdict.proven, BTreeSet::from([peer(1)]));
    }
}
