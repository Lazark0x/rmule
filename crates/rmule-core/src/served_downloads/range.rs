//! The bytes a Served Download vouches for: its part hash set once whole,
//! and its **Verified Range** — the parts whose recorded hash equals the
//! set's at their index (ADR-0113 rule 2).

use std::collections::BTreeSet;
use std::sync::Arc;

use rmule_peer::PartBitmap;
use rmule_primitives::{ED2K_PART_SIZE, PartHash, PartHashSet};

use crate::VerifiedPartRecord;

/// A part hash set holding every hash its file's size calls for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WholeSet(Arc<[PartHash]>);

impl WholeSet {
    /// `hashes` as the whole set of a `file_size`-byte file; `None` when they
    /// are not as many as the size calls for (none held is not a set).
    pub(crate) fn of(file_size: u64, hashes: &[PartHash]) -> Option<Self> {
        let expected = PartHashSet::expected_hash_count(file_size).ok()?;
        (expected > 0 && hashes.len() == expected).then(|| Self(hashes.into()))
    }

    /// The hashes in part order.
    pub(crate) fn hashes(&self) -> &[PartHash] {
        &self.0
    }
}

/// The parts whose recorded hash equals the whole set's at their index: the
/// only bytes the serve side reads from a part file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct VerifiedRange(BTreeSet<u32>);

impl VerifiedRange {
    /// The range `records` hold against `set`. Without a whole set no part is
    /// checked, so the range is empty.
    pub(crate) fn of_records(set: Option<&WholeSet>, records: &[VerifiedPartRecord]) -> Self {
        let Some(set) = set else {
            return Self::default();
        };
        Self(
            records
                .iter()
                .filter(|record| {
                    set.hashes().get(record.part_index as usize) == Some(&record.part_hash)
                })
                .map(|record| record.part_index)
                .collect(),
        )
    }

    /// Whether part `part_index` lies inside the range.
    pub(crate) fn holds(&self, part_index: u32) -> bool {
        self.0.contains(&part_index)
    }

    /// The status a `file_size`-byte file holding this range states: spelt by
    /// the one function the run's own status is ([`PartBitmap::downloader`]),
    /// so what the serve side says and what the run says are one set.
    pub(crate) fn status(&self, file_size: u64) -> PartBitmap {
        PartBitmap::downloader(file_size, |part| self.holds(part.value()))
    }

    /// Whether the range holds any part of the file.
    pub(crate) fn holds_a_part(&self) -> bool {
        !self.0.is_empty()
    }

    /// Whether every byte of `start..end` lies inside the range: each part
    /// it touches is held.
    pub(crate) fn covers(&self, start: u64, end: u64) -> bool {
        if end <= start {
            return true;
        }
        let part = |offset: u64| u32::try_from(offset / ED2K_PART_SIZE).ok();
        match (part(start), part(end - 1)) {
            (Some(first), Some(last)) => (first..=last).all(|part| self.holds(part)),
            _ => false,
        }
    }
}
