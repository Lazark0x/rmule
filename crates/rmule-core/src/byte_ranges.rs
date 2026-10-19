//! A set of byte ranges, exact to the byte: what a part has received and what
//! its workers have been asked for (ADR-0117). Ranges are half-open,
//! `start..end`, kept disjoint and coalesced, so a set reads the same however
//! its pieces arrived — on the 180 KiB grid or off it.

use std::collections::BTreeMap;

/// Disjoint, coalesced half-open byte ranges.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ByteRanges(BTreeMap<u64, u64>);

impl ByteRanges {
    /// Add `start..end`, answering the pieces of it the set did not hold
    /// before, in order.
    pub(crate) fn insert(&mut self, start: u64, end: u64) -> Vec<(u64, u64)> {
        if end <= start {
            return Vec::new();
        }
        let fresh = self.gaps(start, end);
        let mut lo = start;
        let mut hi = end;
        // Every range that touches `start..end`, adjacent ones included, folds
        // into one.
        let touching: Vec<(u64, u64)> = self
            .0
            .range(..=end)
            .rev()
            .take_while(|&(_, &e)| e >= start)
            .map(|(&s, &e)| (s, e))
            .collect();
        for (s, e) in touching {
            self.0.remove(&s);
            lo = lo.min(s);
            hi = hi.max(e);
        }
        self.0.insert(lo, hi);
        fresh
    }

    /// Forget `start..end`.
    pub(crate) fn remove(&mut self, start: u64, end: u64) {
        if end <= start {
            return;
        }
        let overlapping: Vec<(u64, u64)> = self
            .0
            .range(..end)
            .rev()
            .take_while(|&(_, &e)| e > start)
            .map(|(&s, &e)| (s, e))
            .collect();
        for (s, e) in overlapping {
            self.0.remove(&s);
            if s < start {
                self.0.insert(s, start);
            }
            if e > end {
                self.0.insert(end, e);
            }
        }
    }

    /// The bytes of `start..end` the set holds.
    pub(crate) fn covered_within(&self, start: u64, end: u64) -> u64 {
        self.0
            .range(..end)
            .rev()
            .take_while(|&(_, &e)| e > start)
            .map(|(&s, &e)| e.min(end) - s.max(start))
            .sum()
    }

    /// Whether every byte of `start..end` is held.
    pub(crate) fn covers(&self, start: u64, end: u64) -> bool {
        end <= start || self.covered_within(start, end) == end - start
    }

    /// The pieces of `start..end` the set does not hold, in order.
    pub(crate) fn gaps(&self, start: u64, end: u64) -> Vec<(u64, u64)> {
        let mut gaps = Vec::new();
        let mut at = start;
        let first = self
            .0
            .range(..=start)
            .next_back()
            .filter(|&(_, &e)| e > start)
            .map(|(&s, _)| s)
            .unwrap_or(start);
        for (&s, &e) in self.0.range(first..end) {
            if s > at {
                gaps.push((at, s.min(end)));
            }
            at = at.max(e);
            if at >= end {
                break;
            }
        }
        if at < end {
            gaps.push((at, end));
        }
        gaps
    }

    /// How many bytes the set holds.
    pub(crate) fn total(&self) -> u64 {
        self.0.iter().map(|(s, e)| e - s).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges(set: &ByteRanges) -> Vec<(u64, u64)> {
        set.0.iter().map(|(&s, &e)| (s, e)).collect()
    }

    #[test]
    fn inserts_coalesce_and_answer_only_what_was_new() {
        let mut set = ByteRanges::default();
        assert_eq!(set.insert(10, 20), vec![(10, 20)]);
        assert_eq!(set.insert(30, 40), vec![(30, 40)]);
        // Spanning both and the gap between: only the gap and the tails are new.
        assert_eq!(set.insert(5, 45), vec![(5, 10), (20, 30), (40, 45)]);
        assert_eq!(ranges(&set), vec![(5, 45)]);
        // Adjacent ranges fold into one.
        assert_eq!(set.insert(45, 50), vec![(45, 50)]);
        assert_eq!(ranges(&set), vec![(5, 50)]);
        assert_eq!(set.insert(7, 9), Vec::<(u64, u64)>::new());
    }

    #[test]
    fn removal_splits_a_range_and_gaps_read_the_holes() {
        let mut set = ByteRanges::default();
        set.insert(0, 100);
        set.remove(40, 60);
        assert_eq!(ranges(&set), vec![(0, 40), (60, 100)]);
        assert_eq!(set.gaps(0, 100), vec![(40, 60)]);
        assert_eq!(set.gaps(50, 120), vec![(50, 60), (100, 120)]);
        assert_eq!(set.covered_within(30, 70), 20);
        assert!(set.covers(60, 100));
        assert!(!set.covers(39, 41));
        assert_eq!(set.total(), 80);
    }
}
