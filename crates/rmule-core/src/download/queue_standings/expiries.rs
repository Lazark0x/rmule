//! What is due to go from the **Queue Standings**, earliest first: a table
//! that ages against the newest ask pays for what falls due, however much it
//! holds. An entry says when to look at its key, nothing more: the table says
//! what stands, and an entry it has outlived is passed over.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::time::Instant;

/// The keys to look at, by when.
#[derive(Debug)]
pub(super) struct Expiries<K> {
    due: BinaryHeap<Expiry<K>>,
}

impl<K> Default for Expiries<K> {
    fn default() -> Self {
        Self {
            due: BinaryHeap::new(),
        }
    }
}

impl<K> Expiries<K> {
    /// Look at `key` once `at` has passed.
    pub(super) fn add(&mut self, at: Instant, key: K) {
        self.due.push(Expiry { at, key });
    }

    /// The next key due by `now`, taken out.
    pub(super) fn next_due(&mut self, now: Instant) -> Option<K> {
        if self.due.peek()?.at > now {
            return None;
        }
        self.due.pop().map(|expiry| expiry.key)
    }
}

/// One entry, ordered by time alone, earliest greatest: the heap pops the
/// greatest.
#[derive(Debug)]
struct Expiry<K> {
    at: Instant,
    key: K,
}

impl<K> PartialEq for Expiry<K> {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at
    }
}

impl<K> Eq for Expiry<K> {}

impl<K> PartialOrd for Expiry<K> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<K> Ord for Expiry<K> {
    fn cmp(&self, other: &Self) -> Ordering {
        other.at.cmp(&self.at)
    }
}
