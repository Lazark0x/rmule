//! A per-source **interval limiter**: one honored request per
//! [`AccountingKey`] per interval, bounded in both memory and per-datagram
//! cost. The shape every unauthenticated UDP consume in core needs — the
//! source is just the datagram source, so a spoofed-source flood must cost
//! O(1) per datagram and a fixed amount of memory however many addresses it
//! invents.
//!
//! Buckets by [`AccountingKey`] rather than by exact address: an IPv6 sender
//! is delegated a whole `/64` and can mint a fresh address inside it per
//! datagram, so a per-`/128` bucket would be no limit at all (ADR-0087). The
//! key is accounting only — nothing here bans, indexes or identifies.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use rmule_primitives::AccountingKey;

/// Which senders were honored inside the window.
#[derive(Debug)]
pub(crate) struct IntervalLimiter {
    /// Minimum time between two honored requests from one bucket.
    interval: Duration,
    /// Hard cap on tracked buckets. At the cap the oldest honored entry is
    /// evicted, trading an earlier-than-window re-honor of that one bucket
    /// for bounded memory under flood.
    tracked_max: usize,
    /// Per-bucket last-honored times. The map answers "honored inside the
    /// window?" in O(1); `expiry` orders the same entries oldest-first so
    /// pruning pops from the front in O(1) amortized instead of scanning the
    /// map on every datagram.
    seen: HashMap<AccountingKey, Instant>,
    /// The honored entries in stamp order (each honor pushes back). Lazy
    /// expiry: a popped entry acts on the map only while the map still holds
    /// this entry's stamp for the bucket — a bucket re-honored later carries
    /// a newer stamp and its own newer queue entry, so a stale front entry is
    /// discarded without evicting the live one early.
    expiry: VecDeque<(AccountingKey, Instant)>,
}

impl IntervalLimiter {
    pub(crate) fn new(interval: Duration, tracked_max: usize) -> Self {
        Self {
            interval,
            tracked_max,
            seen: HashMap::new(),
            expiry: VecDeque::new(),
        }
    }

    /// Admit one request from `source`: `true` when it is honored (and its
    /// clock stamped), `false` when this bucket was already honored inside
    /// the window. Only an honored request stamps the clock.
    pub(crate) fn admit(&mut self, source: AccountingKey, now: Instant) -> bool {
        // Prune entries past the window from the queue front — O(1) amortized
        // per datagram, where a whole-map `retain` would hand a spoofed-source
        // flood O(n) work per datagram — then any bucket still tracked was
        // honored inside the window: a flood, refused.
        while let Some(&(key, stamp)) = self.expiry.front() {
            if now.saturating_duration_since(stamp) < self.interval {
                break;
            }
            self.expiry.pop_front();
            self.retire(key, stamp);
        }
        if self.seen.contains_key(&source) {
            return false;
        }
        // The hard cap: evict the oldest live entry to admit the new one.
        // Popping continues past stale entries; the queue always covers the
        // map, so a live one is found.
        while self.seen.len() >= self.tracked_max {
            let Some((oldest, stamp)) = self.expiry.pop_front() else {
                break;
            };
            self.retire(oldest, stamp);
        }
        self.seen.insert(source, now);
        self.expiry.push_back((source, now));
        true
    }

    /// Retire one popped expiry-queue entry: remove the map entry only while it
    /// still carries this queue entry's stamp (lazy expiry — a re-honored
    /// bucket owns a newer stamp and a newer queue entry of its own, which
    /// must not be evicted by its predecessor).
    fn retire(&mut self, key: AccountingKey, stamp: Instant) {
        if self.seen.get(&key) == Some(&stamp) {
            self.seen.remove(&key);
        }
    }
}
