//! The **Kad Storer**'s bounded in-memory source index.
//!
//! Stores only *parsed* state ([`KadSourceRow`] plus a size filter and an
//! expiry instant) — never datagram bytes — so everything the storer answers
//! is a re-encoding by construction (the property that makes a storer's
//! answers evidence-grade; see `CONTEXT.md`, **Kad Stimulus Node**).
//!
//! Bounds are the anti-flood posture (mirroring the module docs of
//! `envelope.rs`): a per-key cap that evicts the oldest entry (aMule's
//! `AddSources` posture, minus its off-by-one — rmule holds *exactly* the cap),
//! and a **total-entry cap aMule does not have** (its source index is
//! unbounded per key count; rmule refuses net-new entries once full).
//! Expiry is tick-driven through the node's explicit-time surface, and
//! lookups also filter by expiry so an entry can never be served between its
//! deadline and the next tick.

use std::collections::HashMap;

use crate::{KadId, KadInstant, KadSourceRow};

/// One indexed publish: the re-encodable row, the published size (searches
/// filter on it), and when the entry stops existing.
#[derive(Clone, Copy, Debug)]
struct StoredSource {
    row: KadSourceRow,
    file_size: Option<u64>,
    expires_at: KadInstant,
}

/// What a publish did to the index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StoreOutcome {
    /// Indexed (new, replaced, or evicting-oldest), with the load byte to
    /// ack: 1 for a key's first entry, `count × 100 / per-key cap` while
    /// filling, 100 when the cap evicted the oldest entry.
    Stored { load: u8, rows_for_key: usize },
    /// The total-entry cap is reached and this publish would grow the index.
    RejectedIndexFull,
}

/// The bounded source index (see the module docs for the bound semantics).
#[derive(Debug)]
pub(crate) struct SourceStore {
    per_key_cap: usize,
    total_cap: usize,
    keys: HashMap<KadId, Vec<StoredSource>>,
    total: usize,
}

impl SourceStore {
    pub(crate) fn new(per_key_cap: usize, total_cap: usize) -> Self {
        Self {
            per_key_cap,
            total_cap,
            keys: HashMap::new(),
            total: 0,
        }
    }

    /// Index one parsed publish. Entries for a key age in insertion order;
    /// a publish from an endpoint already indexed for the key (same IP and
    /// same TCP *or* UDP port — aMule's dedupe rule) replaces that entry in
    /// place, refreshing its expiry without changing its age position.
    pub(crate) fn publish(
        &mut self,
        key: KadId,
        row: KadSourceRow,
        file_size: Option<u64>,
        expires_at: KadInstant,
    ) -> StoreOutcome {
        let entry = StoredSource {
            row,
            file_size,
            expires_at,
        };
        let entries = self.keys.entry(key).or_default();

        if let Some(existing) = entries.iter_mut().find(|stored| {
            stored.row.ip == row.ip
                && (stored.row.tcp_port == row.tcp_port || stored.row.udp_port == row.udp_port)
        }) {
            *existing = entry;
            return StoreOutcome::Stored {
                load: Self::load_for(entries.len(), self.per_key_cap),
                rows_for_key: entries.len(),
            };
        }

        if entries.len() >= self.per_key_cap {
            // Evict the oldest entry for the key: net index growth is zero,
            // so the total cap cannot be exceeded through this path.
            entries.remove(0);
            entries.push(entry);
            return StoreOutcome::Stored {
                load: 100,
                rows_for_key: entries.len(),
            };
        }

        if self.total >= self.total_cap {
            if entries.is_empty() {
                self.keys.remove(&key);
            }
            return StoreOutcome::RejectedIndexFull;
        }

        let load = Self::load_for(entries.len(), self.per_key_cap);
        entries.push(entry);
        self.total += 1;
        StoreOutcome::Stored {
            load,
            rows_for_key: entries.len(),
        }
    }

    /// The aMule load curve: a key's first entry reports 1, after that the
    /// pre-insert count as a percentage of the per-key cap.
    fn load_for(count_before: usize, per_key_cap: usize) -> u8 {
        if count_before == 0 {
            return 1;
        }
        u8::try_from(count_before * 100 / per_key_cap).expect("count is capped at per_key_cap")
    }

    /// Unexpired rows for a key, newest first (aMule iterates its newest-first
    /// source list), filtered by the searched size: a zero search size, an
    /// unsized entry, or an exact match qualifies. The caller applies start
    /// offsets and result budgets.
    pub(crate) fn lookup(
        &self,
        now: KadInstant,
        key: KadId,
        searched_size: u64,
    ) -> Vec<KadSourceRow> {
        let Some(entries) = self.keys.get(&key) else {
            return Vec::new();
        };
        entries
            .iter()
            .rev()
            .filter(|stored| stored.expires_at > now)
            .filter(|stored| {
                searched_size == 0 || stored.file_size.is_none_or(|size| size == searched_size)
            })
            .map(|stored| stored.row)
            .collect()
    }

    /// Prune every entry whose lifetime has elapsed.
    pub(crate) fn tick(&mut self, now: KadInstant) {
        let mut removed = 0usize;
        self.keys.retain(|_, entries| {
            let before = entries.len();
            entries.retain(|stored| stored.expires_at > now);
            removed += before - entries.len();
            !entries.is_empty()
        });
        self.total -= removed;
    }

    /// The earliest entry expiry, for the node's wake schedule.
    pub(crate) fn next_wake(&self) -> Option<KadInstant> {
        self.keys
            .values()
            .flat_map(|entries| entries.iter().map(|stored| stored.expires_at))
            .min()
    }
}
