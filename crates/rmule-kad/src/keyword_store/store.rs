//! The bounded keyword index itself: publish intake behind the global,
//! per-keyword and duplicate-refresh caps, the sweep that expires entries at
//! their 24 h lifetime, and the budgeted search serve. Refuses publishes a
//! firewalled node has no business accepting (ADR-0062).

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::net::{PUBLISH_TOLERANCE, distance_top_word, is_lan_ip};
use crate::search_tree::SearchTree;
use crate::{KadId, KadInstant};

use super::entry::{
    KeywordEntry, KeywordFileOutcome, KeywordPublishFile, KeywordPublishOutcome, decrement_subnet,
};
use super::query::{UnknownSearchOperator, matches_tree, validate_operators};
use super::result::KeywordResultRow;
use super::{
    KEYWORD_DUPLICATE_GUARD_THRESHOLD, KEYWORD_GLOBAL_CAP, KEYWORD_PER_KEYWORD_CAP,
    KEYWORD_PUBLISH_BATCH_CAP, KEYWORD_RESULT_BUDGET, KEYWORD_SWEEP_INTERVAL,
    TRUST_WORTHY_THRESHOLD,
};

/// The bounded keyword index a **Kad Storer** serves (see the module docs for
/// the full provenance and simplifications).
#[derive(Debug, Default)]
pub struct KeywordStore {
    /// Per-keyword rows in insertion order (a `Vec`, not an ordered map: the
    /// per-keyword cap of 50 000 makes a linear scan for the per-file dedupe
    /// lookup bounded and simple, matching `source_store.rs`'s own idiom of a
    /// plain `Vec` searched by `find`/`position`).
    keywords: HashMap<KadId, Vec<(KadId, KeywordEntry)>>,
    total_rows: usize,
    /// `CKeyEntry::s_globalPublishIPs`: a `/24`-subnet publish-count map
    /// shared across every entry in the store (not just one keyword), read by
    /// [`KeywordEntry::trust`] and kept in step with every entry's tracked
    /// publisher list.
    subnet_publishers: HashMap<u32, u32>,
    next_sweep_at: KadInstant,
}

impl KeywordStore {
    /// An empty index: no keywords, no publishers tracked, first sweep due at
    /// the driver's zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Index one `KADEMLIA2_PUBLISH_KEY_REQ` batch (the **Kad Storer**'s
    /// accept path). `own_udp_firewalled` and the tolerance gate mirror
    /// `Process2PublishKeyRequest`'s two early-return checks, run before a
    /// single file is inspected; the per-file caps/load/duplicate-guard
    /// mirror `CIndexed::AddKeyword`.
    pub fn publish_batch(
        &mut self,
        now: KadInstant,
        own_id: KadId,
        own_udp_firewalled: bool,
        from: Ipv4Addr,
        keyword: KadId,
        files: Vec<KeywordPublishFile>,
    ) -> KeywordPublishOutcome {
        if own_udp_firewalled {
            return KeywordPublishOutcome::Dropped;
        }
        if !is_lan_ip(from) && distance_top_word(own_id, keyword) > PUBLISH_TOLERANCE {
            return KeywordPublishOutcome::Dropped;
        }

        let mut ack_load = 0u8;
        let mut outcomes = Vec::with_capacity(files.len().min(KEYWORD_PUBLISH_BATCH_CAP));
        for file in files.into_iter().take(KEYWORD_PUBLISH_BATCH_CAP) {
            let outcome = self.try_index_one(now, keyword, from, file);
            match outcome {
                KeywordFileOutcome::Stored { load } => ack_load = load,
                KeywordFileOutcome::RejectedTotalIndexFull
                | KeywordFileOutcome::RejectedKeywordIndexFull
                | KeywordFileOutcome::RejectedRefreshThrottled => ack_load = 100,
                KeywordFileOutcome::RejectedInvalidEntry => {}
            }
            outcomes.push(outcome);
        }
        KeywordPublishOutcome::Processed {
            ack_load,
            files: outcomes,
        }
    }

    fn try_index_one(
        &mut self,
        now: KadInstant,
        keyword: KadId,
        from: Ipv4Addr,
        file: KeywordPublishFile,
    ) -> KeywordFileOutcome {
        // Unconditional, before even the entry validation (`AddKeyword`'s
        // first check).
        if self.total_rows > KEYWORD_GLOBAL_CAP {
            return KeywordFileOutcome::RejectedTotalIndexFull;
        }
        let Some(filename) = file.filename.filter(|name| !name.is_empty()) else {
            return KeywordFileOutcome::RejectedInvalidEntry;
        };
        let Some(size) = file.size.filter(|&size| size != 0) else {
            return KeywordFileOutcome::RejectedInvalidEntry;
        };

        let Self {
            keywords,
            subnet_publishers,
            total_rows,
            ..
        } = self;
        let rows = keywords.entry(keyword).or_default();

        if rows.is_empty() {
            rows.push((
                file.file_id,
                KeywordEntry::new(now, size, filename, file.tags, from, subnet_publishers),
            ));
            *total_rows += 1;
            return KeywordFileOutcome::Stored { load: 1 };
        }

        // Snapshot taken before this operation: both the load formula and the
        // duplicate-guard threshold read the pre-insert count.
        let index_total = rows.len();
        if index_total > KEYWORD_PER_KEYWORD_CAP {
            return KeywordFileOutcome::RejectedKeywordIndexFull;
        }
        let load = u8::try_from(index_total * 100 / KEYWORD_PER_KEYWORD_CAP).expect(
            "index_total is capped at KEYWORD_PER_KEYWORD_CAP, so the percentage is <= 100",
        );

        if let Some((_, entry)) = rows.iter_mut().find(|(id, _)| *id == file.file_id) {
            if index_total > KEYWORD_DUPLICATE_GUARD_THRESHOLD {
                return KeywordFileOutcome::RejectedRefreshThrottled;
            }
            entry.refresh(now, size, filename, file.tags, from, subnet_publishers);
            return KeywordFileOutcome::Stored { load };
        }

        rows.push((
            file.file_id,
            KeywordEntry::new(now, size, filename, file.tags, from, subnet_publishers),
        ));
        *total_rows += 1;
        KeywordFileOutcome::Stored { load }
    }

    /// Answer a `KADEMLIA2_SEARCH_KEY_REQ` (the **Kad Storer**'s serve path):
    /// unexpired, tree-matching rows for `keyword`, trusted entries first
    /// (`SendValidKeywordResult`'s two-pass split), after skipping
    /// `start_position` and capped at [`KEYWORD_RESULT_BUDGET`]. `tree` absent
    /// answers every row (a non-restrictive search); `Err` propagates an
    /// [`UnknownSearchOperator`] the tree's own decode should have already
    /// rejected — this method validates independently so it stays correct for
    /// any caller, not only the wire codec below.
    pub fn lookup(
        &self,
        now: KadInstant,
        keyword: KadId,
        start_position: u16,
        tree: Option<&SearchTree>,
    ) -> Result<Vec<KeywordResultRow>, UnknownSearchOperator> {
        if let Some(tree) = tree {
            validate_operators(tree)?;
        }
        let Some(rows) = self.keywords.get(&keyword) else {
            return Ok(Vec::new());
        };

        let mut trusted = Vec::new();
        let mut untrusted = Vec::new();
        for (file_id, entry) in rows {
            if entry.expires_at <= now {
                continue;
            }
            if tree.is_some_and(|tree| !matches_tree(entry, tree)) {
                continue;
            }
            let trust = entry.trust(&self.subnet_publishers);
            let row = KeywordResultRow {
                file_id: *file_id,
                tags: entry.serve_tags(trust),
            };
            if trust >= TRUST_WORTHY_THRESHOLD {
                trusted.push(row);
            } else {
                untrusted.push(row);
            }
        }
        trusted.extend(untrusted);
        Ok(trusted
            .into_iter()
            .skip(usize::from(start_position))
            .take(KEYWORD_RESULT_BUDGET)
            .collect())
    }

    /// Prune every entry whose lifetime has elapsed, throttled to at most
    /// once per [`KEYWORD_SWEEP_INTERVAL`] (`CIndexed::Clean`'s throttle).
    pub fn tick(&mut self, now: KadInstant) {
        if now < self.next_sweep_at {
            return;
        }
        let mut removed = 0usize;
        let mut evicted_ips = Vec::new();
        self.keywords.retain(|_, rows| {
            rows.retain(|(_, entry)| {
                let keep = entry.expires_at > now;
                if !keep {
                    removed += 1;
                    evicted_ips.extend(entry.publishers.iter().map(|publisher| publisher.ip));
                }
                keep
            });
            !rows.is_empty()
        });
        for ip in evicted_ips {
            decrement_subnet(&mut self.subnet_publishers, ip);
        }
        self.total_rows -= removed;
        self.next_sweep_at = now + KEYWORD_SWEEP_INTERVAL;
    }

    /// The next instant [`tick`](Self::tick) has sweeping work to (possibly)
    /// do. Always `Some`: the sweep throttle exists independent of content,
    /// matching aMule's `m_lastClean`, which is armed from construction. A
    /// driver with no other work should still consult [`is_empty`](Self::is_empty)
    /// — an empty index has nothing to expire, so waking for its perpetual
    /// re-arm would keep the node forever un-idle.
    #[must_use]
    pub fn next_wake(&self) -> Option<KadInstant> {
        Some(self.next_sweep_at)
    }

    /// How many `(keyword, file)` rows the index holds — aMule's
    /// `CIndexed::m_totalIndexKeyword`.
    #[must_use]
    pub fn len(&self) -> usize {
        self.total_rows
    }

    /// Whether the index holds no rows — a driver folds this into its own
    /// wake so an empty keyword store contributes no perpetual sweep wake.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total_rows == 0
    }
}

// ---------------------------------------------------------------------------
// Wire codec
// ---------------------------------------------------------------------------
