//! One keyword's indexed entry: the dual-form file record a publish stores,
//! the publisher and filename tallies that aggregate across republishes, and
//! the trust score a subnet-spread of publishers earns. Caps and formulas are
//! aMule's (`CIndexed::AddKeyword`, cited in the parent's provenance).

use std::collections::HashMap;
use std::net::Ipv4Addr;

use rmule_primitives::{Ed2kText, Tag, TagName, TagValue};

use crate::{KadId, KadInstant};

use super::{
    KEYWORD_ENTRY_LIFETIME, KEYWORD_MAX_TRACKED_PUBLISHERS, TAG_FILENAME, TAG_FILESIZE,
    TAG_PUBLISHINFO, TRUST_POINTS_PER_SUBNET,
};

/// One decoded per-file row from a `KADEMLIA2_PUBLISH_KEY_REQ` batch.
///
/// `filename`/`size` are the two tags the accept path always types and
/// removes from the generic list (`Process2PublishKeyRequest`'s `TAG_FILENAME`
/// / `TAG_FILESIZE` branches); `tags` is everything else, verbatim — a
/// duplicate FILENAME or FILESIZE tag is dropped either way, matching aMule
/// (only the first occurrence populates the typed field; every occurrence is
/// removed from the generic list).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeywordPublishFile {
    /// The file's Kad ID — what the row is indexed and deduped by.
    pub file_id: KadId,
    /// The published name; `None` fails validation, since a nameless row is
    /// unsearchable.
    pub filename: Option<String>,
    /// The published size, the full 64 bits `TAG_FILESIZE` carries; `None`
    /// (or zero) fails validation too.
    pub size: Option<u64>,
    /// Every other tag, verbatim, re-encoded untouched when the row is served.
    pub tags: Vec<Tag>,
}

/// Outcome of indexing one file within a publish batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeywordFileOutcome {
    /// Indexed (the keyword's first-ever file, a refresh, or a net-new file
    /// under an existing keyword), with the load byte a real ack would carry.
    Stored {
        /// The load byte a real ack would carry for this file.
        load: u8,
    },
    /// [`KEYWORD_GLOBAL_CAP`](crate::keyword_store::KEYWORD_GLOBAL_CAP) is reached; not indexed, ack load forced to 100.
    RejectedTotalIndexFull,
    /// This keyword's own [`KEYWORD_PER_KEYWORD_CAP`](crate::keyword_store::KEYWORD_PER_KEYWORD_CAP) is reached; not
    /// indexed, ack load forced to 100.
    RejectedKeywordIndexFull,
    /// The keyword is past [`KEYWORD_DUPLICATE_GUARD_THRESHOLD`](crate::keyword_store::KEYWORD_DUPLICATE_GUARD_THRESHOLD) and this
    /// publish would only refresh an already-indexed file; throttled, ack
    /// load forced to 100.
    RejectedRefreshThrottled,
    /// Missing a non-empty filename or a non-zero size. aMule's validation
    /// gate rejects this **without** touching the shared ack load (unlike the
    /// three cap rejects above, which force it to 100).
    RejectedInvalidEntry,
}

/// Outcome of one whole `KADEMLIA2_PUBLISH_KEY_REQ` batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeywordPublishOutcome {
    /// UDP-firewalled or outside the publish tolerance: the whole batch is
    /// dropped before a single file is inspected — wire-silent, matching
    /// `Process2PublishKeyRequest`'s early `return;`.
    Dropped,
    /// The gates passed. `ack_load` is the byte a real `0x4B` carries: aMule
    /// shares one `load` variable across the whole per-file loop, so it ends
    /// up as the **last** file's outcome (0 if the batch was empty or every
    /// file left it untouched).
    Processed {
        /// The byte the `0x4B` ack carries — one shared value across the whole
        /// batch, so it ends up as the last file's outcome.
        ack_load: u8,
        /// Each file's own outcome, in batch order.
        files: Vec<KeywordFileOutcome>,
    },
}

// ---------------------------------------------------------------------------
// Stored entry
// ---------------------------------------------------------------------------

/// One filename seen for a stored entry, and how many publishers agreed on it
/// (`CEntry::sFileNameEntry`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FileNameEntry {
    name: String,
    popularity: u32,
}

/// One tracked publisher IP and when it was last seen (`CKeyEntry::
/// sPublishingIP`). The list orders oldest-first for FIFO eviction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct TrackedPublisher {
    pub(super) ip: Ipv4Addr,
    last_seen: KadInstant,
}

/// One indexed `(keyword, file)` row: the dual form ADR-0062 specifies — a
/// typed size plus the aggregated name/publisher/trust state for tree
/// evaluation and `TAG_PUBLISHINFO`, and the latest publish's verbatim tag
/// list (excluding FILENAME/FILESIZE) re-served untouched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct KeywordEntry {
    pub(super) size: u64,
    names: Vec<FileNameEntry>,
    pub(super) tags: Vec<Tag>,
    pub(super) publishers: Vec<TrackedPublisher>,
    pub(super) expires_at: KadInstant,
}

impl KeywordEntry {
    pub(super) fn new(
        now: KadInstant,
        size: u64,
        filename: String,
        tags: Vec<Tag>,
        from: Ipv4Addr,
        subnet_publishers: &mut HashMap<u32, u32>,
    ) -> Self {
        increment_subnet(subnet_publishers, from);
        Self {
            size,
            names: vec![FileNameEntry {
                name: filename,
                popularity: 1,
            }],
            tags,
            publishers: vec![TrackedPublisher {
                ip: from,
                last_seen: now,
            }],
            expires_at: now + KEYWORD_ENTRY_LIFETIME,
        }
    }

    /// Apply a re-publish: the fresh size/tags/expiry replace the stored
    /// ones outright (`MergeIPsAndFilenames` never carries these over), while
    /// the name and publisher aggregates merge (`CKeyEntry::
    /// MergeIPsAndFilenames`).
    pub(super) fn refresh(
        &mut self,
        now: KadInstant,
        size: u64,
        filename: String,
        tags: Vec<Tag>,
        from: Ipv4Addr,
        subnet_publishers: &mut HashMap<u32, u32>,
    ) {
        self.size = size;
        self.tags = tags;
        self.expires_at = now + KEYWORD_ENTRY_LIFETIME;
        self.bump_or_add_name(filename);
        self.touch_publisher(now, from, subnet_publishers);
    }

    fn bump_or_add_name(&mut self, filename: String) {
        let lower = filename.to_lowercase();
        if let Some(existing) = self
            .names
            .iter_mut()
            .find(|entry| entry.name.to_lowercase() == lower)
        {
            existing.popularity += 1;
        } else {
            self.names.push(FileNameEntry {
                name: filename,
                popularity: 1,
            });
        }
    }

    fn touch_publisher(
        &mut self,
        now: KadInstant,
        from: Ipv4Addr,
        subnet_publishers: &mut HashMap<u32, u32>,
    ) {
        if let Some(pos) = self.publishers.iter().position(|p| p.ip == from) {
            let mut publisher = self.publishers.remove(pos);
            publisher.last_seen = now;
            self.publishers.push(publisher); // move to back: most-recently-seen
            return;
        }
        increment_subnet(subnet_publishers, from);
        self.publishers.push(TrackedPublisher {
            ip: from,
            last_seen: now,
        });
        if self.publishers.len() > KEYWORD_MAX_TRACKED_PUBLISHERS {
            let evicted = self.publishers.remove(0);
            decrement_subnet(subnet_publishers, evicted.ip);
        }
    }

    /// The name on which most publishers agree (`CEntry::GetCommonFileName`):
    /// highest popularity wins; ties favor whichever was inserted earlier.
    /// Never empty — the store rejects a filename-less publish before an
    /// entry can exist.
    pub(super) fn common_filename(&self) -> &str {
        let mut best: Option<&FileNameEntry> = None;
        for candidate in &self.names {
            if best.is_none_or(|current| candidate.popularity > current.popularity) {
                best = Some(candidate);
            }
        }
        &best
            .expect("a stored keyword entry always has at least one name")
            .name
    }

    /// `CKeyEntry::ReCalculateTrustValue`: ten points per `/24` subnet,
    /// divided among however many of this entry's *currently tracked*
    /// publishers share that subnet right now. Recomputed on demand from the
    /// store's live subnet map rather than cached — rmule has no equivalent
    /// of aMule's `GetTickCount`-driven staleness window (explicit-time
    /// discipline), and recomputing is cheap at this entry's bounded size.
    pub(super) fn trust(&self, subnet_publishers: &HashMap<u32, u32>) -> f64 {
        self.publishers
            .iter()
            .map(|publisher| {
                let count = subnet_publishers
                    .get(&subnet_key(publisher.ip))
                    .copied()
                    .unwrap_or(1)
                    .max(1);
                TRUST_POINTS_PER_SUBNET / f64::from(count)
            })
            .sum()
    }

    /// The tag list a search result row serves: FILENAME (the popularity
    /// winner) and FILESIZE synthesized fresh, then the verbatim rest, then
    /// `TAG_PUBLISHINFO` (`CEntry::WriteTagListInc` +
    /// `CKeyEntry::WriteTagListWithPublishInfo`).
    pub(super) fn serve_tags(&self, trust: f64) -> Vec<Tag> {
        let mut tags = Vec::with_capacity(self.tags.len() + 3);
        tags.push(Tag::new(
            TagName::length_prefixed_id(TAG_FILENAME),
            TagValue::String(Ed2kText::from_utf8(self.common_filename().to_owned())),
        ));
        // A fixed `UINT32` for a size that fits, as before; past 4 GiB the
        // `UINT64` both counterparties' storers write there (aMule
        // `CTagVarInt`, `Entry.cpp:217`; eMuleAI `CKadTagUInt`, `Entry.cpp:184`,
        // narrowed by `DataIO.cpp:292-300`).
        tags.push(Tag::new(
            TagName::length_prefixed_id(TAG_FILESIZE),
            u32::try_from(self.size).map_or(TagValue::U64(self.size), TagValue::U32),
        ));
        tags.extend(self.tags.iter().cloned());
        tags.push(publish_info_tag(
            self.names.len(),
            self.publishers.len(),
            trust,
        ));
        tags
    }
}

pub(super) fn subnet_key(ip: Ipv4Addr) -> u32 {
    u32::from(ip) & 0xFFFF_FF00
}

pub(super) fn increment_subnet(subnet_publishers: &mut HashMap<u32, u32>, ip: Ipv4Addr) {
    *subnet_publishers.entry(subnet_key(ip)).or_insert(0) += 1;
}

pub(super) fn decrement_subnet(subnet_publishers: &mut HashMap<u32, u32>, ip: Ipv4Addr) {
    let key = subnet_key(ip);
    if let Some(count) = subnet_publishers.get_mut(&key) {
        *count -= 1;
        if *count == 0 {
            subnet_publishers.remove(&key);
        }
    }
}

/// `(names&0xFF)<<24 | (publishers&0xFF)<<16 | (trust*100 as u16)`
/// (`CKeyEntry::WriteTagListWithPublishInfo`). `names` can realistically
/// exceed 255 (no cap on distinct filenames); `publishers` cannot (capped at
/// [`KEYWORD_MAX_TRACKED_PUBLISHERS`], the mask is restated for fidelity
/// anyway. `trust*100` saturates into the `u16` via Rust's defined `as` cast
/// (documented divergence from C++'s implementation-defined narrowing).
pub(super) fn publish_info_tag(names: usize, publishers: usize, trust: f64) -> Tag {
    let names_byte = u32::try_from(names).unwrap_or(u32::MAX) & 0xFF;
    let publishers_byte = u32::try_from(publishers).unwrap_or(u32::MAX) & 0xFF;
    let trust_u16 = (trust * 100.0) as u16;
    let value = (names_byte << 24) | (publishers_byte << 16) | u32::from(trust_u16);
    Tag::new(
        TagName::length_prefixed_id(TAG_PUBLISHINFO),
        TagValue::U32(value),
    )
}
