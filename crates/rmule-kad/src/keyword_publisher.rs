//! The **Kad Publisher**'s keyword scheduling (ADR-0062, execution breakdown
//! 3): core registers its complete shared files, this module derives their
//! keywords and paces per-keyword publish walks with aMule's constants —
//! explicit-time, sans-I/O. It emits "publish this keyword's files now"
//! decisions the node turns into `KADEMLIA2_PUBLISH_KEY_REQ` (`0x43`) walks; it
//! holds no socket, clock, or RNG, so identical inputs pace identically (the
//! deterministic tier's publisher-pacing sim scores that).
//!
//! ## Pacing (all aMule's `CSharedFileList::Publish`, cited in ADR-0062)
//!
//! - **complete files only** — the caller registers only complete files (core's
//!   responsibility; the node trusts the registration).
//! - **24 h republish** per keyword (`KADEMLIAREPUBLISHTIMEK`).
//! - **≤ 2 concurrent** store-keyword walks (`KADEMLIATOTALSTOREKEY`) — enforced
//!   by the node (walk count is its state), not here.
//! - **2 s spacing** between publish starts.
//! - **150 files per keyword** per round, then reference rotation — a keyword
//!   with more files publishes a rotating 150-file window each round.
//! - **load embargo** — a keyword whose `0x4B` acks average `> 20` load is
//!   embargoed for `7 days × avgLoad / 100`, enforced at its next due publish.
//!
//! ## The publish gate ([`KadReachability`](crate::KadReachability)(crate::KadReachability), node-side)
//!
//! aMule publishes only when Kad-joined ∧ (TCP-open ∨ a buddy is connected). The
//! reachability and buddy inputs are ADR-0058/ADR-0061 state the node has no
//! self-verdict for yet (only the *responder* exists, not a self-check
//! requester), so the node holds an injected [`KadReachability`](crate::KadReachability) and gates
//! `poll_due` itself; this module paces
//! unconditionally and is only asked for a batch when the gate is open.
//!
//! ## Emit tags (ADR-0062, amended by capture)
//!
//! FILENAME and FILESIZE (typed, the split the storer's decode inverts), plus
//! SOURCES (complete-sources count), plus FILETYPE **only when the file
//! classifies**. Media tags are omitted, byte-identical to aMule publishing with
//! unverified metadata.
//!
//! ADR-0062 states the publisher emits FILETYPE "always" (the "always-four").
//! Capture recipe 2 (aMule publishes → rmule stores) **refutes** that:
//! aMule's genuine `0x43` for an unclassifiable file (`rmulekadkeyword.dat`)
//! carries exactly **three** tags — FILENAME, FILESIZE, SOURCES, no FILETYPE
//! (`SharedFileList`'s `GetFileTypeString` returns empty, and aMule appends the
//! tag only for a non-empty type). rmule mirrors aMule: [`KadSharedFile::file_type`]
//! `= None` emits three tags, `= Some` emits four. The ADR-0062 "always four"
//! claim is superseded here — flagged for the ADR text (this module does not edit
//! the ADR).
//!
//! The FILENAME/FILESIZE split is capture-independent (rmule's own storer types
//! them). The SOURCES/FILETYPE tag *bytes* — including SOURCES' integer-width
//! compaction — are now pinned by the same recipe-2 fixture: rmule's emit is
//! asserted byte-for-byte against aMule's captured `0x43`
//! (`tests/captured_keyword_request.rs`).

use std::time::Duration;

use rmule_primitives::{Ed2kText, FileHash, Tag, TagName, TagValue};

use crate::keyword::{keyword_id, publish_keywords};
use crate::keyword_store::KeywordPublishFile;
use crate::lookup::kad_wire_id;
use crate::{KadId, KadInstant};

/// How often a keyword republishes (aMule's `KADEMLIAREPUBLISHTIMEK`, 24 h —
/// distinct from the 5 h source-publish cadence).
pub const KEYWORD_REPUBLISH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Most keyword publish walks in flight at once (aMule's `KADEMLIATOTALSTOREKEY`).
/// The node enforces it (the walk count is node state); restated here so the
/// node reads one canonical constant.
pub const MAX_CONCURRENT_STORE_KEY_WALKS: usize = 2;

/// Minimum spacing between two keyword publish *starts* (aMule spaces store-key
/// launches by 2 s to avoid a burst).
pub const PUBLISH_START_SPACING: Duration = Duration::from_secs(2);

/// Most files one keyword publishes per round before rotating its reference so a
/// later round covers the rest (aMule's per-keyword publish window).
pub const FILES_PER_KEYWORD_PER_ROUND: usize = 150;

/// A keyword whose ack loads average **above** this (strict) is embargoed
/// (aMule's load-backoff trigger).
pub const LOAD_EMBARGO_THRESHOLD: u8 = 20;

/// The embargo base: an average load of 100 embargoes a keyword for the whole
/// 7 days; a lighter average scales down linearly (`7 days × avgLoad / 100`).
const LOAD_EMBARGO_BASE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// `TAG_SOURCES` — the complete-sources count a keyword publish carries. Name
/// byte and integer-width compaction capture-pinned by recipe 2 (aMule's `0x43`
/// carries it as a one-byte `0x09` `name=0x15` tag; see the captured keyword
/// fixtures).
const TAG_SOURCES: u8 = 0x15;
/// `TAG_FILETYPE` — the file's type string (e.g. `"Audio"`), appended only when
/// the file classifies. Documentation-backed name byte: aMule's captured `0x43`
/// was an unclassifiable file, so FILETYPE was absent (the tag rmule omits too).
const TAG_FILETYPE: u8 = 0x03;

/// A complete shared file core registers for keyword publication. The node
/// derives its keywords (`publish_keywords`) and announces it under each.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KadSharedFile {
    /// The eD2k file hash; its Kad wire form is the per-file result-row ID.
    pub file_hash: FileHash,
    /// The complete filename — the keyword-derivation input and the FILENAME tag.
    pub filename: String,
    /// The file size; the FILESIZE tag, `UINT64` past 4 GiB as aMule's and
    /// eMuleAI's keyword publishers write it.
    pub size: u64,
    /// The complete-sources count for the SOURCES tag.
    pub complete_sources: u32,
    /// The aMule file-type string (core derives it from the aMule type table),
    /// or `None` when the file does not classify. `Some` appends the FILETYPE
    /// tag (four tags); `None` omits it (three) — matching aMule, whose captured
    /// `0x43` for an unclassifiable file carries exactly three tags (recipe 2; see the module
    /// docs). Not a divergence: aMule omits it too.
    pub file_type: Option<String>,
}

impl KadSharedFile {
    /// The keyword result row this file publishes: the wire-form file ID, the
    /// FILENAME/FILESIZE typed fields, and the SOURCES/FILETYPE verbatim tags.
    fn result_row(&self) -> KeywordPublishFile {
        // SOURCES rides aMule's integer-tag compaction (`TagValue::compact_uint`,
        // eMule `CTag::WriteTagToFile`): the captured aMule `0x43` carries a
        // zero-source count as a one-byte `0x09` tag, so a fixed `U32` here would
        // diverge from aMule's own emit by three bytes.
        let mut tags = vec![Tag::new(
            TagName::length_prefixed_id(TAG_SOURCES),
            TagValue::compact_uint(self.complete_sources),
        )];
        if let Some(file_type) = &self.file_type {
            tags.push(Tag::new(
                TagName::length_prefixed_id(TAG_FILETYPE),
                TagValue::String(Ed2kText::from_utf8(file_type.clone())),
            ));
        }
        KeywordPublishFile {
            file_id: KadId::from_bytes(kad_wire_id(*self.file_hash.as_bytes())),
            filename: Some(self.filename.clone()),
            size: Some(self.size),
            tags,
        }
    }
}

/// One keyword's due publish: the keyword target and up to
/// [`FILES_PER_KEYWORD_PER_ROUND`] rotated files to announce under it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeywordPublishBatch {
    pub keyword: KadId,
    pub files: Vec<KeywordPublishFile>,
}

/// One keyword's scheduling state.
#[derive(Clone, Debug)]
struct KeywordSchedule {
    keyword: KadId,
    /// The files registered under this keyword, deduped by file ID (a
    /// re-registration refreshes the row in place).
    files: Vec<KeywordPublishFile>,
    /// Earliest next publish (aMule's per-keyword 24 h cadence).
    next_at: KadInstant,
    /// Load-embargo expiry; `<= next_at` when not embargoed.
    embargo_until: KadInstant,
    /// The reference-rotation offset into `files` for the next round.
    rotation: usize,
}

/// The publisher's keyword scheduling state (see the module docs). Pure
/// bookkeeping with explicit time.
#[derive(Clone, Debug, Default)]
pub(crate) struct KeywordPublisher {
    keywords: Vec<KeywordSchedule>,
    /// The last publish-start instant, for the 2 s spacing gate.
    last_start: Option<KadInstant>,
}

impl KeywordPublisher {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Register (or refresh) a complete shared file: derive its keywords and add
    /// its result row to each keyword's bucket, deduped by file ID. A brand-new
    /// keyword becomes due immediately (`next_at = now`). Returns the keyword
    /// targets touched, in derivation order.
    pub(crate) fn register(&mut self, now: KadInstant, file: &KadSharedFile) -> Vec<KadId> {
        let row = file.result_row();
        let keywords: Vec<KadId> = publish_keywords(&file.filename)
            .iter()
            .map(|word| keyword_id(word))
            .collect();
        for keyword in &keywords {
            let schedule = match self.keywords.iter_mut().find(|k| k.keyword == *keyword) {
                Some(schedule) => schedule,
                None => {
                    self.keywords.push(KeywordSchedule {
                        keyword: *keyword,
                        files: Vec::new(),
                        next_at: now,
                        embargo_until: now,
                        rotation: 0,
                    });
                    self.keywords.last_mut().expect("just pushed a schedule")
                }
            };
            match schedule
                .files
                .iter_mut()
                .find(|existing| existing.file_id == row.file_id)
            {
                Some(existing) => *existing = row.clone(),
                None => schedule.files.push(row.clone()),
            }
        }
        keywords
    }

    /// The earliest-due, non-embargoed keyword's next round — or `None` when
    /// nothing is due, or the 2 s spacing since the last start has not elapsed.
    /// A keyword in `held` — its target walked by another walk — is skipped and
    /// stays due, so it starts once the target is free (ADR-0062, walk
    /// ownership). The caller (the node) has already checked the publish gate
    /// and the concurrent-walk cap; this owns only the pacing and rotation.
    pub(crate) fn poll_due(
        &mut self,
        now: KadInstant,
        held: &[KadId],
    ) -> Option<KeywordPublishBatch> {
        if let Some(last) = self.last_start
            && now < last + PUBLISH_START_SPACING
        {
            return None;
        }
        let index = self
            .keywords
            .iter()
            .enumerate()
            .filter(|(_, k)| {
                k.next_at <= now
                    && k.embargo_until <= now
                    && !k.files.is_empty()
                    && !held.contains(&k.keyword)
            })
            // Ties resolve by insertion order — deterministic.
            .min_by_key(|(index, k)| (k.next_at, *index))
            .map(|(index, _)| index)?;

        let schedule = &mut self.keywords[index];
        let files = rotate_take(
            &schedule.files,
            &mut schedule.rotation,
            FILES_PER_KEYWORD_PER_ROUND,
        );
        schedule.next_at = now + KEYWORD_REPUBLISH_INTERVAL;
        let keyword = schedule.keyword;
        self.last_start = Some(now);
        Some(KeywordPublishBatch { keyword, files })
    }

    /// Give a preempted round back: the keyword is due again at `now` and its
    /// rotation steps back over the `taken` files the round carried, so the
    /// next round announces them. The cadence and embargo the round would have
    /// set are not set — it never completed.
    pub(crate) fn requeue(&mut self, now: KadInstant, keyword: KadId, taken: usize) {
        let Some(schedule) = self.keywords.iter_mut().find(|k| k.keyword == keyword) else {
            return;
        };
        schedule.next_at = now;
        let len = schedule.files.len();
        if len > 0 {
            schedule.rotation = (schedule.rotation + len - taken % len) % len;
        }
    }

    /// Fold a completed keyword publish walk's collected `0x4B` loads into the
    /// load embargo: an average above [`LOAD_EMBARGO_THRESHOLD`] embargoes the
    /// keyword for `7 days × avgLoad / 100` from `now`. An empty ack set (nobody
    /// stored) leaves the keyword unembargoed — it simply retries next cycle.
    pub(crate) fn record_completion(&mut self, now: KadInstant, keyword: KadId, loads: &[u8]) {
        let Ok(count) = u32::try_from(loads.len()) else {
            return;
        };
        if count == 0 {
            return;
        }
        let average = loads.iter().map(|&load| u32::from(load)).sum::<u32>() / count;
        if average <= u32::from(LOAD_EMBARGO_THRESHOLD) {
            return;
        }
        if let Some(schedule) = self.keywords.iter_mut().find(|k| k.keyword == keyword) {
            let embargo_secs = LOAD_EMBARGO_BASE.as_secs() * u64::from(average) / 100;
            schedule.embargo_until = now + Duration::from_secs(embargo_secs);
        }
    }

    /// The earliest instant [`poll_due`](Self::poll_due) could return a batch —
    /// each keyword's due time (`max(next_at, embargo_until)`), floored by the
    /// 2 s spacing since the last start. A keyword in `held` has no wake of its
    /// own: the walk holding it re-drives the publisher when it ends. The node
    /// further gates this by the publish gate and the concurrent-walk cap.
    pub(crate) fn next_wake(&self, held: &[KadId]) -> Option<KadInstant> {
        let spacing_floor = self.last_start.map(|last| last + PUBLISH_START_SPACING);
        self.keywords
            .iter()
            .filter(|k| !k.files.is_empty() && !held.contains(&k.keyword))
            .map(|k| {
                let due = k.next_at.max(k.embargo_until);
                match spacing_floor {
                    Some(floor) => due.max(floor),
                    None => due,
                }
            })
            .min()
    }
}

/// Take up to `cap` files starting at `*rotation` (wrapping), and advance the
/// rotation past them. A keyword with `≤ cap` files always returns all of them
/// (the rotation stays put); a larger keyword returns a moving window so
/// successive rounds cover every file.
fn rotate_take(
    files: &[KeywordPublishFile],
    rotation: &mut usize,
    cap: usize,
) -> Vec<KeywordPublishFile> {
    let len = files.len();
    if len == 0 {
        return Vec::new();
    }
    let take = cap.min(len);
    let start = *rotation % len;
    let batch = (0..take)
        .map(|i| files[(start + i) % len].clone())
        .collect();
    *rotation = (start + take) % len;
    batch
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared_file(hash_byte: u8, filename: &str) -> KadSharedFile {
        KadSharedFile {
            file_hash: FileHash::from_bytes([hash_byte; 16]),
            filename: filename.to_owned(),
            size: 4_096,
            complete_sources: 3,
            file_type: Some("Audio".to_owned()),
        }
    }

    #[test]
    fn an_unclassifiable_file_publishes_three_tags_with_a_compacted_sources() {
        // Capture-matched (recipe 2): aMule's `0x43` for an
        // unclassifiable file carries FILENAME + FILESIZE (typed) + SOURCES only —
        // no FILETYPE — and SOURCES rides integer compaction (0 -> one-byte u8).
        let file = KadSharedFile {
            complete_sources: 0,
            file_type: None,
            ..shared_file(0xAA, "rmulekadkeyword.dat")
        };
        let row = file.result_row();
        assert_eq!(
            row.tags,
            vec![Tag::new(
                TagName::length_prefixed_id(TAG_SOURCES),
                TagValue::U8(0),
            )],
            "None classification omits FILETYPE and narrows SOURCES to u8"
        );
    }

    #[test]
    fn a_classifiable_file_appends_the_filetype_tag() {
        // A classifiable file is aMule's "always-four": SOURCES then FILETYPE
        // after the two typed tags.
        let row = shared_file(0xAA, "song.mp3").result_row();
        assert_eq!(
            row.tags,
            vec![
                Tag::new(TagName::length_prefixed_id(TAG_SOURCES), TagValue::U8(3)),
                Tag::new(
                    TagName::length_prefixed_id(TAG_FILETYPE),
                    TagValue::String(Ed2kText::from_utf8("Audio".to_owned())),
                ),
            ],
            "Some classification appends FILETYPE for the four-tag emit"
        );
    }

    #[test]
    fn each_derived_keyword_publishes_once_then_reschedules_a_day_out() {
        // "alpha beta" derives two keywords; each publishes the file once, 2 s
        // apart, then both are a day out.
        let mut publisher = KeywordPublisher::new();
        let file = shared_file(0xAA, "alpha beta.mp3");
        publisher.register(KadInstant::EPOCH, &file);

        let alpha = keyword_id("alpha");
        let beta = keyword_id("beta");
        let row_id = KadId::from_bytes(kad_wire_id(*file.file_hash.as_bytes()));

        let first = publisher
            .poll_due(KadInstant::EPOCH, &[])
            .expect("a keyword is due");
        assert_eq!(
            first.keyword, alpha,
            "earliest-due ties resolve by insertion order"
        );
        assert_eq!(first.files.len(), 1);
        assert_eq!(first.files[0].file_id, row_id);

        // The 2 s spacing gates the second start.
        assert_eq!(
            publisher.poll_due(KadInstant::from_millis(1_999), &[]),
            None
        );
        let second = publisher
            .poll_due(KadInstant::from_millis(2_000), &[])
            .expect("the second keyword is due after the spacing");
        assert_eq!(second.keyword, beta);

        // Both keywords are now a day out.
        assert_eq!(
            publisher.poll_due(KadInstant::from_millis(4_000), &[]),
            None
        );
    }

    #[test]
    fn a_keyword_republishes_a_day_after_its_start() {
        let mut publisher = KeywordPublisher::new();
        publisher.register(KadInstant::EPOCH, &shared_file(0xAA, "solo.mp3"));

        publisher
            .poll_due(KadInstant::EPOCH, &[])
            .expect("due at first");
        let day = KEYWORD_REPUBLISH_INTERVAL.as_millis() as u64;
        assert_eq!(
            publisher.poll_due(KadInstant::from_millis(day - 1), &[]),
            None,
            "not due a millisecond before the 24 h cadence"
        );
        assert!(
            publisher
                .poll_due(KadInstant::from_millis(day), &[])
                .is_some(),
            "due exactly 24 h after the start"
        );
    }

    /// A publisher holding `count` files under the one keyword "common", and
    /// their file IDs in registration order.
    fn common_keyword(count: usize) -> (KeywordPublisher, Vec<KadId>) {
        let mut publisher = KeywordPublisher::new();
        let mut ids = Vec::new();
        for i in 0..count {
            let file = shared_file(u8::try_from(i).unwrap(), "common.mp3");
            // Distinct hashes ⇒ distinct file rows under the one keyword.
            let file = KadSharedFile {
                file_hash: FileHash::from_bytes({
                    let mut bytes = [0u8; 16];
                    bytes[..2].copy_from_slice(&u16::try_from(i).unwrap().to_le_bytes());
                    bytes
                }),
                ..file
            };
            ids.push(KadId::from_bytes(kad_wire_id(*file.file_hash.as_bytes())));
            publisher.register(KadInstant::EPOCH, &file);
        }

        (publisher, ids)
    }

    #[test]
    fn a_keyword_past_the_round_cap_rotates_its_reference_across_rounds() {
        // 160 files share the keyword "common"; a round publishes 150, and the
        // next round's window rotates to cover the 10 the first round missed.
        let (mut publisher, ids) = common_keyword(FILES_PER_KEYWORD_PER_ROUND + 10);

        let round1 = publisher.poll_due(KadInstant::EPOCH, &[]).unwrap();
        assert_eq!(round1.files.len(), FILES_PER_KEYWORD_PER_ROUND);
        let round1_ids: Vec<KadId> = round1.files.iter().map(|f| f.file_id).collect();
        assert_eq!(round1_ids, ids[..FILES_PER_KEYWORD_PER_ROUND]);

        // Next round (a day later): the window rotates, so its first 10 files
        // are exactly the ones round one did not reach.
        let day = KEYWORD_REPUBLISH_INTERVAL.as_millis() as u64;
        let round2 = publisher
            .poll_due(KadInstant::from_millis(day), &[])
            .unwrap();
        assert_eq!(round2.files.len(), FILES_PER_KEYWORD_PER_ROUND);
        let round2_head: Vec<KadId> = round2.files[..10].iter().map(|f| f.file_id).collect();
        assert_eq!(round2_head, ids[FILES_PER_KEYWORD_PER_ROUND..]);
    }

    /// A preempted round is due again at once and announces the same files: the
    /// rotation steps back over what it carried; a held keyword is skipped
    /// until it is free.
    #[test]
    fn a_requeued_round_is_due_now_with_the_files_it_carried() {
        let (mut publisher, ids) = common_keyword(FILES_PER_KEYWORD_PER_ROUND + 10);
        let round = publisher.poll_due(KadInstant::EPOCH, &[]).unwrap();
        let later = KadInstant::from_millis(5_000);
        publisher.requeue(later, round.keyword, round.files.len());

        assert_eq!(publisher.poll_due(later, &[round.keyword]), None);
        assert_eq!(publisher.next_wake(&[round.keyword]), None);
        assert_eq!(publisher.next_wake(&[]), Some(later));
        let again = publisher.poll_due(later, &[]).unwrap();
        let again_ids: Vec<KadId> = again.files.iter().map(|f| f.file_id).collect();
        assert_eq!(again_ids, ids[..FILES_PER_KEYWORD_PER_ROUND]);
    }

    #[test]
    fn a_high_average_load_embargoes_the_keyword_seven_days_scaled() {
        let mut publisher = KeywordPublisher::new();
        publisher.register(KadInstant::EPOCH, &shared_file(0xAA, "hot.mp3"));
        let keyword = keyword_id("hot");
        publisher.poll_due(KadInstant::EPOCH, &[]).unwrap();

        // avg 50 ⇒ embargo 7 days × 50/100 = 3.5 days from completion — later than
        // the 24 h republish, so the keyword is silent until the embargo lifts.
        publisher.record_completion(KadInstant::EPOCH, keyword, &[40, 60]);
        let day = KEYWORD_REPUBLISH_INTERVAL.as_millis() as u64;
        assert_eq!(
            publisher.poll_due(KadInstant::from_millis(day), &[]),
            None,
            "the 24 h republish is suppressed while the embargo holds"
        );
        let embargo_secs = 7 * 24 * 60 * 60 * 50 / 100;
        assert_eq!(
            publisher.poll_due(KadInstant::from_millis(embargo_secs * 1_000 - 1), &[]),
            None
        );
        assert!(
            publisher
                .poll_due(KadInstant::from_millis(embargo_secs * 1_000), &[])
                .is_some(),
            "publishing resumes exactly when the embargo lifts"
        );
    }

    #[test]
    fn an_average_load_at_or_below_the_threshold_does_not_embargo() {
        let mut publisher = KeywordPublisher::new();
        publisher.register(KadInstant::EPOCH, &shared_file(0xAA, "cool.mp3"));
        let keyword = keyword_id("cool");
        publisher.poll_due(KadInstant::EPOCH, &[]).unwrap();

        // avg 20 is exactly the threshold (strict `>`), so no embargo: the plain
        // 24 h republish stands.
        publisher.record_completion(KadInstant::EPOCH, keyword, &[10, 30]);
        let day = KEYWORD_REPUBLISH_INTERVAL.as_millis() as u64;
        assert!(
            publisher
                .poll_due(KadInstant::from_millis(day), &[])
                .is_some()
        );
    }
}
