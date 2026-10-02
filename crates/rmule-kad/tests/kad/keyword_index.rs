//! The bounded keyword index: the load a publish reports, the global,
//! per-keyword and duplicate-refresh caps, the publisher and filename tallies
//! a republish grows, and the sweep that expires entries at their lifetime.
//!
//! Sixteen lines over the 500-line soft target by choice: the caps interact —
//! a per-keyword rejection moves the global tally the next case reads — so
//! splitting them apart would separate a cap from the state it moves.

use rmule_kad::keyword_store::{
    KEYWORD_DUPLICATE_GUARD_THRESHOLD, KEYWORD_ENTRY_LIFETIME, KEYWORD_GLOBAL_CAP,
    KEYWORD_PER_KEYWORD_CAP, KEYWORD_SWEEP_INTERVAL, KeywordFileOutcome, KeywordPublishOutcome,
    KeywordStore,
};
use rmule_kad::{KadId, KadInstant};
use rmule_primitives::TagValue;
use rmule_testkit::kad_keyword::{
    decode_publish_file_from_tags, decode_publish_file_with_id, far_own_id, file_id, keyword,
    lan_ip, own_id, publish, publish_file, wan_ip,
};

#[test]
fn first_file_for_a_brand_new_keyword_reports_load_one() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;

    let outcome = publish(
        &mut store,
        now,
        lan_ip(1),
        vec![publish_file(1, "some.file", 1000, vec![])],
    );

    assert_eq!(
        outcome,
        KeywordPublishOutcome::Processed {
            ack_load: 1,
            files: vec![KeywordFileOutcome::Stored { load: 1 }],
        }
    );
}

#[test]
fn mid_fill_load_follows_the_documented_percentage_curve() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;

    // Seed KEYWORD_PER_KEYWORD_CAP / 2 distinct files under the keyword, then
    // publish one more: aMule's load is the pre-insert count as a percentage
    // of the per-keyword cap (`indexTotal * 100 / KADEMLIAMAXINDEX`).
    let half = KEYWORD_PER_KEYWORD_CAP / 2;
    for i in 0..half {
        let bytes = (i as u32).to_le_bytes();
        let mut id = [0u8; 16];
        id[..4].copy_from_slice(&bytes);
        let outcome = publish(
            &mut store,
            now,
            lan_ip(1),
            vec![decode_publish_file_with_id(
                KadId::from_bytes(id),
                "seed.file",
                10,
            )],
        );
        assert!(matches!(
            outcome,
            KeywordPublishOutcome::Processed {
                files,
                ..
            } if matches!(files[0], KeywordFileOutcome::Stored { .. })
        ));
    }

    let mut fresh_id = [0u8; 16];
    fresh_id[..4].copy_from_slice(&(half as u32).to_le_bytes());
    let outcome = publish(
        &mut store,
        now,
        lan_ip(1),
        vec![decode_publish_file_with_id(
            KadId::from_bytes(fresh_id),
            "fresh.file",
            10,
        )],
    );

    let expected_load = u8::try_from(half * 100 / KEYWORD_PER_KEYWORD_CAP).unwrap();
    assert_eq!(
        outcome,
        KeywordPublishOutcome::Processed {
            ack_load: expected_load,
            files: vec![KeywordFileOutcome::Stored {
                load: expected_load
            }],
        }
    );
}

#[test]
fn per_keyword_cap_rejects_a_net_new_file_and_forces_load_100() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;

    // aMule's own cap check (`indexTotal > KADEMLIAMAXINDEX`, snapshotted
    // *before* the insert) holds one row past the nominal cap before it
    // rejects — the same off-by-one shape `source_store.rs` documents for
    // its own per-key cap, just checked with a strict `>` here instead of
    // eviction. So the (CAP + 1)-th distinct file (index `CAP`, 0-based)
    // still lands (with `load = 100`); only the (CAP + 2)-th is rejected.
    for i in 0..=(KEYWORD_PER_KEYWORD_CAP + 1) {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let outcome = publish(
            &mut store,
            now,
            lan_ip(1),
            vec![decode_publish_file_with_id(
                KadId::from_bytes(id),
                "seed.file",
                10,
            )],
        );
        if i <= KEYWORD_PER_KEYWORD_CAP {
            assert!(
                matches!(
                    &outcome,
                    KeywordPublishOutcome::Processed { files, .. }
                        if matches!(files[0], KeywordFileOutcome::Stored { .. })
                ),
                "entry {i} should still be indexed at or under the effective cap"
            );
        } else {
            assert_eq!(
                outcome,
                KeywordPublishOutcome::Processed {
                    ack_load: 100,
                    files: vec![KeywordFileOutcome::RejectedKeywordIndexFull],
                }
            );
        }
    }
}

#[test]
fn hot_keyword_throttles_refreshes_past_the_duplicate_guard_but_still_takes_new_files() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;

    // Fill one row past the duplicate-guard threshold: aMule's own check is
    // `indexTotal > KADEMLIAMAXINDEX - 5000`, so the guard needs the
    // pre-insert count to *exceed* the threshold, not merely reach it.
    for i in 0..=KEYWORD_DUPLICATE_GUARD_THRESHOLD {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&(i as u64).to_le_bytes());
        publish(
            &mut store,
            now,
            lan_ip(1),
            vec![decode_publish_file_with_id(
                KadId::from_bytes(id),
                "seed.file",
                10,
            )],
        );
    }

    // A refresh of the very first indexed file is throttled: the guard
    // exists so an already-full keyword can't have its remaining headroom
    // monopolized by re-publishes of files it already has.
    let mut first_id = [0u8; 16];
    first_id[..8].copy_from_slice(&0u64.to_le_bytes());
    let refresh_outcome = publish(
        &mut store,
        now,
        lan_ip(2),
        vec![decode_publish_file_with_id(
            KadId::from_bytes(first_id),
            "seed.file",
            10,
        )],
    );
    assert_eq!(
        refresh_outcome,
        KeywordPublishOutcome::Processed {
            ack_load: 100,
            files: vec![KeywordFileOutcome::RejectedRefreshThrottled],
        }
    );

    // A brand-new file (not yet indexed) is still accepted in the same
    // 45k..50k zone: only refreshes are throttled, not net-new growth.
    let mut new_id = [0u8; 16];
    new_id[..8].copy_from_slice(
        (KEYWORD_DUPLICATE_GUARD_THRESHOLD as u64 + 1)
            .to_le_bytes()
            .as_slice(),
    );
    let new_outcome = publish(
        &mut store,
        now,
        lan_ip(3),
        vec![decode_publish_file_with_id(
            KadId::from_bytes(new_id),
            "new.file",
            10,
        )],
    );
    assert!(matches!(
        new_outcome,
        KeywordPublishOutcome::Processed { files, .. }
            if matches!(files[0], KeywordFileOutcome::Stored { .. })
    ));
}

#[test]
fn global_cap_rejects_a_net_new_row_regardless_of_keyword() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;

    // One row per distinct keyword. Every call takes the brand-new-keyword
    // fast path (`load = 1` unconditionally) until the *global* cap check —
    // which runs before that path, unconditionally, on every call — fires.
    // aMule's own check (`m_totalIndexKeyword > KADEMLIAMAXENTRIES`,
    // snapshotted before the insert) holds one row past the nominal cap
    // before it rejects, the same off-by-one shape as the per-keyword cap.
    for i in 0..=(KEYWORD_GLOBAL_CAP + 1) {
        let mut kw = [0u8; 16];
        kw[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let outcome = store.publish_batch(
            now,
            own_id(),
            false,
            lan_ip(1),
            KadId::from_bytes(kw),
            vec![decode_publish_file_with_id(file_id(1), "f.file", 10)],
        );
        if i <= KEYWORD_GLOBAL_CAP {
            assert_eq!(
                outcome,
                KeywordPublishOutcome::Processed {
                    ack_load: 1,
                    files: vec![KeywordFileOutcome::Stored { load: 1 }],
                },
                "row {i} should still be indexed at or under the effective cap"
            );
        } else {
            assert_eq!(
                outcome,
                KeywordPublishOutcome::Processed {
                    ack_load: 100,
                    files: vec![KeywordFileOutcome::RejectedTotalIndexFull],
                }
            );
        }
    }
}

#[test]
fn missing_filename_or_size_is_rejected_without_touching_the_shared_ack_load() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;

    // No FILENAME, no FILESIZE tag at all in this file's row.
    let no_name_no_size = decode_publish_file_from_tags(1, vec![]);
    let outcome = publish(&mut store, now, lan_ip(1), vec![no_name_no_size]);
    assert_eq!(
        outcome,
        KeywordPublishOutcome::Processed {
            ack_load: 0,
            files: vec![KeywordFileOutcome::RejectedInvalidEntry],
        },
        "an invalid entry leaves the shared ack load at its initial 0, unlike the cap rejects"
    );
}

// ---------------------------------------------------------------------------
// Firewalled refusal + distance/tolerance gate
// ---------------------------------------------------------------------------

#[test]
fn firewalled_storer_silently_drops_the_whole_batch() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;

    let outcome = store.publish_batch(
        now,
        own_id(),
        true, // own_udp_firewalled
        lan_ip(1),
        keyword(),
        vec![publish_file(1, "some.file", 10, vec![])],
    );

    assert_eq!(outcome, KeywordPublishOutcome::Dropped);
    assert!(
        store
            .lookup(now, keyword(), 0, None)
            .expect("no tree")
            .is_empty(),
        "a dropped batch indexes nothing"
    );
}

#[test]
fn wan_publish_outside_tolerance_is_dropped() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;

    let outcome = store.publish_batch(
        now,
        far_own_id(),
        false,
        wan_ip(1),
        keyword(),
        vec![publish_file(1, "some.file", 10, vec![])],
    );

    assert_eq!(outcome, KeywordPublishOutcome::Dropped);
}

#[test]
fn lan_publish_bypasses_the_tolerance_gate() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;

    let outcome = store.publish_batch(
        now,
        far_own_id(),
        false,
        lan_ip(1),
        keyword(),
        vec![publish_file(1, "some.file", 10, vec![])],
    );

    assert!(matches!(
        outcome,
        KeywordPublishOutcome::Processed { files, .. }
            if matches!(files[0], KeywordFileOutcome::Stored { load: 1 })
    ));
}

// ---------------------------------------------------------------------------
// Aggregation: names, publishers, trust, TAG_PUBLISHINFO
// ---------------------------------------------------------------------------

#[test]
fn republish_from_a_new_ip_grows_publisher_count_while_the_subnet_touches_only_this_file() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;

    publish(
        &mut store,
        now,
        lan_ip(1),
        vec![publish_file(1, "movie.mkv", 1000, vec![])],
    );
    let solo_rows = store.lookup(now, keyword(), 0, None).unwrap();
    let solo_info = publish_info_of(&solo_rows[0]);
    // One publisher, its own /24 subnet touching nothing else: trust = 10.0/1
    // -> 1000 (*100).
    assert_eq!(solo_info, (1, 1, 1000));

    // A second, DISTINCT publisher on the SAME /24 subnet, still touching
    // only this one file: the subnet's global count rises to 2 (one per
    // tracked publisher this file has), and this file's trust sums 10.0/2
    // over its now-two tracked publishers — back to 10.0. Trust dilutes a
    // subnet's activity *spread across different files* (see the dedicated
    // `trusted_entries_serve_before_untrusted_ones…` test), not headcount on
    // one file alone.
    publish(
        &mut store,
        now,
        lan_ip(2),
        vec![publish_file(1, "movie.mkv", 1000, vec![])],
    );
    let shared_rows = store.lookup(now, keyword(), 0, None).unwrap();
    let shared_info = publish_info_of(&shared_rows[0]);
    assert_eq!(
        shared_info,
        (1, 2, 1000),
        "10.0/2 summed over 2 publishers exclusive to this file is still 10.0 -> 1000"
    );
}

#[test]
fn a_new_filename_for_the_same_file_grows_name_popularity() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;

    publish(
        &mut store,
        now,
        lan_ip(1),
        vec![publish_file(1, "movie.mkv", 1000, vec![])],
    );
    publish(
        &mut store,
        now,
        lan_ip(2),
        vec![publish_file(1, "Movie.mkv", 1000, vec![])], // same name, different case
    );
    publish(
        &mut store,
        now,
        lan_ip(3),
        vec![publish_file(1, "a-different-name.mkv", 1000, vec![])],
    );

    let rows = store.lookup(now, keyword(), 0, None).unwrap();
    let (names, publishers, _trust) = publish_info_of(&rows[0]);
    assert_eq!(
        names, 2,
        "case-insensitive dedupe keeps the two distinct names"
    );
    assert_eq!(publishers, 3);
}

#[test]
fn republishing_from_the_same_ip_refreshes_without_growing_publisher_count() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;

    publish(
        &mut store,
        now,
        lan_ip(1),
        vec![publish_file(1, "movie.mkv", 1000, vec![])],
    );
    publish(
        &mut store,
        now,
        lan_ip(1),
        vec![publish_file(1, "movie.mkv", 1000, vec![])],
    );

    let rows = store.lookup(now, keyword(), 0, None).unwrap();
    let (_, publishers, _) = publish_info_of(&rows[0]);
    assert_eq!(publishers, 1);
}

fn publish_info_of(row: &rmule_kad::keyword_store::KeywordResultRow) -> (u32, u32, u32) {
    let tag = row
        .tags
        .iter()
        .find(|t| t.name().id() == Some(0x33))
        .expect("served rows always carry TAG_PUBLISHINFO");
    let TagValue::U32(value) = tag.value() else {
        panic!("TAG_PUBLISHINFO is a u32 tag")
    };
    let names = value >> 24;
    let publishers = (value >> 16) & 0xFF;
    let trust = value & 0xFFFF;
    (names, publishers, trust)
}

// ---------------------------------------------------------------------------
// Expiry + throttled sweep
// ---------------------------------------------------------------------------

#[test]
fn lookup_hides_expired_entries_even_before_the_next_sweep() {
    // `lookup` filters by expiry itself on every call (mirroring
    // `source_store.rs`'s own documented contract: "lookups also filter by
    // expiry so an entry can never be served between its deadline and the
    // next tick"), independent of whether `tick` has run at all.
    let mut store = KeywordStore::new();
    let start = KadInstant::EPOCH;

    publish(
        &mut store,
        start,
        lan_ip(1),
        vec![publish_file(1, "movie.mkv", 1000, vec![])],
    );
    assert!(!store.lookup(start, keyword(), 0, None).unwrap().is_empty());

    let past_lifetime = start + KEYWORD_ENTRY_LIFETIME + std::time::Duration::from_secs(1);
    assert!(
        store
            .lookup(past_lifetime, keyword(), 0, None)
            .unwrap()
            .is_empty(),
        "expired per the lifetime, hidden without needing a sweep first"
    );
}

#[test]
fn the_expiry_sweep_is_throttled_to_at_most_once_per_interval() {
    // `CIndexed::Clean`'s throttle (`if (m_lastClean > tNow) return;`): a
    // second tick within `KEYWORD_SWEEP_INTERVAL` of the last actual sweep is
    // a no-op, observable via `next_wake` staying put; a tick at or after the
    // interval sweeps again and reschedules.
    let mut store = KeywordStore::new();
    let start = KadInstant::EPOCH;

    store.tick(start); // the very first tick is always due; primes the timer
    let primed_wake = store.next_wake();
    assert_eq!(primed_wake, Some(start + KEYWORD_SWEEP_INTERVAL));

    let still_throttled = start + (KEYWORD_SWEEP_INTERVAL - std::time::Duration::from_secs(1));
    store.tick(still_throttled);
    assert_eq!(
        store.next_wake(),
        primed_wake,
        "a tick inside the throttle window does not reschedule the sweep"
    );

    let interval_elapsed = start + KEYWORD_SWEEP_INTERVAL;
    store.tick(interval_elapsed);
    assert_eq!(
        store.next_wake(),
        Some(interval_elapsed + KEYWORD_SWEEP_INTERVAL),
        "a tick at/after the interval sweeps again and reschedules from itself"
    );
}

// ---------------------------------------------------------------------------
// Serve: FILENAME/FILESIZE synthesis, verbatim passthrough, batching, offset,
// trusted-first ordering
// ---------------------------------------------------------------------------
