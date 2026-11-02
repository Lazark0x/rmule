//! What a publisher can make the store hold: a stranger writes the bytes, so the
//! index is bounded in bytes as well as rows, and a republish under a new name
//! buys nothing past the names a row keeps.

use rmule_kad::KadInstant;
use rmule_kad::keyword_store::{
    KEYWORD_BYTE_BUDGET, KEYWORD_ENTRY_LIFETIME, KEYWORD_NAME_CAP, KEYWORD_NAMES_PER_ENTRY,
    KEYWORD_SWEEP_INTERVAL, KeywordFileOutcome, KeywordPublishOutcome, KeywordStore,
};
use rmule_primitives::{Ed2kText, Tag, TagName, TagValue};
use rmule_testkit::kad_keyword::{
    decode_publish_file_with_id, file_id, lan_ip, publish, publish_file,
};

fn stored(outcome: &KeywordPublishOutcome) -> bool {
    matches!(
        outcome,
        KeywordPublishOutcome::Processed { files, .. }
            if matches!(files[0], KeywordFileOutcome::Stored { .. })
    )
}

#[test]
fn a_filename_is_cut_at_its_cap_on_a_character() {
    let mut store = KeywordStore::new();
    let name = "\u{e9}".repeat(KEYWORD_NAME_CAP);

    let outcome = publish(
        &mut store,
        KadInstant::EPOCH,
        lan_ip(1),
        vec![publish_file(1, &name, 1000, vec![])],
    );

    assert!(stored(&outcome));
    assert_eq!(store.held_bytes(), KEYWORD_NAME_CAP);
}

#[test]
fn a_republish_under_a_new_name_past_the_cap_holds_nothing_more() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;
    let republish = |store: &mut KeywordStore, n: usize| {
        publish(
            store,
            now,
            lan_ip(1),
            vec![publish_file(1, &format!("name-{n:04}"), 1000, vec![])],
        )
    };
    for n in 0..KEYWORD_NAMES_PER_ENTRY {
        assert!(stored(&republish(&mut store, n)));
    }
    let full = store.held_bytes();

    assert!(
        stored(&republish(&mut store, KEYWORD_NAMES_PER_ENTRY)),
        "the row renews"
    );

    assert_eq!(store.held_bytes(), full);
}

/// Past the budget a publish is refused as a full index, and the sweep gives
/// the bytes back. The rows here are wider than a datagram's, so the budget
/// fills in a few publishes.
#[test]
fn the_index_refuses_past_its_byte_budget_and_the_sweep_returns_the_bytes() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;
    let wide = |id: u8| {
        let mut file = decode_publish_file_with_id(file_id(id), "wide.file", 10);
        file.tags = (0..252)
            .map(|at: usize| {
                Tag::new(
                    TagName::length_prefixed_id(0xF0),
                    TagValue::String(Ed2kText::from_utf8(format!("{at:0>65000}"))),
                )
            })
            .collect();
        file
    };

    let mut id = 0;
    while store.held_bytes() < KEYWORD_BYTE_BUDGET {
        id += 1;
        assert!(stored(&publish(&mut store, now, lan_ip(1), vec![wide(id)])));
    }

    let refused = publish(&mut store, now, lan_ip(1), vec![wide(id + 1)]);

    assert_eq!(
        refused,
        KeywordPublishOutcome::Processed {
            ack_load: 100,
            files: vec![KeywordFileOutcome::RejectedTotalIndexFull],
        }
    );

    store.tick(now + KEYWORD_ENTRY_LIFETIME + KEYWORD_SWEEP_INTERVAL);
    assert_eq!(store.held_bytes(), 0);
}
