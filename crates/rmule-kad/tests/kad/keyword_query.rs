//! Matching a search expression against an indexed entry: substring matching
//! on the common filename, boolean combinations, meta terms, the numeric
//! relations and the unknown-operator rejection.

use rmule_kad::KadInstant;
use rmule_kad::keyword_store::{KeywordStore, UnknownSearchOperator};
use rmule_kad::search_tree::{BoolOp, SearchTree};
use rmule_primitives::{Ed2kText, TagValue};
use rmule_testkit::kad_keyword::{keyword, lan_ip, publish, publish_file, verbatim_tag};

#[test]
fn string_term_matches_a_substring_of_the_common_filename_case_insensitively() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;
    publish(
        &mut store,
        now,
        lan_ip(1),
        vec![publish_file(1, "The.Matrix.1999.mkv", 10, vec![])],
    );

    let hit = SearchTree::Term("MATRIX".to_owned());
    let miss = SearchTree::Term("inception".to_owned());

    assert_eq!(
        store.lookup(now, keyword(), 0, Some(&hit)).unwrap().len(),
        1
    );
    assert!(
        store
            .lookup(now, keyword(), 0, Some(&miss))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn boolean_and_or_not_combine_string_terms() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;
    publish(
        &mut store,
        now,
        lan_ip(1),
        vec![publish_file(1, "the.matrix.mkv", 10, vec![])],
    );

    let matrix = || SearchTree::Term("matrix".to_owned());
    let inception = || SearchTree::Term("inception".to_owned());

    let and_tree = SearchTree::Bool {
        op: BoolOp::And,
        left: Box::new(matrix()),
        right: Box::new(inception()),
    };
    assert!(
        store
            .lookup(now, keyword(), 0, Some(&and_tree))
            .unwrap()
            .is_empty()
    );

    let or_tree = SearchTree::Bool {
        op: BoolOp::Or,
        left: Box::new(matrix()),
        right: Box::new(inception()),
    };
    assert_eq!(
        store
            .lookup(now, keyword(), 0, Some(&or_tree))
            .unwrap()
            .len(),
        1
    );

    // aMule's NOT is binary: `left && !right`.
    let not_tree = SearchTree::Bool {
        op: BoolOp::Not,
        left: Box::new(matrix()),
        right: Box::new(inception()),
    };
    assert_eq!(
        store
            .lookup(now, keyword(), 0, Some(&not_tree))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn meta_term_matches_a_verbatim_string_tag_case_insensitively() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;
    let filetype = verbatim_tag(0x03, TagValue::String(Ed2kText::from_utf8("Video")));
    publish(
        &mut store,
        now,
        lan_ip(1),
        vec![publish_file(1, "movie.mkv", 10, vec![filetype])],
    );

    let hit = SearchTree::MetaTerm {
        value: "video".to_owned(),
        tag: vec![0x03],
    };
    let miss = SearchTree::MetaTerm {
        value: "audio".to_owned(),
        tag: vec![0x03],
    };

    assert_eq!(
        store.lookup(now, keyword(), 0, Some(&hit)).unwrap().len(),
        1
    );
    assert!(
        store
            .lookup(now, keyword(), 0, Some(&miss))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn meta_term_file_format_derives_from_the_filename_extension() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;
    publish(
        &mut store,
        now,
        lan_ip(1),
        vec![publish_file(1, "movie.MKV", 10, vec![])],
    );

    let hit = SearchTree::MetaTerm {
        value: "mkv".to_owned(),
        tag: vec![0x04], // TAG_FILEFORMAT
    };
    assert_eq!(
        store.lookup(now, keyword(), 0, Some(&hit)).unwrap().len(),
        1
    );
}

#[test]
fn numeric_relation_matches_filesize_via_the_virtual_fallback() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;
    publish(
        &mut store,
        now,
        lan_ip(1),
        vec![publish_file(1, "movie.mkv", 1_000_000, vec![])],
    );

    // mmop 0x03 = ">=" per `CreateSearchExpressionTree`'s `_aOps` table.
    let ge = SearchTree::U32Relation {
        value: 999_999,
        op: 0x03,
        tag: vec![0x02], // TAG_FILESIZE
    };
    let too_big = SearchTree::U32Relation {
        value: 2_000_000,
        op: 0x03,
        tag: vec![0x02],
    };

    assert_eq!(store.lookup(now, keyword(), 0, Some(&ge)).unwrap().len(), 1);
    assert!(
        store
            .lookup(now, keyword(), 0, Some(&too_big))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn numeric_relation_matches_a_generic_verbatim_numeric_tag() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;
    let sources = verbatim_tag(0x15, TagValue::U32(7)); // TAG_SOURCES
    publish(
        &mut store,
        now,
        lan_ip(1),
        vec![publish_file(1, "movie.mkv", 10, vec![sources])],
    );

    // mmop 0x00 = "=".
    let eq = SearchTree::U32Relation {
        value: 7,
        op: 0x00,
        tag: vec![0x15],
    };
    let ne_value = SearchTree::U32Relation {
        value: 8,
        op: 0x00,
        tag: vec![0x15],
    };

    assert_eq!(store.lookup(now, keyword(), 0, Some(&eq)).unwrap().len(), 1);
    assert!(
        store
            .lookup(now, keyword(), 0, Some(&ne_value))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn every_documented_numeric_operator_byte_maps_to_its_relation() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;
    publish(
        &mut store,
        now,
        lan_ip(1),
        vec![publish_file(1, "movie.mkv", 100, vec![])],
    );

    let cases: [(u8, u32, bool); 6] = [
        (0x00, 100, true), // =
        (0x01, 50, true),  // >
        (0x02, 200, true), // <
        (0x03, 100, true), // >=
        (0x04, 100, true), // <=
        (0x05, 50, true),  // <>
    ];
    for (op, value, expect_match) in cases {
        let tree = SearchTree::U32Relation {
            value,
            op,
            tag: vec![0x02],
        };
        let matched = !store
            .lookup(now, keyword(), 0, Some(&tree))
            .unwrap()
            .is_empty();
        assert_eq!(matched, expect_match, "operator byte {op:#x}");
    }
}

#[test]
fn an_unknown_numeric_operator_byte_rejects_the_whole_search() {
    let store = KeywordStore::new();
    let now = KadInstant::EPOCH;

    let tree = SearchTree::U32Relation {
        value: 1,
        op: 0x06, // one past the documented 0x00..=0x05 range
        tag: vec![0x02],
    };

    assert_eq!(
        store.lookup(now, keyword(), 0, Some(&tree)),
        Err(UnknownSearchOperator(0x06))
    );
}

// ---------------------------------------------------------------------------
// Wire codec
// ---------------------------------------------------------------------------
