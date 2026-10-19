//! Serving a keyword search: the synthesized filename and filesize tags, the
//! trust order rows come back in, the 300-row budget, and the fifty-rows-per
//! -datagram batching.

use std::net::Ipv4Addr;

use rmule_kad::keyword_store::{
    KEYWORD_RESULT_ROWS_PER_DATAGRAM, KeywordStore, encode_search_key_res,
};
use rmule_kad::{KadEnvelope, KadId, KadInstant, KadNode};
use rmule_primitives::{Ed2kText, TagValue};
use rmule_testkit::kad_keyword::{
    decode_publish_file_from_tags, decode_publish_file_with_id, file_id, keyword, lan_ip, name_tag,
    own_id, publish, publish_file, verbatim_tag, wan_ip,
};

#[test]
fn serve_synthesizes_filename_and_filesize_and_preserves_the_rest_verbatim() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;
    let filetype = verbatim_tag(0x03, TagValue::String(Ed2kText::from_utf8("Video")));

    publish(
        &mut store,
        now,
        lan_ip(1),
        vec![publish_file(
            1,
            "movie.mkv",
            123_456,
            vec![filetype.clone()],
        )],
    );

    let rows = store.lookup(now, keyword(), 0, None).unwrap();
    assert_eq!(rows.len(), 1);
    let tags = &rows[0].tags;

    assert_eq!(tags[0].name().id(), Some(0x01));
    assert_eq!(
        tags[0].value(),
        &TagValue::String(Ed2kText::from_utf8("movie.mkv"))
    );
    assert_eq!(tags[1].name().id(), Some(0x02));
    assert_eq!(tags[1].value(), &TagValue::U32(123_456));
    assert!(tags.contains(&filetype), "FILETYPE is re-served untouched");
    assert_eq!(
        tags.last().unwrap().name().id(),
        Some(0x33),
        "TAG_PUBLISHINFO trails the row"
    );

    let projected = rows[0].project(KadNode::KAD_VERSION);
    assert_eq!(
        projected.file_type.as_deref(),
        Some("Video"),
        "the requester's typed projection carries the publisher's \
         classification, not just the verbatim tag"
    );
}

/// A file past 4 GiB keeps its size through the store: aMule's
/// and eMuleAI's keyword publishers write `TAG_FILESIZE` as `UINT64` there
/// (`CTagVarInt`, kno `Search.cpp:1714`; `CKadTagUInt`, eMuleAI
/// `Search.cpp:1650` narrowed by `DataIO.cpp:292-300`), and both searchers
/// drop a keyword row that has no size (kno `Search.cpp:1455-1456`, eMuleAI
/// `Search.cpp:1402-1403`).
#[test]
fn a_file_past_four_gib_is_stored_and_served_with_its_uint64_size() {
    const FIVE_GIB: u64 = 5 * 1024 * 1024 * 1024;
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;

    let file = decode_publish_file_from_tags(
        1,
        vec![
            name_tag("movie.mkv"),
            verbatim_tag(0x02, TagValue::U64(FIVE_GIB)),
        ],
    );
    assert_eq!(
        file.size,
        Some(FIVE_GIB),
        "the publish reader keeps 64 bits"
    );
    publish(&mut store, now, lan_ip(1), vec![file]);

    let rows = store.lookup(now, keyword(), 0, None).unwrap();
    assert_eq!(rows.len(), 1, "the entry is indexed, not refused size-less");
    assert_eq!(rows[0].tags[1].name().id(), Some(0x02));
    assert_eq!(rows[0].tags[1].value(), &TagValue::U64(FIVE_GIB));
    assert_eq!(rows[0].project(KadNode::KAD_VERSION).size, Some(FIVE_GIB));
}

#[test]
fn trusted_entries_serve_before_untrusted_ones_regardless_of_publish_order() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;
    let spammer = Ipv4Addr::new(203, 0, 113, 7);

    // One publisher spreads its `/24` subnet's global publish budget across
    // 20 *other* files before touching "crowded.file": aMule's trust dilutes
    // by how many DIFFERENT entries a subnet's activity has touched, not by
    // publisher headcount on any single entry (`ReCalculateTrustValue`'s own
    // worked example: "if [a subnet] publishes 6 [entries] alone, each entry
    // has 3/6=0.5").
    for i in 0..20u8 {
        let mut id = [0u8; 16];
        id[0] = 0x10;
        id[1] = i;
        publish(
            &mut store,
            now,
            spammer,
            vec![decode_publish_file_with_id(
                KadId::from_bytes(id),
                "spam.file",
                10,
            )],
        );
    }
    publish(
        &mut store,
        now,
        spammer,
        vec![publish_file(1, "crowded.file", 10, vec![])],
    );
    // A lone publisher on an otherwise-untouched subnet keeps the full
    // 10.0/1 trust: `wan_ip(1)`'s subnet has no other activity.
    publish(
        &mut store,
        now,
        wan_ip(1),
        vec![publish_file(2, "trusted.file", 10, vec![])],
    );

    let rows = store.lookup(now, keyword(), 0, None).unwrap();
    assert_eq!(rows.len(), 22);
    assert_eq!(rows[0].file_id, file_id(2), "the trusted file serves first");
}

#[test]
fn offset_skips_rows_and_the_budget_caps_at_300() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;

    for i in 0..10u8 {
        publish(
            &mut store,
            now,
            wan_ip(i),
            vec![publish_file(i, "distinct.file", 10, vec![])],
        );
    }

    let all = store.lookup(now, keyword(), 0, None).unwrap();
    assert_eq!(all.len(), 10);
    let skipped = store.lookup(now, keyword(), 3, None).unwrap();
    assert_eq!(skipped.len(), 7);
    assert_eq!(skipped[0].file_id, all[3].file_id);
}

#[test]
fn encode_batches_fifty_rows_per_datagram() {
    let mut store = KeywordStore::new();
    let now = KadInstant::EPOCH;

    for i in 0..120u16 {
        let mut id = [0u8; 16];
        id[..2].copy_from_slice(&i.to_le_bytes());
        publish(
            &mut store,
            now,
            wan_ip(1),
            vec![decode_publish_file_with_id(
                KadId::from_bytes(id),
                "many.file",
                10,
            )],
        );
    }

    let rows = store.lookup(now, keyword(), 0, None).unwrap();
    assert_eq!(rows.len(), 120);
    let envelopes = encode_search_key_res(own_id(), keyword(), &rows);
    assert_eq!(envelopes.len(), 3, "120 rows batch as 50 + 50 + 20");
    for envelope in &envelopes {
        assert_eq!(envelope.opcode(), 0x3B);
    }
    assert_eq!(
        u16::from_le_bytes(envelope_row_count(&envelopes[0])),
        u16::try_from(KEYWORD_RESULT_ROWS_PER_DATAGRAM).unwrap()
    );
    assert_eq!(u16::from_le_bytes(envelope_row_count(&envelopes[2])), 20);
}

fn envelope_row_count(envelope: &KadEnvelope) -> [u8; 2] {
    // `[16B sender][16B keyword][2B row count LE] ...`
    let payload = envelope.payload();
    [payload[32], payload[33]]
}

#[test]
fn zero_matching_rows_serve_zero_envelopes() {
    let store = KeywordStore::new();
    let now = KadInstant::EPOCH;

    let rows = store.lookup(now, keyword(), 0, None).unwrap();
    assert!(rows.is_empty());
    assert!(encode_search_key_res(own_id(), keyword(), &rows).is_empty());
}

// ---------------------------------------------------------------------------
// Search-expression tree evaluation
// ---------------------------------------------------------------------------
