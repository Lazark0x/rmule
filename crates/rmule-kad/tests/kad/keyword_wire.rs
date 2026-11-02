//! The `0x43`/`0x33`/`0x3B` keyword codecs: what a publish batch and a search
//! request decode to, the caps a malformed one hits, and the round trips
//! between rmule's encoder and its own decoder.

use rmule_kad::KadEnvelope;
use rmule_kad::keyword_store::{
    KEYWORD_PUBLISH_BATCH_CAP, KEYWORD_RESULT_ROWS_PER_DATAGRAM, KeywordDecodeError,
    KeywordPublishFile, KeywordResultRow, UnknownSearchOperator, decode_publish_key_req,
    decode_search_key_req, decode_search_key_res, encode_publish_key_req, encode_search_key_req,
    encode_search_key_res,
};
use rmule_kad::search_tree::{BoolOp, SearchTree};
use rmule_primitives::TagValue;
use rmule_testkit::kad_keyword::{
    file_id, keyword, name_tag, own_id, publish_envelope, publish_file, size_tag, verbatim_tag,
};

#[test]
fn decode_publish_key_req_reads_a_multi_file_batch() {
    let file_one = {
        let tags = vec![name_tag("one.file"), size_tag(10)];
        let mut row = Vec::new();
        row.extend_from_slice(file_id(1).as_bytes());
        row.push(u8::try_from(tags.len()).unwrap());
        for tag in &tags {
            row.extend_from_slice(&tag.encode());
        }
        row
    };
    let file_two = {
        let tags = vec![name_tag("two.file"), size_tag(20)];
        let mut row = Vec::new();
        row.extend_from_slice(file_id(2).as_bytes());
        row.push(u8::try_from(tags.len()).unwrap());
        for tag in &tags {
            row.extend_from_slice(&tag.encode());
        }
        row
    };
    let mut rows = Vec::new();
    rows.extend(file_one);
    rows.extend(file_two);

    let (decoded_keyword, files) =
        decode_publish_key_req(&publish_envelope(keyword(), rows, 2)).unwrap();

    assert_eq!(decoded_keyword, keyword());
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].file_id, file_id(1));
    assert_eq!(files[0].filename.as_deref(), Some("one.file"));
    assert_eq!(files[0].size, Some(10));
    assert_eq!(files[1].file_id, file_id(2));
}

#[test]
fn decode_publish_key_req_rejects_a_batch_declaring_more_than_the_cap() {
    let declared = u16::try_from(KEYWORD_PUBLISH_BATCH_CAP + 1).unwrap();
    let envelope = publish_envelope(keyword(), Vec::new(), declared);

    assert_eq!(
        decode_publish_key_req(&envelope),
        Err(KeywordDecodeError::TooManyFiles { declared })
    );
}

#[test]
fn decode_search_key_req_separates_the_restrictive_flag_from_the_offset() {
    let mut plain_payload = Vec::new();
    plain_payload.extend_from_slice(keyword().as_bytes());
    plain_payload.extend_from_slice(&0u16.to_le_bytes());
    let (kw, offset, tree) =
        decode_search_key_req(&KadEnvelope::plain(0x33, plain_payload)).unwrap();
    assert_eq!(kw, keyword());
    assert_eq!(offset, 0);
    assert!(tree.is_none());

    let tree_bytes = SearchTree::Term("hello".to_owned()).encode();
    let mut restrictive_payload = Vec::new();
    restrictive_payload.extend_from_slice(keyword().as_bytes());
    restrictive_payload.extend_from_slice(&(0x8000u16 | 5u16).to_le_bytes());
    restrictive_payload.extend_from_slice(&tree_bytes);
    let (kw, offset, tree) =
        decode_search_key_req(&KadEnvelope::plain(0x33, restrictive_payload)).unwrap();
    assert_eq!(kw, keyword());
    assert_eq!(offset, 5);
    assert_eq!(tree, Some(SearchTree::Term("hello".to_owned())));
}

#[test]
fn decode_search_key_req_rejects_a_tree_with_an_unknown_numeric_operator() {
    let tree_bytes = SearchTree::U32Relation {
        value: 1,
        op: 0x09,
        tag: vec![0x02],
    }
    .encode();
    let mut payload = Vec::new();
    payload.extend_from_slice(keyword().as_bytes());
    payload.extend_from_slice(&0x8000u16.to_le_bytes());
    payload.extend_from_slice(&tree_bytes);

    assert_eq!(
        decode_search_key_req(&KadEnvelope::plain(0x33, payload)),
        Err(KeywordDecodeError::InvalidSearchExpression(
            UnknownSearchOperator(0x09)
        ))
    );
}

// ---------------------------------------------------------------------------
// Publisher/requester codec mirrors (ADR-0062 breakdown 3): the emit half of
// the symmetric keyword codec round-trips through the storer's decode half.
// ---------------------------------------------------------------------------

#[test]
fn encode_publish_key_req_round_trips_through_the_storer_decode() {
    // The publisher's 0x43 is exactly what the storer accepts: FILENAME and
    // FILESIZE synthesized from the typed fields, then the verbatim rest.
    let files = vec![
        publish_file(
            0xC1,
            "track one.mp3",
            4_096,
            vec![verbatim_tag(0x15, TagValue::U32(3))],
        ),
        publish_file(0xC2, "track two.mp3", 8_192, vec![]),
    ];
    let envelope = encode_publish_key_req(keyword(), &files);
    assert_eq!(envelope.opcode(), 0x43);

    let (decoded_keyword, decoded_files) =
        decode_publish_key_req(&envelope).expect("the publisher's emit decodes at the storer");
    assert_eq!(decoded_keyword, keyword());
    assert_eq!(
        decoded_files, files,
        "the batch survives the emit->accept round-trip"
    );
}

#[test]
fn encode_publish_key_req_panics_past_the_emit_batch_cap() {
    let too_many: Vec<KeywordPublishFile> = (0..=KEYWORD_PUBLISH_BATCH_CAP)
        .map(|i| publish_file(u8::try_from(i % 250).unwrap(), "f.dat", 1, vec![]))
        .collect();
    let result = std::panic::catch_unwind(|| encode_publish_key_req(keyword(), &too_many));
    assert!(
        result.is_err(),
        "a batch past the 50-file cap is refused, not emitted"
    );
}

#[test]
fn encode_search_key_req_non_restrictive_round_trips_as_plain_keyword() {
    // The v1 requester's unfiltered emit: plain keyword, offset 0, no tree.
    let envelope = encode_search_key_req(keyword(), 0, None);
    assert_eq!(envelope.opcode(), 0x33);
    let (kw, offset, tree) = decode_search_key_req(&envelope).expect("plain search decodes");
    assert_eq!(kw, keyword());
    assert_eq!(offset, 0);
    assert_eq!(tree, None, "the plain path sets no restrictive tree");
}

#[test]
fn encode_search_key_req_restrictive_round_trips_the_tree_and_offset() {
    // The dormant filtered-search seam: a restrictive tree + non-zero offset
    // survives the emit->accept round-trip with the top bit split off cleanly.
    let tree = SearchTree::Bool {
        op: BoolOp::And,
        left: Box::new(SearchTree::Term("alpha".to_owned())),
        right: Box::new(SearchTree::Term("beta".to_owned())),
    };
    let envelope = encode_search_key_req(keyword(), 7, Some(&tree));
    let (kw, offset, decoded_tree) = decode_search_key_req(&envelope).expect("restrictive decodes");
    assert_eq!(kw, keyword());
    assert_eq!(offset, 7);
    assert_eq!(decoded_tree, Some(tree));
}

#[test]
fn decode_search_key_res_reads_back_the_storer_serve_with_every_tag() {
    // The requester decodes exactly the dual-form rows the storer serves —
    // FILENAME/FILESIZE synthesized plus the verbatim rest plus TAG_PUBLISHINFO.
    let rows = vec![
        KeywordResultRow {
            file_id: file_id(0xD1),
            tags: vec![
                name_tag("song.mp3"),
                size_tag(1_024),
                verbatim_tag(0x33, TagValue::U32(0x0102_0304)),
            ],
            aich_roots: Vec::new(),
        },
        KeywordResultRow {
            file_id: file_id(0xD2),
            tags: vec![name_tag("other.mp3"), size_tag(2_048)],
            aich_roots: Vec::new(),
        },
    ];
    let envelopes = encode_search_key_res(own_id(), keyword(), &rows);
    assert_eq!(envelopes.len(), 1);

    let decoded = decode_search_key_res(&envelopes[0]).expect("the storer's 0x3B decodes");
    assert_eq!(
        decoded, rows,
        "every file ID and tag survives serve->decode"
    );
}

#[test]
fn decode_search_key_res_rejects_a_non_search_res_opcode() {
    let envelope = KadEnvelope::plain(0x43, vec![0u8; 34]);
    assert_eq!(
        decode_search_key_res(&envelope),
        Err(KeywordDecodeError::NotASearchKeyRes { opcode: 0x43 })
    );
}

#[test]
fn decode_search_key_res_batches_across_multiple_datagrams() {
    // A serve larger than one datagram (>50 rows) decodes per-envelope; the
    // requester concatenates them into the one result stream.
    let rows: Vec<KeywordResultRow> = (0..(KEYWORD_RESULT_ROWS_PER_DATAGRAM + 10))
        .map(|i| KeywordResultRow {
            file_id: file_id(u8::try_from(i).unwrap()),
            tags: vec![name_tag("f.mp3"), size_tag(1)],
            aich_roots: Vec::new(),
        })
        .collect();
    let envelopes = encode_search_key_res(own_id(), keyword(), &rows);
    assert_eq!(envelopes.len(), 2, "50 rows per datagram");
    let mut decoded = Vec::new();
    for envelope in &envelopes {
        decoded.extend(decode_search_key_res(envelope).expect("each batch decodes"));
    }
    assert_eq!(decoded, rows);
}
