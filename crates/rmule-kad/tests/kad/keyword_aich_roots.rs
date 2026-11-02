//! The AICH roots a keyword answer carries (ADR-0038): a storer at Kad v9 or
//! later writes `TAG_KADAICHHASHRESULT` beside `TAG_PUBLISHINFO`, and the
//! keyword result keeps each root with its popularity; from an older storer
//! the tag is ignored, as eMule ignores it (`Search.cpp:1127-1146`). The
//! answers are rmule's own encodings of eMule's layout (`Entry.cpp:680-710`);
//! no counterparty bytes with the tag are captured yet.

use rmule_kad::keyword::keyword_id;
use rmule_kad::keyword_store::encode_search_key_res;
use rmule_kad::{
    KadAichRootReport, KadCommand, KadEvent, KadId, KadInstant, KadKeywordResult,
    KadKeywordSearchRequest, KadNode, KadNodeConfig, KadNodeStart, KeywordResultRow,
};
use rmule_primitives::{AichRootHash, Tag, TagName, TagValue, UserHash};
use rmule_testkit::drain_split;
use rmule_testkit::kad_keyword::{file_id, name_tag, size_tag};
use rmule_testkit::kad_node::{hello_req_at_version, lookup_res_bytes};
use rmule_testkit::kad_source::contact_endpoint;

const ROOT: AichRootHash = AichRootHash::from_bytes([0xA1; AichRootHash::BYTE_LEN]);

fn kw() -> KadId {
    keyword_id("keyword")
}

/// A contact ID inside the keyword's search tolerance.
fn near_keyword() -> KadId {
    let mut bytes = *kw().as_bytes();
    bytes[12] ^= 10;
    KadId::from_bytes(bytes)
}

/// A node whose keyword search fanned its `0x33` to one storer at Kad
/// `version`, and the storer's answer to it: one row whose 20 publishers
/// reported [`ROOT`] 12 times.
fn answered_by_a_storer_at(version: u8) -> Vec<KadKeywordResult> {
    let now = KadInstant::EPOCH;
    let mut node = KadNode::new(KadNodeStart::new(
        KadNodeConfig {
            id: KadId::from_bytes([0x0F; 16]),
            tcp_port: 4662,
            udp_port: 4672,
            user_hash: UserHash::from_bytes([0xEE; 16]),
        },
        now,
    ));
    let storer = contact_endpoint(10);
    node.handle_datagram(
        now,
        storer,
        &hello_req_at_version(near_keyword(), storer, version),
    );
    let _ = drain_split(&mut node);
    node.handle_command(
        now,
        KadCommand::SearchKeywords {
            request: KadKeywordSearchRequest::new("keyword"),
        },
    );
    let _ = drain_split(&mut node);
    node.handle_datagram(now, storer, &lookup_res_bytes(kw(), &[]));
    let _ = drain_split(&mut node);

    let row = KeywordResultRow {
        file_id: file_id(0xA1),
        tags: vec![
            name_tag("keyword song.mp3"),
            size_tag(4_096),
            // One name, 20 publishers, trust 1.00.
            Tag::new(
                TagName::length_prefixed_id(0x33),
                TagValue::U32(0x0114_0064),
            ),
        ],
        aich_roots: vec![KadAichRootReport {
            popularity: 12,
            root: ROOT,
        }],
    };
    let answer = encode_search_key_res(near_keyword(), kw(), &[row]);
    node.handle_datagram(now, storer, &answer[0].encode());
    let (_, events) = drain_split(&mut node);
    match events.as_slice() {
        [KadEvent::KeywordsFound { results, .. }] => results.clone(),
        other => panic!("expected one KeywordsFound, got {other:?}"),
    }
}

#[test]
fn a_v9_storers_aich_roots_ride_the_keyword_result_with_its_publishers() {
    let results = answered_by_a_storer_at(9);

    assert_eq!(
        results[0].aich_roots,
        vec![KadAichRootReport {
            popularity: 12,
            root: ROOT,
        }]
    );
    assert_eq!(results[0].publishers(), Some(20));
}

#[test]
fn a_v8_storers_aich_roots_are_ignored() {
    let results = answered_by_a_storer_at(8);

    assert_eq!(results[0].aich_roots, Vec::new());
    assert_eq!(
        results[0].filename.as_deref(),
        Some("keyword song.mp3"),
        "the row itself stands"
    );
}
