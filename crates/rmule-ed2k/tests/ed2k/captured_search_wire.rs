//! The `search-wire` capture (runs 1790603580 and 1790604060):
//! aMule's own search requests, and what Lugdunum and ed2k-server answered to
//! aMule and to rmule. Provenance in the fixture's `meta.toml`.

use rmule_ed2k::{SearchRequest, SearchResults};
use rmule_primitives::{Ed2kText, KeywordQuery, Packet};

fn frame(name: &str) -> Packet {
    Packet::decode_exact(&crate::fixture::captured("search-wire-20260928", name))
        .expect("a whole captured frame")
}

fn names(name: &str) -> Vec<String> {
    SearchResults::decode_packet(&frame(name))
        .expect("the answer decodes")
        .results()
        .iter()
        .map(|row| row.primary_name().to_display_string())
        .collect()
}

/// aMule joins the words into one term; rmule sends them AND-ed. Both are the
/// same query, and Lugdunum answered both with the same bytes.
#[test]
fn amules_joined_request_and_rmules_split_one_ask_lugdunum_the_same_thing() {
    let amule = SearchRequest::decode_packet(&frame("amule_search_req_joined_0x16.bin"))
        .expect("aMule's request decodes");
    let phrase = Ed2kText::from_utf8("ubuntu desktop");
    assert_eq!(amule.query().phrase(), &phrase);
    let rmule = SearchRequest::from_query(KeywordQuery::new(phrase).unwrap()).encode_packet();
    assert_eq!(
        SearchRequest::decode_packet(&rmule).unwrap().query(),
        amule.query()
    );
    assert_eq!(
        frame("lugdunum_search_res_split_0x33.bin"),
        frame("lugdunum_search_res_joined_0x33.bin")
    );
    assert_eq!(
        names("lugdunum_search_res_split_0x33.bin"),
        ["ubuntu-desktop-wire.bin"]
    );
}

/// ed2k-server writes `FT_FILETYPE` as an integer. The row is kept — aMule
/// keeps it too — rather than the whole answer dropped.
#[test]
fn an_integer_file_type_keeps_the_row() {
    assert_eq!(
        names("ed2ksrv_search_res_typetag_0x33.bin"),
        ["ubuntu-desktop-wire.bin"]
    );
}

/// A Related-Files Search for a file with five sources answers with the file
/// and what its sources also hold; one with a single source answers empty.
#[test]
fn lugdunum_answers_a_related_search_only_for_a_file_with_enough_sources() {
    assert_eq!(
        names("lugdunum_related_res_0x33.bin"),
        ["relatedpopular-wire.bin", "relatedcompanion-1-wire.bin"]
    );
    assert!(names("lugdunum_related_res_rare_0x33.bin").is_empty());
}

/// Every captured answer ends in the more-results byte, and every one of them
/// says `0x00`: the last page. rmule's own encoding ends the same way.
#[test]
fn a_captured_answer_says_it_is_the_last_page() {
    for name in [
        "lugdunum_search_res_joined_0x33.bin",
        "lugdunum_related_res_0x33.bin",
        "lugdunum_related_res_rare_0x33.bin",
        "ed2ksrv_search_res_typetag_0x33.bin",
    ] {
        let captured = frame(name);
        let answer = SearchResults::decode_packet(&captured).expect("the answer decodes");
        assert!(!answer.more_available(), "{name}");
        assert_eq!(
            answer.encode_packet().payload().last(),
            captured.payload().last(),
            "{name}"
        );
    }
}
