//! Captured-provenance keyword-ANSWER decoder tests (ADR-0062 recipes 1 + 3):
//! the genuine STOCK aMule 2.3.3 `KADEMLIA2_PUBLISH_RES` (`0x4B`)
//! and `KADEMLIA2_SEARCH_RES` (`0x3B`) answer bytes for the two legs rmule drives
//! as **Kad Publisher** and **Kad Requester**.
//!
//! The ROLE INVERSION of the flow-J capture: there aMule published + searched and
//! rmule stored; here rmule published + searched and aMule stored, with aMule
//! pinned to the keyword target so it received the publish and served the search
//! (harness `kad-fake-public-source --keyword`, run 1785135112). These bytes are
//! aMule-authored (its accept + serve); rmule's own `0x43`/`0x33` request bytes are
//! proven byte-for-byte in `captured_keyword_request.rs`. Provenance:
//! `fixtures/keyword/captured/fake-public-amule-kad-keyword-answers-20260727/`.

use crate::fixture::{KEYWORD, PUBLISHED_FILE_ID};
use rmule_kad::keyword::keyword_id;
use rmule_kad::keyword_store::decode_search_key_res;
use rmule_kad::{Kad2Message, KadDecoded, KadEnvelope, KadId, decode_exact};

const PUBLISH_RES: &[u8] = include_bytes!(
    "../fixtures/keyword/captured/fake-public-amule-kad-keyword-answers-20260727/publish_res_0x4b.bin"
);
const SEARCH_RES: &[u8] = include_bytes!(
    "../fixtures/keyword/captured/fake-public-amule-kad-keyword-answers-20260727/search_res_0x3b.bin"
);

fn envelope_of(datagram: &[u8]) -> KadEnvelope {
    let KadDecoded::Plain(envelope) =
        decode_exact(datagram).expect("captured datagram is a plain 0xE4 envelope")
    else {
        panic!("captured keyword answer must decode as a plain 0xE4 envelope");
    };
    envelope
}

#[test]
fn amule_acked_rmule_keyword_publish_with_a_new_keyword_load() {
    // Publisher leg: stock aMule accepted rmule's `0x43` and answered `0x4B`. The
    // ack keys the KEYWORD (not the file) and carries the shared load — 1 for a
    // brand-new keyword's first file (`CIndexed::AddKeyword`).
    let publish_res =
        Kad2Message::decode(&envelope_of(PUBLISH_RES)).expect("0x4B decodes as a publish response");
    let Kad2Message::PublishRes {
        file,
        load,
        options,
    } = publish_res
    else {
        panic!("expected PublishRes, got {publish_res:?}");
    };
    assert_eq!(
        file,
        keyword_id(KEYWORD),
        "aMule acked the keyword rmule published — a live re-confirmation of the fold"
    );
    assert_eq!(load, 1, "a brand-new keyword's first file reports load 1");
    assert_eq!(
        options, 0,
        "2.3.3's storer leaves the future-use options byte 0"
    );
}

#[test]
fn amule_answered_rmule_keyword_search_with_rmules_own_file() {
    // Requester leg: stock aMule answered rmule's `0x33` with one row — rmule's
    // OWN published file, carrying the tags rmule published plus aMule's
    // synthesized TAG_PUBLISHINFO. The search-back finds the file; the requester's
    // decode faces real aMule bytes.
    let rows =
        decode_search_key_res(&envelope_of(SEARCH_RES)).expect("0x3B decodes as keyword results");
    assert_eq!(
        rows.len(),
        1,
        "aMule served exactly rmule's one published file"
    );

    let result = rows[0].project();
    assert_eq!(
        result.file_id,
        KadId::from_bytes(PUBLISHED_FILE_ID),
        "the served row is rmule's shared file (wire-form ID)"
    );
    assert_eq!(result.filename.as_deref(), Some("rmulekadkeyword.dat"));
    assert_eq!(result.size, Some(65_536));
    assert_eq!(
        result.complete_sources,
        Some(0),
        "the SOURCES count rmule published, re-served"
    );
    assert_eq!(
        result.file_type, None,
        "`.dat` does not classify, so neither rmule's publish nor aMule's \
         re-serve carries TAG_FILETYPE (a capture against aMule corrected \
         ADR-0062 here) — an app-side Type has to come from the name"
    );
    assert_eq!(
        result.publish_info,
        Some(0x0101_03e8),
        "aMule's storer synthesized TAG_PUBLISHINFO (names=1, publishers=1, trust*100=1000)"
    );
}
