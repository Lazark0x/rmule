//! Captured-provenance keyword-request decoder tests (ADR-0062 recipes 2+4):
//! the genuine STOCK aMule 2.3.3 `KADEMLIA2_SEARCH_KEY_REQ`
//! (`0x33`) and `KADEMLIA2_PUBLISH_KEY_REQ` (`0x43`) bytes the keyword search
//! and keyword store rows name.
//!
//! These are the ROLE INVERSION of the `0x3B` source capture: aMule was the Kad
//! publisher AND requester, rmule the storer. rmule's KadID was pinned to the
//! keyword target so aMule's publish and search rendezvoused on it, and rmule's
//! keyword store decoded + served every datagram (harness flow J,
//! `kad-inverted-keyword`, run 1785026780). These bytes are aMule-authored;
//! rmule's are never evidence. Provenance:
//! `fixtures/keyword/captured/fake-public-amule-kad-keyword-20260726/`.
//!
//! The load-bearing fact each datagram carries: the on-wire keyword ID equals
//! `keyword_id("rmulekadkeyword")` EXACTLY — so aMule's `GetKeywordHash` and
//! rmule's fold (MD4 over the lowercased UTF-8 token, per-32-bit-word wire swap)
//! are byte-identical. ADR-0062's recipe-2 "keyword-ID derivation fold (byte
//! parity)" claim, capture-proven rather than asserted.

use crate::fixture::{KEYWORD, PUBLISHED_FILE_ID};
use rmule_kad::keyword::keyword_id;
use rmule_kad::keyword_store::{
    KeywordPublishFile, decode_publish_key_req, decode_search_key_req, encode_publish_key_req,
    encode_search_key_req,
};
use rmule_kad::{KadDecoded, KadEnvelope, KadId, decode_exact};
use rmule_primitives::{Tag, TagName, TagValue};

const SEARCH_PLAIN: &[u8] = include_bytes!(
    "../fixtures/keyword/captured/fake-public-amule-kad-keyword-20260726/search_key_req_0x33.bin"
);
const SEARCH_TREE: &[u8] = include_bytes!(
    "../fixtures/keyword/captured/fake-public-amule-kad-keyword-20260726/search_key_req_tree_0x33.bin"
);
const PUBLISH: &[u8] = include_bytes!(
    "../fixtures/keyword/captured/fake-public-amule-kad-keyword-20260726/publish_key_req_0x43.bin"
);

/// Strip the `0xE4` protocol envelope from a full on-wire datagram, the way the
/// live receive path does before routing a keyword request to the store.
fn envelope_of(datagram: &[u8]) -> KadEnvelope {
    let KadDecoded::Plain(envelope) =
        decode_exact(datagram).expect("captured datagram is a plain 0xE4 envelope")
    else {
        panic!("captured keyword request must decode as a plain 0xE4 envelope");
    };
    envelope
}

#[test]
fn amule_keyword_hash_matches_rmule_fold_byte_for_byte() {
    // Every captured request — plain search, restrictive search, publish —
    // carries the SAME keyword ID, and it equals rmule's own derivation. This is
    // the fold parity the whole inversion hinges on: had aMule's GetKeywordHash
    // differed by one byte, none of these datagrams would have reached rmule.
    let ours = keyword_id(KEYWORD);
    let (plain_kw, _, _) =
        decode_search_key_req(&envelope_of(SEARCH_PLAIN)).expect("plain 0x33 decodes");
    let (tree_kw, _, _) =
        decode_search_key_req(&envelope_of(SEARCH_TREE)).expect("restrictive 0x33 decodes");
    let (publish_kw, _) = decode_publish_key_req(&envelope_of(PUBLISH)).expect("0x43 decodes");
    assert_eq!(plain_kw, ours, "plain search target == keyword_id");
    assert_eq!(tree_kw, ours, "restrictive search target == keyword_id");
    assert_eq!(publish_kw, ours, "publish keyword == keyword_id");
}

#[test]
fn plain_search_key_req_has_no_restrictive_tree() {
    let (_, start_position, tree) =
        decode_search_key_req(&envelope_of(SEARCH_PLAIN)).expect("plain 0x33 decodes");
    assert_eq!(start_position, 0, "the 2.3.3 requester always pages from 0");
    assert!(
        tree.is_none(),
        "a one-word Kad search clears the restrictive-tree flag (startpos top bit)"
    );
}

#[test]
fn restrictive_search_key_req_decodes_and_round_trips_the_tree() {
    let envelope = envelope_of(SEARCH_TREE);
    let (_, start_position, tree) =
        decode_search_key_req(&envelope).expect("restrictive 0x33 decodes");
    assert_eq!(start_position, 0, "low 15 bits of startpos are 0");
    let tree = tree.expect("a two-word Kad search sets the restrictive-tree flag");
    // rmule's search-tree codec must re-encode aMule's genuine tree byte-for-byte
    // (the payload after the 16-byte keyword and the 2-byte startpos).
    let tree_bytes = &envelope.payload()[16 + 2..];
    assert_eq!(
        tree.encode(),
        tree_bytes,
        "rmule re-encodes aMule's restrictive tree byte-for-byte"
    );
}

#[test]
fn publish_key_req_decodes_the_batch_the_storer_indexes() {
    let (_, files) = decode_publish_key_req(&envelope_of(PUBLISH)).expect("0x43 decodes");
    assert_eq!(files.len(), 1, "the batch carries one shared file");
    let file = &files[0];
    assert_eq!(
        file.filename.as_deref(),
        Some("rmulekadkeyword.dat"),
        "aMule's FILENAME tag, extension intact",
    );
    assert_eq!(
        file.size,
        Some(65_536),
        "aMule's FILESIZE tag = the 64 KiB shared file",
    );
}

// --- recipe 1 + 3 emit: rmule's own 0x33 / 0x43 == aMule's captured bytes ---
//
// ADR-0062 recipes 1 (rmule publishes → aMule stores) and 3 (rmule searches →
// aMule serves) name a *live* capture of rmule's request bytes. But rmule's
// bytes are never evidence (ADR-0045) — so the byte-exact proof is the inverse:
// rmule's encoder must reproduce aMule's *own* genuine `0x33`/`0x43` (recipe 2/4,
// committed above) datagram-for-datagram. A live run then only needs aMule's
// answer (`0x4B`/`0x3B`) as the counterparty evidence, because these tests
// already pin that what rmule puts on the wire is what a stock aMule 2.3.3 puts
// on the wire for the same query and the same shared file.

#[test]
fn rmule_plain_search_key_req_emit_is_byte_identical_to_amule() {
    // The v1 requester's unfiltered emit: the lead keyword, offset 0, no tree.
    // It must reproduce aMule's genuine plain `0x33` byte-for-byte — same target
    // (the fold parity above), same zero startpos, same absent tree.
    let emitted = encode_search_key_req(keyword_id(KEYWORD), 0, None).encode();
    assert_eq!(
        emitted, SEARCH_PLAIN,
        "rmule's plain 0x33 == aMule's captured plain 0x33"
    );
}

#[test]
fn rmule_publish_key_req_emit_is_byte_identical_to_amule() {
    // rmule's publisher emit for the exact file aMule shared: one file, three
    // tags (FILENAME, FILESIZE, SOURCES), FILETYPE omitted because the file is
    // unclassifiable — and SOURCES narrowed to a one-byte `0x09` tag by aMule's
    // integer compaction. A fixed `U32` SOURCES (rmule's earlier emit) would
    // diverge here by three bytes; the assertion pins the compaction.
    let file = KeywordPublishFile {
        file_id: KadId::from_bytes(PUBLISHED_FILE_ID),
        filename: Some("rmulekadkeyword.dat".to_owned()),
        size: Some(65_536),
        tags: vec![Tag::new(
            TagName::length_prefixed_id(0x15),
            TagValue::compact_uint(0),
        )],
    };
    let emitted = encode_publish_key_req(keyword_id(KEYWORD), &[file]).encode();
    assert_eq!(
        emitted, PUBLISH,
        "rmule's 0x43 == aMule's captured 0x43 (3-tag, SOURCES compacted to u8)"
    );
}
