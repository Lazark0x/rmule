//! **Keyword Derivation** fold vectors (ADR-0062, execution breakdown 1).
//!
//! The fold must be byte-parity with aMule: a divergent lowercase or a
//! mistokenized word yields a different MD4 and the file silently never
//! matches. Every fold rule in the ADR gets a vector here.
//!
//! ## Provenance
//!
//! The keyword-ID vectors are grounded in the **RFC 1320** MD4 test suite
//! (`MD4("abc")` / `MD4("abcdefghijklmnopqrstuvwxyz")`, mathematical ground
//! truth) mapped to Kad wire form by the capture-proven per-32-bit-word swap
//! (`KadEvidence::KadIdByteOrder`, the same `SetValueBE`/`WriteUInt128` path a
//! file-hash search target rides). The tokenization vectors are ADR-derived
//! (aMule `SearchManager`/`KnownFile` line cites in ADR-0062). The **multilingual
//! fold** (non-ASCII lowercase) and the exact **extension-strip** semantics are
//! the surfaces capture recipe 2 (aMule publishes → rmule stores) pins; the
//! ASCII fold is trivially safe and pinned here.

use rmule_kad::KadId;
use rmule_kad::keyword::{
    keyword_id, lead_keyword, publish_keywords, search_keywords, search_target,
};

/// `MD4("abc") = a448017aaf21d8525fc10ae87aa6729d` (RFC 1320 A.5), each 32-bit
/// word's bytes reversed into Kad wire order.
const ABC_KEYWORD_ID: [u8; 16] = [
    0x7a, 0x01, 0x48, 0xa4, 0x52, 0xd8, 0x21, 0xaf, 0xe8, 0x0a, 0xc1, 0x5f, 0x9d, 0x72, 0xa6, 0x7a,
];

/// `MD4("abcdefghijklmnopqrstuvwxyz") = d79e1c308aa5bbcdeea8ed63df412da9`
/// (RFC 1320 A.5), per-32-bit-word byte-reversed.
const ALPHABET_KEYWORD_ID: [u8; 16] = [
    0x30, 0x1c, 0x9e, 0xd7, 0xcd, 0xbb, 0xa5, 0x8a, 0x63, 0xed, 0xa8, 0xee, 0xa9, 0x2d, 0x41, 0xdf,
];

#[test]
fn keyword_id_is_md4_over_utf8_in_kad_wire_order() {
    // Plain MD4 of the (already-lowercased) word, mapped to Kad wire form.
    assert_eq!(keyword_id("abc"), KadId::from_bytes(ABC_KEYWORD_ID));
    assert_eq!(
        keyword_id("abcdefghijklmnopqrstuvwxyz"),
        KadId::from_bytes(ALPHABET_KEYWORD_ID)
    );
}

#[test]
fn tokenizes_on_the_full_separator_set() {
    // ` ()[]{}<>,._-!?:;\/"` all split. Each qualifying (>= 3-byte) run survives.
    let separated =
        "one(two)three[four]five{six}<seven>eight,nine.ten_xxx-yyy!zzz?www:vvv;uuu\\ttt/sss\"rrr";
    assert_eq!(
        search_keywords(separated),
        vec![
            "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "xxx",
            "yyy", "zzz", "www", "vvv", "uuu", "ttt", "sss", "rrr",
        ]
    );
    // Consecutive separators never yield an empty token.
    assert_eq!(search_keywords("foo   ...bar"), vec!["foo", "bar"]);
}

#[test]
fn keeps_tokens_of_at_least_three_utf8_bytes_not_chars() {
    // Two-byte tokens dropped, three-byte kept.
    assert_eq!(search_keywords("ab abc de fgh"), vec!["abc", "fgh"]);
    // `aé` is 2 *chars* but 3 *bytes* (0x61 0xC3 0xA9): a byte-count rule keeps
    // it; a char-count rule would drop it. `xy` (2 bytes) is dropped.
    assert_eq!(search_keywords("aé xy"), vec!["aé"]);
}

#[test]
fn lowercases_ascii() {
    assert_eq!(
        search_keywords("Hello WORLD Foo"),
        vec!["hello", "world", "foo"]
    );
}

#[test]
fn search_keeps_duplicates_publish_dedupes() {
    // Search keeps every occurrence, order preserved.
    assert_eq!(
        search_keywords("test test test"),
        vec!["test", "test", "test"]
    );
    // Publish dedupes (first occurrence wins, order preserved).
    assert_eq!(publish_keywords("test test other"), vec!["test", "other"]);
}

#[test]
fn publish_strips_the_file_extension_search_does_not() {
    // `.` is itself a separator, so publish stripping the extension *removes*
    // the trailing extension token that search would otherwise keep.
    assert_eq!(publish_keywords("report.pdf"), vec!["report"]);
    assert_eq!(search_keywords("report.pdf"), vec!["report", "pdf"]);
    // Only the last extension is stripped; interior dots still tokenize.
    assert_eq!(
        publish_keywords("holiday.trip.mkv"),
        vec!["holiday", "trip"]
    );
    // A dotless name strips nothing.
    assert_eq!(publish_keywords("readme file"), vec!["readme", "file"]);
}

#[test]
fn search_target_is_the_first_qualifying_token() {
    // Target = MD4 of the query's first >= 3-byte token.
    assert_eq!(
        search_target("abc def"),
        Some(KadId::from_bytes(ABC_KEYWORD_ID))
    );
    // A leading sub-3-byte run is skipped; the first *qualifying* token wins.
    assert_eq!(
        search_target("xy abc"),
        Some(KadId::from_bytes(ABC_KEYWORD_ID))
    );
    // No qualifying token → no target.
    assert_eq!(search_target("ab"), None);
    assert_eq!(search_target(""), None);
}

#[test]
fn empty_and_all_separator_inputs_yield_no_keywords() {
    assert!(search_keywords("").is_empty());
    assert!(search_keywords("   ").is_empty());
    assert!(publish_keywords("").is_empty());
    assert!(publish_keywords(".mkv").is_empty());
}

/// aMule's Kad keyword rearrangement (`SearchList.cpp:126-141`): the longest
/// eligible word, not the first. Derived from source; the captured aMule `0x33`
/// for `rmulekadkeyword parityprobe` targets the longer, first word
/// (`captured_keyword_request`).
#[test]
fn the_lead_keyword_is_the_longest_eligible_word() {
    let lead = |phrase: &str, words: &[&str]| {
        let words: Vec<String> = words.iter().map(ToString::to_string).collect();
        lead_keyword(phrase, &words)
    };
    assert_eq!(
        lead(
            "The oxymoronaccelerator 2",
            &["The", "oxymoronaccelerator", "2"]
        )
        .as_deref(),
        Some("oxymoronaccelerator"),
        "eMule's own example"
    );
    assert_eq!(
        lead(
            "rmulekadkeyword parityprobe",
            &["rmulekadkeyword", "parityprobe"]
        )
        .as_deref(),
        Some("rmulekadkeyword")
    );
    assert_eq!(
        lead(
            "ubuntu-desktop-edition linux",
            &["ubuntu-desktop-edition", "linux"]
        )
        .as_deref(),
        Some("ubuntu"),
        "a word holding a separator never leads; the first token stays"
    );
    assert_eq!(
        lead(
            r#"the "matrix reloaded" dvd"#,
            &["the", r#""matrix reloaded""#, "dvd"]
        )
        .as_deref(),
        Some("the"),
        "a quoted run never leads; equal length keeps the first"
    );
    assert_eq!(
        lead("Ubuntu-22.04", &["Ubuntu-22.04"]).as_deref(),
        Some("ubuntu"),
        "one word: no rearrangement"
    );
    assert_eq!(lead("a b", &["a", "b"]), None);
}
