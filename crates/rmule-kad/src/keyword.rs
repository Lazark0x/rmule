//! **Keyword Derivation** (ADR-0062): the byte-exact pipeline from a filename
//! or query to Kad keyword IDs.
//!
//! One module owns both directions. Byte parity is load-bearing: a divergent
//! lowercase fold gives a different MD4 and the file silently never matches, so
//! the fold follows aMule to the letter. The pipeline is: split on the
//! separator set, keep tokens of at least three UTF-8 **bytes**, lowercase,
//! then MD4 over the UTF-8 bytes. The publish direction strips the file
//! extension and dedupes first; the search direction keeps duplicates and
//! targets the first token.
//!
//! ## Provenance
//!
//! - Separator set, byte-min boundary, lowercase order, and the two-direction
//!   split are aMule's (`SearchManager`/`KnownFile` line cites in ADR-0062).
//! - The keyword ID is plain MD4 over the lowercased word's UTF-8 bytes
//!   (`Kademlia::GetKeywordHash`, Kademlia.cpp#L500-L510), mapped to Kad wire
//!   form by the capture-proven per-32-bit-word swap (`kad_wire_id`) — the
//!   same `CUInt128::SetValueBE` / `WriteUInt128` path a file-hash search
//!   target rides.
//! - The **multilingual fold** (non-ASCII `to_lowercase` vs aMule's wx/ICU
//!   `MakeLower`) and the exact **extension-strip** semantics are pinned by
//!   capture recipe 2 (aMule publishes → rmule stores). Until then ASCII is
//!   pinned deterministically and `to_lowercase` stands as the fold; any
//!   divergence a capture surfaces is matched byte-for-byte here.

use std::collections::HashSet;

use md4::{Digest, Md4};

use crate::KadId;
use crate::lookup::kad_wire_id;

/// aMule's Kad keyword separator set (`WORD_SEPERATORS`, SearchManager.h#L89):
/// tokenization splits on any of these.
///
/// All members are ASCII, so splitting the UTF-8 string on them as `char`s is
/// byte-identical to aMule splitting the wide string (an ASCII byte never
/// occurs inside a multi-byte UTF-8 sequence). The backslash is the one member
/// the ADR's markdown rendering leaves ambiguous (a C++ `\\` collapsed to `\`);
/// it is included per the canonical constant and is unobservable to real
/// filenames, which never contain `\`.
const SEPARATORS: [char; 20] = [
    ' ', '(', ')', '[', ']', '{', '}', '<', '>', ',', '.', '_', '-', '!', '?', ':', ';', '\\', '/',
    '"',
];

/// aMule keeps only tokens of at least three UTF-8 **bytes** — bytes, not chars
/// (SearchManager.cpp#L242).
const MIN_KEYWORD_BYTES: usize = 3;

/// The Kad keyword ID of one already-lowercased word: plain MD4 over its UTF-8
/// bytes, mapped to Kad wire form.
///
/// Expects a token as [`search_keywords`]/[`publish_keywords`] produce it
/// (already lowercased); it hashes the bytes verbatim, matching aMule's
/// `GetKeywordHash`, which does not re-lowercase.
#[must_use]
pub fn keyword_id(word: &str) -> KadId {
    let digest = Md4::digest(word.as_bytes());
    let mut raw = [0u8; KadId::BYTE_LEN];
    raw.copy_from_slice(&digest);
    KadId::from_bytes(kad_wire_id(raw))
}

/// Tokenize + fold for the **search** direction: split on the separator set,
/// keep tokens of at least three UTF-8 bytes, lowercase — **duplicates kept**,
/// order preserved (SearchManager.cpp#L123).
#[must_use]
pub fn search_keywords(query: &str) -> Vec<String> {
    fold(query)
}

/// The search **target**: the keyword ID of the query's first qualifying token
/// (SearchManager.cpp#L128), or `None` when the query has no >= 3-byte token.
#[must_use]
pub fn search_target(query: &str) -> Option<KadId> {
    fold(query).first().map(|word| keyword_id(word))
}

/// The keyword a Kad search walks toward, as aMule chooses it: the query's
/// first qualifying token (`SearchList.cpp:612-619`), replaced — when the query
/// holds two or more words — by its longest word, "generally assum\[ing\] that
/// the longer keywords are rarer" so the popular node indexing "the" is spared
/// (`SearchList.cpp:126-141`; eMule `SearchResultsWnd.cpp:791-805`).
///
/// `words` are the query's lexed words (quoted runs keep their quotes). A word
/// qualifies when it holds no separator — a quoted run never does — and at
/// least three characters, and it replaces the lead only when strictly longer,
/// counted in characters; the first of equal length stays. The result is
/// lowercased, as `PrepareFindKeywords` re-folds it. `None` when the phrase
/// has no ≥ 3-byte token.
#[must_use]
pub fn lead_keyword(phrase: &str, words: &[String]) -> Option<String> {
    let mut lead = fold(phrase).into_iter().next()?;
    if words.len() < 2 {
        return Some(lead);
    }
    let mut lead_chars = lead.chars().count();
    for word in words {
        let chars = word.chars().count();
        if chars >= MIN_KEYWORD_BYTES && chars > lead_chars && !word.contains(SEPARATORS) {
            lead = word.to_lowercase();
            lead_chars = chars;
        }
    }
    Some(lead)
}

/// Tokenize + fold for the **publish** direction: strip the file extension
/// first (KnownFile.cpp#L1491), fold, then **dedupe** (first occurrence wins,
/// order preserved).
#[must_use]
pub fn publish_keywords(filename: &str) -> Vec<String> {
    dedupe(fold(strip_extension(filename)))
}

/// Split, keep >= 3-byte tokens, then lowercase — in aMule's order (the byte
/// length is checked on the raw token at L242, `MakeLower` follows at L243).
fn fold(text: &str) -> Vec<String> {
    text.split(|c: char| SEPARATORS.contains(&c))
        .filter(|token| token.len() >= MIN_KEYWORD_BYTES)
        .map(str::to_lowercase)
        .collect()
}

/// Drop the last file extension (everything from the final `.`), matching
/// `wxFileName::GetName`. `.` is itself a separator, so this removes the
/// trailing extension token the search path would otherwise keep.
fn strip_extension(filename: &str) -> &str {
    match filename.rfind('.') {
        Some(dot) => &filename[..dot],
        None => filename,
    }
}

/// Order-preserving dedupe, first occurrence wins.
fn dedupe(words: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    words
        .into_iter()
        .filter(|word| seen.insert(word.clone()))
        .collect()
}

/// A **Kad Requester** keyword query (ADR-0062): the raw query the node walks
/// toward and filters returned rows against.
///
/// The walk [`target`](Self::target) is the first ≥ 3-byte token's keyword ID
/// (`SearchManager.cpp#L128`); it is `None` for a query with no qualifying
/// token (nothing to search). The [`residual_tokens`](Self::residual_tokens) are
/// every token — the v1 requester emits only the lead keyword and matches the
/// remaining words against returned filenames **client-side** (the documented
/// effectiveness delta vs aMule's storer-side tree filtering; the tree emit that
/// closes it waits for a front end that issues filtered searches).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KadKeywordSearchRequest {
    query: String,
}

impl KadKeywordSearchRequest {
    /// A search for this query. The lead keyword the walk targets and the
    /// residual tokens the results are filtered by are both derived from it.
    #[must_use]
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
        }
    }

    /// The raw query string.
    #[must_use]
    pub fn query(&self) -> &str {
        &self.query
    }

    /// The keyword ID the walk targets, or `None` when the query has no
    /// ≥ 3-byte token.
    #[must_use]
    pub fn target(&self) -> Option<KadId> {
        search_target(&self.query)
    }

    /// Every token a returned row's filename must contain — the client-side
    /// multi-word filter. A single-word query's lone token is already implied by
    /// the keyword index, so the filter is a no-op there.
    #[must_use]
    pub fn residual_tokens(&self) -> Vec<String> {
        search_keywords(&self.query)
    }
}
