//! When a [`SearchResult`] answers a [`KeywordQuery`] — the predicate
//! **Search Attribution** reads (ADR-0034). An eD2k answer and
//! a `0x99` carry no search id, so a row reaches a search because of what it
//! contains: [`KeywordQuery::matches`] when the row must *prove* the query,
//! [`KeywordQuery::contradicts`] when the server already said it answers it and
//! only a field the row carries can overrule that.

use icu_normalizer::DecomposingNormalizerBorrowed;

use super::{KeywordQuery, SearchResult};

/// Where a phrase splits into tokens, beside whitespace: every character
/// aMule's keyword tokenizer splits on (`SearchManager.h:135`) or ed2k-server's
/// filename tokenizer does (`keyword_index.rs:47-56`). The union, because a
/// finer split gives shorter tokens and so the looser reading.
const SEPARATORS: [char; 32] = [
    '(', ')', '[', ']', '{', '}', '<', '>', ',', '.', '_', '-', '!', '?', ':', ';', '\\', '/', '"',
    '@', '#', '$', '%', '^', '&', '*', '+', '=', '|', '\'', '`', '~',
];

/// `text`'s words as both measured servers index them (bench run
/// 1790603580, Lugdunum; 1790604060, ed2k-server): split on whitespace and
/// `SEPARATORS`, folded by case and — Lugdunum's reading, the looser of the
/// two — by accent: decomposed (NFD), combining marks dropped.
fn words(text: &str) -> Vec<String> {
    DecomposingNormalizerBorrowed::new_nfd()
        .normalize(text)
        .chars()
        .filter(|c| !is_combining_mark(*c))
        .flat_map(char::to_lowercase)
        .collect::<String>()
        .split(|c: char| c.is_whitespace() || SEPARATORS.contains(&c))
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The combining-mark blocks an NFD decomposition of a Latin, Greek or
/// Cyrillic accented letter splits into.
fn is_combining_mark(c: char) -> bool {
    matches!(
        c,
        '\u{0300}'..='\u{036F}'
            | '\u{1AB0}'..='\u{1AFF}'
            | '\u{1DC0}'..='\u{1DFF}'
            | '\u{20D0}'..='\u{20FF}'
            | '\u{FE20}'..='\u{FE2F}'
    )
}

/// One clause's verdict against a row: proven, refuted, or not decidable
/// because the row does not carry the field.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Holds,
    Fails,
    Unknown,
}

impl KeywordQuery {
    /// Does `result` **prove** this query — every keyword token inside one of
    /// its names, and every constraint shown to hold by a field it carries?
    ///
    /// **Keywords.** The words the query sends ([`KeywordQuery::terms`]: an
    /// explicit `AND` is no keyword), each split again on whitespace and on
    /// `SEPARATORS`. Every query word must be a **whole word** of one name,
    /// folded by case and accent, and a quoted run's words must stand in one
    /// name in order, side by side: both measured servers match whole words
    /// only, Lugdunum folds accents and reads a quoted run as a phrase
    /// (`docs/protocol/search-request.md`, rulings; runs 1790603580,
    /// 1790604060).
    ///
    /// **Constraints.** Size bounds inclusive against the row's size;
    /// availability against the reported count; type against the row's class
    /// (name first, then `FT_FILETYPE`) at wire resolution
    /// ([`crate::Ed2kFileClass::search_term`], so `"Pro"` admits archives and
    /// CD images); extension against any name's extension or `FT_FILEFORMAT`,
    /// ASCII case-insensitive. A field the row does not carry proves nothing,
    /// so the row does not match — aMule drops a result of unknown type the
    /// same way (`SearchList.cpp:1130-1140`).
    #[must_use]
    pub fn matches(&self, result: &SearchResult) -> bool {
        self.keywords_in(result)
            && self
                .constraint_verdicts(result)
                .iter()
                .all(|verdict| *verdict == Verdict::Holds)
    }

    /// Does a field `result` carries **contradict** one of this query's
    /// constraints? The keywords are not read, and an absent field
    /// contradicts nothing: this is the test for a row the server returned *as
    /// its answer to this query*, where the server's own matching — on fields
    /// the row may not echo — stands, and only what the row plainly shows can
    /// overrule it (ed2k-server, for one, ignores the availability floor).
    #[must_use]
    pub fn contradicts(&self, result: &SearchResult) -> bool {
        self.constraint_verdicts(result).contains(&Verdict::Fails)
    }

    fn keywords_in(&self, result: &SearchResult) -> bool {
        let names: Vec<Vec<String>> = result
            .names()
            .iter()
            .map(|name| words(&name.to_display_string()))
            .collect();
        self.terms().iter().all(|term| {
            let term = term.to_display_string();
            match term
                .strip_prefix('"')
                .and_then(|inner| inner.strip_suffix('"'))
            {
                // A quoted run is an ordered phrase, as Lugdunum reads it:
                // its words, in order, side by side in one name.
                Some(inner) => {
                    let phrase = words(inner);
                    names.iter().any(|name| {
                        phrase.is_empty()
                            || name
                                .windows(phrase.len())
                                .any(|window| window == phrase.as_slice())
                    })
                }
                None => words(&term)
                    .iter()
                    .all(|word| names.iter().any(|name| name.contains(word))),
            }
        })
    }

    fn constraint_verdicts(&self, result: &SearchResult) -> [Verdict; 5] {
        let size = result.file_size();
        [
            self.min_size
                .map_or(Verdict::Holds, |min| holds(size >= min)),
            self.max_size
                .map_or(Verdict::Holds, |max| holds(size <= max)),
            self.min_availability.map_or(Verdict::Holds, |min| {
                match result.reported_availability() {
                    Some(have) => holds(have >= min),
                    None => Verdict::Unknown,
                }
            }),
            self.file_type
                .map_or(Verdict::Holds, |wanted| match result.file_class() {
                    Some(class) => holds(class.search_term() == wanted.search_term()),
                    None => Verdict::Unknown,
                }),
            self.extension
                .as_ref()
                .map_or(Verdict::Holds, |wanted| extension_verdict(wanted, result)),
        ]
    }
}

fn holds(proven: bool) -> Verdict {
    if proven {
        Verdict::Holds
    } else {
        Verdict::Fails
    }
}

fn extension_verdict(wanted: &crate::Ed2kText, result: &SearchResult) -> Verdict {
    let Ok(wanted) = wanted.try_as_str() else {
        return Verdict::Unknown;
    };
    let wanted = wanted.trim_start_matches('.');
    let from_names = result.names().iter().filter_map(|name| {
        name.try_as_str()
            .ok()
            .and_then(|name| name.rsplit_once('.').map(|(_, ext)| ext.to_string()))
    });
    let from_tag = result
        .file_format()
        .and_then(|value| value.try_as_str().ok())
        .map(str::to_string);
    let mut known = from_names.chain(from_tag).peekable();
    if known.peek().is_none() {
        return Verdict::Unknown;
    }
    holds(known.any(|have| have.eq_ignore_ascii_case(wanted)))
}
