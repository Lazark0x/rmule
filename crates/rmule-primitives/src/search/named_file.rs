//! A search that names one file by its hash. ed2k-server reads these forms as
//! Lugdunum's `Is_ed2k_search` does (`proto/search.rs:118`) and answers them
//! from its hash index, so the answer carries none of the phrase's words and
//! only the hash can prove it (ADR-0034).

use crate::{FileHash, KeywordQuery};

const FILE_LINK: &[u8] = b"ed2k://|file|";
const MAGNET_ED2KHASH: &[u8] = b"magnet:?xt=urn:ed2khash:";
const MAGNET_ED2K: &[u8] = b"magnet:?xt=urn:ed2k:";
const SHORT_FORM: &[u8] = b"ed2k:";
/// A hash's hex digits; whatever follows them is not read.
const HEX_LEN: usize = FileHash::BYTE_LEN * 2;

/// The file a search names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NamedFile {
    pub(super) file_hash: FileHash,
    /// The size the phrase gave; `None` when it gave none or gave 0, which a
    /// server reads the same way.
    pub(super) size: Option<u64>,
}

impl KeywordQuery {
    /// The file this query names by its hash. Only a query that goes out as
    /// one term and nothing else: a constraint joins the term in an AND, and a
    /// server then reads it as a word.
    pub(super) fn named_file(&self) -> Option<NamedFile> {
        let unconstrained = self.file_type().is_none()
            && self.min_size().is_none()
            && self.max_size().is_none()
            && self.min_availability().is_none()
            && self.extension().is_none();
        let terms = self.terms();
        match terms.as_slice() {
            [term] if unconstrained => read(term.as_bytes()),
            _ => None,
        }
    }
}

/// `word` as a file reference, in ed2k-server's forms. Its sixth, an
/// `<a href= ed2k://` link, holds a blank and so is never one word.
fn read(word: &[u8]) -> Option<NamedFile> {
    let (hash, size) = if let Some(link) = after_prefix(word, FILE_LINK) {
        // `NAME|SIZE|HASH`.
        let (_, after_name) = split_at_bar(link)?;
        let (size, digits) = leading_number(after_name);
        let (_, hash) = split_at_bar(&after_name[digits..])?;
        (hash, size)
    } else if let Some(hash) = after_prefix(word, MAGNET_ED2KHASH) {
        (hash, 0)
    } else if let Some(hash) = after_prefix(word, MAGNET_ED2K) {
        (hash, 0)
    } else {
        let rest = after_prefix(word, SHORT_FORM)?;
        let (size, digits) = leading_number(rest);
        (rest[digits..].strip_prefix(b":")?, size)
    };
    let file_hash = hex_hash(hash.get(..HEX_LEN)?)?;
    Some(NamedFile {
        file_hash,
        size: (size != 0).then_some(size),
    })
}

fn after_prefix<'a>(word: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let head = word.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &word[prefix.len()..])
}

fn split_at_bar(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let bar = bytes.iter().position(|byte| *byte == b'|')?;
    Some((&bytes[..bar], &bytes[bar + 1..]))
}

/// The digits `bytes` opens with, and how many there are; past `u64`, 0.
fn leading_number(bytes: &[u8]) -> (u64, usize) {
    let digits = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
    let value = std::str::from_utf8(&bytes[..digits])
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(0);
    (value, digits)
}

fn hex_hash(hex: &[u8]) -> Option<FileHash> {
    let mut bytes = [0u8; FileHash::BYTE_LEN];
    for (byte, pair) in bytes.iter_mut().zip(hex.chunks_exact(2)) {
        let high = char::from(pair[0]).to_digit(16)?;
        let low = char::from(pair[1]).to_digit(16)?;
        *byte = u8::try_from(high << 4 | low).ok()?;
    }
    Some(FileHash::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Ed2kFileClass, Ed2kText, SearchResult};

    const HEX: &str = "A1B2C3D4E5F60718293A4B5C6D7E8F90";

    fn query(phrase: &str) -> KeywordQuery {
        KeywordQuery::new(Ed2kText::from_utf8(phrase)).unwrap()
    }

    fn row(hex: &str, size: u64) -> SearchResult {
        let file_hash = hex_hash(hex.as_bytes()).unwrap();
        let name = vec![Ed2kText::from_utf8("field-recording.wav")];
        SearchResult::new(file_hash, size, name, Vec::new()).unwrap()
    }

    /// Every form the server reads as a hash, in any case, proves by the hash
    /// and, where it gave one, the size.
    #[test]
    fn each_form_the_server_reads_as_a_hash_proves_by_it() {
        let lower = HEX.to_lowercase();
        for (phrase, size) in [
            (format!("ed2k::{HEX}"), None),
            (format!("ED2K::{lower}"), None),
            (format!("ed2k:700:{HEX}"), Some(700)),
            (format!("ed2k://|file|a.iso|700|{HEX}|/"), Some(700)),
            (format!("magnet:?xt=urn:ed2k:{HEX}"), None),
            (format!("magnet:?xt=urn:ed2khash:{HEX}"), None),
        ] {
            let query = query(&phrase);
            assert_eq!(query.named_file().map(|file| file.size), Some(size));
            assert!(query.matches(&row(HEX, 700)), "{phrase}");
            assert!(!query.matches(&row(&"B".repeat(32), 700)), "{phrase}");
            assert_eq!(
                query.matches(&row(HEX, 701)),
                size.is_none(),
                "{phrase}: a size given must hold"
            );
        }
    }

    /// The server sends these down its keyword path, so the words decide.
    #[test]
    fn a_phrase_the_server_reads_as_words_names_no_file() {
        for phrase in [
            format!("ed2k::{}", &HEX[..31]),
            format!("ed2k::{}", "Z".repeat(32)),
            format!("{HEX} ed2k::{HEX}"),
            format!("ed2k://|server|1.2.3.4|4661|{HEX}"),
            HEX.to_owned(),
        ] {
            assert_eq!(query(&phrase).named_file(), None, "{phrase}");
        }
        let constrained = query(&format!("ed2k::{HEX}")).with_file_type(Ed2kFileClass::Audio);
        assert_eq!(constrained.named_file(), None);
    }
}
