//! How a typed phrase becomes the words a search sends
//! (`docs/protocol/search-request.md`): the lexer eMule and aMule run over the
//! search box, reduced to the all-AND queries rmule offers.
//!
//! Words are separated by whitespace and by `(` `)` — characters aMule's lexer
//! never puts inside a word (`Scanner.l:45`). A double-quoted run is one word
//! and keeps its quotes, as eMule sends it (`Scanner.l:454-456`). `AND` is the
//! join itself and is dropped; `OR` and `NOT` would need a boolean tree rmule
//! does not offer, so a phrase holding them is refused rather than sent with
//! them as words, which no counterparty does. Both clients refuse more than ten
//! operators (aMule `SearchList.cpp:113-115`), so more than eleven words are
//! refused too.
//!
//! Every separator is ASCII, so the lexer works on bytes: a phrase that is not
//! UTF-8 keeps its bytes on the wire.

/// The most words one query may hold: eleven words are ten ANDs.
pub(super) const MAX_WORDS: usize = 11;

/// Why a typed phrase cannot be sent as a keyword query — a code a front end
/// words.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum QueryFault {
    /// A double quote opens a run that never closes.
    #[error("search phrase has an unterminated quote")]
    UnterminatedQuote,
    /// `OR` or `NOT`, which need a boolean tree rmule does not offer.
    #[error("search phrase uses OR or NOT, which rmule does not offer")]
    BooleanOperator,
    /// No word at all, which would ask a server to match everything.
    #[error("search phrase must hold a word")]
    NoWord,
    /// More than eleven words — ten ANDs, the most either client sends.
    #[error("search phrase has more than eleven words")]
    TooManyWords,
}

/// The phrase's words, in order, or why the phrase cannot be sent.
pub(super) fn lex(phrase: &[u8]) -> Result<Vec<Vec<u8>>, QueryFault> {
    let mut words = Vec::new();
    let mut rest = phrase;
    while let Some((&first, tail)) = rest.split_first() {
        if first.is_ascii_whitespace() || first == b'(' || first == b')' {
            rest = tail;
        } else if first == b'"' {
            let Some(close) = tail.iter().position(|&byte| byte == b'"') else {
                return Err(QueryFault::UnterminatedQuote);
            };
            // An empty quoted run is no word (eMule `Scanner.l:465`).
            if close > 0 {
                words.push(rest[..close + 2].to_vec());
            }
            rest = &tail[close + 1..];
        } else {
            let end = rest
                .iter()
                .position(|&byte| byte.is_ascii_whitespace() || matches!(byte, b'(' | b')' | b'"'))
                .unwrap_or(rest.len());
            match &rest[..end] {
                b"AND" => {}
                b"OR" | b"NOT" => {
                    return Err(QueryFault::BooleanOperator);
                }
                word => words.push(word.to_vec()),
            }
            rest = &rest[end..];
        }
    }
    if words.is_empty() {
        return Err(QueryFault::NoWord);
    }
    if words.len() > MAX_WORDS {
        return Err(QueryFault::TooManyWords);
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::lex;

    fn words(phrase: &str) -> Vec<String> {
        lex(phrase.as_bytes())
            .expect("a phrase rmule sends")
            .into_iter()
            .map(|word| String::from_utf8(word).expect("utf-8"))
            .collect()
    }

    #[test]
    fn blanks_and_parentheses_separate_words_and_punctuation_stays_inside_one() {
        assert_eq!(words("  ubuntu   desktop "), ["ubuntu", "desktop"]);
        assert_eq!(words("ubuntu-22.04_lts (x64)"), ["ubuntu-22.04_lts", "x64"]);
        assert_eq!(words("café\tété"), ["café", "été"]);
    }

    #[test]
    fn a_quoted_run_is_one_word_with_its_quotes() {
        assert_eq!(
            words(r#"live "at wembley" 1986"#),
            ["live", r#""at wembley""#, "1986"]
        );
        assert_eq!(words(r#"a"b c"d"#), ["a", r#""b c""#, "d"]);
        assert_eq!(words(r#"x "" y"#), ["x", "y"], "an empty run is no word");
        assert!(lex(br#"x "open"#).is_err());
    }

    #[test]
    fn and_is_the_join_and_or_not_are_refused() {
        assert_eq!(words("rock AND roll"), ["rock", "roll"]);
        assert_eq!(words("rock and roll"), ["rock", "and", "roll"]);
        assert_eq!(words(r#""rock AND roll""#), [r#""rock AND roll""#]);
        assert!(lex(b"rock OR roll").is_err());
        assert!(lex(b"rock NOT roll").is_err());
        assert_eq!(words("-live"), ["-live"], "aMule has no minus rule");
    }

    #[test]
    fn a_phrase_needs_a_word_and_at_most_eleven() {
        assert!(lex(b"AND").is_err());
        assert!(lex(br#"() """#).is_err());
        assert_eq!(words("a b c d e f g h i j k").len(), 11);
        assert!(lex(b"a b c d e f g h i j k l").is_err());
    }
}
