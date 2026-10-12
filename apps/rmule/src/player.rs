//! The **Player Command** (ADR-0114): the operator's player as words split by
//! POSIX rules, never a shell line. Quotes and backslashes are honoured;
//! nothing is expanded, globbed or run as an operator, and a word starting
//! with `#` comments out the rest. The first word is the program, so it may
//! not hold [`PLACEHOLDER`]: the downloaded file is never the program run.

/// The word the download's path replaces, inside any word — aMule's, so an
/// aMule player string carries over.
pub const PLACEHOLDER: &str = "%PARTFILE";

/// Why a Player Command text does not split into a player's words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsplittable {
    /// A quote is never closed, or the text ends in a lone backslash.
    OpenQuote,
    /// No first word names a program: every word is a comment, or the first
    /// one holds [`PLACEHOLDER`].
    NoProgram,
}

/// Split `text` into the player's words.
///
/// # Errors
/// [`Unsplittable`] when the words do not split or do not start with a
/// program.
pub fn split(text: &str) -> Result<Vec<String>, Unsplittable> {
    let words = shlex::split(text).ok_or(Unsplittable::OpenQuote)?;
    match words.first() {
        Some(program) if !program.contains(PLACEHOLDER) => Ok(words),
        _ => Err(Unsplittable::NoProgram),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_text_splits_by_posix_rules_with_nothing_expanded() {
        assert_eq!(
            split(r#"'/opt/my player/mpv' --title="a b" \$HOME *.mkv # rest"#),
            Ok(vec![
                "/opt/my player/mpv".to_string(),
                "--title=a b".to_string(),
                "$HOME".to_string(),
                "*.mkv".to_string(),
            ])
        );
    }

    #[test]
    fn an_open_quote_or_a_lone_backslash_is_refused() {
        assert_eq!(split(r#"mpv "--title=a"#), Err(Unsplittable::OpenQuote));
        assert_eq!(split(r"mpv \"), Err(Unsplittable::OpenQuote));
    }

    #[test]
    fn a_first_word_that_is_the_file_or_no_word_at_all_is_refused() {
        assert_eq!(split("%PARTFILE --fs"), Err(Unsplittable::NoProgram));
        assert_eq!(split("x%PARTFILE"), Err(Unsplittable::NoProgram));
        assert_eq!(split("# only a comment"), Err(Unsplittable::NoProgram));
        assert_eq!(
            split("vlc %PARTFILE"),
            Ok(vec!["vlc".to_string(), "%PARTFILE".to_string()])
        );
    }
}
