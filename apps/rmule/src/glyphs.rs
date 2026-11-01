//! Which glyphs a frame ends in. Views draw one set, the Unicode one; the
//! [`GlyphTier`] rewrites the finished frame, cell for cell, so a terminal
//! that cannot show that set takes no layout of its own and no view can miss
//! a mark.
//!
//! Box drawing and the marks are East Asian Ambiguous, and most are outside
//! the Linux console's font. Every replacement is one ASCII cell.

use ratatui::buffer::Buffer;

/// Which glyphs the terminal draws one cell wide.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GlyphTier {
    /// Everything.
    #[default]
    Unicode,
    /// The operator's own text, but not the frame's marks: an ambiguous-wide
    /// terminal, and a console font that lacks them.
    Plain,
    /// ASCII alone: a terminal on a legacy charset. Text outside ASCII shows
    /// as `?`, which keeps the columns; its bytes would draw as noise.
    Ascii,
}

impl GlyphTier {
    /// Rewrite a finished frame.
    pub fn apply(self, buffer: &mut Buffer) {
        if self == Self::Unicode {
            return;
        }
        for cell in &mut buffer.content {
            let symbol = cell.symbol();
            if symbol.is_ascii() {
                continue;
            }
            let mut chars = symbol.chars();
            let plain = match (chars.next().and_then(plain_mark), chars.next()) {
                (Some(mark), None) => mark,
                _ if self == Self::Ascii => '?',
                _ => continue,
            };
            cell.set_char(plain);
        }
    }

    /// Rewrite text for somewhere a frame does not reach: the terminal's title.
    #[must_use]
    pub fn text(self, text: &str) -> String {
        match self {
            Self::Unicode => text.to_string(),
            Self::Plain => text.chars().map(|c| plain_mark(c).unwrap_or(c)).collect(),
            Self::Ascii => text
                .chars()
                .map(|c| {
                    if c.is_ascii() {
                        c
                    } else {
                        plain_mark(c).unwrap_or('?')
                    }
                })
                .collect(),
        }
    }
}

/// The one ASCII cell for a frame mark or a typographic sign in a sentence.
fn plain_mark(mark: char) -> Option<char> {
    Some(match mark {
        '─' | '╌' | '—' | '–' | '‐' | '−' => '-',
        '━' | '═' => '=',
        '│' | '┃' | '║' | '╎' => '|',
        '┌' | '┐' | '└' | '┘' | '├' | '┤' | '┬' | '┴' | '┼' => '+',
        '┏' | '┓' | '┗' | '┛' | '╔' | '╗' | '╚' | '╝' => '#',
        '▸' | '▶' | '❯' | '›' | '→' | '»' => '>',
        '‹' | '←' | '«' | '◂' => '<',
        '▲' | '↑' => '^',
        '▼' | '↓' => 'v',
        '█' | '▓' | '▮' | '▇' | '▆' | '▅' => '#',
        '▒' | '▄' | '▃' | '▂' | '▁' => '=',
        '░' | '·' | '…' => '.',
        '●' | '✱' | '•' => '*',
        '○' => 'o',
        '✗' | '×' => 'x',
        '✓' => '+',
        '≈' => '~',
        '≥' => '>',
        '≤' => '<',
        '’' | '‘' => '\'',
        '“' | '”' => '"',
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use ratatui::layout::Rect;
    use ratatui::style::Style;

    use super::*;

    fn line(text: &str) -> Buffer {
        let mut buffer = Buffer::empty(Rect::new(0, 0, 16, 1));
        buffer.set_string(0, 0, text, Style::new());
        buffer
    }

    fn drawn(buffer: &Buffer) -> String {
        let glyphs: String = buffer.content().iter().map(|cell| cell.symbol()).collect();
        glyphs.trim_end().to_string()
    }

    #[test]
    fn each_tier_keeps_what_its_terminal_can_show() {
        let mut plain = line("▸ Файл…");
        GlyphTier::Plain.apply(&mut plain);
        assert_eq!(drawn(&plain), "> Файл.");

        let mut ascii = line("▸ Файл…");
        GlyphTier::Ascii.apply(&mut ascii);
        assert_eq!(drawn(&ascii), "> ????.");

        let mut unicode = line("▸ Файл…");
        GlyphTier::Unicode.apply(&mut unicode);
        assert_eq!(drawn(&unicode), "▸ Файл…");
    }

    /// A double-width character gives up its width with its glyph, and the
    /// column after it still lines up.
    #[test]
    fn a_wide_character_keeps_its_columns() {
        let mut ascii = line("聖a");
        GlyphTier::Ascii.apply(&mut ascii);
        assert_eq!(drawn(&ascii), "? a");
    }

    /// Everything a golden draws that is not a fixture's own text has its
    /// one-cell replacement, so a new mark cannot slip through the tier.
    #[test]
    fn every_mark_a_golden_draws_has_a_replacement() {
        let goldens = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/goldens");
        let mut unmapped = std::collections::BTreeSet::new();
        for entry in std::fs::read_dir(goldens).expect("goldens") {
            let text = std::fs::read_to_string(entry.expect("entry").path()).expect("golden");
            unmapped.extend(
                text.chars()
                    .filter(|c| !c.is_ascii() && plain_mark(*c).is_none() && !is_fixture_text(*c)),
            );
        }
        assert!(unmapped.is_empty(), "{unmapped:?}");
    }

    /// The fixtures' Japanese file names.
    fn is_fixture_text(c: char) -> bool {
        matches!(c, '\u{3000}'..='\u{9FFF}')
    }
}
