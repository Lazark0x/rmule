//! What this terminal can show, read once at the start: the environment's
//! claims and the terminal's own answers (`probe`) become one [`Capability`],
//! from which the theme takes its tier and its side of the ground and the
//! frame its glyph tier. Pure, so every reading is proven without a terminal.

use crate::glyphs::GlyphTier;
use crate::probe::Answers;

/// The environment's facts about the terminal.
#[derive(Clone, Copy, Debug, Default)]
pub struct TerminalEnv<'a> {
    /// `COLORTERM`.
    pub colorterm: Option<&'a str>,
    /// `TERM`.
    pub term: Option<&'a str>,
    /// `NO_COLOR` is set and not empty.
    pub no_color: bool,
    /// The locale that rules character types: `LC_ALL`, `LC_CTYPE` or `LANG`,
    /// the first that is set and not empty.
    pub locale: Option<&'a str>,
}

/// How many colours the terminal has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColourTier {
    /// Any colour by its value.
    Truecolor,
    /// The xterm 256-colour table.
    Indexed256,
    /// The sixteen named colours, as the terminal's own settings paint them.
    Ansi16,
    /// None: asked for by `NO_COLOR`, or a terminal without any.
    None,
}

/// What a run's terminal can show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capability {
    /// How many colours.
    pub colour: ColourTier,
    /// Whether the terminal's ground is light, if it said what it is.
    pub light_ground: Option<bool>,
    /// Which glyphs it draws one cell wide.
    pub glyphs: GlyphTier,
}

impl Capability {
    /// Read the environment and the terminal's answers together. An answer
    /// beats a claim: a terminal that measured its own glyph says more than
    /// a locale, and `LC_ALL=C` on a UTF-8 terminal is common and harmless.
    #[must_use]
    pub fn read(env: TerminalEnv<'_>, answers: &Answers) -> Self {
        Self {
            colour: colour_tier(env),
            light_ground: answers.background.map(crate::theme::contrast::is_light),
            glyphs: glyph_tier(env, answers.box_cells),
        }
    }
}

fn colour_tier(env: TerminalEnv<'_>) -> ColourTier {
    if env.no_color {
        return ColourTier::None;
    }
    if env
        .colorterm
        .is_some_and(|value| value == "truecolor" || value == "24bit")
    {
        return ColourTier::Truecolor;
    }
    match env.term {
        Some("linux" | "ansi" | "cons25") => ColourTier::Ansi16,
        Some(term) if term.ends_with("-16color") => ColourTier::Ansi16,
        Some(term) if term.starts_with("vt") => ColourTier::None,
        _ => ColourTier::Indexed256,
    }
}

/// `box_cells`: how far the terminal's cursor moved over one box-drawing
/// character. Two cells is an ambiguous-wide terminal; more is a terminal
/// taking the character's three bytes for three characters. Without that
/// measure a named legacy charset goes by its name, and a console whose font
/// holds few of the marks by its `TERM`.
fn glyph_tier(env: TerminalEnv<'_>, box_cells: Option<u16>) -> GlyphTier {
    match box_cells {
        Some(3..) => return GlyphTier::Ascii,
        Some(2) => return GlyphTier::Plain,
        None if env.locale.is_some_and(names_legacy_charset) => return GlyphTier::Ascii,
        _ => {}
    }
    match env.term {
        Some("linux" | "ansi" | "cons25") => GlyphTier::Plain,
        Some(term) if term.starts_with("vt") => GlyphTier::Plain,
        _ => GlyphTier::Unicode,
    }
}

/// A locale naming a charset other than UTF-8: `ru_RU.KOI8-R`, not `C`, whose
/// terminal is usually UTF-8 all the same.
fn names_legacy_charset(locale: &str) -> bool {
    let Some((_, charset)) = locale.split_once('.') else {
        return false;
    };
    let charset = charset.split('@').next().unwrap_or(charset);
    !charset.eq_ignore_ascii_case("utf-8") && !charset.eq_ignore_ascii_case("utf8")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tier_of(term: &str) -> ColourTier {
        let env = TerminalEnv {
            term: Some(term),
            ..TerminalEnv::default()
        };
        colour_tier(env)
    }

    #[test]
    fn a_console_with_sixteen_colours_gets_them_and_one_with_none_gets_none() {
        for term in ["linux", "ansi", "cons25", "xterm-16color"] {
            assert_eq!(tier_of(term), ColourTier::Ansi16, "{term}");
        }
        assert_eq!(tier_of("vt100"), ColourTier::None);
        assert_eq!(tier_of("xterm-256color"), ColourTier::Indexed256);
    }

    #[test]
    fn no_color_beats_what_the_terminal_claims() {
        let env = TerminalEnv {
            colorterm: Some("truecolor"),
            no_color: true,
            ..TerminalEnv::default()
        };
        assert_eq!(colour_tier(env), ColourTier::None);
    }

    fn glyphs(term: &str, locale: &str, box_cells: Option<u16>) -> GlyphTier {
        let env = TerminalEnv {
            term: Some(term),
            locale: Some(locale),
            ..TerminalEnv::default()
        };
        glyph_tier(env, box_cells)
    }

    #[test]
    fn the_terminals_own_measure_beats_the_locale() {
        let tier = |cells| glyphs("xterm", "ru_RU.KOI8-R", cells);
        assert_eq!(tier(Some(1)), GlyphTier::Unicode, "it does read UTF-8");
        assert_eq!(tier(Some(3)), GlyphTier::Ascii);
        assert_eq!(tier(None), GlyphTier::Ascii, "the name is all there is");
        let c_locale = |cells| glyphs("xterm", "C", cells);
        assert_eq!(c_locale(None), GlyphTier::Unicode);
        assert_eq!(c_locale(Some(1)), GlyphTier::Unicode);
        assert_eq!(c_locale(Some(3)), GlyphTier::Ascii);
    }

    #[test]
    fn an_ambiguous_wide_terminal_and_a_console_keep_their_text_and_lose_the_marks() {
        assert_eq!(glyphs("xterm", "ja_JP.UTF-8", Some(2)), GlyphTier::Plain);
        assert_eq!(glyphs("linux", "en_US.UTF-8", Some(1)), GlyphTier::Plain);
        assert_eq!(glyphs("vt220", "en_US.UTF-8", None), GlyphTier::Plain);
        assert_eq!(glyphs("xterm", "en_US.utf8", Some(1)), GlyphTier::Unicode);
    }
}
