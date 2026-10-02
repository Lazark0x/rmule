//! Semantic theme tokens (spec §5, survey §4): call sites read roles, never
//! raw colors. The locked truecolor dark default, the light variant and the
//! hand-tuned 256-safe one all sit behind the same struct.

use ratatui::style::{Color, Modifier, Style};

#[derive(Clone, Copy, Debug)]
/// One resolved palette for the run. The three constructors below differ only
/// in the values; no call site may reach past a role to a literal color.
pub struct Theme {
    /// Behind the whole frame.
    pub bg: Color,
    /// Fill for surfaces drawn on top of it — tables, the help overlay.
    pub panel: Color,
    /// Default text.
    pub fg: Color,
    /// Secondary text and frame furniture: units, hints, placeholders.
    pub dim: Color,
    /// The one hue marking structure worth following — focused border, active
    /// tab, key names.
    pub accent: Color,
    /// Attention that is not a verdict: the action flash, an edited field.
    /// Deliberately the same amber as [`warn`](Self::warn) in every palette.
    pub highlight: Color,
    /// Verdict on a state that needs nothing: connected, complete, High ID.
    pub good: Color,
    /// Verdict on a state that works but is degraded: Low ID, no contacts.
    pub warn: Color,
    /// Verdict on a state that failed or stopped.
    pub bad: Color,
    /// Background of the cursor row — a fill, never a text color.
    pub selection: Color,
    /// A search result already downloading or paused (ADR-0100, Known-File
    /// Marks). The mark colours stand apart from the source tints — `good`,
    /// `fg`, `dim` — so a mark never reads as a source count.
    pub mark_downloading: Color,
    /// A search result whose download failed and still holds its place
    /// (ADR-0094, "Failed"): its re-add restarts that download.
    pub mark_failed: Color,
    /// A search result in the Shared File Registry: on disk now.
    pub mark_have: Color,
    /// A search result in the Shared File Registry that rmule cannot read now:
    /// neither on disk for certain nor gone.
    pub mark_withheld: Color,
    /// A search result in the Had Set: once shared, since gone from the disk.
    pub mark_had: Color,
    /// A search result the operator cancelled before it completed.
    pub mark_cancelled: Color,
}

impl Theme {
    /// The prototype-locked dark palette (spec §5).
    #[must_use]
    pub const fn default_dark() -> Self {
        Self {
            bg: Color::Rgb(0x10, 0x12, 0x18),
            panel: Color::Rgb(0x18, 0x1B, 0x23),
            fg: Color::Rgb(0xD6, 0xDB, 0xE6),
            dim: Color::Rgb(0x78, 0x80, 0x91),
            accent: Color::Rgb(0x56, 0xB6, 0xC2),
            highlight: Color::Rgb(0xE0, 0xAF, 0x68),
            good: Color::Rgb(0x78, 0xBE, 0x6E),
            warn: Color::Rgb(0xE0, 0xAF, 0x68),
            bad: Color::Rgb(0xD6, 0x69, 0x61),
            selection: Color::Rgb(0x2D, 0x34, 0x42),
            mark_downloading: Color::Rgb(0x7A, 0xA2, 0xF7),
            mark_failed: Color::Rgb(0xF7, 0x76, 0x8E),
            mark_have: Color::Rgb(0xBB, 0x9A, 0xF7),
            mark_withheld: Color::Rgb(0x9A, 0xA8, 0xD8),
            mark_had: Color::Rgb(0xE0, 0x8F, 0xB0),
            mark_cancelled: Color::Rgb(0xB0, 0x8A, 0x78),
        }
    }

    /// The light variant (spec §5): same roles, contrast-inverted, accents
    /// darkened for light-background legibility.
    #[must_use]
    pub const fn light() -> Self {
        Self {
            bg: Color::Rgb(0xF2, 0xF3, 0xF7),
            panel: Color::Rgb(0xE8, 0xEA, 0xF0),
            fg: Color::Rgb(0x2A, 0x2F, 0x3A),
            dim: Color::Rgb(0x6B, 0x72, 0x80),
            accent: Color::Rgb(0x0E, 0x7C, 0x8A),
            highlight: Color::Rgb(0xA5, 0x6A, 0x00),
            good: Color::Rgb(0x3E, 0x8A, 0x34),
            warn: Color::Rgb(0xA5, 0x6A, 0x00),
            bad: Color::Rgb(0xB0, 0x3A, 0x30),
            selection: Color::Rgb(0xC9, 0xD0, 0xDE),
            mark_downloading: Color::Rgb(0x2E, 0x5B, 0xBA),
            mark_failed: Color::Rgb(0xC4, 0x26, 0x4F),
            mark_have: Color::Rgb(0x7A, 0x3F, 0xB0),
            mark_withheld: Color::Rgb(0x4A, 0x55, 0x8C),
            mark_had: Color::Rgb(0xA8, 0x3A, 0x6E),
            mark_cancelled: Color::Rgb(0x8A, 0x5A, 0x44),
        }
    }

    /// Hand-tuned 256-color-safe fallback (spec §5): no auto-quantization
    /// exists in ratatui/crossterm (survey §4), so terminals without
    /// truecolor get real `Indexed` picks, not mangled RGB.
    #[must_use]
    pub const fn fallback_256() -> Self {
        Self {
            bg: Color::Indexed(233), // near #121212
            panel: Color::Indexed(234),
            fg: Color::Indexed(253),        // #dadada
            dim: Color::Indexed(245),       // #8a8a8a
            accent: Color::Indexed(73),     // #5fafaf cadet cyan
            highlight: Color::Indexed(179), // #d7af5f amber
            good: Color::Indexed(71),       // #5faf5f
            warn: Color::Indexed(179),
            bad: Color::Indexed(167),              // #d75f5f
            selection: Color::Indexed(237),        // #3a3a3a
            mark_downloading: Color::Indexed(111), // #87afff
            mark_failed: Color::Indexed(204),      // #ff5f87
            mark_have: Color::Indexed(141),        // #af87ff
            mark_withheld: Color::Indexed(146),    // #afafd7
            mark_had: Color::Indexed(175),         // #d787af
            mark_cancelled: Color::Indexed(137),   // #af875f
        }
    }

    /// Pure theme selection from environment facts (spec §5 degrade story):
    /// an explicit `RMULE_THEME` override (`dark`/`light`/`256`) wins;
    /// otherwise the `COLORTERM=truecolor|24bit` convention decides between
    /// the truecolor dark default and the 256-safe fallback. Detection stays
    /// in the caller; this function never reads the environment itself.
    #[must_use]
    pub fn select(override_name: Option<&str>, colorterm: Option<&str>) -> Self {
        match override_name {
            Some("light") => return Self::light(),
            Some("256") => return Self::fallback_256(),
            Some("dark") => return Self::default_dark(),
            _ => {}
        }
        let truecolor = colorterm.is_some_and(|v| v == "truecolor" || v == "24bit");
        if truecolor {
            Self::default_dark()
        } else {
            Self::fallback_256()
        }
    }

    /// Whole-frame base: foreground on the app background.
    #[must_use]
    pub fn base(&self) -> Style {
        Style::new().fg(self.fg).bg(self.bg)
    }

    /// Borders and frame furniture.
    #[must_use]
    pub fn chrome(&self) -> Style {
        Style::new().fg(self.dim)
    }

    /// De-emphasized text (placeholders, degrade states, separators).
    #[must_use]
    pub fn dim_text(&self) -> Style {
        Style::new().fg(self.dim)
    }

    /// The active tab: accent-inverted (spec §3.1).
    #[must_use]
    pub fn tab_active(&self) -> Style {
        Style::new()
            .fg(self.bg)
            .bg(self.accent)
            .add_modifier(Modifier::BOLD)
    }

    /// Inactive tabs.
    #[must_use]
    pub fn tab_inactive(&self) -> Style {
        Style::new().fg(self.dim)
    }

    /// The transient action flash (amber ✱, spec §3.1).
    #[must_use]
    pub fn flash(&self) -> Style {
        Style::new().fg(self.highlight).add_modifier(Modifier::BOLD)
    }
}

impl Default for Theme {
    fn default() -> Self {
        Self::default_dark()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_prefers_the_explicit_override() {
        let light = Theme::select(Some("light"), Some("truecolor"));
        assert_eq!(light.bg, Theme::light().bg);
        let forced_256 = Theme::select(Some("256"), Some("truecolor"));
        assert_eq!(forced_256.bg, Theme::fallback_256().bg);
    }

    #[test]
    fn truecolor_detection_gates_the_dark_default() {
        assert_eq!(
            Theme::select(None, Some("truecolor")).bg,
            Theme::default_dark().bg
        );
        assert_eq!(
            Theme::select(None, Some("24bit")).bg,
            Theme::default_dark().bg
        );
        assert_eq!(Theme::select(None, None).bg, Theme::fallback_256().bg);
        assert_eq!(
            Theme::select(None, Some("yes")).bg,
            Theme::fallback_256().bg
        );
    }

    /// ADR-0100: a marked row trades its source tint for the mark's colour,
    /// so in every palette a mark must differ from each tint and from the
    /// other marks, or the eye reads one as the other.
    #[test]
    fn every_mark_colour_stands_apart_from_the_source_tints_and_each_other() {
        for t in [Theme::default_dark(), Theme::light(), Theme::fallback_256()] {
            let marks = [
                t.mark_downloading,
                t.mark_failed,
                t.mark_have,
                t.mark_withheld,
                t.mark_had,
                t.mark_cancelled,
            ];
            for (i, mark) in marks.iter().enumerate() {
                for tint in [t.good, t.fg, t.dim] {
                    assert_ne!(*mark, tint);
                }
                assert!(!marks[i + 1..].contains(mark), "{mark:?} twice");
            }
        }
    }

    #[test]
    fn the_256_fallback_uses_no_rgb_values_anywhere() {
        // The whole point of the hand-tuned theme (spec §5): a non-truecolor
        // terminal must never receive an RGB escape it would mangle.
        let t = Theme::fallback_256();
        for color in [
            t.bg,
            t.panel,
            t.fg,
            t.dim,
            t.accent,
            t.highlight,
            t.good,
            t.warn,
            t.bad,
            t.selection,
            t.mark_downloading,
            t.mark_failed,
            t.mark_have,
            t.mark_withheld,
            t.mark_had,
            t.mark_cancelled,
        ] {
            assert!(
                matches!(color, Color::Indexed(_)),
                "fallback theme leaked a non-indexed color: {color:?}"
            );
        }
    }
}
