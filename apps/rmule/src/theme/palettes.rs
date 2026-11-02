//! Every palette in one place: the same roles, and only the values differ.
//! Each pair a frame draws reads at 4.5:1 or better on its own ground (WCAG
//! 1.4.3), the test beside the theme's mark test measures every one, and the
//! grounds a selected row and a scroll bar put under text are tuned for it.

use ratatui::style::Color;

use super::Theme;

impl Theme {
    /// The truecolor dark palette (spec §5).
    #[must_use]
    pub const fn default_dark() -> Self {
        Self {
            light: false,
            bg: Color::Rgb(0x10, 0x12, 0x18),
            panel: Color::Rgb(0x18, 0x1B, 0x23),
            fg: Color::Rgb(0xD6, 0xDB, 0xE6),
            dim: Color::Rgb(0x90, 0x96, 0xA5),
            accent: Color::Rgb(0x56, 0xB6, 0xC2),
            on_accent: Color::Rgb(0x10, 0x12, 0x18),
            highlight: Color::Rgb(0xE0, 0xAF, 0x68),
            good: Color::Rgb(0x78, 0xBE, 0x6E),
            warn: Color::Rgb(0xE0, 0xAF, 0x68),
            bad: Color::Rgb(0xDC, 0x7C, 0x75),
            selection: Color::Rgb(0x26, 0x2C, 0x39),
            scroll_track: Color::Rgb(0x23, 0x27, 0x31),
            mark_downloading: Color::Rgb(0x7A, 0xA2, 0xF7),
            mark_failed: Color::Rgb(0xF7, 0x76, 0x8E),
            mark_have: Color::Rgb(0xBB, 0x9A, 0xF7),
            mark_withheld: Color::Rgb(0x9A, 0xA8, 0xD8),
            mark_had: Color::Rgb(0xE0, 0x8F, 0xB0),
            mark_cancelled: Color::Rgb(0xA6, 0xB0, 0xB4),
        }
    }

    /// The light variant (spec §5): same roles, contrast-inverted, accents
    /// darkened for light-background legibility.
    #[must_use]
    pub const fn light() -> Self {
        Self {
            light: true,
            bg: Color::Rgb(0xF2, 0xF3, 0xF7),
            panel: Color::Rgb(0xE8, 0xEA, 0xF0),
            fg: Color::Rgb(0x2A, 0x2F, 0x3A),
            dim: Color::Rgb(0x57, 0x5D, 0x68),
            accent: Color::Rgb(0x0B, 0x67, 0x73),
            on_accent: Color::Rgb(0xF2, 0xF3, 0xF7),
            highlight: Color::Rgb(0x80, 0x52, 0x00),
            good: Color::Rgb(0x2E, 0x68, 0x26),
            warn: Color::Rgb(0x80, 0x52, 0x00),
            bad: Color::Rgb(0xA3, 0x36, 0x2C),
            selection: Color::Rgb(0xDC, 0xE1, 0xEB),
            scroll_track: Color::Rgb(0xD6, 0xDA, 0xE4),
            mark_downloading: Color::Rgb(0x2C, 0x57, 0xB4),
            mark_failed: Color::Rgb(0xB0, 0x22, 0x47),
            mark_have: Color::Rgb(0x7A, 0x3F, 0xB0),
            mark_withheld: Color::Rgb(0x4A, 0x55, 0x8C),
            mark_had: Color::Rgb(0x9C, 0x36, 0x66),
            mark_cancelled: Color::Rgb(0x3F, 0x5C, 0x6B),
        }
    }

    /// Hand-tuned 256-color-safe fallback (spec §5): no auto-quantization
    /// exists in ratatui/crossterm (survey §4), so terminals without
    /// truecolor get real `Indexed` picks, not mangled RGB.
    #[must_use]
    pub const fn fallback_256() -> Self {
        Self {
            light: false,
            bg: Color::Indexed(233), // near #121212
            panel: Color::Indexed(234),
            fg: Color::Indexed(253),        // #dadada
            dim: Color::Indexed(248),       // #a8a8a8
            accent: Color::Indexed(73),     // #5fafaf cadet cyan
            on_accent: Color::Indexed(233), // near #121212
            highlight: Color::Indexed(179), // #d7af5f amber
            good: Color::Indexed(71),       // #5faf5f
            warn: Color::Indexed(179),
            bad: Color::Indexed(174),              // #d78787
            selection: Color::Indexed(236),        // #303030
            scroll_track: Color::Indexed(235),     // #262626
            mark_downloading: Color::Indexed(111), // #87afff
            mark_failed: Color::Indexed(204),      // #ff5f87
            mark_have: Color::Indexed(141),        // #af87ff
            mark_withheld: Color::Indexed(146),    // #afafd7
            mark_had: Color::Indexed(175),         // #d787af
            mark_cancelled: Color::Indexed(173),   // #d7875f
        }
    }

    /// The 256-colour palette for a terminal that says its ground is light.
    #[must_use]
    pub const fn light_256() -> Self {
        Self {
            light: true,
            bg: Color::Indexed(255), // #eeeeee
            panel: Color::Indexed(254),
            fg: Color::Indexed(236),        // #303030
            dim: Color::Indexed(240),       // #585858
            accent: Color::Indexed(24),     // #005f87
            on_accent: Color::Indexed(255), // #eeeeee
            highlight: Color::Indexed(58),  // #5f5f00
            good: Color::Indexed(22),       // #005f00
            warn: Color::Indexed(58),
            bad: Color::Indexed(124),             // #af0000
            selection: Color::Indexed(253),       // #dadada
            scroll_track: Color::Indexed(253),    // #dadada
            mark_downloading: Color::Indexed(25), // #005faf
            mark_failed: Color::Indexed(125),     // #af005f
            mark_have: Color::Indexed(54),        // #5f0087
            mark_withheld: Color::Indexed(17),    // #00005f
            mark_had: Color::Indexed(89),         // #87005f
            mark_cancelled: Color::Indexed(52),   // #5f0000
        }
    }

    /// The sixteen named colours on the terminal's own ground, which the
    /// Linux console and its kin paint black. A selected row reverses, so a
    /// row's own colours keep their contrast, and no fill is needed.
    #[must_use]
    pub const fn ansi() -> Self {
        Self {
            light: false,
            bg: Color::Reset,
            panel: Color::Reset,
            fg: Color::Reset,
            dim: Color::Gray,
            accent: Color::LightCyan,
            on_accent: Color::Black,
            highlight: Color::LightYellow,
            good: Color::LightGreen,
            warn: Color::LightYellow,
            bad: Color::LightRed,
            selection: Color::Reset,
            scroll_track: Color::Reset,
            mark_downloading: Color::Cyan,
            mark_failed: Color::LightRed,
            mark_have: Color::LightMagenta,
            mark_withheld: Color::LightCyan,
            mark_had: Color::LightYellow,
            mark_cancelled: Color::White,
        }
    }

    /// The sixteen named colours on a light ground, which leaves few that
    /// read: a verdict that needs nothing is black, and its word says it.
    #[must_use]
    pub const fn ansi_light() -> Self {
        Self {
            light: true,
            bg: Color::Reset,
            panel: Color::Reset,
            fg: Color::Reset,
            dim: Color::Reset,
            accent: Color::Blue,
            on_accent: Color::White,
            highlight: Color::Magenta,
            good: Color::Black,
            warn: Color::Magenta,
            bad: Color::Red,
            selection: Color::Reset,
            scroll_track: Color::Reset,
            mark_downloading: Color::Blue,
            mark_failed: Color::Red,
            mark_have: Color::Magenta,
            mark_withheld: Color::Yellow,
            mark_had: Color::LightBlue,
            mark_cancelled: Color::DarkGray,
        }
    }

    /// No colour at all: the terminal's own, for `NO_COLOR` and a terminal
    /// without any. The words, the `▸`, and reverse, bold, underline and a
    /// heavy border carry everything; every role is the terminal's default.
    #[must_use]
    pub const fn mono() -> Self {
        let none = Color::Reset;
        Self {
            light: false,
            bg: none,
            panel: none,
            fg: none,
            dim: none,
            accent: none,
            on_accent: none,
            highlight: none,
            good: none,
            warn: none,
            bad: none,
            selection: none,
            scroll_track: none,
            mark_downloading: none,
            mark_failed: none,
            mark_have: none,
            mark_withheld: none,
            mark_had: none,
            mark_cancelled: none,
        }
    }

    /// This palette on the terminal's own ground, for a terminal that said
    /// what its ground is: the frame paints none of its own.
    #[must_use]
    pub const fn on_own_ground(self) -> Self {
        Self {
            bg: Color::Reset,
            ..self
        }
    }
}
