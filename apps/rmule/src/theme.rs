//! Semantic theme tokens (spec §5, survey §4): call sites read roles, never
//! raw colors. Every palette sits behind the same struct (`palettes`); which
//! one a run gets follows the terminal's [`Capability`]. What colour cannot
//! carry, shape does: a theme with no accent reverses, underlines and draws a
//! heavy border, in the role methods here, so no view asks which theme it is.

use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, BorderType};

use crate::capability::{Capability, ColourTier};

pub mod contrast;
mod palettes;

/// One resolved palette for the run. The constructors below differ only
/// in the values; no call site may reach past a role to a literal color.
#[derive(Clone, Copy, Debug)]
pub struct Theme {
    /// A palette for a light ground.
    pub light: bool,
    /// Behind the whole frame. On the terminal's own ground it paints nothing.
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
    /// Text on a fill of [`accent`](Self::accent).
    pub on_accent: Color,
    /// Attention that is not a verdict: an edited field. Deliberately the
    /// same amber as [`warn`](Self::warn) in every palette.
    pub highlight: Color,
    /// Verdict on a state that needs nothing: connected, complete, High ID.
    pub good: Color,
    /// Verdict on a state that works but is degraded: Low ID, no contacts.
    pub warn: Color,
    /// Verdict on a state that failed or stopped.
    pub bad: Color,
    /// Background of the cursor row — a fill, never a text color. A theme
    /// with no fill to spare leaves it `Reset`, and the row reverses instead.
    pub selection: Color,
    /// A scroll bar's track: a solid column, behind the thumb and the `▲` `▼`.
    pub scroll_track: Color,
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
    /// The palette for a run: an explicit `RMULE_THEME` override
    /// (`dark`/`light`/`256`/`16`/`mono`) wins and paints what it names;
    /// otherwise the terminal's [`Capability`] picks the tier, and a terminal
    /// that said what its ground is keeps it and gets the palette for that
    /// side. One that did not say gets the opaque palette, the one ground
    /// every pair is known to read on.
    #[must_use]
    pub fn select(override_name: Option<&str>, capability: Capability) -> Self {
        let light = capability.light_ground == Some(true);
        match override_name {
            Some("light") => return Self::light(),
            Some("256") => return Self::fallback_256(),
            Some("16") => return Self::ansi_for(light),
            Some("dark") => return Self::default_dark(),
            Some("mono") => return Self::mono(),
            _ => {}
        }
        let opaque = match capability.colour {
            ColourTier::None => return Self::mono(),
            ColourTier::Ansi16 => return Self::ansi_for(light),
            ColourTier::Indexed256 if light => Self::light_256(),
            ColourTier::Indexed256 => Self::fallback_256(),
            ColourTier::Truecolor if light => Self::light(),
            ColourTier::Truecolor => Self::default_dark(),
        };
        if capability.light_ground.is_some() {
            opaque.on_own_ground()
        } else {
            opaque
        }
    }

    /// The sixteen-colour palette for a ground of this side.
    #[must_use]
    pub const fn ansi_for(light: bool) -> Self {
        if light {
            Self::ansi_light()
        } else {
            Self::ansi()
        }
    }

    /// Whether this theme has no colour to mark structure with, so shape
    /// must.
    #[must_use]
    pub fn colourless(&self) -> bool {
        self.accent == Color::Reset
    }

    /// The ground a pane sits in, bordered: the focused pane's border is the
    /// accent, or heavy and bold where there is no accent to show.
    #[must_use]
    pub fn pane(&self, focused: bool) -> Block<'static> {
        match (focused, self.colourless()) {
            (false, _) => Block::bordered().border_style(self.chrome()),
            (true, false) => Block::bordered().border_style(Style::new().fg(self.accent)),
            (true, true) => Block::bordered()
                .border_type(BorderType::Thick)
                .border_style(Style::new().add_modifier(Modifier::BOLD)),
        }
    }

    /// A pane's title, where the title follows the focus.
    #[must_use]
    pub fn pane_title(&self, focused: bool) -> Style {
        if focused {
            Style::new().fg(self.accent).add_modifier(Modifier::BOLD)
        } else {
            self.dim_text()
        }
    }

    /// A table's column headers, set off from the data by weight, and by a
    /// line where colour cannot help.
    #[must_use]
    pub fn header(&self) -> Style {
        let style = self.dim_text().add_modifier(Modifier::BOLD);
        if self.colourless() {
            style.add_modifier(Modifier::UNDERLINED)
        } else {
            style
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

    /// A scroll bar's thumb.
    #[must_use]
    pub fn thumb(&self) -> Style {
        Style::new().fg(self.fg)
    }

    /// A scroll bar's track column and its `▲` `▼`, on the track colour.
    #[must_use]
    pub fn scroll_track(&self) -> Style {
        Style::new().fg(self.dim).bg(self.scroll_track)
    }

    /// Whether a scroll bar may draw the thumb's edges part-way down a cell:
    /// only while the thumb's colour, `fg`, stands apart from the track's,
    /// `scroll_track`. A part-cell edge shows where the thumb ends by colour
    /// alone, so a theme without the contrast draws whole cells.
    #[must_use]
    pub fn thumb_in_eighths(&self) -> bool {
        self.fg != self.scroll_track
    }

    /// The label of the field a form's cursor is on: the accent, reversed
    /// where there is no accent.
    #[must_use]
    pub fn focused_label(&self) -> Style {
        if self.colourless() {
            self.accent_fill()
        } else {
            Style::new().fg(self.accent)
        }
    }

    /// Text on the accent: a fill that reverses where there is no accent.
    #[must_use]
    pub fn accent_fill(&self) -> Style {
        if self.colourless() {
            Style::new().add_modifier(Modifier::REVERSED)
        } else {
            Style::new().fg(self.on_accent).bg(self.accent)
        }
    }

    /// The active tab: accent-inverted (spec §3.1).
    #[must_use]
    pub fn tab_active(&self) -> Style {
        self.accent_fill().add_modifier(Modifier::BOLD)
    }

    /// Inactive tabs.
    #[must_use]
    pub fn tab_inactive(&self) -> Style {
        Style::new().fg(self.dim)
    }

    /// The transient action flash (✱): the accent, because a receipt is not a
    /// warning and amber is the warning's colour.
    #[must_use]
    pub fn flash(&self) -> Style {
        Style::new().fg(self.accent).add_modifier(Modifier::BOLD)
    }
}

impl Default for Theme {
    fn default() -> Self {
        Self::default_dark()
    }
}

#[cfg(test)]
mod tests;
