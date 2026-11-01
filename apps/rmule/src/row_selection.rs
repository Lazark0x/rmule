//! **Row Selection** (ADR-0072): the one mark a table puts on its selected row.
//!
//! The row wears the `▸` marker in its gutter and the selection background
//! across its whole line. In the focused pane it is bold; in a pane without the
//! focus it is the same row, dimmed and still marked, so moving the focus never
//! hides where the operator was. The table builds its gutter with [`gutter`]
//! and finishes the selected row with [`mark_row`].
//!
//! Beside it every scrollable list keeps a `Viewport` (`viewport`): what part
//! of it is on screen, which its scroll bar and its count are drawn from.

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use crate::theme::Theme;

pub(crate) mod tags;
pub(crate) mod viewport;

/// The marker and its separator: the two gutter cells of a selected row.
pub const MARKER: &str = "▸ ";

/// A tagged row's gutter.
pub const TAGGED: &str = " •";

/// The gutter of a tagged row under the cursor.
const BOTH: &str = "▸•";

/// The style of the selected row: bold in the focused pane, dimmed in another.
/// It sets no foreground, so a row's own colours — a result's Known-File Mark,
/// a status, a withheld file's warning — still say what they say.
#[must_use]
pub fn selection_style(theme: &Theme, focused: bool) -> Style {
    let style = Style::new().bg(theme.selection);
    if focused {
        style.add_modifier(Modifier::BOLD)
    } else {
        style.add_modifier(Modifier::DIM)
    }
}

/// The two-cell gutter of a row the table draws itself: the marker on the
/// selected row, then the mark of a tagged one.
#[must_use]
pub fn gutter(selected: bool, tagged: bool, focused: bool, theme: &Theme) -> Span<'static> {
    let tag = Style::new().fg(theme.accent);
    match (selected, tagged) {
        (true, false) => Span::styled(MARKER, selection_style(theme, focused)),
        (true, true) => Span::styled(BOTH, selection_style(theme, focused).fg(theme.accent)),
        (false, true) => Span::styled(TAGGED, tag),
        (false, false) => Span::raw("  "),
    }
}

/// Put the selection on every line of a row the table drew itself, gutter
/// included: the background runs to the pane's edge and the row keeps its own
/// colours.
pub fn mark_row(lines: &mut [Line<'static>], focused: bool, theme: &Theme) {
    let style = selection_style(theme, focused);
    for line in lines {
        line.style = line.style.patch(style);
        for span in &mut line.spans {
            span.style = span.style.patch(style);
        }
    }
}

#[cfg(test)]
mod tests;
