//! **Row Selection** (ADR-0072): the one mark a table puts on its selected row.
//!
//! The row wears the `▸` marker in its gutter and the selection across its
//! whole line: a fill, or reverse video in a theme with no fill to spare. In
//! the focused pane it is bold; in a pane without the focus it is the same row
//! and still marked, underlined where it has no fill, so moving the focus never
//! hides where the operator was. The table builds its gutter with [`gutter`]
//! and finishes the selected row with [`mark_row`].
//!
//! Beside it every scrollable list keeps a `Viewport` (`viewport`): what part
//! of it is on screen, which its scroll bar and its count are drawn from.

use ratatui::buffer::Buffer;
use ratatui::layout::Position;
use ratatui::style::{Color, Modifier, Style};
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

/// The style of the selected row: bold in the focused pane, plain in another.
/// It sets no foreground, so a row's own colours — a result's Known-File Mark,
/// a status, a withheld file's warning — still say what they say. Reverse
/// video swaps a row's colours and keeps their contrast.
#[must_use]
pub fn selection_style(theme: &Theme, focused: bool) -> Style {
    match (theme.selection, focused) {
        (Color::Reset, true) => Style::new().add_modifier(Modifier::BOLD | Modifier::REVERSED),
        (Color::Reset, false) => Style::new().add_modifier(Modifier::UNDERLINED),
        (fill, true) => Style::new().bg(fill).add_modifier(Modifier::BOLD),
        (fill, false) => Style::new().bg(fill),
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

/// Where the keys are, for the terminal's own cursor to rest on: an open
/// menu's item, else the focused pane's selected row. Those are the markers a
/// frame draws bold, and a row's alone wears the selection.
#[must_use]
pub fn focus_point(buffer: &Buffer, theme: &Theme) -> Option<Position> {
    let marker = MARKER.trim_end();
    let selection = selection_style(theme, true);
    let (bold, worn) = (Modifier::BOLD, selection.add_modifier);
    let mut row = None;
    for position in buffer.area.positions() {
        let cell = &buffer[position];
        if cell.symbol() != marker || !cell.modifier.contains(bold) {
            continue;
        }
        let selected =
            cell.modifier.contains(worn) && Some(cell.bg) == selection.bg.or(Some(Color::Reset));
        if !selected {
            return Some(position);
        }
        row = row.or(Some(position));
    }
    row
}

#[cfg(test)]
mod tests;
