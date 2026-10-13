//! **Row Selection** (ADR-0072): the one mark a table puts on its selected row.
//!
//! The row wears the `▸` marker in its gutter and the selection background
//! across its whole line. In the focused pane it is bold; in a pane without the
//! focus it is the same row, dimmed and still marked, so moving the focus never
//! hides where the operator was. A table drawn by ratatui's `Table` hands
//! [`selection_style`] to `row_highlight_style` and [`MARKER`] to
//! `highlight_symbol`; a table that draws its own lines builds its gutter with
//! [`gutter`] and finishes the selected row with [`mark_row`].
//!
//! Beside it every scrollable list keeps a `Viewport` (`viewport`): what part
//! of it is on screen, which its scroll bar and its count are drawn from.

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use crate::theme::Theme;

pub(crate) mod viewport;

/// The marker and its separator: the two gutter cells of a selected row.
pub const MARKER: &str = "▸ ";

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
/// selected row, blank otherwise.
#[must_use]
pub fn gutter(selected: bool, focused: bool, theme: &Theme) -> Span<'static> {
    if selected {
        Span::styled(MARKER, selection_style(theme, focused))
    } else {
        Span::raw("  ")
    }
}

/// Put the selection on every line of a row the table drew itself, gutter
/// included: the background runs to the pane's edge and the row keeps its own
/// colours, as a ratatui `Table` row does under its highlight style.
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
