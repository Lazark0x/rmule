//! De-truncation primitives: greedy column widths and wrap-overflow
//! text layout.
//!
//! One policy every surface in this crate shares, so no view budgets columns
//! or clips text its own way:
//!
//! - **Greedy widths** — the identity/name column of a row takes every column
//!   the fixed ones leave over ([`greedy_widths`]), so text can never be cut
//!   while free space exists.
//! - **Wrap overflow** — content that is genuinely wider than its column grows
//!   *down* instead of being clipped ([`wrap_text`], [`column_lines`],
//!   [`wrapped_cell`]). No renderer in this crate emits a truncation ellipsis.

use ratatui::style::Style;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::Cell;

/// Wrap `text` to at most `width` columns, breaking at a space when one falls
/// inside the window and hard-breaking any word that is wider than the whole
/// column. Always returns at least one line (empty input ⇒ one empty line).
///
/// Measured in `char`s, matching how the rest of the crate sizes cells.
pub(crate) fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= width {
        return vec![text.to_string()];
    }

    let mut lines = Vec::new();
    let mut start = 0usize;
    while start < chars.len() {
        if chars.len() - start <= width {
            lines.push(chars[start..].iter().collect());
            break;
        }
        // The window is one wider than the column: a space sitting exactly at
        // the boundary is consumed by the break rather than pushed down.
        let window = &chars[start..start + width + 1];
        match window.iter().rposition(|c| *c == ' ') {
            Some(cut) if cut > 0 => {
                lines.push(chars[start..start + cut].iter().collect());
                start += cut + 1;
            }
            // No usable break point — the word is longer than the column.
            _ => {
                lines.push(chars[start..start + width].iter().collect());
                start += width;
            }
        }
    }
    lines
}

/// Saturating `usize` → `u16` for rect dimensions.
pub(crate) fn clamp_u16(value: usize) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

/// What a table declares about its columns for [`greedy_widths`].
pub(crate) struct TableColumns<'a> {
    /// Each column's floor; the greedy column's is its floor, not its width.
    pub floors: &'a [usize],
    /// Each column's header as drawn — its label, plus the sort's arrow on
    /// the column holding it. A header is never split: no column is given
    /// less than its header.
    pub headers: &'a [usize],
    /// The greedy column, which absorbs the slack. It holds the free text; every
    /// other column holds bounded content and is served first, from `wants`.
    pub flex: usize,
    /// Each column's widest value drawn now, in cells and capped by the table,
    /// or `0` (and an empty slice) for a column with nothing to ask. Slack goes
    /// to these before it goes to `flex`, the column that gives way last
    /// first, so an endpoint, a phase or a rate is on one line whenever the
    /// pane has room for it and the free-text column gets what remains.
    pub wants: &'a [usize],
    /// The order columns give way in when the pane cannot hold every header
    /// on one line: the first listed goes first. The greedy column never
    /// gives way.
    pub give_way: &'a [usize],
}

/// Column widths where exactly one column is greedy: every column keeps at
/// least its floor and its header, and `flex` absorbs all the slack, so a
/// name column is never narrower than the pane allows.
///
/// A pane narrower than the floors shrinks every column toward its header,
/// in proportion to what each has above it — cells wrap, so a narrow column
/// costs height, never characters — and a header never wraps. A pane
/// narrower than the headers takes columns away in the table's give-way
/// order until the rest fit: a column that gave way is `0` wide, draws
/// nothing and still costs its gap, and the table says which ones are not
/// shown ([`gave_way`]). Only a pane too narrow for the greedy column's own
/// header falls back to shrinking every remaining column alike.
pub(crate) fn greedy_widths(total: usize, table: &TableColumns<'_>, gap: usize) -> Vec<usize> {
    let columns = table.floors.len();
    let header = |index: usize| table.headers.get(index).copied().unwrap_or(1).max(1);
    let floor: Vec<usize> = (0..columns)
        .map(|index| table.floors[index].max(header(index)))
        .collect();
    let gaps = gap * columns.saturating_sub(1);
    let room = total.saturating_sub(gaps);
    let natural: usize = floor.iter().sum();

    if room >= natural {
        let mut out = floor;
        let mut slack = room - natural;
        let served = table
            .give_way
            .iter()
            .rev()
            .copied()
            .chain((0..columns).filter(|index| !table.give_way.contains(index)));
        for index in served.filter(|index| *index != table.flex && *index < columns) {
            let want = table.wants.get(index).copied().unwrap_or(0);
            let raise = want.saturating_sub(out[index]).min(slack);
            out[index] += raise;
            slack -= raise;
        }
        out[table.flex] += slack;
        return out;
    }

    let mut shown = vec![true; columns];
    let mut need: usize = (0..columns).map(header).sum();
    for &index in table.give_way {
        if need <= room {
            break;
        }
        if index != table.flex && index < columns && shown[index] {
            shown[index] = false;
            need -= header(index);
        }
    }
    if need > room {
        return shrink_alike(room, &floor, &shown);
    }

    // The proportional shrink, then every column below its header raised to
    // it, paid for one cell at a time by the column furthest above its own.
    let natural_shown: usize = (0..columns)
        .filter(|index| shown[*index])
        .map(|index| floor[index])
        .sum();
    let mut out: Vec<usize> = (0..columns)
        .map(|index| {
            if shown[index] {
                (floor[index] * room / natural_shown.max(1)).max(header(index))
            } else {
                0
            }
        })
        .collect();
    let mut used: usize = out.iter().sum();
    while used > room {
        let Some(widest) = (0..columns)
            .filter(|index| out[*index] > header(*index))
            .max_by_key(|index| out[*index] - header(*index))
        else {
            break;
        };
        out[widest] -= 1;
        used -= 1;
    }
    out[table.flex] += room - used;
    out
}

/// The last resort, a pane too narrow for even the greedy column's header:
/// every shown column scales down alike and none vanishes, so its cells —
/// header too — wrap.
fn shrink_alike(room: usize, floor: &[usize], shown: &[bool]) -> Vec<usize> {
    let count = shown.iter().filter(|shown| **shown).count();
    let natural: usize = floor
        .iter()
        .zip(shown)
        .filter(|(_, shown)| **shown)
        .map(|(width, _)| width)
        .sum();
    if room < count || natural == 0 {
        return shown.iter().map(|shown| usize::from(*shown)).collect();
    }
    let mut out: Vec<usize> = floor
        .iter()
        .zip(shown)
        .map(|(width, shown)| {
            if *shown {
                (width * room / natural).max(1)
            } else {
                0
            }
        })
        .collect();
    // The `max(1)` floors can overshoot; shave the widest columns back until
    // the row fits exactly.
    let mut used: usize = out.iter().sum();
    while used > room {
        let Some(widest) = out
            .iter()
            .enumerate()
            .filter(|(_, width)| **width > 1)
            .max_by_key(|(_, width)| **width)
            .map(|(index, _)| index)
        else {
            break;
        };
        out[widest] -= 1;
        used -= 1;
    }
    out
}

/// The labels of the columns that gave way at `widths`, left to right;
/// empty when every column is shown.
pub(crate) fn gave_way<'a>(
    labels: impl IntoIterator<Item = &'a str>,
    widths: &[usize],
) -> Vec<&'a str> {
    labels
        .into_iter()
        .zip(widths)
        .filter(|(_, width)| **width == 0)
        .map(|(label, _)| label)
        .collect()
}

/// What to say about the columns that gave way, in at most `room` cells: the
/// columns by name when they fit, else how many, so the note is never cut.
/// `None` when every column shows, or `room` holds no form at all.
pub(crate) fn gave_way_note(hidden: &[&str], room: usize) -> Option<String> {
    if hidden.is_empty() {
        return None;
    }
    let count = hidden.len();
    let columns = if count == 1 { "column" } else { "columns" };
    [
        format!(" too narrow to show: {} ", hidden.join(", ")),
        format!(" {count} {columns} not shown "),
        format!(" {count} hidden "),
    ]
    .into_iter()
    .find(|note| note.chars().count() <= room)
}

/// One laid-out column of a wrapped row.
pub(crate) struct Column {
    pub text: String,
    pub style: Style,
    /// Right-align inside the column (numeric columns).
    pub right: bool,
}

impl Column {
    pub fn left(text: impl Into<String>, style: Style) -> Self {
        Self {
            text: text.into(),
            style,
            right: false,
        }
    }

    pub fn right(text: impl Into<String>, style: Style) -> Self {
        Self {
            text: text.into(),
            style,
            right: true,
        }
    }
}

/// Render one row of `columns` at `widths`, wrapping every cell and growing
/// the row to as many display lines as the tallest cell needs. `marker` is the
/// row gutter (a selection glyph on the first line, blanks on continuations),
/// so a wrapped row still reads as one row.
pub(crate) fn column_lines(
    columns: &[Column],
    widths: &[usize],
    gap: usize,
    marker: &Span<'static>,
) -> Vec<Line<'static>> {
    let wrapped: Vec<Vec<String>> = columns
        .iter()
        .zip(widths)
        .map(|(column, width)| {
            if *width == 0 {
                Vec::new()
            } else {
                wrap_text(&column.text, *width)
            }
        })
        .collect();
    let height = wrapped.iter().map(Vec::len).max().unwrap_or(1);
    let blank = " ".repeat(marker.content.chars().count());

    (0..height)
        .map(|row| {
            let mut spans = vec![if row == 0 {
                marker.clone()
            } else {
                Span::styled(blank.clone(), marker.style)
            }];
            for (index, (column, width)) in columns.iter().zip(widths).enumerate() {
                if index > 0 && gap > 0 {
                    spans.push(Span::raw(" ".repeat(gap)));
                }
                let width = *width;
                // A column that gave way draws nothing; its gap stays.
                if width == 0 {
                    continue;
                }
                let text = wrapped[index].get(row).cloned().unwrap_or_default();
                let padded = if column.right {
                    format!("{text:>width$}")
                } else {
                    format!("{text:<width$}")
                };
                spans.push(Span::styled(padded, column.style));
            }
            Line::from(spans)
        })
        .collect()
}

/// Prose wrapped to `width` and styled uniformly.
pub(crate) fn wrapped_lines(text: &str, width: usize, style: Style) -> Vec<Line<'static>> {
    wrap_text(text, width)
        .into_iter()
        .map(|line| Line::from(Span::styled(line, style)))
        .collect()
}

/// A label/value pair (a modal key-value row, a help binding, a log entry)
/// whose value wraps under itself: continuation lines hang at the value column
/// so the pair still reads as one row. `value_width` is the value column.
pub(crate) fn labeled_lines(
    label: Span<'static>,
    value: &str,
    value_style: Style,
    value_width: usize,
) -> Vec<Line<'static>> {
    let hang = " ".repeat(label.content.chars().count());
    wrap_text(value, value_width)
        .into_iter()
        .enumerate()
        .map(|(index, part)| {
            let head = if index == 0 {
                label.clone()
            } else {
                Span::styled(hang.clone(), label.style)
            };
            Line::from(vec![head, Span::styled(part, value_style)])
        })
        .collect()
}

/// A `Table` cell whose text wraps to `width` instead of being clipped, plus
/// the row height it needs. A column that gave way (`width` 0) draws an
/// empty cell one line high.
pub(crate) fn wrapped_cell(
    text: &str,
    width: usize,
    style: Style,
    right: bool,
) -> (Cell<'static>, u16) {
    if width == 0 {
        // Not `Cell::default()`: its column span is zero, so a row would
        // skip the column and draw every later cell one column to the left.
        return (Cell::from(""), 1);
    }
    let lines = wrap_text(text, width);
    let height = u16::try_from(lines.len()).unwrap_or(u16::MAX);
    let text = Text::from(
        lines
            .into_iter()
            .map(|line| Line::from(Span::styled(line, style)))
            .collect::<Vec<_>>(),
    );
    let text = if right {
        text.right_aligned()
    } else {
        text.left_aligned()
    };
    (Cell::from(text), height)
}

#[cfg(test)]
mod tests;
