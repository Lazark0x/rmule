//! Prose that does not fit its width folds onto further lines: modals, help,
//! the log, a status note. Table rows never do (ADR-0119); `crate::table` fits
//! those on one line.
//!
//! Also the one measure of text in this crate, [`display_width`].

use ratatui::style::Style;
use ratatui::text::{Line, Span};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// The cells `text` takes on a terminal: a wide glyph takes two, a combining
/// mark none. The one measure of text in this crate.
pub(crate) fn display_width(text: &str) -> usize {
    UnicodeWidthStr::width(text)
}

fn glyph_width(glyph: char) -> usize {
    UnicodeWidthChar::width(glyph).unwrap_or(0)
}

/// The start of `text` that fits `width` cells.
pub(crate) fn first_cells(text: &str, width: usize) -> String {
    let mut cells = 0usize;
    text.chars()
        .take_while(|glyph| {
            cells += glyph_width(*glyph);
            cells <= width
        })
        .collect()
}

/// Wrap `text` to at most `width` cells, breaking at a space when one falls
/// inside the window and hard-breaking any word that is wider than the whole
/// column. Always returns at least one line (empty input ⇒ one empty line).
/// A glyph wider than the column takes a line of its own.
pub(crate) fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    if display_width(text) <= width {
        return vec![text.to_string()];
    }
    let chars: Vec<char> = text.chars().collect();

    let mut lines = Vec::new();
    let mut start = 0usize;
    while start < chars.len() {
        let mut end = start;
        let mut cells = 0usize;
        while end < chars.len() && cells + glyph_width(chars[end]) <= width {
            cells += glyph_width(chars[end]);
            end += 1;
        }
        if end == chars.len() {
            lines.push(chars[start..].iter().collect());
            break;
        }
        // The window takes one glyph past the column: a space sitting exactly
        // at the boundary is consumed by the break rather than pushed down.
        match chars[start..=end].iter().rposition(|c| *c == ' ') {
            Some(cut) if cut > 0 => {
                lines.push(chars[start..start + cut].iter().collect());
                start += cut + 1;
            }
            // No usable break point — the word is longer than the column.
            _ => {
                let end = end.max(start + 1);
                lines.push(chars[start..end].iter().collect());
                start = end;
            }
        }
    }
    lines
}

/// Saturating `usize` → `u16` for rect dimensions.
pub(crate) fn clamp_u16(value: usize) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
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
    let hang = " ".repeat(display_width(&label.content));
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

#[cfg(test)]
mod tests;
