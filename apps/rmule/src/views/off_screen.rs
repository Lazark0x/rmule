//! What a narrow table does not show of its selected row: the values
//! of the columns that gave way, and any figure a cell had to shorten, printed
//! in full on one wrapped `Off-screen:` line at the bottom of the table, just
//! above the border's note naming the hidden columns. Every table says them
//! the same way, so a column giving way never loses its value.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::widgets::Paragraph;

use crate::theme::Theme;
use crate::wrap::{clamp_u16, wrapped_lines};

/// The selected row's values in the columns that gave way at `widths`, each
/// as `Label value`, left to right.
#[must_use]
pub(crate) fn hidden<'a>(
    labels: impl IntoIterator<Item = &'a str>,
    values: &[String],
    widths: &[usize],
) -> Vec<String> {
    labels
        .into_iter()
        .zip(values)
        .zip(widths)
        .filter(|(_, width)| **width == 0)
        .map(|((label, value), _)| format!("{label} {value}"))
        .collect()
}

/// Draw `parts` as the `Off-screen:` line at the bottom of `body`, wrapped
/// rather than cut, and return what is left of `body` above it — all of it
/// when there is nothing off screen. The line takes at most half the body, so
/// the rows it speaks of stay in sight.
pub(crate) fn draw(frame: &mut Frame, body: Rect, parts: &[String], theme: &Theme) -> Rect {
    if parts.is_empty() || body.height < 2 || body.width == 0 {
        return body;
    }
    let lines = wrapped_lines(
        &format!("Off-screen: {}", parts.join(" · ")),
        usize::from(body.width),
        Style::new().fg(theme.fg),
    );
    let height = clamp_u16(lines.len()).min(body.height / 2);
    let line_area = Rect::new(body.x, body.bottom() - height, body.width, height);
    frame.render_widget(Paragraph::new(lines), line_area);
    Rect::new(body.x, body.y, body.width, body.height - height)
}

#[cfg(test)]
mod tests {
    use super::hidden;

    #[test]
    fn only_the_columns_that_gave_way_are_said_with_their_labels() {
        let values = ["bunny.mp4", "87.7 MB", "42%"].map(String::from);
        assert_eq!(
            hidden(["File", "Size", "Done"], &values, &[12, 0, 0]),
            vec!["Size 87.7 MB".to_string(), "Done 42%".to_string()]
        );
        assert!(hidden(["File", "Size"], &values[..2], &[12, 8]).is_empty());
    }
}
