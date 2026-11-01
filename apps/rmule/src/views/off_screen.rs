//! What a table does not show of its selected row: the values of the columns
//! that gave way, and the full value of any cell that had to shorten or cut
//! it, printed on one `Off-screen:` line at the bottom of the table, just
//! above the border's note naming the hidden columns. Every table says them
//! the same way, so a row on one line never loses a value (ADR-0119).

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::widgets::Paragraph;

use crate::table::Cell;
use crate::theme::Theme;
use crate::words::labels;
use crate::wrap::{clamp_u16, wrap_text, wrapped_lines};

/// What the selected row's `cells` do not show at `widths`, each as `Label
/// value`, left to right: the value of a column that gave way, and the full
/// value of one the cell had to shorten.
#[must_use]
pub(crate) fn hidden<'a>(
    labels: impl IntoIterator<Item = &'a str>,
    cells: &[Cell],
    widths: &[usize],
) -> Vec<String> {
    labels
        .into_iter()
        .zip(cells)
        .zip(widths)
        .filter(|((_, cell), width)| cell.hides_at(**width))
        .map(|((label, cell), _)| format!("{label} {}", cell.text))
        .collect()
}

/// The lines the `Off-screen:` line of `parts` takes at the bottom of `body`:
/// none when there is nothing off screen, and at most half the body, so the
/// rows it speaks of stay in sight.
#[must_use]
pub(crate) fn height(body: Rect, parts: &[String]) -> u16 {
    if parts.is_empty() || body.height < 2 || body.width == 0 {
        return 0;
    }
    clamp_u16(wrap_text(&text(parts), usize::from(body.width)).len()).min(body.height / 2)
}

fn text(parts: &[String]) -> String {
    format!("{}{}", labels::OFF_SCREEN, parts.join(" · "))
}

/// Draw `parts` as the `Off-screen:` line at the bottom of `body`, wrapped
/// rather than cut, in the `held` lines its table keeps for it, and return
/// what is left of `body` above them. A line held with nothing to say stays
/// blank: the rows above it do not move as the cursor walks them.
pub(crate) fn draw(
    frame: &mut Frame,
    body: Rect,
    parts: &[String],
    held: u16,
    theme: &Theme,
) -> Rect {
    if held == 0 {
        return body;
    }
    let said = height(body, parts).min(held);
    if said > 0 {
        let lines = wrapped_lines(
            &text(parts),
            usize::from(body.width),
            Style::new().fg(theme.fg),
        );
        let line_area = Rect::new(body.x, body.bottom() - said, body.width, said);
        frame.render_widget(Paragraph::new(lines), line_area);
    }
    Rect::new(body.x, body.y, body.width, body.height - held)
}

#[cfg(test)]
mod tests {
    use ratatui::style::Style;

    use super::hidden;
    use crate::table::Cell;

    fn cells(texts: &[&str]) -> Vec<Cell> {
        texts
            .iter()
            .map(|text| Cell::new(*text, Style::new()))
            .collect()
    }

    #[test]
    fn a_column_that_gave_way_and_a_value_that_was_cut_are_both_said() {
        let row = cells(&["a-long-name.mp4", "87.7 MB", "42%"]);
        assert_eq!(
            hidden(["File", "Size", "Done"], &row, &[8, 0, 4]),
            vec![
                "File a-long-name.mp4".to_string(),
                "Size 87.7 MB".to_string()
            ]
        );
    }

    #[test]
    fn a_row_that_shows_everything_says_nothing() {
        let row = cells(&["bunny.mp4", "87.7 MB"]);
        assert!(hidden(["File", "Size"], &row, &[12, 8]).is_empty());
    }

    /// A figure drawn in its short form still rides the line in full.
    #[test]
    fn a_shortened_figure_is_said_whole() {
        let row = [Cell::new("12 (340)", Style::new()).or_short("12")];
        assert_eq!(
            hidden(["Requests"], &row, &[4]),
            vec!["Requests 12 (340)".to_string()]
        );
    }
}
