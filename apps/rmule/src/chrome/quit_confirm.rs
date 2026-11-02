//! The quit confirm: a quit over anything under way, a download or a peer in
//! the upload queue, asks first, because `q` is one key from a letter typed on
//! the wrong tab.

use std::cell::Cell;

use ratatui::Frame;
use ratatui::style::Style;
use ratatui::text::Line;

use crate::theme::Theme;
use crate::views::modal::Modal;
use crate::words::app as words;
use crate::wrap::wrapped_lines;

/// Draw the confirm over the whole frame, saying what `cost` a quit has.
pub(super) fn draw(frame: &mut Frame, cost: words::QuitCost, theme: &Theme) {
    let lines = |width: u16| {
        let text_w = usize::from(width).saturating_sub(2).max(1);
        let mut lines = wrapped_lines(
            &words::quit_confirm(cost),
            text_w,
            Style::new().fg(theme.fg),
        );
        lines.push(Line::raw(""));
        lines.push(crate::views::modal::answer_line(theme));
        lines
    };
    let area = frame.area();
    Modal::new(words::QUIT_TITLE, theme)
        .flash_title(theme)
        .at_least(6)
        .draw_scrolled(frame, area, 44, theme, &Cell::default(), lines);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::golden::assert_golden;

    #[test]
    fn golden_quit_confirm_counts_what_it_stops() {
        assert_golden("quit_confirm", 80, 24, |frame| {
            let cost = words::QuitCost {
                running: 2,
                ..words::QuitCost::default()
            };
            draw(frame, cost, &Theme::default_dark());
        });
    }
}
