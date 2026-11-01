//! The quit confirm: a quit over running downloads asks first, because `q` is
//! one key from a letter typed on the wrong tab.

use std::cell::Cell;

use ratatui::Frame;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use crate::theme::Theme;
use crate::views::modal::Modal;
use crate::words::app as words;
use crate::wrap::wrapped_lines;

/// Draw the confirm over the whole frame, for `running` downloads.
pub(super) fn draw(frame: &mut Frame, running: usize, theme: &Theme) {
    let key = |text: &'static str| {
        Span::styled(
            text,
            Style::new().fg(theme.accent).add_modifier(Modifier::BOLD),
        )
    };
    let lines = |width: u16| {
        let text_w = usize::from(width).saturating_sub(2).max(1);
        let mut lines = wrapped_lines(
            &words::quit_confirm(running),
            text_w,
            Style::new().fg(theme.fg),
        );
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![
            key("y"),
            Span::styled(words::QUIT_YES, Style::new().fg(theme.fg)),
            key("Esc"),
            Span::styled(words::QUIT_NO, Style::new().fg(theme.fg)),
        ]));
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
            draw(frame, 2, &Theme::default_dark());
        });
    }
}
