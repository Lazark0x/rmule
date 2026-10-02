//! The query input line: what has been typed, and how tall the block has to
//! grow to show it whole.
//!
//! The block wraps rather than truncates, so a long query stays readable
//! instead of scrolling out of sight.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};

use super::SearchesView;
use crate::form::CURSOR;
use crate::theme::Theme;
use crate::wrap::{clamp_u16, labeled_lines};

/// The query-input block is three inner lines (query + method + filters) inside
/// a border → 5 rows tall; it grows when a line wraps or the filter
/// editor is open, and the results table takes the rest.
const INPUT_HEIGHT: u16 = 5;

impl SearchesView {
    /// Rows the input block needs at `inner_width`: the border pair plus the
    /// wrapped query, method and filter lines.
    pub(super) fn input_height(&self, inner_width: usize, theme: &Theme) -> u16 {
        let inner_width = inner_width.max(1);
        let query = self.query_lines(inner_width, false, theme).len();
        let method = self.method_lines(inner_width, theme).len();
        let filters = self.filter_lines(inner_width, theme).len();
        clamp_u16(query + method + filters + 2).max(INPUT_HEIGHT)
    }

    pub(super) fn draw_input(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let focused = self.input_focused;
        let editing = self.filters_open;
        let border = if focused || editing {
            theme.accent
        } else {
            theme.dim
        };
        let hint = if editing {
            " Tab field  ←→ type  Enter search  Esc close "
        } else {
            " / focus  ←→ method  o options "
        };
        let block = crate::views::title::titled(
            Block::bordered().border_style(Style::new().fg(border)),
            area.width,
            (" Search ", Style::new().fg(theme.fg)),
            (hint, theme.dim_text()),
        );
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if inner.height == 0 || inner.width == 0 {
            return;
        }
        let inner_width = usize::from(inner.width);
        let mut lines = self.query_lines(inner_width, focused, theme);
        lines.extend(self.method_lines(inner_width, theme));
        lines.extend(self.filter_lines(inner_width, theme));
        frame.render_widget(Paragraph::new(lines), inner);
    }

    /// The typed query, wrapped under the `❯ ` prompt: a long query
    /// grows the input block instead of scrolling out of sight.
    fn query_lines(&self, width: usize, focused: bool, theme: &Theme) -> Vec<Line<'static>> {
        let prompt_style = if focused {
            Style::new().fg(theme.accent)
        } else {
            theme.dim_text()
        };
        let body_w = width.saturating_sub(2).max(1);
        // A Related-Files entry is named, not typed: the input holds nothing
        // to edit, and Enter there starts a keyword search from what is typed.
        if self.showing_related()
            && let Some(line) = self.related_query_line()
        {
            return labeled_lines(
                Span::styled("❯ ", prompt_style),
                &line,
                Style::new().fg(theme.fg),
                body_w,
            );
        }
        let mut lines = labeled_lines(
            Span::styled("❯ ", prompt_style),
            &self.query,
            Style::new().fg(theme.fg),
            body_w,
        );
        if focused {
            // The caret trails the text; it starts a fresh line rather than
            // pushing the last wrapped line past the pane edge.
            let full = lines.last().is_some_and(|line| line.width() >= width);
            if full {
                lines.push(Line::from(Span::raw("  ")));
            }
            if let Some(last) = lines.last_mut() {
                last.spans
                    .push(Span::styled(CURSOR, Style::new().fg(theme.accent)));
            }
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use crate::state::UiState;
    use ratatui::crossterm::event::KeyCode;
    use std::time::Instant;

    use crate::golden::assert_golden;

    use super::*;
    use crate::fixture::*;

    #[test]
    fn golden_searches_typing() {
        let state = UiState::default();
        let theme = Theme::default_dark();
        let mut view = SearchesView::new();
        view.handle_key(press(KeyCode::Char('/')), &state);
        for c in "big buck bunny".chars() {
            view.handle_key(press(KeyCode::Char(c)), &state);
        }
        assert_golden("searches_typing", 78, 21, |frame| {
            view.draw(frame, frame.area(), &state, &theme, Instant::now());
        });
    }

    #[test]
    fn a_long_typed_query_wraps_the_input_block_open() {
        let state = UiState::default();
        let mut view = SearchesView::new();
        view.handle_key(press(KeyCode::Char('/')), &state);
        for c in "a-very-long-search-phrase ".repeat(5).chars() {
            view.handle_key(press(KeyCode::Char(c)), &state);
        }
        // 4 rows is the unwrapped block; the query alone needs several more.
        let height = view.input_height(76, &Theme::default_dark());
        assert!(
            height > INPUT_HEIGHT,
            "the input block grew to {height} rows"
        );
    }
}
