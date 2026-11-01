//! The query input line: what has been typed, and how tall the block has to
//! grow to show it whole.
//!
//! Left alone the query wraps rather than truncates, so a long one stays
//! readable. While it holds the keyboard it is one line, scrolled around the
//! caret, with the reason a commit was refused under it.

use ratatui::Frame;
use ratatui::layout::{Position, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};

use super::SearchesView;
use crate::state::UiState;
use crate::theme::Theme;
use crate::wrap::{clamp_u16, labeled_lines, wrapped_lines};

/// The query-input block is three inner lines (query + who it asks + filters) inside
/// a border → 5 rows tall; it grows when a line wraps or the filter
/// editor is open, and the results table takes the rest.
const INPUT_HEIGHT: u16 = 5;

/// The query line's prompt, and the cells it takes.
const PROMPT: &str = "❯ ";
const PROMPT_W: usize = 2;

impl SearchesView {
    /// Rows the input block needs at `inner_width`: the border pair plus the
    /// wrapped query, who-it-asks and filter lines.
    pub(super) fn input_height(&self, inner_width: usize, state: &UiState, theme: &Theme) -> u16 {
        let inner_width = inner_width.max(1);
        let query = self.query_lines(inner_width, theme).0.len();
        let refusal = self.refusal_lines(inner_width, theme).len();
        let asks = self.asks_lines(inner_width, state, theme).len();
        let filters = self.filter_lines(inner_width, theme).0.len();
        clamp_u16(query + refusal + asks + filters + 2).max(INPUT_HEIGHT)
    }

    /// The block, and where the caret is while a field in it is open.
    pub(super) fn draw_input(
        &self,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
    ) -> Option<Position> {
        let focused = self.input_focused;
        let editing = self.filters_open;
        let border = if focused || editing {
            theme.accent
        } else {
            theme.dim
        };
        let hint = if editing {
            " Tab field  ←→ type  Enter search  Esc close "
        } else if focused {
            " Enter search  Esc leave "
        } else {
            " i focus  o options "
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
            return None;
        }
        let inner_width = usize::from(inner.width);
        let (mut lines, query_caret) = self.query_lines(inner_width, theme);
        lines.extend(self.refusal_lines(inner_width, theme));
        lines.extend(self.asks_lines(inner_width, state, theme));
        let above_filters = lines.len();
        let (filter_lines, filter_caret) = self.filter_lines(inner_width, theme);
        lines.extend(filter_lines);
        let caret = match (focused, filter_caret) {
            (true, _) => query_caret.map(|column| (0, column)),
            (false, Some((line, column))) => Some((above_filters + line, column)),
            (false, None) => None,
        };
        let shown = 0..lines.len();
        frame.render_widget(Paragraph::new(lines), inner);
        crate::views::caret_in(inner, shown, caret)
    }

    /// Why the typed query was not sent.
    fn refusal_lines(&self, width: usize, theme: &Theme) -> Vec<Line<'static>> {
        self.refusal.as_ref().map_or_else(Vec::new, |why| {
            wrapped_lines(&format!("✗ {why}"), width, Style::new().fg(theme.bad))
        })
    }

    /// The query under the `❯ ` prompt, and the caret's column while it
    /// holds the keyboard: one line scrolled around the caret then, and
    /// wrapped whole otherwise, so a long query grows the block instead of
    /// going out of sight.
    fn query_lines(&self, width: usize, theme: &Theme) -> (Vec<Line<'static>>, Option<u16>) {
        let focused = self.input_focused;
        let prompt_style = if focused {
            Style::new().fg(theme.accent)
        } else {
            theme.dim_text()
        };
        let prompt = Span::styled(PROMPT, prompt_style);
        let body_w = width.saturating_sub(PROMPT_W).max(1);
        if focused {
            let shown = self
                .query
                .show(body_w, Style::new().fg(theme.fg), theme.dim_text());
            let mut spans = vec![prompt];
            spans.extend(shown.spans);
            return (
                vec![Line::from(spans)],
                Some(clamp_u16(PROMPT_W) + shown.caret),
            );
        }
        // A Related-Files entry is named, not typed: the input holds nothing
        // to edit, and Enter there starts a keyword search from what is typed.
        let related = self
            .showing_related()
            .then(|| self.related_query_line())
            .flatten();
        let text = related.as_deref().unwrap_or(self.query.text());
        (
            labeled_lines(prompt, text, Style::new().fg(theme.fg), body_w),
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::state::UiState;
    use ratatui::crossterm::event::KeyCode;
    use std::time::Instant;

    use crate::golden::assert_golden_caret;

    use super::*;
    use crate::fixture::*;

    #[test]
    fn golden_searches_typing() {
        let state = UiState::default();
        let theme = Theme::default_dark();
        let mut view = SearchesView::by_name();
        view.handle_key(press(KeyCode::Char('/')), &state);
        for c in "big buck bunny".chars() {
            view.handle_key(press(KeyCode::Char(c)), &state);
        }
        assert_golden_caret("searches_typing", 78, 21, |frame| {
            view.draw(frame, frame.area(), &state, &theme, Instant::now())
        });
    }

    #[test]
    fn a_long_query_left_alone_wraps_the_input_block_open() {
        let state = UiState::default();
        let mut view = SearchesView::by_name();
        view.handle_key(press(KeyCode::Char('/')), &state);
        for c in "a-very-long-search-phrase ".repeat(5).chars() {
            view.handle_key(press(KeyCode::Char(c)), &state);
        }
        view.handle_key(press(KeyCode::Esc), &state);
        // 4 rows is the unwrapped block; the query alone needs several more.
        let height = view.input_height(76, &UiState::default(), &Theme::default_dark());
        assert!(
            height > INPUT_HEIGHT,
            "the input block grew to {height} rows"
        );
    }
}
