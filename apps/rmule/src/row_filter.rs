//! The **Row Filter**: `/` in every list. It narrows the list to the rows that
//! hold what is typed, as it is typed, on the one line editor; `Enter` keeps
//! the filter and hands the keys back to the list, `Esc` clears it. The arrows
//! and the page keys still move the list while the field holds the keys.
//!
//! A row is matched by its words, case and accents folded as the Table Sort
//! folds them, each typed word found in any of them. A table offers its text
//! columns ([`keeps_row`]); the log and Settings offer their lines.

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Position, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::line_edit::LineEdit;
use crate::table_sort::{ColumnKind, SortValue, SortedTable, fold};
use crate::theme::Theme;
use crate::views::ViewOutcome;
use crate::wrap::{clamp_u16, display_width};

/// The cells of the `/` before the typed text.
const MARK_W: usize = 2;

/// One list's filter.
#[derive(Clone, Debug, Default)]
pub(crate) struct RowFilter {
    edit: LineEdit,
    /// Whether its field holds the keyboard.
    typing: bool,
    /// The typed words, folded.
    words: Vec<String>,
    /// Moves whenever the words do, for a table's memo.
    generation: u64,
}

impl RowFilter {
    /// A filter whose field holds the keyboard from the start: help's.
    #[must_use]
    pub(crate) fn typing_from_the_start() -> Self {
        Self {
            typing: true,
            ..Self::default()
        }
    }

    /// Keep the field holding the keyboard, whatever the last key said.
    pub(crate) const fn keep_typing(&mut self) {
        self.typing = true;
    }

    /// Whether its field holds the keyboard.
    #[must_use]
    pub(crate) const fn typing(&self) -> bool {
        self.typing
    }

    /// Whether anything is typed.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.edit.is_empty()
    }

    /// Whether its line is on show.
    #[must_use]
    pub(crate) fn shown(&self) -> bool {
        self.typing || !self.is_empty()
    }

    /// What a list's memo stands on.
    #[must_use]
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    fn typed(&mut self) {
        self.words = self.edit.text().split_whitespace().map(fold).collect();
        self.generation += 1;
    }

    fn clear(&mut self) {
        self.edit.set("");
        self.typing = false;
        self.typed();
    }

    /// Offer the list's key. `Some` when the filter took it; `rows` says
    /// whether the list has anything to filter, so `/` over nothing is left to
    /// whoever else binds it.
    pub(crate) fn key(&mut self, key: &KeyEvent, rows: bool) -> Option<ViewOutcome> {
        if !self.typing {
            return match key.code {
                KeyCode::Char('/') if rows => {
                    self.typing = true;
                    Some(ViewOutcome::Redraw)
                }
                KeyCode::Esc if !self.is_empty() => {
                    self.clear();
                    Some(ViewOutcome::Redraw)
                }
                _ => None,
            };
        }
        match key.code {
            KeyCode::Esc => self.clear(),
            KeyCode::Enter => {
                self.typing = false;
                if self.is_empty() {
                    self.clear();
                }
            }
            KeyCode::Tab | KeyCode::BackTab => {
                self.typing = false;
                return None;
            }
            KeyCode::Up | KeyCode::Down | KeyCode::PageUp | KeyCode::PageDown => return None,
            _ => {
                if self.edit.key(key) {
                    self.typed();
                }
            }
        }
        Some(ViewOutcome::Redraw)
    }

    /// A paste into the open field, whole.
    pub(crate) fn paste(&mut self, text: &str) -> Option<ViewOutcome> {
        if !self.typing {
            return None;
        }
        self.edit.paste(text);
        self.typed();
        Some(ViewOutcome::Redraw)
    }

    /// Whether a row of these `texts` stays: every typed word is in one of them.
    #[must_use]
    pub(crate) fn keeps<'a>(&self, texts: impl IntoIterator<Item = &'a str>) -> bool {
        if self.words.is_empty() {
            return true;
        }
        let folded: Vec<String> = texts.into_iter().map(fold).collect();
        self.words
            .iter()
            .all(|word| folded.iter().any(|text| text.contains(word.as_str())))
    }

    /// Take the filter's line off the foot of `area`, while it is on show.
    #[must_use]
    pub(crate) fn carve(&self, area: Rect) -> (Rect, Rect) {
        if !self.shown() || area.height < 2 {
            return (area, Rect::default());
        }
        let list = Rect::new(area.x, area.y, area.width, area.height - 1);
        let line = Rect::new(area.x, area.bottom() - 1, area.width, 1);
        (list, line)
    }

    /// Draw the filter on `line`: what is typed, and how many of `total` rows
    /// hold it. Where the caret is while the field holds the keyboard.
    pub(crate) fn draw(
        &self,
        frame: &mut Frame,
        line: Rect,
        (kept, total): (usize, usize),
        theme: &Theme,
    ) -> Option<Position> {
        if line.height == 0 || line.width == 0 {
            return None;
        }
        let count = crate::words::rows::filter_count(kept, total);
        let count_w = display_width(&count) + 1;
        let room = usize::from(line.width).saturating_sub(MARK_W + count_w);
        let style = Style::new().fg(if self.typing { theme.fg } else { theme.dim });
        let shown = self.edit.show(room, style, theme.dim_text());
        let mut spans = vec![Span::styled("/ ", Style::new().fg(theme.accent))];
        spans.extend(shown.spans);
        frame.render_widget(Paragraph::new(Line::from(spans)), line);
        frame.render_widget(
            Paragraph::new(Span::styled(count, theme.dim_text())).right_aligned(),
            line,
        );
        self.typing
            .then(|| Position::new(line.x + clamp_u16(MARK_W) + shown.caret, line.y))
    }
}

/// Whether `row` of the table `T` stays under `filter`: its text columns are
/// what the filter reads.
#[must_use]
pub(crate) fn keeps_row<T: SortedTable>(filter: &RowFilter, row: &T::Row) -> bool {
    if filter.is_empty() {
        return true;
    }
    let values: Vec<_> = T::COLUMNS
        .iter()
        .filter(|spec| matches!(spec.kind, ColumnKind::Text))
        .filter_map(|spec| T::value(spec.column, row))
        .collect();
    filter.keeps(values.iter().filter_map(|value| match value {
        SortValue::Text(text) => Some(text.as_ref()),
        _ => None,
    }))
}

#[cfg(test)]
mod tests {
    use ratatui::crossterm::event::KeyCode;

    use super::*;
    use crate::fixture::press;

    fn typed(text: &str) -> RowFilter {
        let mut filter = RowFilter::default();
        filter.key(&press(KeyCode::Char('/')), true);
        for letter in text.chars() {
            filter.key(&press(KeyCode::Char(letter)), true);
        }
        filter
    }

    #[test]
    fn every_typed_word_must_be_found_folded_in_some_text() {
        let filter = typed("CAFE mp3");
        assert!(filter.keeps(["Café del Mar", "track.mp3"]));
        assert!(filter.keeps(["café.MP3"]));
        assert!(!filter.keeps(["café.ogg"]));
    }

    #[test]
    fn enter_keeps_it_esc_clears_it_and_arrows_stay_the_lists() {
        let mut filter = typed("deb");
        assert!(filter.typing());
        assert!(filter.key(&press(KeyCode::Down), true).is_none());
        assert!(
            filter.typing(),
            "the field keeps the keys while the list moves"
        );
        filter.key(&press(KeyCode::Enter), true);
        assert!(!filter.typing());
        assert!(filter.shown(), "the filter stands");
        assert!(filter.key(&press(KeyCode::Char('j')), true).is_none());
        filter.key(&press(KeyCode::Esc), true);
        assert!(!filter.shown());
        assert!(
            filter.key(&press(KeyCode::Esc), true).is_none(),
            "with nothing to clear Esc is someone else's"
        );
    }

    #[test]
    fn a_slash_over_no_rows_is_left_alone() {
        let mut filter = RowFilter::default();
        assert!(filter.key(&press(KeyCode::Char('/')), false).is_none());
        assert!(!filter.typing());
    }
}
