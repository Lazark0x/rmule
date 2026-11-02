//! The one line editor: every place an operator types runs on it.
//!
//! A [`LineEdit`] holds one line of text and a caret on a grapheme boundary.
//! [`LineEdit::key`] is the whole key map, readline's and the arrows', so no
//! view reads an editing key; [`LineEdit::paste`] inserts at the caret; and
//! [`LineEdit::show`] lays the line into a width, scrolled sideways around the
//! caret and measured in terminal cells, with `‹` / `›` where text lies
//! beyond an edge. It says which column the caret is in: that is where the
//! view puts the terminal's real cursor, which an input method composes at.
//!
//! The Key Gate asks [`LineEdit::claims`] whether a chord is an editing key,
//! so a field takes `Ctrl-A` and no unbound chord reaches a view.

use std::cell::Cell;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::style::Style;
use ratatui::text::Span;
use unicode_segmentation::UnicodeSegmentation;

use crate::wrap::display_width;

/// Shown where text lies beyond the left edge of the field.
const MORE_LEFT: &str = "‹";
/// Shown where text lies beyond the right edge of the field.
const MORE_RIGHT: &str = "›";

/// One editing act.
#[derive(Clone, Copy)]
enum Edit {
    Insert(char),
    Left,
    Right,
    WordLeft,
    WordRight,
    Home,
    End,
    DeleteBack,
    DeleteForward,
    /// Cut back to the last space (readline's `Ctrl-W`).
    CutBlankBack,
    /// Cut back to the start of a word.
    CutWordBack,
    /// Cut forward to the end of a word.
    CutWordForward,
    CutToStart,
    CutToEnd,
    Yank,
}

/// What `key` asks of a line editor, if anything. Ctrl with Alt on a character
/// is AltGr, which is text.
fn edit_of(key: &KeyEvent) -> Option<Edit> {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    let chord = ctrl || alt;
    Some(match key.code {
        KeyCode::Char(typed) if ctrl == alt => Edit::Insert(typed),
        KeyCode::Char(letter) if ctrl => match letter.to_ascii_lowercase() {
            'a' => Edit::Home,
            'e' => Edit::End,
            'b' => Edit::Left,
            'f' => Edit::Right,
            'd' => Edit::DeleteForward,
            'h' => Edit::DeleteBack,
            'k' => Edit::CutToEnd,
            'u' => Edit::CutToStart,
            'w' => Edit::CutBlankBack,
            'y' => Edit::Yank,
            _ => return None,
        },
        KeyCode::Char(letter) => match letter.to_ascii_lowercase() {
            'b' => Edit::WordLeft,
            'f' => Edit::WordRight,
            'd' => Edit::CutWordForward,
            _ => return None,
        },
        KeyCode::Left if chord => Edit::WordLeft,
        KeyCode::Right if chord => Edit::WordRight,
        KeyCode::Left => Edit::Left,
        KeyCode::Right => Edit::Right,
        KeyCode::Home => Edit::Home,
        KeyCode::End => Edit::End,
        KeyCode::Backspace if chord => Edit::CutWordBack,
        KeyCode::Backspace => Edit::DeleteBack,
        KeyCode::Delete if chord => Edit::CutWordForward,
        KeyCode::Delete => Edit::DeleteForward,
        _ => return None,
    })
}

/// `text` as one line: line breaks and tabs become spaces, and nothing a
/// terminal would act on stays in it.
pub(crate) fn one_line(text: &str) -> String {
    let spaced: String = text
        .trim()
        .chars()
        .map(|c| {
            if matches!(c, '\n' | '\r' | '\t') {
                ' '
            } else {
                c
            }
        })
        .collect();
    crate::words::plain(&spaced)
}

/// One line of typed text and its caret.
#[derive(Clone, Debug, Default)]
pub(crate) struct LineEdit {
    text: String,
    /// A byte offset on a grapheme boundary of `text`.
    caret: usize,
    /// What the last cut took, for `Ctrl-Y`.
    cut: String,
    /// The first cell on screen, kept between frames so the text moves only
    /// when the caret would leave the field.
    first: Cell<usize>,
}

/// The line as it fits a field.
pub(crate) struct Shown {
    pub spans: Vec<Span<'static>>,
    /// The caret's column from the field's left edge.
    pub caret: u16,
}

impl LineEdit {
    /// A line holding `text`, the caret at its end.
    pub(crate) fn new(text: impl Into<String>) -> Self {
        let text = text.into();
        Self {
            caret: text.len(),
            text,
            ..Self::default()
        }
    }

    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Replace the text, the caret at its end.
    pub(crate) fn set(&mut self, text: &str) {
        self.text.clear();
        self.text.push_str(text);
        self.caret = self.text.len();
    }

    /// Whether `key` is one a line editor acts on.
    pub(crate) fn claims(key: &KeyEvent) -> bool {
        edit_of(key).is_some()
    }

    /// Act on `key`; whether it was an editing key.
    pub(crate) fn key(&mut self, key: &KeyEvent) -> bool {
        let Some(edit) = edit_of(key) else {
            return false;
        };
        self.apply(edit);
        true
    }

    /// Insert `text`, made one line, at the caret.
    pub(crate) fn paste(&mut self, text: &str) {
        self.insert(&one_line(text));
    }

    fn insert(&mut self, text: &str) {
        self.text.insert_str(self.caret, text);
        self.caret += text.len();
    }

    fn apply(&mut self, edit: Edit) {
        match edit {
            Edit::Insert(typed) => self.insert(typed.encode_utf8(&mut [0; 4])),
            Edit::Left => self.caret = self.grapheme_before(),
            Edit::Right => self.caret = self.grapheme_after(),
            Edit::WordLeft => self.caret = self.word_before(),
            Edit::WordRight => self.caret = self.word_after(),
            Edit::Home => self.caret = 0,
            Edit::End => self.caret = self.text.len(),
            Edit::DeleteBack => {
                let start = self.grapheme_before();
                self.remove(start..self.caret);
            }
            Edit::DeleteForward => {
                let end = self.grapheme_after();
                self.remove(self.caret..end);
            }
            Edit::CutBlankBack => {
                let start = self.text[..self.caret]
                    .trim_end()
                    .rfind(char::is_whitespace)
                    .map_or(0, |at| {
                        at + self.text[at..].chars().next().map_or(0, char::len_utf8)
                    });
                self.cut(start..self.caret);
            }
            Edit::CutWordBack => self.cut(self.word_before()..self.caret),
            Edit::CutWordForward => self.cut(self.caret..self.word_after()),
            Edit::CutToStart => self.cut(0..self.caret),
            Edit::CutToEnd => self.cut(self.caret..self.text.len()),
            Edit::Yank => {
                let cut = std::mem::take(&mut self.cut);
                self.insert(&cut);
                self.cut = cut;
            }
        }
    }

    fn remove(&mut self, range: std::ops::Range<usize>) {
        self.caret = range.start;
        self.text.replace_range(range, "");
    }

    fn cut(&mut self, range: std::ops::Range<usize>) {
        if !range.is_empty() {
            self.cut = self.text[range.clone()].to_string();
        }
        self.remove(range);
    }

    fn grapheme_before(&self) -> usize {
        self.text[..self.caret]
            .grapheme_indices(true)
            .next_back()
            .map_or(0, |(at, _)| at)
    }

    fn grapheme_after(&self) -> usize {
        self.text[self.caret..]
            .graphemes(true)
            .next()
            .map_or(self.caret, |grapheme| self.caret + grapheme.len())
    }

    /// The start of the word at or before the caret.
    fn word_before(&self) -> usize {
        let head = self.text[..self.caret].trim_end_matches(|c: char| !c.is_alphanumeric());
        head.rfind(|c: char| !c.is_alphanumeric()).map_or(0, |at| {
            at + head[at..].chars().next().map_or(0, char::len_utf8)
        })
    }

    /// The end of the word at or after the caret.
    fn word_after(&self) -> usize {
        let tail = &self.text[self.caret..];
        let word = tail.trim_start_matches(|c: char| !c.is_alphanumeric());
        let start = tail.len() - word.len();
        self.caret
            + start
            + word
                .find(|c: char| !c.is_alphanumeric())
                .unwrap_or(word.len())
    }

    /// Lay the line into `width` cells, one of them for the caret past the
    /// end: `style` for the text, `more` for the marks at a cut edge.
    pub(crate) fn show(&self, width: usize, style: Style, more: Style) -> Shown {
        let room = width.max(1);
        let total = display_width(&self.text);
        let caret = display_width(&self.text[..self.caret]);
        let first = scrolled(self.first.get(), caret, total, room);
        self.first.set(first);
        let cut_left = first > 0;
        let cut_right = total + 1 > first + room;
        let low = first + usize::from(cut_left);
        let high = first + room - usize::from(cut_right);

        let mut spans = Vec::new();
        if cut_left {
            spans.push(Span::styled(MORE_LEFT, more));
        }
        let mut body = String::new();
        let mut cell = 0;
        for grapheme in self.text.graphemes(true) {
            let end = cell + display_width(grapheme);
            if cell >= low && end <= high {
                body.push_str(grapheme);
            } else {
                // A wide glyph across an edge leaves a blank for the half
                // that is on screen.
                let inside = end.min(high).saturating_sub(cell.max(low));
                body.extend(std::iter::repeat_n(' ', inside));
            }
            cell = end;
        }
        spans.push(Span::styled(body, style));
        if cut_right {
            spans.push(Span::styled(MORE_RIGHT, more));
        }
        Shown {
            spans,
            caret: crate::wrap::clamp_u16(caret - first),
        }
    }
}

/// The first cell on screen, from `first` on the last frame: unchanged while
/// the caret stays clear of the marks, and never leaving room to spare at the
/// end of the line.
fn scrolled(first: usize, caret: usize, total: usize, room: usize) -> usize {
    if total < room {
        return 0;
    }
    let last = total + 1 - room;
    let mut first = first.min(last);
    if caret <= first && first > 0 {
        // A third of the field stays in view behind the caret.
        first = caret.saturating_sub(room / 3);
    }
    if first > 0 && caret == first {
        first -= 1;
    }
    if caret + 1 >= first + room && caret < total {
        first = caret + 2 - room;
    } else if caret >= first + room {
        first = caret + 1 - room;
    }
    first.min(last)
}

#[cfg(test)]
mod tests;
