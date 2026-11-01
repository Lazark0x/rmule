//! The frame every modal shares: a cleared, bordered panel centered over the
//! view, its title on the top border, its lines inside. A view builds the
//! lines and picks the tone; the frame is drawn here once. Every modal
//! scrolls under a Viewport when the frame is too short for it.

use std::cell::Cell;
use std::ops::Range;

use ratatui::Frame;
use ratatui::crossterm::event::KeyCode;
use ratatui::layout::{Position, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph};

use super::centered;
use crate::form::ModalLines;
use crate::row_selection::viewport::{BAR_W, Viewport, split};
use crate::table_sort::RowMove;
use crate::theme::Theme;
use crate::wrap::clamp_u16;

/// What a modal's body lays out for one width.
struct ModalLaid {
    lines: Vec<Line<'static>>,
    focus: Option<Range<usize>>,
    caret: Option<(usize, u16)>,
}

/// One modal's frame, drawn by [`Modal::draw_scrolled`].
pub(crate) struct Modal {
    title: String,
    border: Style,
    title_style: Style,
    padded: bool,
    min_height: u16,
}

impl Modal {
    /// A modal in the chrome's tone, its title marked as the active tab is.
    pub(crate) fn new(title: impl Into<String>, theme: &Theme) -> Self {
        Self {
            title: title.into(),
            border: theme.chrome(),
            title_style: theme.tab_active(),
            padded: false,
            min_height: 0,
        }
    }

    /// The title in the flash's style rather than the active tab's.
    pub(crate) fn flash_title(mut self, theme: &Theme) -> Self {
        self.title_style = theme.flash();
        self
    }

    /// The whole frame in the tone of a refusal or a removal.
    pub(crate) fn danger(mut self, theme: &Theme) -> Self {
        let bad = Style::new().fg(theme.bad);
        self.border = bad;
        self.title_style = bad;
        self
    }

    /// One blank column between the border and the text on each side.
    pub(crate) fn padded(mut self) -> Self {
        self.padded = true;
        self
    }

    /// Never shorter than `height` rows, borders included.
    pub(crate) fn at_least(mut self, height: u16) -> Self {
        self.min_height = height;
        self
    }

    /// Clear a panel centered in `area` and draw the frame and a list in it:
    /// the rows `rows(width)` lays out for a panel `width` wide, the cursor on
    /// row `cursor`, followed by `viewport` when the frame is too short for
    /// every row. Its bar's column then widens the panel when the frame has
    /// the room, else the rows are laid out for a panel one column narrower;
    /// the count is on the bottom border.
    pub(crate) fn draw_list(
        self,
        frame: &mut Frame,
        area: Rect,
        (width, cursor): (u16, usize),
        theme: &Theme,
        viewport: &Cell<Viewport>,
        rows: impl Fn(u16) -> Vec<Vec<Line<'static>>>,
    ) {
        let mut laid = rows(width);
        let lines: usize = laid.iter().map(Vec::len).sum();
        let height = clamp_u16(lines + 2).max(self.min_height).min(area.height);
        let bar = lines > usize::from(height.saturating_sub(2));
        let width = if !bar {
            width
        } else if width < area.width {
            width + BAR_W
        } else {
            laid = rows(width.saturating_sub(BAR_W));
            width
        };
        let modal = centered(area, width, height);
        let (inner, bar) = split(self.open(frame, modal, theme), bar);
        let text = self.text(inner);
        let heights: Vec<u16> = laid.iter().map(|row| clamp_u16(row.len())).collect();
        let mut place = viewport.get();
        let first = place.follow(cursor, laid.len(), text.height, |index| heights[index]);
        viewport.set(place);
        let shown: Vec<Line<'static>> = laid
            .into_iter()
            .skip(first)
            .flatten()
            .take(usize::from(text.height))
            .collect();
        frame.render_widget(Paragraph::new(shown), text);
        place.draw(frame, modal, bar, theme);
    }

    /// Clear a panel centered in `area` and draw the frame and the lines
    /// `lines(width)` lays out for a panel `width` wide, scrolled by
    /// `viewport` when the frame is too short for them all: its bar's column
    /// widens the panel when the frame has the room, else the lines are laid
    /// out for a panel one column narrower, and the count says the last line
    /// on screen.
    pub(crate) fn draw_scrolled(
        self,
        frame: &mut Frame,
        area: Rect,
        width: u16,
        theme: &Theme,
        viewport: &Cell<Viewport>,
        lines: impl Fn(u16) -> Vec<Line<'static>>,
    ) {
        self.draw_laid(frame, area, width, theme, viewport, |width| ModalLaid {
            lines: lines(width),
            focus: None,
            caret: None,
        });
    }

    /// [`Modal::draw_scrolled`] for a form: `lines(width)` also says which
    /// lines the focused field takes, and the viewport keeps them on screen
    /// until the operator scrolls it by hand. Returns where the caret is, when
    /// it is on screen.
    pub(crate) fn draw_form(
        self,
        frame: &mut Frame,
        area: Rect,
        width: u16,
        theme: &Theme,
        viewport: &Cell<Viewport>,
        lines: impl Fn(u16) -> ModalLines,
    ) -> Option<Position> {
        self.draw_laid(frame, area, width, theme, viewport, |width| {
            let laid = lines(width);
            ModalLaid {
                lines: laid.lines,
                focus: Some(laid.focus),
                caret: laid.caret,
            }
        })
    }

    fn draw_laid(
        self,
        frame: &mut Frame,
        area: Rect,
        width: u16,
        theme: &Theme,
        viewport: &Cell<Viewport>,
        lines: impl Fn(u16) -> ModalLaid,
    ) -> Option<Position> {
        let mut laid = lines(width);
        let height = clamp_u16(laid.lines.len() + 2)
            .max(self.min_height)
            .min(area.height);
        let bar = laid.lines.len() > usize::from(height.saturating_sub(2));
        let width = if !bar {
            width
        } else if width < area.width {
            width + BAR_W
        } else {
            laid = lines(width.saturating_sub(BAR_W));
            width
        };
        let modal = centered(area, width, height);
        let (inner, bar) = split(self.open(frame, modal, theme), bar);
        let text = self.text(inner);
        let mut place = viewport.get();
        let shown = match laid.focus {
            Some(focus) => {
                let first = place.follow_span(focus, laid.lines.len(), text.height, (0, 0));
                first..(first + usize::from(text.height)).min(laid.lines.len())
            }
            None => place.show(laid.lines.len(), text.height),
        };
        viewport.set(place);
        frame.render_widget(Paragraph::new(laid.lines[shown.clone()].to_vec()), text);
        place.draw(frame, modal, bar, theme);
        crate::views::caret_in(text, shown, laid.caret)
    }

    /// Clear `modal` and draw its frame; returns the inside of the border.
    fn open(&self, frame: &mut Frame, modal: Rect, theme: &Theme) -> Rect {
        let block = Block::bordered()
            .border_style(self.border)
            .style(Style::new().fg(theme.fg).bg(theme.panel))
            .title_top(Line::from(Span::styled(
                self.title.clone(),
                self.title_style,
            )));
        let inner = block.inner(modal);
        frame.render_widget(Clear, modal);
        frame.render_widget(block, modal);
        inner
    }

    /// Where the text goes inside the border: all of it, or one column in
    /// on each side when padded.
    const fn text(&self, inner: Rect) -> Rect {
        if self.padded {
            Rect::new(
                inner.x + 1,
                inner.y,
                inner.width.saturating_sub(2),
                inner.height,
            )
        } else {
            inner
        }
    }
}

/// The one reading of a confirm's keys: `Some(true)` for `y`, `Some(false)` for
/// `n`, `Esc` or `q`, `None` for a key that answers nothing. `q` declines so it
/// never falls through to quit from under a question.
pub(crate) const fn confirm_key(code: KeyCode) -> Option<bool> {
    match code {
        KeyCode::Char('y' | 'Y') => Some(true),
        KeyCode::Char('n' | 'N' | 'q') | KeyCode::Esc => Some(false),
        _ => None,
    }
}

/// Scroll a modal that only reads — a confirm, the details — by `code` when
/// it is one of the list keys: a line, a page, the ends.
pub(crate) fn scroll_key(viewport: &mut Cell<Viewport>, code: KeyCode) {
    if let Some(movement) = RowMove::of(code) {
        viewport.get_mut().scroll(movement);
    }
}

/// Scroll a form by a key a field has no use for — the page keys — and let
/// the focus pull it back when a field takes a key. Whether `code` was one of
/// them; the form's own keys are the caller's.
pub(crate) fn scroll_form(viewport: &mut Cell<Viewport>, code: KeyCode) -> bool {
    if !matches!(code, KeyCode::PageDown | KeyCode::PageUp) {
        return false;
    }
    if let Some(movement) = RowMove::of(code) {
        viewport.get_mut().hold(movement);
    }
    true
}

/// A form's field took a key: the viewport follows its focus again.
pub(crate) fn release_form(viewport: &mut Cell<Viewport>) {
    viewport.get_mut().release();
}
