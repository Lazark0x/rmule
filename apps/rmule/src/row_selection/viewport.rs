//! The **Viewport** (ADR-0072, "Viewport"): what part of a scrollable list is
//! on screen, and the scroll bar and the count drawn from it.
//!
//! The draw writes it. A list with a cursor asks it to [`follow`] the cursor;
//! one without asks it to [`show`] the list where it was scrolled, and its
//! keys [`scroll`] it between draws within what the last draw laid out. An
//! item is whatever the list scrolls by — a row however many lines it wraps
//! to, or a line. A [`Viewport`] is `Copy`, so a `&self` draw keeps one in a
//! `Cell`.
//!
//! [`follow`]: Viewport::follow
//! [`show`]: Viewport::show
//! [`scroll`]: Viewport::scroll

use std::ops::Range;

use ratatui::Frame;
use ratatui::layout::{Position, Rect};
use ratatui::style::Style;
use ratatui::symbols::scrollbar::DOUBLE_VERTICAL;
use ratatui::text::Span;
use ratatui::widgets::Paragraph;

use crate::table_sort::RowMove;
use crate::theme::Theme;
use crate::wrap::clamp_u16;

/// The column the bar takes at a list's inner right edge.
pub(crate) const BAR_W: u16 = 1;

/// Whether a list needs its bar's column: surely when it has more items than
/// its viewport has lines, else when laid out at its full width its wrapped
/// rows overflow — asked only of a list short enough to be cheap to lay out.
#[must_use]
pub(crate) fn needs_bar(items: usize, room: u16, overflows_at_full_width: impl FnOnce() -> bool) -> bool {
    items > usize::from(room) || overflows_at_full_width()
}

/// `area` split into where a list draws its items and where its bar goes:
/// the right column while it has a `bar`, nothing otherwise.
#[must_use]
pub(crate) fn split(area: Rect, bar: bool) -> (Rect, Rect) {
    let bar = if bar { BAR_W.min(area.width) } else { 0 };
    let list = Rect {
        width: area.width - bar,
        ..area
    };
    (list, Rect::new(list.right(), area.y, bar, area.height))
}

/// What part of a list is on screen, as the last draw laid it out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Viewport {
    /// The first item on screen.
    first: usize,
    /// The items on screen whole from `first`; a single item taller than the
    /// viewport counts as shown.
    shown: usize,
    /// The items in the list.
    total: usize,
    /// The cursor's row and how many rows there are, in a list with a cursor:
    /// what the count says. A table's rows are its items; the Settings form
    /// scrolls by lines and counts its rows.
    cursor: Option<(usize, usize)>,
    /// A list without a cursor resting on its end keeps the end in view as
    /// items arrive.
    tail: bool,
}

impl Viewport {
    /// A list without a cursor that opens on its end and keeps it in view
    /// until scrolled back: the log.
    #[must_use]
    pub(crate) const fn at_end() -> Self {
        Self {
            first: 0,
            shown: 0,
            total: 0,
            cursor: None,
            tail: true,
        }
    }

    /// Lay out a list of `total` rows, row `index` being `height(index)`
    /// lines, in `room` lines with the cursor on row `cursor`: the first row
    /// moves no further than keeps the cursor wholly on screen, and no rows
    /// stay hidden above while room is blank below. Returns the first row.
    ///
    /// Only rows that can be on screen are measured, whatever the list's
    /// length — a server list is thousands of rows and this runs every frame.
    pub(crate) fn follow(
        &mut self,
        cursor: usize,
        total: usize,
        room: u16,
        mut height: impl FnMut(usize) -> u16,
    ) -> usize {
        let Some(last) = total.checked_sub(1) else {
            *self = Self::default();
            return 0;
        };
        let cursor = cursor.min(last);
        self.place(cursor..cursor + 1, total, room, &mut height);
        self.cursor = Some((cursor, total));
        self.first
    }

    /// Lay out a list of `total` one-line items in `room` lines with the
    /// cursor covering the lines `span` (a form's field): the first line moves
    /// no further than keeps the span on screen. The count says `row` of
    /// `rows`. Returns the first line.
    pub(crate) fn follow_span(
        &mut self,
        span: Range<usize>,
        total: usize,
        room: u16,
        (row, rows): (usize, usize),
    ) -> usize {
        if total == 0 {
            *self = Self::default();
            return 0;
        }
        let start = span.start.min(total - 1);
        let span = start..span.end.clamp(start + 1, total);
        self.place(span, total, room, &mut |_| 1);
        self.cursor = (rows > 0).then(|| (row.min(rows - 1), rows));
        self.first
    }

    /// Lay out a list without a cursor, `total` one-line items in `room`
    /// lines: where it was scrolled, pulled back so no room is blank below
    /// while items are hidden above, or on its end while it rests there. The
    /// lines on screen.
    pub(crate) fn show(&mut self, total: usize, room: u16) -> Range<usize> {
        let room = usize::from(room);
        let last = total.saturating_sub(room);
        self.first = if self.tail { last } else { self.first.min(last) };
        self.shown = room.min(total - self.first);
        self.total = total;
        self.cursor = None;
        self.first..self.first + self.shown
    }

    /// Scroll a list without a cursor by a key's move, within what the last
    /// draw laid out: a step is that many lines, the ends are the first and
    /// last page. Landing on the last page rests it on its end. Whether it
    /// moved.
    pub(crate) fn scroll(&mut self, movement: RowMove) -> bool {
        let last = self.total.saturating_sub(self.shown);
        let first = match movement {
            RowMove::Step(lines) => self.first.saturating_add_signed(lines).min(last),
            RowMove::First => 0,
            RowMove::Last => last,
        };
        let moved = first != self.first;
        // A key that moves nothing leaves the rest where it was — except `G`,
        // which asks for the end.
        if moved || movement == RowMove::Last {
            self.tail = first == last;
        }
        self.first = first;
        moved
    }

    /// A page of a list without a cursor: the lines the last draw showed, at
    /// least one.
    #[must_use]
    pub(crate) fn page(&self) -> isize {
        isize::try_from(self.shown.max(1)).unwrap_or(isize::MAX)
    }

    /// The first item on screen.
    #[must_use]
    pub(crate) const fn first(&self) -> usize {
        self.first
    }

    /// Whether some of the list is off screen.
    #[must_use]
    pub(crate) const fn overflows(&self) -> bool {
        self.shown < self.total
    }

    /// The thumb's cells on a `track` cells long: its size the share of the
    /// list on screen, its place the share above it. It touches an end only
    /// when the list is at that end, while the track leaves it room to.
    /// `None` while the list fits.
    #[must_use]
    pub(crate) fn thumb(&self, track: u16) -> Option<Range<u16>> {
        if !self.overflows() || track == 0 {
            return None;
        }
        let wide = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        let (first, shown, total) = (wide(self.first), wide(self.shown), wide(self.total));
        let cells = u64::from(track);
        let size = ((cells * shown + total / 2) / total).clamp(1, cells);
        let travel = cells - size;
        let furthest = total - shown;
        let mut start = (travel * first + furthest / 2) / furthest;
        if travel >= 2 {
            if first > 0 {
                start = start.max(1);
            }
            if first < furthest {
                start = start.min(travel - 1);
            }
        }
        let narrow = |n: u64| u16::try_from(n).unwrap_or(track);
        Some(narrow(start)..narrow(start + size))
    }

    /// What the bottom border says: the cursor's row over the rows, or —
    /// while a list without a cursor overflows — the last item on screen over
    /// the total.
    #[must_use]
    pub(crate) fn count(&self) -> Option<String> {
        match self.cursor {
            Some((row, rows)) => Some(crate::words::viewport::count(row + 1, rows)),
            None if self.overflows() => Some(crate::words::viewport::count(
                self.first + self.shown,
                self.total,
            )),
            None => None,
        }
    }

    /// Draw the bar down `bar` — the list's inner right column — while the
    /// list overflows, and the count at the right end of `pane`'s bottom
    /// border. Returns the stretch of that border left of the count, for a
    /// note that gives way before it does.
    pub(crate) fn draw(&self, frame: &mut Frame, pane: Rect, bar: Rect, theme: &Theme) -> Rect {
        self.draw_bar(frame, bar, theme);
        self.draw_count(frame, crate::views::bottom_border(pane), theme)
    }

    /// Draw the count at the right end of `line`, and return what is left of
    /// `line` before it, a cell apart: all of it when there is no count or it
    /// does not fit.
    pub(crate) fn draw_count(&self, frame: &mut Frame, line: Rect, theme: &Theme) -> Rect {
        let Some(count) = self.count().filter(|_| line.width > 0) else {
            return line;
        };
        let text = format!(" {count} ");
        let width = clamp_u16(Span::raw(&text).width());
        if width > line.width {
            return line;
        }
        let at = Rect::new(line.right() - width, line.y, width, 1);
        frame.render_widget(Paragraph::new(Span::styled(text, theme.dim_text())), at);
        Rect {
            width: line.width - width.saturating_add(1).min(line.width),
            ..line
        }
    }

    /// The bar down `bar`, while the list overflows: `▲` and `▼` at its ends
    /// once it is three cells tall, the thumb on the track between.
    pub(crate) fn draw_bar(&self, frame: &mut Frame, bar: Rect, theme: &Theme) {
        if bar.width == 0 || bar.height == 0 {
            return;
        }
        let arrows = bar.height >= 3;
        let track = if arrows { bar.height - 2 } else { bar.height };
        let Some(thumb) = self.thumb(track) else {
            return;
        };
        let rail = theme.dim_text();
        let held = Style::new().fg(theme.fg);
        let buffer = frame.buffer_mut();
        for line in 0..bar.height {
            let (symbol, style) = match (arrows, line) {
                (true, 0) => (DOUBLE_VERTICAL.begin, rail),
                (true, l) if l == bar.height - 1 => (DOUBLE_VERTICAL.end, rail),
                _ => {
                    let cell = if arrows { line - 1 } else { line };
                    if thumb.contains(&cell) {
                        (DOUBLE_VERTICAL.thumb, held)
                    } else {
                        (DOUBLE_VERTICAL.track, rail)
                    }
                }
            };
            if let Some(cell) = buffer.cell_mut(Position::new(bar.x, bar.y + line)) {
                cell.set_symbol(symbol).set_style(style);
            }
        }
    }

    /// The first item `span` can start on, and how many items show from it.
    fn place(
        &mut self,
        span: Range<usize>,
        total: usize,
        room: u16,
        height: &mut impl FnMut(usize) -> u16,
    ) {
        let room = u32::from(room);
        // The highest first item that keeps the span whole on screen: walk
        // up from its end while the items still fit.
        let mut used: u32 = span.clone().map(|index| u32::from(height(index))).sum();
        let mut top = span.start;
        while top > 0 {
            let above = u32::from(height(top - 1));
            if used + above > room {
                break;
            }
            used += above;
            top -= 1;
        }
        // The highest first item that still fills the room to the list's end.
        let mut fill = total;
        let mut below = 0;
        while fill > 0 {
            let next = u32::from(height(fill - 1));
            if below + next > room {
                break;
            }
            below += next;
            fill -= 1;
        }
        let first = self.first.min(fill).clamp(top, span.start);
        let mut shown = 0;
        let mut lines = 0;
        for index in first..total {
            let next = u32::from(height(index));
            if room == 0 || (shown > 0 && lines + next > room) {
                break;
            }
            lines += next;
            shown += 1;
        }
        *self = Self {
            first,
            shown,
            total,
            cursor: None,
            tail: false,
        };
    }
}

#[cfg(test)]
mod tests;
