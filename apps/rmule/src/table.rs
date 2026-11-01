//! The one table: every list in the TUI draws through here, one line per row
//! (ADR-0119). A table states its columns once ([`Table`]) and answers for a
//! row's cells ([`Cell`]); this module budgets the widths (**Greedy width**),
//! fits each value into its cell, marks the selected row, keeps the Viewport
//! on the cursor and says what the row did not show on the **Off-screen
//! line**.
//!
//! Only the rows on screen and the selected row are ever asked for their
//! cells, so a list of ten thousand results costs what a page of it costs.

use ratatui::Frame;
use ratatui::layout::{Position, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::row_selection::viewport::{self, Viewport};
use crate::row_selection::{gutter, mark_row};
use crate::table_sort::{SortedTable, TableSort, header_label, header_widths};
use crate::theme::Theme;
use crate::views::off_screen;
use crate::views::say_gave_way;
use crate::wrap::{clamp_u16, display_width};

pub(crate) use cut::cut_middle;
pub(crate) use widths::{TableColumns, gave_way, gave_way_note, greedy_widths};

mod cut;
mod widths;

/// The blank cells between two shown columns.
pub(crate) const GAP: usize = 1;

/// One cell of a row: its full value, which the Off-screen line says whenever
/// the cell cannot, and how it is drawn.
pub(crate) struct Cell {
    /// The full value.
    pub text: String,
    /// A shorter form drawn when the full value does not fit, before any cut:
    /// a figure with its detail left off.
    short: Option<String>,
    /// The cell's own drawing, in place of `text`: a chunk bar.
    drawn: Option<Vec<Span<'static>>>,
    pub style: Style,
}

impl Cell {
    pub(crate) fn new(text: impl Into<String>, style: Style) -> Self {
        Self {
            text: text.into(),
            short: None,
            drawn: None,
            style,
        }
    }

    /// Fall back to `short` where the full value does not fit.
    #[must_use]
    pub(crate) fn or_short(mut self, short: impl Into<String>) -> Self {
        self.short = Some(short.into());
        self
    }

    /// Draw `spans` in the cell; `text` stays what the Off-screen line says.
    #[must_use]
    pub(crate) fn drawn(mut self, spans: Vec<Span<'static>>) -> Self {
        self.drawn = Some(spans);
        self
    }

    /// Whether the cell cannot say its full value at `width`.
    #[must_use]
    pub(crate) fn hides_at(&self, width: usize) -> bool {
        self.drawn.is_none() && display_width(&self.text) > width
    }

    /// The text the cell draws at `width`, on one line.
    fn fitted(&self, width: usize) -> String {
        if display_width(&self.text) <= width {
            return self.text.clone();
        }
        match &self.short {
            Some(short) if display_width(short) <= width => short.clone(),
            _ => cut_middle(&self.text, width),
        }
    }

    fn spans(&self, width: usize, right: bool) -> Vec<Span<'static>> {
        if let Some(spans) = &self.drawn {
            return spans.clone();
        }
        vec![Span::styled(
            pad(&self.fitted(width), width, right),
            self.style,
        )]
    }
}

/// `text` padded with spaces to `width` cells, on the left when `right`.
fn pad(text: &str, width: usize, right: bool) -> String {
    let fill = " ".repeat(width.saturating_sub(display_width(text)));
    if right {
        format!("{fill}{text}")
    } else {
        format!("{text}{fill}")
    }
}

/// What a table states about itself, once.
pub(crate) struct Table<'a> {
    labels: Vec<&'static str>,
    headers: Vec<String>,
    /// Each column's alignment: amounts right, words left ([`ColumnKind`]).
    ///
    /// [`ColumnKind`]: crate::table_sort::ColumnKind
    right: Vec<bool>,
    floors: Vec<usize>,
    header_widths: Vec<usize>,
    flex: usize,
    flex_pair: Option<usize>,
    wants: &'a [usize],
    give_way: &'a [usize],
    gutter: usize,
    header_style: Style,
    empty: Option<&'a str>,
}

impl<'a> Table<'a> {
    /// The table `T` under `sort`, with the declared column `floors`.
    #[must_use]
    pub(crate) fn of<T: SortedTable>(
        sort: &TableSort<T>,
        floors: &[usize],
        flex: usize,
        give_way: &'a [usize],
        header_style: Style,
    ) -> Self {
        let columns = T::COLUMNS;
        Self {
            labels: columns.iter().map(|column| column.label).collect(),
            headers: columns
                .iter()
                .map(|column| header_label(column.label, sort.arrow(column.column)))
                .collect(),
            right: columns
                .iter()
                .map(|column| column.kind.right_aligned())
                .collect(),
            floors: floors.to_vec(),
            header_widths: header_widths(sort),
            flex,
            flex_pair: None,
            wants: &[],
            give_way,
            gutter: GUTTER,
            header_style,
            empty: None,
        }
    }

    /// The widest value each column shows now, capped by the table.
    #[must_use]
    pub(crate) const fn wants(mut self, wants: &'a [usize]) -> Self {
        self.wants = wants;
        self
    }

    /// A second free-text column, levelled with the greedy one.
    #[must_use]
    pub(crate) const fn flex_pair(mut self, pair: usize) -> Self {
        self.flex_pair = Some(pair);
        self
    }

    /// A gutter wider than the selection marker's two cells.
    #[must_use]
    pub(crate) const fn gutter(mut self, cells: usize) -> Self {
        self.gutter = cells;
        self
    }

    /// A column drawn by its cells, not as an amount: its header sits left.
    #[must_use]
    pub(crate) fn left(mut self, column: usize) -> Self {
        self.right[column] = false;
        self
    }

    /// What the table says under its header with no row to show.
    #[must_use]
    pub(crate) const fn empty(mut self, text: &'a str) -> Self {
        self.empty = Some(text);
        self
    }

    fn widths(&self, room: u16, bar: bool) -> Vec<usize> {
        let bar = if bar { viewport::BAR_W } else { 0 };
        let total = usize::from(room.saturating_sub(bar)).saturating_sub(self.gutter);
        greedy_widths(
            total,
            &TableColumns {
                floors: &self.floors,
                headers: &self.header_widths,
                flex: self.flex,
                flex_pair: self.flex_pair,
                wants: self.wants,
                give_way: self.give_way,
            },
            GAP,
        )
    }

    fn header(&self, widths: &[usize]) -> Line<'static> {
        let cells: Vec<Cell> = self
            .headers
            .iter()
            .map(|header| Cell::new(header.clone(), self.header_style))
            .collect();
        let marker = Span::styled(" ".repeat(self.gutter), self.header_style);
        self.line(&cells, widths, marker)
    }

    fn line(&self, cells: &[Cell], widths: &[usize], marker: Span<'static>) -> Line<'static> {
        let mut spans = vec![marker];
        let mut first = true;
        for ((cell, width), right) in cells.iter().zip(widths).zip(&self.right) {
            if *width == 0 {
                continue;
            }
            if !first {
                spans.push(Span::raw(" ".repeat(GAP)));
            }
            first = false;
            spans.extend(cell.spans(*width, *right));
        }
        Line::from(spans)
    }
}

/// The two cells of the selection marker.
const GUTTER: usize = 2;

/// A table's rows, for one draw.
pub(crate) struct Rows<'a> {
    /// How many there are.
    pub count: usize,
    /// The row the cursor is on.
    pub selected: Option<usize>,
    /// Whether the table's pane holds the focus.
    pub focused: bool,
    /// One row's cells at some widths, in the table's column order.
    pub cells: &'a dyn Fn(usize, &[usize]) -> Vec<Cell>,
    /// A gutter of the table's own, in place of the selection marker's.
    pub marker: Option<&'a dyn Fn(usize) -> Span<'static>>,
}

/// Where a table landed, for the clicks that follow it.
#[derive(Clone, Debug, Default)]
pub(crate) struct Drawn {
    /// The header cells, gutter excluded: a click there sorts.
    header: Rect,
    widths: Vec<usize>,
    /// The rows on screen.
    rows: Rect,
    first: usize,
    shown: usize,
}

impl Drawn {
    /// The header as drawn: its area, then its column widths.
    #[must_use]
    pub(crate) fn header(&self) -> (Rect, &[usize]) {
        (self.header, &self.widths)
    }

    /// The display row a click at (`column`, `row`) lands on, if any.
    #[must_use]
    pub(crate) fn hit(&self, column: u16, row: u16) -> Option<usize> {
        if !self.rows.contains(Position::new(column, row)) {
            return None;
        }
        let line = usize::from(row - self.rows.y);
        (line < self.shown).then_some(self.first + line)
    }
}

#[cfg(test)]
impl Drawn {
    /// The screen line display row `index` is on, if it was drawn.
    pub(crate) fn line_of(&self, index: usize) -> Option<u16> {
        let drawn = index.checked_sub(self.first)?;
        (drawn < self.shown).then(|| self.rows.y + clamp_u16(drawn))
    }

    pub(crate) const fn header_height(&self) -> u16 {
        self.header.height
    }

    pub(crate) const fn rows_height(&self) -> u16 {
        self.rows.height
    }
}

/// Draw `table` into `body`, the inside of the bordered `pane`: its header,
/// the rows the Viewport keeps on the cursor, the scroll bar, the Off-screen
/// line and the bottom border's count and note.
///
/// A pane too short for a header and a row drops the header, so the row the
/// keys act on stays in sight.
pub(crate) fn draw(
    frame: &mut Frame,
    (pane, body): (Rect, Rect),
    table: &Table<'_>,
    rows: &Rows<'_>,
    viewport: &mut Viewport,
    theme: &Theme,
) -> Drawn {
    let said_of = |row: usize, widths: &[usize]| {
        off_screen::hidden(
            table.labels.iter().copied(),
            &(rows.cells)(row, widths),
            widths,
        )
    };
    let said = |widths: &[usize]| {
        rows.selected
            .filter(|row| *row < rows.count)
            .map_or_else(Vec::new, |row| said_of(row, widths))
    };
    // The lines the Off-screen line holds: as many as the rows on screen
    // could ask for, so the frame stands still as the cursor walks them.
    let held = |widths: &[usize]| {
        let height = off_screen::height(body, &said(widths));
        if rows.selected.is_none() {
            return height;
        }
        let room = body.height.saturating_sub(height.max(1) + 1);
        let mut place = *viewport;
        let first = place.follow(rows.selected.unwrap_or(0), rows.count, room, |_| 1);
        let last = first.saturating_add(usize::from(room)).min(rows.count);
        (first..last)
            .map(|row| off_screen::height(body, &said_of(row, widths)))
            .fold(height, u16::max)
    };
    let bar = {
        let widths = table.widths(body.width, false);
        let room = body.height.saturating_sub(held(&widths)).saturating_sub(1);
        rows.count > usize::from(room)
    };
    let widths = table.widths(body.width, bar);
    let list = off_screen::draw(frame, body, &said(&widths), held(&widths), theme);
    let (list, bar) = viewport::split(list, bar);
    let header_h = u16::from(list.height >= 2);
    let room = list.height - header_h;
    let cursor = rows.selected.unwrap_or(0);
    let first = viewport.follow(cursor, rows.count, room, |_| 1);
    let mut lines = Vec::with_capacity(usize::from(list.height));
    if header_h > 0 {
        lines.push(table.header(&widths));
    }
    let shown = rows.count.saturating_sub(first).min(usize::from(room));
    for index in first..first + shown {
        let selected = rows.selected == Some(index);
        let marker = rows.marker.map_or_else(
            || gutter(selected, rows.focused, theme),
            |marker| marker(index),
        );
        let mut line = [table.line(&(rows.cells)(index, &widths), &widths, marker)];
        if selected {
            mark_row(&mut line, rows.focused, theme);
        }
        lines.extend(line);
    }
    if let (0, Some(empty)) = (rows.count, table.empty) {
        lines.push(Line::from(Span::styled(
            format!("{}{empty}", " ".repeat(table.gutter)),
            theme.dim_text(),
        )));
    }
    frame.render_widget(Paragraph::new(lines), list);
    let foot = viewport.draw(frame, pane, bar, theme);
    if rows.count > 0 {
        say_gave_way(
            frame,
            foot,
            &gave_way(table.labels.iter().copied(), &widths),
            theme,
        );
    }
    let gutter_w = clamp_u16(table.gutter);
    Drawn {
        header: Rect::new(
            list.x.saturating_add(gutter_w),
            list.y,
            list.width.saturating_sub(gutter_w),
            header_h,
        ),
        widths,
        rows: Rect::new(list.x, list.y + header_h, list.width, room),
        first,
        shown,
    }
}

#[cfg(test)]
mod tests;
