//! What a table does with the sort's keys and its header: `s` and `S` move or
//! reverse the sort, a click on a header cell sorts by that column, and either
//! way the new sort is handed on to be kept — written once, so a fix to the
//! hit test lands in every table.

use ratatui::layout::Rect;

use super::{SortedTable, TableSort, column_at};
use crate::action::Action;
use crate::config::PrefEdit;
use crate::views::ViewOutcome;

impl<T: SortedTable> TableSort<T> {
    /// `s` (`next`) moves the sort to the next column, `S` reverses it; the
    /// outcome keeps it.
    pub fn key(&mut self, next: bool) -> ViewOutcome {
        if next {
            self.next_column();
        } else {
            self.reverse();
        }
        self.kept()
    }

    /// A click at (`column`, `row`) on a header laid out over `header` as
    /// `widths` separated by `gap` blank cells: sort by the column under it and
    /// keep the sort. `None` when the click was not on a header cell.
    pub fn header_click(
        &mut self,
        header: Rect,
        widths: &[usize],
        gap: usize,
        column: u16,
        row: u16,
    ) -> Option<ViewOutcome> {
        let on_header =
            row >= header.y && row < header.y.saturating_add(header.height) && column >= header.x;
        if !on_header {
            return None;
        }
        let at = column_at(column - header.x, widths, gap)?;
        self.click(T::COLUMNS[at].column);
        Some(self.kept())
    }

    /// The outcome that has the preferences keep this sort.
    fn kept(&self) -> ViewOutcome {
        let (column, direction) = self.stored();
        ViewOutcome::Emit(Action::Preference(PrefEdit::TableSort {
            table: T::TABLE,
            column,
            direction,
        }))
    }
}
