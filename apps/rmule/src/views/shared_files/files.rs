//! The shared-files table (spec §3.5).
//!
//! Every row is a **Shared File Registry** entry (see [`crate::state::SharedRow`]):
//! **File** is the name it is shared under, **State** whether it is offered
//! or withheld — why, in words, and since when rmule noticed (ADR-0100, "The
//! registry against the disk") — and **Size** its exact size, all
//! read off the registry, with the short hash and a dash standing in only for
//! the moment between a share edge and core's next File History answer.
//! **Uploading** counts the peers holding a slot for it now; **Requests**,
//! **Accepted** and **Transferred** — in aMule's own order
//! (`amule-kno/src/SharedFilesCtrl.cpp:158-160`) — show this run's serve
//! counter, then in brackets the all-time one core keeps beside the registry
//! row — `3 (12)`, the way aMule's Shared Files list writes session and
//! all-time in one cell. Each column's floor holds the pair at its realistic
//! widest on one line; when the pane is too narrow for every floor,
//! the widest-floored pair columns give way first — each drops its all-time
//! figure rather than wrapping, since a figure is never split across lines.
//! The selected row's dropped figures are never lost: they reprint in full,
//! wrapped like any other text, on an `Off-screen:` note under the header.
//!
//! The table scrolls: the selected row is always drawn.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};

use super::sort::{SharedColumn, SharedLine, SharedTable};
use super::{GUTTER_W, Pane, SharedView, num_style, pane_border, render_empty, table_widths};
use crate::row_selection::{gutter, mark_row};
use crate::state::{UiState, withheld_words};
use crate::table_sort::{SortedTable, TableSort, arrow_floors, header_label, header_widths};
use crate::theme::Theme;
use crate::views::{DrawnRows, day, human_size, say_gave_way, scroll_to_show};
use crate::wrap::{Column, TableColumns, clamp_u16, column_lines, gave_way};

/// Fixed widths of the files table's non-name columns: State · Size ·
/// Uploading · Requests · Accepted · Transferred — State fits `folder
/// missing` and wraps `since` and its day under it; Size fits `1023.9 MB`.
/// Requests, Accepted and Transferred hold the run-and-all-time pair at its
/// realistic widest on one line: `999999 (999999)` (15) for a
/// count, `999.9 GB (999.9 GB)` (19) for a byte figure — a pair that cannot
/// fit its assigned width drops the all-time figure instead of wrapping.
/// `File` is greedy — it takes whatever they leave over, and its
/// content wraps rather than clipping.
const FILE_COLS: [usize; 7] = [12, 14, 9, 10, 15, 15, 19];

/// The order the files table's columns give way in when the pane cannot hold
/// every header: Accepted, Requests, Transferred — the counters, whose
/// selected-row figures the `Off-screen:` note then reprints in full — then
/// Uploading, Size and State. File never gives way.
const FILE_GIVE_WAY: [usize; 6] = [5, 4, 6, 3, 2, 1];

/// The header, the sort's arrow on the column holding it. The column holding
/// it is floored wide enough for the arrow ([`arrow_floors`]), so the header
/// is one line.
fn files_header(
    widths: &[usize],
    sort: &TableSort<SharedTable>,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let style = theme.dim_text().add_modifier(Modifier::BOLD);
    let labels: Vec<Column> = SharedTable::COLUMNS
        .iter()
        .map(|column| {
            let label = header_label(column.label, sort.arrow(column.column));
            if matches!(column.column, SharedColumn::File | SharedColumn::State) {
                Column::left(label, style)
            } else {
                Column::right(label, style)
            }
        })
        .collect();
    column_lines(&labels, widths, 1, &Span::styled("  ", style))
}

/// A run-and-all-time pair, and whether it had to drop the all-time
/// figure to hold `width`: `text(run)` is always shorter than the pair, so
/// dropping to it is the one thing guaranteed to stop the wrap.
fn paired_text(run: u64, total: u64, text: fn(u64) -> String, width: usize) -> (String, bool) {
    // NBSP glues a figure's number to its unit so the hard-break in
    // `wrap_text` cannot land inside one (`999.9 GB`, never `999.9` then `GB`).
    let glued = |n| text(n).replace(' ', "\u{a0}");
    let full = format!("{} ({})", glued(run), glued(total));
    if full.chars().count() <= width {
        (full, false)
    } else {
        (glued(run), true)
    }
}

/// The selected row's Requests/Accepted/Transferred figures shortened or
/// hidden for space: reprinted in full, so cutting the cell
/// loses nothing. Widths are indexed by [`SharedTable::COLUMNS`]'s order
/// (Requests, Accepted, Transferred at 4, 5, 6).
fn selected_detail(line: &SharedLine, widths: &[usize]) -> Vec<String> {
    let all_time = line.all_time.unwrap_or_default();
    let mut parts = Vec::new();
    if let Some(run) = line.requests
        && paired_text(run, all_time.requests, |n| n.to_string(), widths[4]).1
    {
        parts.push(format!("Requests {run} ({})", all_time.requests));
    }
    if let Some(run) = line.accepted
        && paired_text(run, all_time.accepted, |n| n.to_string(), widths[5]).1
    {
        parts.push(format!("Accepted {run} ({})", all_time.accepted));
    }
    if let Some(run) = line.transferred
        && paired_text(run, all_time.transferred, human_size, widths[6]).1
    {
        parts.push(format!(
            "Transferred {} ({})",
            human_size(run),
            human_size(all_time.transferred)
        ));
    }
    parts
}

/// The columns before the counters, whose hidden values
/// [`crate::views::off_screen::hidden`] says; the counters say their own.
const LEADING_COLUMNS: usize = 4;

/// One file's row. The selected row is marked whichever pane holds the focus.
fn files_row(
    line: &SharedLine,
    widths: &[usize],
    selected: bool,
    focused: bool,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let mut row = column_lines(
        &file_columns(line, widths, theme),
        widths,
        1,
        &gutter(selected, focused, theme),
    );
    if selected {
        mark_row(&mut row, focused, theme);
    }
    row
}

/// One shared file's cells, in [`SharedTable::COLUMNS`]' order: what its row
/// draws, and what the `Off-screen:` line says of a column that gave way.
fn file_columns(line: &SharedLine, widths: &[usize], theme: &Theme) -> Vec<Column> {
    let dim = theme.dim_text();
    let plain = Style::new().fg(theme.fg);
    // A withheld row is offered to nobody: its name is dimmed and its State
    // says why, in the warning colour.
    let name_plain = if line.withheld.is_some() { dim } else { plain };
    let (name, name_style) = match &line.name {
        Some(name) => (name.clone(), name_plain),
        None => (crate::words::units::short_hash(line.file_hash), dim),
    };
    let state = line.withheld.map_or_else(
        || Column::left("shared", dim),
        |held| {
            Column::left(
                format!("{} since {}", withheld_words(held.reason), day(held.since)),
                Style::new().fg(theme.warn),
            )
        },
    );
    let size = line.size.map_or_else(
        || Column::right("—", dim),
        |size| Column::right(human_size(size), plain),
    );
    let count = |value: Option<u64>| {
        value.map_or_else(
            || Column::right("—", dim),
            |value| Column::right(value.to_string(), num_style(value, theme)),
        )
    };
    let all_time = line.all_time.unwrap_or_default();
    let with_all_time = |run: Option<u64>, total: u64, text: fn(u64) -> String, width: usize| {
        run.map_or_else(
            || Column::right("—", dim),
            |run| {
                Column::right(
                    paired_text(run, total, text, width).0,
                    num_style(total, theme),
                )
            },
        )
    };
    let requests = with_all_time(
        line.requests,
        all_time.requests,
        |n| n.to_string(),
        widths[4],
    );
    let accepted = with_all_time(
        line.accepted,
        all_time.accepted,
        |n| n.to_string(),
        widths[5],
    );
    let transferred = with_all_time(
        line.transferred,
        all_time.transferred,
        human_size,
        widths[6],
    );
    vec![
        Column::left(name, name_style),
        state,
        size,
        count(Some(line.uploading)),
        requests,
        accepted,
        transferred,
    ]
}

/// The title's total: the share set's size, once every row's is known.
fn total_size(lines: &[SharedLine]) -> Option<u64> {
    lines.iter().map(|line| line.size).sum::<Option<u64>>()
}

impl SharedView {
    pub(super) fn draw_files(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
    ) {
        // Nothing to click until a table is drawn.
        self.header_area = Rect::default();
        self.file_rows = DrawnRows::default();
        let focused = self.focus == Pane::Files;
        let lines_in_order = self.sorted_lines(state);

        // Column widths, off the border alone: a title never changes a
        // bordered block's interior, so this can be decided before the
        // title is — the detail notice below needs to know it first.
        let bare_inner = Block::bordered().inner(area);
        let floors = arrow_floors(&self.sort, &FILE_COLS, 0);
        let headers = header_widths(&self.sort);
        let widths = table_widths(
            bare_inner,
            &TableColumns {
                floors: &floors,
                headers: &headers,
                flex: 0,
                wants: &[],
                give_way: &FILE_GIVE_WAY,
            },
        );

        // Header line (spec §3.5): file count + total size.
        let total = total_size(&lines_in_order).map_or_else(|| "—".to_string(), human_size);
        let title = format!(
            " Shared Files · {} · {total} ",
            crate::words::scan::files(lines_in_order.len())
        );
        let hint = if state.shared.is_empty() {
            ""
        } else {
            " s sort  S reverse "
        };
        let block = crate::views::title::titled(
            Block::bordered().border_style(pane_border(theme, focused)),
            area.width,
            (&title, theme.dim_text()),
            (hint, theme.dim_text()),
        );
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if inner.height == 0 || inner.width == 0 {
            return;
        }
        let inner = self.draw_strip(frame, inner, state, theme);

        if lines_in_order.is_empty() {
            let empty = self.directory_filter(state).map_or_else(
                || crate::words::scan::NOTHING_SHARED.to_string(),
                crate::words::scan::nothing_under,
            );
            render_empty(frame, inner, &empty, theme);
            return;
        }
        say_gave_way(
            frame,
            area,
            &gave_way(SharedTable::COLUMNS.iter().map(|c| c.label), &widths),
            theme,
        );
        // The selected row's values that gave way, in full: a hidden
        // column's value, and a counter shortened to fit —
        // the drop loses nothing, it moves off the row onto this line.
        let off_screen = lines_in_order
            .get(self.files_selected)
            .map_or_else(Vec::new, |line| {
                let values: Vec<String> = file_columns(line, &widths, theme)
                    .into_iter()
                    .map(|column| column.text)
                    .collect();
                let mut parts = crate::views::off_screen::hidden(
                    SharedTable::COLUMNS
                        .iter()
                        .take(LEADING_COLUMNS)
                        .map(|c| c.label),
                    &values,
                    &widths,
                );
                parts.extend(selected_detail(line, &widths));
                parts
            });
        let inner = crate::views::off_screen::draw(frame, inner, &off_screen, theme);

        let mut lines = files_header(&widths, &self.sort, theme);
        let header_h = clamp_u16(lines.len()).min(inner.height);
        self.header_area = Rect::new(
            inner.x.saturating_add(clamp_u16(GUTTER_W)),
            inner.y,
            inner.width.saturating_sub(clamp_u16(GUTTER_W)),
            header_h,
        );
        self.header_cols.clone_from(&widths);

        let top_h = header_h;

        let rows: Vec<Vec<Line<'static>>> = lines_in_order
            .iter()
            .enumerate()
            .map(|(idx, line)| files_row(line, &widths, idx == self.files_selected, focused, theme))
            .collect();
        let heights: Vec<u16> = rows.iter().map(|row| clamp_u16(row.len())).collect();
        let room = inner.height.saturating_sub(top_h);
        self.files_offset = scroll_to_show(self.files_offset, self.files_selected, &heights, room);
        lines.extend(rows.into_iter().skip(self.files_offset).flatten());
        self.file_rows = DrawnRows::new(
            Rect::new(inner.x, inner.y + top_h, inner.width, room),
            self.files_offset,
            heights[self.files_offset..].to_vec(),
        );
        frame.render_widget(Paragraph::new(lines), inner);
    }
}

#[cfg(test)]
mod tests;
