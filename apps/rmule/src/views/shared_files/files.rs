//! The shared-files table (spec §3.5).
//!
//! Every row is a **Shared File Registry** entry (see [`crate::state::SharedRow`]):
//! **File** is the name it is shared under, **State** whether it is offered
//! or withheld — why, in words, and since when rmule noticed (ADR-0106, "The registry against the
//! disk") — and **Size** its exact size, all
//! read off the registry, with the short hash and a dash standing in only for
//! the moment between a share edge and core's next File History answer.
//! **Uploading** counts the peers holding a slot for it now; **Requests**,
//! **Accepted** and **Transferred** — in aMule's own order
//! (`amule-kno/src/SharedFilesCtrl.cpp:158-160`) — show this run's serve
//! counter, then in brackets the all-time one core keeps beside the registry
//! row — `3 (12)`, the way aMule's Shared Files list writes session and
//! all-time in one cell. A column asks for the pair at its realistic widest;
//! one too narrow for it drops the all-time figure, and the selected row's
//! dropped figures ride the Off-screen line in full.
//!
//! The table scrolls: the selected row is always drawn.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::widgets::Block;

use super::sort::SharedLine;
use super::{Pane, SharedView, num_style, pane_border, render_empty};
use crate::state::{UiState, withheld_words};
use crate::table::{self, Cell, Rows, Table};
use crate::theme::Theme;
use crate::views::{day, human_size};
use crate::words::serve::PARTIAL;

/// Floors of the files table's columns: File · State · Size · Uploading ·
/// Requests · Accepted · Transferred. State fits `folder missing`, Size fits
/// `1023.9 MB`, a counter its run figure. `File` is greedy: its entry is the
/// room it keeps before other columns give way to it.
const FILE_COLS: [usize; 7] = [30, 14, 9, 9, 8, 8, 11];

/// What the counters ask for: the run-and-all-time pair at its realistic
/// widest, `999999 (999999)` and `999.9 GB (999.9 GB)`.
const FILE_WANTS: [usize; 7] = [0, 0, 0, 0, 15, 15, 19];

/// The order the files table's columns give way in: Accepted, Requests,
/// Transferred — the counters, whose selected-row figures the Off-screen line
/// says in full — then Uploading, Size and State. File never gives way.
const FILE_GIVE_WAY: [usize; 6] = [5, 4, 6, 3, 2, 1];

/// A run-and-all-time pair, falling back to the run figure in a cell too
/// narrow for both.
fn paired(run: u64, total: u64, text: fn(u64) -> String, style: Style) -> Cell {
    Cell::new(format!("{} ({})", text(run), text(total)), style).or_short(text(run))
}

/// One shared file's cells, in `SharedTable::COLUMNS`' order.
fn file_cells(line: &SharedLine, theme: &Theme) -> Vec<Cell> {
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
        || Cell::new(if line.partial { PARTIAL } else { "shared" }, dim),
        |held| {
            let why = withheld_words(held.reason);
            Cell::new(
                format!("{why} since {}", day(held.since)),
                Style::new().fg(theme.warn),
            )
            .or_short(why)
        },
    );
    let size = line.size.map_or_else(
        || Cell::new("—", dim),
        |size| Cell::new(human_size(size), plain),
    );
    let all_time = line.all_time.unwrap_or_default();
    let with_all_time = |run: Option<u64>, total: u64, text: fn(u64) -> String| {
        run.map_or_else(
            || Cell::new("—", dim),
            |run| paired(run, total, text, num_style(total, theme)),
        )
    };
    vec![
        Cell::new(name, name_style),
        state,
        size,
        Cell::new(line.uploading.to_string(), num_style(line.uploading, theme)),
        with_all_time(line.requests, all_time.requests, |n| n.to_string()),
        with_all_time(line.accepted, all_time.accepted, |n| n.to_string()),
        with_all_time(line.transferred, all_time.transferred, human_size),
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
        let focused = self.focus == Pane::Files;
        let lines_in_order = self.sorted_lines(state);

        // Header line (spec §3.5): file count + total size.
        let total = total_size(&lines_in_order).map_or_else(|| "—".to_string(), human_size);
        let tagged = if self.tags.is_empty() {
            String::new()
        } else {
            format!("· {} ", crate::words::app::tagged(self.tags.len()))
        };
        let title = format!(
            " Shared Files · {} · {total} {tagged}",
            crate::words::scan::files(lines_in_order.len())
        );
        let hint = if lines_in_order.is_empty() {
            ""
        } else {
            " m menu  / filter  Tab uploads  Space tag  s sort  S reverse  z zoom "
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

        if lines_in_order.is_empty() && !self.filter.shown() {
            let empty = self.directory_filter(state).map_or_else(
                || crate::words::scan::NOTHING_SHARED.to_string(),
                crate::words::scan::nothing_under,
            );
            render_empty(frame, inner, &empty, theme);
            return;
        }
        let cells = |index: usize, _: &[usize]| file_cells(&lines_in_order[index], theme);
        let header_style = theme.dim_text().add_modifier(Modifier::BOLD);
        let table = Table::of(&self.sort, &FILE_COLS, 0, &FILE_GIVE_WAY, header_style)
            .wants(&FILE_WANTS)
            .empty(crate::words::app::NO_MATCH);
        let tagged = |index: usize| self.tags.contains(&lines_in_order[index].file_hash);
        let rows = Rows {
            count: lines_in_order.len(),
            selected: Some(self.files_selected),
            focused,
            cells: &cells,
            marker: None,
            tagged: Some(&tagged),
            filter: Some((&self.filter, state.shared.len())),
        };
        self.drawn_files = table::draw(
            frame,
            (area, inner),
            &table,
            &rows,
            &mut self.files_viewport,
            theme,
        );
    }
}

#[cfg(test)]
mod tests;
