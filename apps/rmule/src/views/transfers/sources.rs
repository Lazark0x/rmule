//! The sources pane for the selected download: one row per worker slot,
//! naming the peer, its phase and what it is moving, then one per source
//! whose dial ended before its hello and that no slot holds ([`row`]).
//!
//! The title names the download as its table row does. A source row's speed
//! is real — the `bytes_received` its slot carries while receiving,
//! differenced and smoothed by [`crate::rates`]. **Software** is the client
//! the slot's peer named in its hello, a dash until that hello completes.
//!
//! The pane is ordered by its own **Table Sort** ([`sort`]).

use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::Style;
use ratatui::text::Span;
use ratatui::widgets::{Cell, HighlightSpacing, Row, Table};
use rmule_core::DownloadId;

use super::downloads::display_name;
use super::{
    COL_SPACING, Pane, SYMBOL_W, TransfersView, draw_centered, pane_block, selected_id,
    table_widths,
};
use crate::row_selection::{MARKER, selection_style, viewport};
use crate::state::{DownloadRow, DownloadStatus, NO_NETWORK_WAIT, UiState};
use crate::table_sort::{SortedTable, arrow_floors, header_label, header_widths};
use crate::theme::Theme;
use crate::views::{DrawnRows, say_gave_way};
use crate::views::{rate_cell, software_label};
use crate::words::Sentence;
use crate::words::download::source_wait_words;
use crate::wrap::{TableColumns, clamp_u16, gave_way, wrapped_cell};

mod row;
pub(super) mod sort;

use row::{SourceRow, source_rows};
use sort::SourcesTable;

/// Sources table columns: Source · Software · Phase · Speed. `Software` holds
/// the text a peer chose to call itself, so it is greedy and takes the slack
/// left after the others; they are bounded — an endpoint, a phase, a rate —
/// and ask for the widest drawn, up to [`SOURCE_CAPS`].
const SOURCE_COLS: [usize; 4] = [22, 12, 16, 10];
const SOURCE_FLEX: usize = 1;

/// The most each bounded column asks for: an IPv6 endpoint with its port, a
/// phase or why a dial ended, a rate of several MB/s. Software is greedy and
/// asks for nothing.
const SOURCE_CAPS: [Option<usize>; 4] = [Some(47), None, Some(64), Some(14)];

/// The order the sources table's columns give way in when the pane cannot
/// hold every header: Speed, Phase, then Source. Software never gives way.
const SOURCE_GIVE_WAY: [usize; 3] = [3, 2, 0];

impl TransfersView {
    pub(super) fn draw_sources(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
        ids: &[DownloadId],
        now: Instant,
    ) {
        let focused = self.focus == Pane::Sources;
        self.source_rows = DrawnRows::default();
        self.source_header_area = Rect::default();
        let selected = selected_id(ids, &self.table_state);
        let title = match selected {
            Some(id) => {
                let row = state.downloads.get(&id);
                let (name, _) = display_name(
                    row.and_then(|r| r.metadata.as_ref()),
                    row.and_then(|r| r.file_hash),
                );
                format!(" Sources · {name} ")
            }
            None => " Sources ".to_string(),
        };
        let block = pane_block(area.width, (&title, ""), focused, theme);
        let inner = block.inner(area);

        // A row waiting for sources or a network has none to list, and the
        // pane says what would end the wait rather than only that it is empty.
        let selected_row = selected.and_then(|id| state.downloads.get(&id));
        let (Some(id), Some(diag)) = (selected, self.selected_diag(state, ids)) else {
            frame.render_widget(block, area);
            let reconnect_wait = reconnect_wait(state, now);
            let text = match selected {
                Some(_) => idle_text(selected_row, reconnect_wait.as_ref()),
                None => "no download selected",
            };
            draw_centered(frame, inner, text, theme.dim_text());
            return;
        };
        let listed = source_rows(diag);
        if listed.is_empty() {
            frame.render_widget(block, area);
            let reconnect_wait = reconnect_wait(state, now);
            let text = idle_text(selected_row, reconnect_wait.as_ref());
            draw_centered(frame, inner, text, theme.dim_text());
            return;
        }

        let block = pane_block(area.width, (&title, " s sort  S reverse "), focused, theme);
        // Greedy endpoint column, wrapping cells; the sorted column is
        // floored wide enough for its arrow, so the header stays one line.
        let keys = self.source_keys(state, Some(id));
        let workers: Vec<SourceRow<'_>> = keys
            .iter()
            .filter_map(|key| listed.iter().find(|row| row.key() == *key).copied())
            .collect();
        let widest = |text: &dyn Fn(&SourceRow<'_>) -> String| {
            workers
                .iter()
                .map(|worker| text(worker).chars().count())
                .max()
                .unwrap_or(0)
        };
        let widths_drawn = [
            widest(&|worker| worker.source_label()),
            0,
            widest(&|worker| worker.phase_cell()),
            widest(&|worker| rate_cell(worker.bps(id, state), theme).0),
        ];
        let mut wants = [0; 4];
        for (index, cap) in SOURCE_CAPS.into_iter().enumerate() {
            if let Some(cap) = cap {
                wants[index] = widths_drawn[index].min(cap);
            }
        }
        let floors = arrow_floors(&self.source_sort, &SOURCE_COLS, SOURCE_FLEX);
        let headers = header_widths(&self.source_sort);
        let values: Vec<Vec<String>> = workers
            .iter()
            .map(|worker| {
                vec![
                    worker.source_label(),
                    worker
                        .software()
                        .map_or_else(|| "—".to_string(), software_label),
                    worker.phase_cell(),
                    rate_cell(worker.bps(id, state), theme).0,
                ]
            })
            .collect();
        let row_at = |worker: &SourceRow<'_>, cols: &[usize]| -> (Row<'static>, u16) {
            let (source, source_h) = wrapped_cell(
                &worker.source_label(),
                cols[0],
                Style::new().fg(theme.fg),
                false,
            );
            let (phase, phase_h) = wrapped_cell(
                &worker.phase_cell(),
                cols[2],
                Style::new().fg(theme.fg),
                false,
            );
            // Per-slot receive rate, differenced from the `bytes_received`
            // this worker carries while receiving.
            let (speed_text, speed_style) = rate_cell(worker.bps(id, state), theme);
            let (speed, speed_h) = wrapped_cell(&speed_text, cols[3], speed_style, false);
            // Degrade: a dash until the slot's peer completes its hello —
            // and for good for a source whose dial ended before it.
            let (software, software_h) = worker.software().map_or_else(
                || (Cell::from(Span::styled("—", theme.dim_text())), 1),
                |s| {
                    wrapped_cell(
                        &software_label(s),
                        cols[1],
                        Style::new().fg(theme.fg),
                        false,
                    )
                },
            );
            let height = source_h.max(phase_h).max(speed_h).max(software_h);
            (
                Row::new(vec![source, software, phase, speed]).height(height),
                height,
            )
        };
        let cols_at = |bar: bool| {
            table_widths(
                area,
                bar,
                &TableColumns {
                    floors: &floors,
                    headers: &headers,
                    flex: SOURCE_FLEX,
                    wants: &wants,
                    give_way: &SOURCE_GIVE_WAY,
                },
            )
        };
        // The selected source's values in the columns that gave way.
        let selected = self.sources_state.selected();
        let off_screen_at = |cols: &[usize]| {
            selected
                .and_then(|index| values.get(index))
                .map_or_else(Vec::new, |row| {
                    crate::views::off_screen::hidden(
                        SourcesTable::COLUMNS.iter().map(|c| c.label),
                        row,
                        cols,
                    )
                })
        };
        let framed = block.inner(area);
        // The header is one line: its labels are fixed and fit their floors.
        let bar = viewport::needs_bar(workers.len(), framed.height.saturating_sub(1), || {
            let cols = cols_at(false);
            let room = framed
                .height
                .saturating_sub(crate::views::off_screen::height(
                    framed,
                    &off_screen_at(&cols),
                ))
                .saturating_sub(1);
            let drawn: u32 = workers
                .iter()
                .map(|worker| u32::from(row_at(worker, &cols).1))
                .sum();
            drawn > u32::from(room)
        });
        let cols = cols_at(bar);
        let header = Row::new(
            SourcesTable::COLUMNS
                .iter()
                .map(|column| header_label(column.label, self.source_sort.arrow(column.column))),
        )
        .style(theme.dim_text());
        let (rows, heights): (Vec<_>, Vec<u16>) =
            workers.iter().map(|worker| row_at(worker, &cols)).unzip();
        let widths = cols
            .iter()
            .map(|width| Constraint::Length(clamp_u16(*width)));
        let table = Table::new(rows, widths)
            .header(header)
            .column_spacing(COL_SPACING)
            .row_highlight_style(selection_style(theme, focused))
            .highlight_symbol(MARKER)
            // The gutter is always there, so a header click lands where drawn.
            .highlight_spacing(HighlightSpacing::Always);
        frame.render_widget(block, area);
        let table_area =
            crate::views::off_screen::draw(frame, framed, &off_screen_at(&cols), theme);
        let (list, bar) = viewport::split(table_area, bar);
        let first = self.source_viewport.follow(
            self.sources_state.selected().unwrap_or(0),
            heights.len(),
            list.height.saturating_sub(1),
            |index| heights[index],
        );
        *self.sources_state.offset_mut() = first;
        frame.render_stateful_widget(table, list, &mut self.sources_state);
        let foot = self.source_viewport.draw(frame, area, bar, theme);
        say_gave_way(
            frame,
            foot,
            &gave_way(SourcesTable::COLUMNS.iter().map(|c| c.label), &cols),
            theme,
        );
        // Below the one header line, down to the `Off-screen:` line if any.
        let inner = Rect::new(
            list.x,
            list.y.saturating_add(1),
            list.width,
            list.height.saturating_sub(1),
        );
        self.source_header_area = Rect::new(
            inner.x.saturating_add(SYMBOL_W),
            inner.y.saturating_sub(1),
            inner.width.saturating_sub(SYMBOL_W),
            1,
        );
        self.source_header_cols = cols;
        self.source_rows = DrawnRows::new(inner, first, heights[first..].to_vec());
    }
}

/// What a download waiting for a network waits for while core re-makes the
/// operator's lost session.
/// What the pane says of a selected download with no source to list: what
/// its run waits on, when it said so — a reconnect under way first, as that
/// is what ends a wait for a network — else that none is active.
fn idle_text<'a>(row: Option<&DownloadRow>, reconnect: Option<&'a Sentence>) -> &'a str {
    let wait = row.and_then(|row| row.source_wait).map(source_wait_words);
    match row.map(|row| row.status) {
        Some(DownloadStatus::NoConnection) => reconnect
            .map(Sentence::as_str)
            .or(wait)
            .unwrap_or(NO_NETWORK_WAIT),
        _ => wait.unwrap_or("no active sources"),
    }
}

fn reconnect_wait(state: &UiState, now: Instant) -> Option<Sentence> {
    state
        .reconnect
        .as_ref()
        .map(|reconnect| reconnect.line(now))
}

#[cfg(test)]
mod tests {

    use crate::golden::assert_golden;

    use super::*;
    use crate::fixture::*;

    #[test]
    fn golden_sources_focus() {
        let mut view = TransfersView::new();
        view.focus = Pane::Sources;
        let state = three_downloads();
        assert_golden("transfers_sources_focus", GOLDEN_W, GOLDEN_H, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now());
        });
    }

    /// A source another download of its peer holds the link to waits on that
    /// link, and its row says so (ADR-0107).
    #[test]
    fn a_source_waiting_on_its_peers_link_says_so_on_its_row() {
        let mut view = TransfersView::new();
        let mut state = three_downloads();
        let row = state
            .diagnostics
            .downloads
            .get_mut(&download_id(1))
            .expect("the first row");
        let worker = row.workers.values_mut().next().expect("a slot");
        let waiting = worker.peer_endpoint().expect("the slot holds a peer");
        worker.mark_link_turn(rmule_core::LinkTurn::Waiting);
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(200, 24)).expect("terminal");
        terminal
            .draw(|frame| {
                let area = frame.area();
                view.draw(frame, area, &state, &Theme::default_dark(), now());
            })
            .expect("draw");
        let buffer = terminal.backend().buffer();
        let shown: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            shown
                .lines()
                .any(|line| line.contains(&crate::words::units::address(waiting))
                    && line.contains("waits for the link")),
            "{shown}"
        );
    }

    /// A seed refused under a `required` policy for its unknown crypt stance
    /// says so on its own row after its slot took its next peer (ADR-0110,
    /// "The cause is the source's, not the slot's").
    #[test]
    fn a_dial_that_ended_before_the_hello_says_why_after_its_slot_moved_on() {
        let mut view = TransfersView::new();
        let mut state = three_downloads();
        let row = state
            .diagnostics
            .downloads
            .get_mut(&download_id(1))
            .expect("the first row");
        let worker = row.workers.values_mut().next().expect("a slot");
        let refused = worker.peer_endpoint().expect("the slot holds a peer");
        row.dial_ends.insert(
            refused,
            rmule_core::diagnostics::SourceDialEnd {
                cause: rmule_core::DialEnd::CryptStanceUnknown,
                at: now(),
                remembered: true,
            },
        );
        worker.attach_peer(peer_endpoint(77));
        worker.transition(rmule_core::diagnostics::WorkerPhase::Connecting);
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(200, 24)).expect("terminal");
        terminal
            .draw(|frame| {
                let area = frame.area();
                view.draw(frame, area, &state, &Theme::default_dark(), now());
            })
            .expect("draw");
        let buffer = terminal.backend().buffer();
        let shown: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        let ended = shown
            .lines()
            .find(|line| line.contains("refused: its crypt stance is unknown"))
            .unwrap_or_else(|| panic!("no row says the cause:\n{shown}"));
        assert!(
            ended.contains(&crate::words::units::address(refused)) && ended.contains("remembered"),
            "{ended}"
        );
        assert!(
            shown.contains("connecting"),
            "the slot's next dial: {shown}"
        );
    }

    /// A selected row waiting for a network says, where its sources
    /// would be, what would end the wait.
    #[test]
    fn a_row_waiting_for_a_network_says_what_would_end_the_wait() {
        let mut view = TransfersView::new();
        let mut state = three_downloads();
        state
            .downloads
            .get_mut(&download_id(1))
            .expect("the first row")
            .status = DownloadStatus::NoConnection;
        state.diagnostics.downloads.remove(&download_id(1));
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 24)).expect("terminal");
        terminal
            .draw(|frame| {
                let area = frame.area();
                view.draw(frame, area, &state, &Theme::default_dark(), now());
            })
            .expect("draw");
        let buffer = terminal.backend().buffer();
        let shown: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            shown.contains("connect to a server, or enable Kad"),
            "{shown}"
        );
    }
}
