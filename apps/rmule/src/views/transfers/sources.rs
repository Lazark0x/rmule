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
use ratatui::layout::Rect;
use ratatui::style::Style;
use rmule_core::DownloadId;

use super::downloads::display_name;
use super::{Pane, TransfersView, draw_centered, pane_block, selected_id};
use crate::state::{DownloadRow, DownloadStatus, NO_NETWORK_WAIT, UiState};
use crate::table::{self, Cell, Rows, Table};
use crate::theme::Theme;
use crate::views::{rate_cell, software_label};
use crate::words::Sentence;
use crate::words::download::source_wait_words;
use crate::wrap::display_width;

mod row;
pub(super) mod sort;

use row::{SourceRow, source_rows};

/// Sources table columns: Source · Software · Phase · Speed. `Software` holds
/// the text a peer chose to call itself, so it is greedy and takes the slack
/// left after the others; they are bounded — an endpoint, a phase, a rate —
/// and ask for the widest drawn, up to [`SOURCE_CAPS`]. Source's floor holds an
/// IPv4 endpoint with its port.
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
        let selected = selected_id(ids, self.selected);
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
        if let Some(text) = self.idle_sources_text(state, ids, now) {
            let block = pane_block(area.width, (&title, ""), focused, theme);
            let inner = block.inner(area);
            frame.render_widget(block, area);
            draw_centered(frame, inner, &text, theme.dim_text());
            return;
        }
        let (Some(id), Some(diag)) = (selected, self.selected_diag(state, ids)) else {
            return;
        };
        let listed = source_rows(diag);

        let block = pane_block(
            area.width,
            (&title, " Tab downloads  / filter  s sort  S reverse  z zoom "),
            focused,
            theme,
        );
        let keys = self.source_keys(state, Some(id));
        let workers: Vec<SourceRow<'_>> = keys
            .iter()
            .filter_map(|key| listed.iter().find(|row| row.key() == *key).copied())
            .collect();
        let plain = Style::new().fg(theme.fg);
        // Per-slot receive rate, differenced from the `bytes_received` this
        // worker carries while receiving. Software is a dash until the slot's
        // peer completes its hello — and for good for a source whose dial
        // ended before it.
        let cells = |index: usize, _: &[usize]| {
            let worker = &workers[index];
            let (speed, speed_style) = rate_cell(worker.bps(id, state), theme);
            vec![
                Cell::new(worker.source_label(), plain),
                worker.software().map_or_else(
                    || Cell::new("—", theme.dim_text()),
                    |software| Cell::new(software_label(software), plain),
                ),
                Cell::new(worker.phase_cell(), plain),
                Cell::new(speed, speed_style),
            ]
        };
        let mut wants = [0; 4];
        for (index, cap) in SOURCE_CAPS.into_iter().enumerate() {
            if let Some(cap) = cap {
                let widest = (0..workers.len())
                    .map(|row| display_width(&cells(row, &[])[index].text))
                    .max()
                    .unwrap_or(0);
                wants[index] = widest.min(cap);
            }
        }
        let table = Table::of(
            &self.source_sort,
            &SOURCE_COLS,
            SOURCE_FLEX,
            &SOURCE_GIVE_WAY,
            theme.dim_text(),
        )
        .wants(&wants);
        let rows = Rows {
            count: workers.len(),
            selected: self.source_selected,
            focused,
            cells: &cells,
            marker: None,
            tagged: None,
            filter: Some((&self.source_filter, listed.len())),
        };
        let inner = block.inner(area);
        frame.render_widget(block, area);
        self.source_drawn = table::draw(
            frame,
            (area, inner),
            &table,
            &rows,
            &mut self.source_viewport,
            theme,
        );
    }
}

impl TransfersView {
    /// What the pane says in place of a table with no source to list, a row
    /// waiting for sources or a network saying what would end the wait.
    /// `None` while there are rows.
    pub(super) fn idle_sources_text(
        &self,
        state: &UiState,
        ids: &[DownloadId],
        now: Instant,
    ) -> Option<String> {
        let selected = selected_id(ids, self.selected);
        let selected_row = selected.and_then(|id| state.downloads.get(&id));
        let listed = self
            .selected_diag(state, ids)
            .is_some_and(|diag| !source_rows(diag).is_empty());
        if listed {
            return None;
        }
        let reconnect_wait = reconnect_wait(state, now);
        Some(
            match selected {
                Some(_) => idle_text(selected_row, reconnect_wait.as_ref()),
                None => "no download selected",
            }
            .to_string(),
        )
    }
}

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
        let mut view = TransfersView::by_name();
        view.focus = Pane::Sources;
        let state = three_downloads();
        assert_golden("transfers_sources_focus", GOLDEN_W, GOLDEN_H, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now());
        });
    }

    /// A source handed over to another download has no slot and keeps a row,
    /// sorted by its rank behind every slot and ahead of an ended dial
    /// (ADR-0090).
    #[test]
    fn a_handed_over_source_has_a_row_saying_so() {
        let mut view = TransfersView::by_name();
        let mut state = three_downloads();
        let handed = rmule_primitives::PeerEndpoint::V4(rmule_primitives::Ipv4Endpoint::new(
            std::net::Ipv4Addr::new(198, 51, 100, 40),
            4662,
        ));
        let row = state
            .diagnostics
            .downloads
            .get_mut(&download_id(1))
            .expect("the first row");
        row.handed_over.insert(handed);
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(150, 24)).expect("terminal");
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
                .any(|line| line.contains(&crate::words::units::address(handed))
                    && line.contains(crate::words::download::HANDED_OVER)),
            "{shown}"
        );
    }

    /// A source another download of its peer holds the link to waits on that
    /// link, and its row says so (ADR-0107).
    #[test]
    fn a_source_waiting_on_its_peers_link_says_so_on_its_row() {
        let mut view = TransfersView::by_name();
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
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(150, 24)).expect("terminal");
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
    /// "the cause outlives the slot").
    #[test]
    fn a_dial_that_ended_before_the_hello_says_why_after_its_slot_moved_on() {
        let mut view = TransfersView::by_name();
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
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(150, 24)).expect("terminal");
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
        let mut view = TransfersView::by_name();
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
