//! The upload-peers pane: who holds a slot for the selected file, and who is
//! waiting in the queue at what rank.
//!
//! A slot-holder's **Speed** is real — its monotonic `bytes_sent` differenced
//! and smoothed by [`crate::rates`]. A queued peer holds no slot, so it has no
//! counter and reads a dash. **File** is the file the peer is served or waits
//! for, by the name it is shared under. **Software** is the client the peer's
//! hello named, written as aMule writes it; a dash when core held no hello.
//!
//! The pane scrolls: the selected row is always drawn.
//!
//! Beyond the global keys, `a` toggles the active-uploads-only filter
//! (default on); the pane title reports which way it is set. The pane is
//! ordered by its own **Table Sort** ([`sort`]).

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Paragraph};
use rmule_primitives::FileHash;

use super::rate_cell;
use super::{Pane, SharedView, pane_border, render_empty, table_widths};
use crate::row_selection::{gutter, mark_row};
use crate::state::{UiState, UploadPeer, UploadState};
use crate::table_sort::{SortedTable, TableSort, arrow_floors, header_label, header_widths};
use crate::theme::Theme;
use crate::views::{DrawnRows, say_gave_way, scroll_to_show, software_label};
use crate::words::units::short_hash;
use crate::wrap::{Column, TableColumns, clamp_u16, column_lines, gave_way, wrapped_lines};

pub(super) mod sort;

use sort::{PeerColumn, PeersTable};

/// Floors of the peers table's columns: Peer · Software · State · Speed ·
/// File. `File` holds the free text and is greedy: it takes the slack left
/// after the others. They are bounded and floored at their usual widest value
/// — an IPv4 endpoint, `aMule v2.3.3`, `Queued #99`, a rate to `999.9 KB/s` —
/// and asked for the widest drawn, up to [`PEER_CAPS`].
const PEER_COLS: [usize; 5] = [21, 12, 12, 10, 12];

/// The most each bounded column asks for: an IPv6 endpoint with its port,
/// a client name with a short mod, a queue rank of five digits, a rate of
/// several MB/s.
const PEER_CAPS: [usize; 4] = [47, 24, 14, 14];

/// The greedy column: the file the peer is served or waits for.
const PEER_FLEX: usize = 4;

/// The order the peers table's columns give way in when the pane cannot hold
/// every header: Software, Speed, State, then Peer. File never gives way.
const PEER_GIVE_WAY: [usize; 4] = [1, 3, 2, 0];

/// The header, the sort's arrow on the column holding it, which is floored
/// wide enough for it ([`arrow_floors`]).
fn peers_header(
    widths: &[usize],
    sort: &TableSort<PeersTable>,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let style = theme.dim_text().add_modifier(Modifier::BOLD);
    let labels: Vec<Column> = PeersTable::COLUMNS
        .iter()
        .map(|column| {
            let label = header_label(column.label, sort.arrow(column.column));
            if column.column == PeerColumn::Speed {
                Column::right(label, style)
            } else {
                Column::left(label, style)
            }
        })
        .collect();
    column_lines(&labels, widths, 1, &Span::styled("  ", style))
}

/// The file a peer is served or waits for, by its shared name — a Partial
/// Share's by its download's; the short hash until a name is read.
fn file_label(state: &UiState, file: FileHash) -> (String, bool) {
    state
        .shared
        .get(&file)
        .and_then(crate::state::SharedRow::name)
        .or_else(|| {
            state
                .partial_download(file)
                .and_then(|download| download.metadata.as_ref())
                .map(|metadata| metadata.name.to_display_string())
        })
        .map_or_else(|| (short_hash(file), false), |name| (name, true))
}

fn peers_row(
    peer: &UploadPeer,
    state: &UiState,
    bps: f64,
    widths: &[usize],
    selected: bool,
    focused: bool,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let mut row = column_lines(
        &peer_columns(peer, state, bps, theme),
        widths,
        1,
        &gutter(selected, focused, theme),
    );
    if selected {
        mark_row(&mut row, focused, theme);
    }
    row
}

/// One upload peer's cells, in [`PeersTable::COLUMNS`]' order: what its row
/// draws, and what the `Off-screen:` line says of a column that gave way.
fn peer_columns(peer: &UploadPeer, state: &UiState, bps: f64, theme: &Theme) -> Vec<Column> {
    let addr = crate::words::units::address(peer.peer);
    let (state_text, file) = match peer.state {
        UploadState::Uploading { file } => ("Uploading".to_string(), file),
        UploadState::Queued { rank, file } => (format!("Queued #{rank}"), file),
    };
    let (file_text, named) = file_label(state, file);
    let dim = theme.dim_text();
    let plain = Style::new().fg(theme.fg);
    // A queued peer holds no slot, so core keeps no counter for it and the
    // meter is an honest dash.
    let (speed_text, speed_style) = rate_cell(bps, theme);
    let (software, software_style) = peer
        .software
        .as_ref()
        .map_or_else(|| ("—".to_string(), dim), |s| (software_label(s), plain));
    vec![
        Column::left(addr, plain),
        Column::left(software, software_style),
        Column::left(state_text, plain),
        Column::right(speed_text, speed_style),
        Column::left(file_text, if named { plain } else { dim }),
    ]
}

fn is_uploading(peer: &UploadPeer) -> bool {
    matches!(peer.state, UploadState::Uploading { .. })
}

impl SharedView {
    /// The peers the pane shows under the current filter: only slot-holders
    /// when active-only is on, everyone otherwise.
    pub(super) fn visible_peers<'a>(&self, state: &'a UiState) -> Vec<&'a UploadPeer> {
        state
            .upload_peers
            .values()
            .filter(|peer| !self.active_only || is_uploading(peer))
            .collect()
    }

    pub(super) fn draw_peers(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
    ) {
        self.peer_rows = DrawnRows::default();
        self.peer_header_area = Rect::default();
        let focused = self.focus == Pane::Peers;
        let mode = if self.active_only {
            "active only"
        } else {
            "all"
        };
        let hint = if state.upload_peers.is_empty() {
            ""
        } else {
            " s sort  S reverse "
        };
        let block = crate::views::title::titled(
            Block::bordered().border_style(pane_border(theme, focused)),
            area.width,
            (&format!(" Uploads · {mode} "), theme.dim_text()),
            (hint, theme.dim_text()),
        );
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if inner.height == 0 || inner.width == 0 {
            return;
        }

        if state.upload_peers.is_empty() {
            render_empty(frame, inner, "no upload activity", theme);
            return;
        }

        let visible = self.ordered_peers(state);
        // Filtered-out peers are counted, never silently truncated (spec §3.5).
        let hidden = state.upload_peers.len() - visible.len();
        let footer = (hidden > 0).then(|| format!("  {hidden} hidden queued"));

        let (body, footer_area) = match &footer {
            Some(_) if inner.height >= 2 => {
                let parts =
                    Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).split(inner);
                (parts[0], Some(parts[1]))
            }
            _ => (inner, None),
        };

        let bps_of = |peer: &UploadPeer| {
            state
                .rates
                .upload_bps
                .get(&peer.peer)
                .copied()
                .unwrap_or(0.0)
        };
        let cells: Vec<Vec<Column>> = visible
            .iter()
            .map(|peer| peer_columns(peer, state, bps_of(peer), theme))
            .collect();
        let mut wants = [0; 5];
        for (index, cap) in PEER_CAPS.into_iter().enumerate() {
            let widest = cells
                .iter()
                .map(|row| row[index].text.chars().count())
                .max()
                .unwrap_or(0);
            wants[index] = widest.min(cap);
        }
        let floors = arrow_floors(&self.peer_sort, &PEER_COLS, PEER_FLEX);
        let headers = header_widths(&self.peer_sort);
        let widths = table_widths(
            body,
            &TableColumns {
                floors: &floors,
                headers: &headers,
                flex: PEER_FLEX,
                wants: &wants,
                give_way: &PEER_GIVE_WAY,
            },
        );
        say_gave_way(
            frame,
            area,
            &gave_way(PeersTable::COLUMNS.iter().map(|c| c.label), &widths),
            theme,
        );
        // The selected peer's values in the columns that gave way.
        let off_screen = visible
            .get(self.peers_selected)
            .map_or_else(Vec::new, |peer| {
                let bps = state
                    .rates
                    .upload_bps
                    .get(&peer.peer)
                    .copied()
                    .unwrap_or(0.0);
                let values: Vec<String> = peer_columns(peer, state, bps, theme)
                    .into_iter()
                    .map(|column| column.text)
                    .collect();
                crate::views::off_screen::hidden(
                    PeersTable::COLUMNS.iter().map(|c| c.label),
                    &values,
                    &widths,
                )
            });
        let body = crate::views::off_screen::draw(frame, body, &off_screen, theme);
        let mut lines = peers_header(&widths, &self.peer_sort, theme);
        let header_h = clamp_u16(lines.len()).min(body.height);
        self.peer_header_area = Rect::new(
            body.x.saturating_add(clamp_u16(super::GUTTER_W)),
            body.y,
            body.width.saturating_sub(clamp_u16(super::GUTTER_W)),
            header_h,
        );
        self.peer_header_cols.clone_from(&widths);
        let mut heights = Vec::with_capacity(visible.len());
        if visible.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no active uploads",
                theme.dim_text(),
            )));
        } else {
            let rows: Vec<Vec<Line<'static>>> = visible
                .iter()
                .enumerate()
                .map(|(idx, peer)| {
                    // Join the folded peer row with the tick's synthesized
                    // rate by endpoint — the same key core's upload counters
                    // use.
                    let bps = state
                        .rates
                        .upload_bps
                        .get(&peer.peer)
                        .copied()
                        .unwrap_or(0.0);
                    let selected = idx == self.peers_selected;
                    peers_row(peer, state, bps, &widths, selected, focused, theme)
                })
                .collect();
            heights = rows.iter().map(|row| clamp_u16(row.len())).collect();
            let room = body.height - header_h;
            self.peers_offset =
                scroll_to_show(self.peers_offset, self.peers_selected, &heights, room);
            lines.extend(rows.into_iter().skip(self.peers_offset).flatten());
        }
        let first = self.peers_offset.min(heights.len());
        self.peer_rows = DrawnRows::new(
            Rect::new(
                body.x,
                body.y + header_h,
                body.width,
                body.height - header_h,
            ),
            first,
            heights[first..].to_vec(),
        );
        frame.render_widget(Paragraph::new(lines), body);
        if let (Some(area), Some(text)) = (footer_area, footer) {
            frame.render_widget(
                Paragraph::new(Text::from(wrapped_lines(
                    &text,
                    usize::from(area.width),
                    theme.dim_text(),
                ))),
                area,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use ratatui::crossterm::event::KeyCode;

    use super::*;
    use crate::fixture::{GOLDEN_H, GOLDEN_W, file_hash, peer_endpoint, press, theme};
    use crate::golden::render_to_lines;

    /// More waiters than the pane has lines: the selection stays drawn as it
    /// moves down the queue, and each waiter names the file it waits for.
    #[test]
    fn the_pane_scrolls_to_keep_the_selection_on_screen() {
        let mut state = UiState::default();
        state.shared.insert(
            file_hash(1),
            crate::state::SharedRow {
                file_hash: file_hash(1),
                path: Some("/dl/film.mkv".into()),
                file_size: Some(1),
                withheld: None,
            },
        );
        for rank in 1..=20u8 {
            let peer = peer_endpoint(rank);
            state.upload_peers.insert(
                peer,
                UploadPeer {
                    peer,
                    state: UploadState::Queued {
                        rank: u16::from(rank),
                        file: file_hash(1),
                    },
                    software: None,
                },
            );
        }
        let mut view = SharedView::default();
        view.handle_key(press(KeyCode::Char('a')), &state); // show waiters
        view.handle_key(press(KeyCode::Tab), &state); // into the peers pane
        for _ in 0..19 {
            view.handle_key(press(KeyCode::Char('j')), &state);
            let drawn = render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
                view.draw(frame, frame.area(), &state, &theme(), Instant::now());
            });
            let expected = format!("Queued #{} ", view.peers_selected + 1);
            assert!(
                drawn.lines().any(|line| line.contains('▸')
                    && line.contains(&expected)
                    && line.contains("film.mkv")),
                "{expected} selected but not drawn:\n{drawn}"
            );
        }
    }

    /// The file name takes the pane's slack and the bounded columns take what
    /// their values need: an upload fits the pane's width on one line when it
    /// can, and a rate never parts from its unit.
    #[test]
    fn the_file_takes_the_slack_and_a_rate_stays_on_one_line() {
        let name = "Vmware Workstation Pro 17.6.0 Und 17.5 Linux Key [8341e5b2].rar";
        let mut state = UiState::default();
        state.shared.insert(
            file_hash(1),
            crate::state::SharedRow {
                file_hash: file_hash(1),
                path: Some(format!("/dl/{name}").into()),
                file_size: Some(1),
                withheld: None,
            },
        );
        let peer = peer_endpoint(1);
        state.upload_peers.insert(
            peer,
            UploadPeer {
                peer,
                state: UploadState::Uploading { file: file_hash(1) },
                software: Some(crate::fixture::amule_233()),
            },
        );
        state.rates.upload_bps.insert(peer, 2255.1 * 1024.0);
        let words: Vec<&str> = name.split(' ').collect();
        // (pane width, most lines the file name may take)
        for (width, name_lines) in [(150u16, 1usize), (80, 5)] {
            let mut view = SharedView::default();
            let drawn = render_to_lines(width, 10, |frame| {
                view.draw_peers(frame, frame.area(), &state, &theme());
            });
            let rate_lines = drawn.lines().filter(|line| line.contains("2255.1 KB/s"));
            assert_eq!(
                rate_lines.count(),
                1,
                "{width} cells: the rate wrapped:\n{drawn}"
            );
            let taken = drawn
                .lines()
                .filter(|line| words.iter().any(|word| line.contains(word)))
                .count();
            assert!(
                (1..=name_lines).contains(&taken),
                "{width} cells: the name took {taken} lines, at most {name_lines}:\n{drawn}"
            );
        }
    }
}
