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
use ratatui::style::Style;
use ratatui::text::Text;
use ratatui::widgets::Paragraph;
use rmule_primitives::FileHash;

use super::rate_cell;
use super::{Pane, SharedView, render_empty};
use crate::state::{UiState, UploadPeer, UploadState};
use crate::table::{self, Cell, Rows, Table, widest};
use crate::theme::Theme;
use crate::views::software_label;
use crate::words::units::{self, short_hash};
use crate::words::{absent, hints, serve, shared as words};
use crate::wrap::{display_width, wrapped_lines};

pub(super) mod sort;

/// Floors of the peers table's columns: Peer · Software · State · Speed ·
/// File. `File` holds the free text and is greedy: its entry is the room it
/// keeps before other columns give way to it, and it takes the slack left
/// after the others. They are bounded and floored at their usual widest value
/// — an IPv4 endpoint, `aMule v2.3.3`, a queue rank of two digits, a rate — and
/// asked for the widest drawn, up to [`PEER_CAPS`].
fn peer_floors() -> [usize; 5] {
    let state = widest(&[
        serve::UPLOADING.to_string(),
        serve::DIALING_BACK.to_string(),
        serve::queued_words(99),
    ]);
    [21, 12, state, units::rate_cells(), 24]
}

/// The most each bounded column asks for: an IPv6 endpoint with its port,
/// a client name with a short mod, a queue rank of five digits, a rate of
/// several MB/s.
const PEER_CAPS: [usize; 4] = [47, 24, 14, 14];

/// The greedy column: the file the peer is served or waits for.
const PEER_FLEX: usize = 4;

/// The order the peers table's columns give way in when the pane cannot hold
/// every header: Software, Speed, State, then Peer. File never gives way.
const PEER_GIVE_WAY: [usize; 4] = [1, 3, 2, 0];

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

/// One upload peer's cells, in `PeersTable::COLUMNS`' order.
fn peer_cells(peer: &UploadPeer, state: &UiState, bps: Option<f64>, theme: &Theme) -> Vec<Cell> {
    let addr = crate::words::units::address(peer.peer);
    let (state_text, file) = match peer.state {
        UploadState::Uploading { file } => (crate::words::serve::UPLOADING.to_string(), file),
        UploadState::DialingBack { file } => (crate::words::serve::DIALING_BACK.to_string(), file),
        UploadState::Queued { rank, file } => (crate::words::serve::queued_words(rank), file),
    };
    let (file_text, named) = file_label(state, file);
    let dim = theme.dim_text();
    let plain = Style::new().fg(theme.fg);
    // A queued peer holds no slot, so core keeps no counter for it: no meter
    // stands behind the cell.
    let software = peer.software.as_ref().map_or_else(
        || Cell::absent(absent::UNKNOWN, dim),
        |software| Cell::new(software_label(software), plain),
    );
    vec![
        Cell::new(addr, plain),
        software,
        Cell::new(state_text, plain),
        rate_cell(bps, theme),
        Cell::new(file_text, if named { plain } else { dim }),
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
        let focused = self.focus == Pane::Peers;
        let mode = if self.active_only {
            words::ACTIVE_ONLY
        } else {
            words::ALL_PEERS
        };
        let hint = if state.upload_peers.is_empty() {
            String::new()
        } else {
            hints::line(&[
                if self.active_only {
                    hints::ALL_PEERS
                } else {
                    hints::ACTIVE_PEERS
                },
                hints::FILTER,
                hints::TO_FILES,
                hints::SORT,
                hints::REVERSE,
                hints::ZOOM,
            ])
        };
        let block = crate::views::title::titled(
            theme.pane(focused),
            area.width,
            (&words::uploads_title(mode), theme.dim_text()),
            (&hint, theme.dim_text()),
        );
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if inner.height == 0 || inner.width == 0 {
            return;
        }

        if state.upload_peers.is_empty() {
            render_empty(frame, inner, words::NO_UPLOAD_ACTIVITY, theme);
            return;
        }

        let visible = self.ordered_peers(state);
        // Filtered-out peers are counted, never silently truncated (spec §3.5).
        let hidden = self
            .visible_peers(state)
            .len()
            .abs_diff(state.upload_peers.len());
        let footer =
            (hidden > 0).then(|| format!("  {}", crate::words::serve::hidden_queued(hidden)));

        let (body, footer_area) = match &footer {
            Some(_) if inner.height >= 2 => {
                let parts =
                    Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).split(inner);
                (parts[0], Some(parts[1]))
            }
            _ => (inner, None),
        };

        let bps_of = |peer: &UploadPeer| state.rates.upload_bps.get(&peer.peer).copied();
        // Join the folded peer row with the tick's synthesized rate by
        // endpoint — the same key core's upload counters use.
        let cells = |index: usize, _: &[usize]| {
            let peer = visible[index];
            peer_cells(peer, state, bps_of(peer), theme)
        };
        let wants = self.peer_wants_memo.get(self.peer_key(state), || {
            let mut wants = vec![0; 5];
            for row in 0..visible.len() {
                let cells = cells(row, &[]);
                for (want, (cell, cap)) in wants.iter_mut().zip(cells.iter().zip(PEER_CAPS)) {
                    *want = display_width(&cell.text).min(cap).max(*want);
                }
            }
            wants
        });
        let table = Table::of(
            &self.peer_sort,
            &peer_floors(),
            PEER_FLEX,
            &PEER_GIVE_WAY,
            theme.header(),
        )
        .wants(&wants)
        .empty(if self.peer_filter.shown() {
            crate::words::rows::NO_MATCH
        } else {
            words::NO_ACTIVE_UPLOADS
        });
        let rows = Rows {
            count: visible.len(),
            selected: Some(self.peers_selected),
            focused,
            cells: &cells,
            marker: None,
            tagged: None,
            filter: Some((&self.peer_filter, state.upload_peers.len())),
        };
        self.drawn_peers = table::draw(
            frame,
            (area, body),
            &table,
            &rows,
            &mut self.peers_viewport,
            theme,
        );
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
    use crate::views::View;

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
        view.handle_key(press(KeyCode::Char('f')), &state); // show waiters
        view.handle_key(press(KeyCode::Tab), &state); // into the peers pane
        for _ in 0..19 {
            view.handle_key(press(KeyCode::Char('j')), &state);
            let drawn = render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
                view.draw(frame, frame.area(), &state, &theme(), Instant::now());
            });
            let expected = format!(
                "{} ",
                crate::words::serve::queued_words(
                    u16::try_from(view.peers_selected + 1).expect("a small rank")
                )
            );
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
        for (width, name_lines) in [(150u16, 1usize), (80, 3)] {
            let mut view = SharedView::default();
            let drawn = render_to_lines(width, 10, |frame| {
                view.draw_peers(frame, frame.area(), &state, &theme());
            });
            let rate_lines = drawn.lines().filter(|line| line.contains("2.2 MB/s"));
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
