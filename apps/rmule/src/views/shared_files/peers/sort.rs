//! The upload-peers pane's **Table Sort** (ADR-0070): its
//! columns, how a peer answers for each, the `s` / `S` keys while the pane has
//! focus and the header click. The cursor is bound to the peer's endpoint, so
//! a peer that moves up the queue keeps the selection.
//!
//! Software sorts by the client's family rank, then its version; State by
//! rank — a slot-holder first, then the queue in its own order — never by the
//! words either renders.

use crate::stored_keys as column_keys;
use crate::words::columns;
use std::borrow::Cow;
use std::sync::Arc;
use std::time::Instant;

use rmule_primitives::PeerEndpoint;

use crate::row_filter::keeps_row;

use super::super::SharedView;
use super::file_label;
use crate::state::{UiState, UploadPeer, UploadState};
use crate::table_sort::{ColumnKind, ColumnSpec, SortValue, SortedTable, TableSort, TableSorts};
use crate::views::ViewOutcome;
use crate::views::software::SoftwareRanks;

/// The upload-peers pane, as the sort sees it.
pub(in crate::views::shared_files) struct PeersTable;

/// The upload-peers pane's visible columns, left to right.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::views::shared_files) enum PeerColumn {
    Peer,
    Software,
    State,
    Speed,
    File,
}

/// One upload peer's sortable facts.
pub(in crate::views::shared_files) struct PeerLine {
    peer: PeerEndpoint,
    endpoint: String,
    software: Option<u64>,
    state: u64,
    /// Whole bytes per second; `None` while nothing is metered.
    speed: Option<u64>,
    /// The shared name of the file it is served or waits for; `None` until
    /// the registry's name is read.
    file: Option<String>,
}

/// A slot-holder first, then a waiter dialled back to its held slot, then
/// the queue by its rank: the State column's rank.
fn state_rank(state: UploadState) -> u64 {
    match state {
        UploadState::Uploading { .. } => 0,
        UploadState::DialingBack { .. } => 1,
        UploadState::Queued { rank, .. } => 2 + u64::from(rank),
    }
}

impl PeerLine {
    fn new(peer: &UploadPeer, state: &UiState, ranks: &SoftwareRanks) -> Self {
        let file = match peer.state {
            UploadState::Uploading { file }
            | UploadState::DialingBack { file }
            | UploadState::Queued { file, .. } => file,
        };
        let (name, named) = file_label(state, file);
        let bps = state
            .rates
            .upload_bps
            .get(&peer.peer)
            .copied()
            .unwrap_or(0.0);
        Self {
            peer: peer.peer,
            endpoint: peer.peer.to_string(),
            software: ranks.rank(peer.software.as_ref()),
            state: state_rank(peer.state),
            speed: (bps > 0.0).then_some(bps as u64),
            file: named.then_some(name),
        }
    }
}

impl SortedTable for PeersTable {
    type Row = PeerLine;
    type Column = PeerColumn;
    type Identity = PeerEndpoint;
    const TABLE: &'static str = column_keys::TABLE_UPLOAD_PEERS;
    const COLUMNS: &'static [ColumnSpec<PeerColumn>] = &[
        ColumnSpec::new(
            PeerColumn::Peer,
            column_keys::PEER,
            columns::PEER,
            ColumnKind::Text,
        ),
        ColumnSpec::new(
            PeerColumn::Software,
            column_keys::SOFTWARE,
            columns::SOFTWARE,
            ColumnKind::Rank,
        ),
        ColumnSpec::new(
            PeerColumn::State,
            column_keys::STATE,
            columns::STATE,
            ColumnKind::Rank,
        ),
        ColumnSpec::new(
            PeerColumn::Speed,
            column_keys::SPEED,
            columns::SPEED,
            ColumnKind::Quantity,
        ),
        ColumnSpec::new(
            PeerColumn::File,
            column_keys::FILE,
            columns::FILE,
            ColumnKind::Text,
        ),
    ];
    const NAME: PeerColumn = PeerColumn::Peer;

    fn value(column: PeerColumn, row: &PeerLine) -> Option<SortValue<'_>> {
        match column {
            PeerColumn::Peer => Some(SortValue::Text(Cow::Borrowed(&row.endpoint))),
            PeerColumn::Software => row.software.map(SortValue::Quantity),
            PeerColumn::State => Some(SortValue::Quantity(row.state)),
            PeerColumn::Speed => row.speed.map(SortValue::Quantity),
            PeerColumn::File => row
                .file
                .as_deref()
                .map(|name| SortValue::Text(Cow::Borrowed(name))),
        }
    }

    fn identity(row: &PeerLine) -> PeerEndpoint {
        row.peer
    }
}

/// What the pane's order stands on: the peers, the files they name, the
/// tick's rates (which a stopped core clears), the sort and the filters.
#[derive(PartialEq)]
pub(in crate::views::shared_files) struct OrderKey {
    peers: u64,
    tick: Option<Instant>,
    core_alive: bool,
    shared: u64,
    partial_shares: u64,
    downloads: u64,
    active_only: bool,
    sort: TableSort<PeersTable>,
    typed: u64,
}

impl SharedView {
    /// The peers the pane shows, in display order.
    pub(in crate::views::shared_files) fn ordered_peers<'a>(
        &self,
        state: &'a UiState,
    ) -> Vec<&'a UploadPeer> {
        self.peer_order(state)
            .iter()
            .filter_map(|peer| state.upload_peers.get(peer))
            .collect()
    }

    /// The shown peers' endpoints in display order — what the cursor is
    /// placed against.
    pub(in crate::views::shared_files) fn peer_ids(&self, state: &UiState) -> Vec<PeerEndpoint> {
        self.peer_order(state).to_vec()
    }

    /// A frame asks more than once, and the queue can hold thousands.
    fn peer_order(&self, state: &UiState) -> Arc<[PeerEndpoint]> {
        let key = OrderKey {
            peers: state.upload_peers.revision(),
            tick: state.last_snapshot_at,
            core_alive: state.core_alive,
            shared: state.shared.revision(),
            partial_shares: state.partial_shares.revision(),
            downloads: state.downloads.revision(),
            active_only: self.active_only,
            sort: self.peer_sort,
            typed: self.peer_filter.generation(),
        };
        self.peers_memo.get(key, || {
            let visible = self.visible_peers(state);
            let ranks =
                SoftwareRanks::new(visible.iter().filter_map(|peer| peer.software.as_ref()));
            let lines: Vec<PeerLine> = visible
                .iter()
                .map(|peer| PeerLine::new(peer, state, &ranks))
                .collect();
            self.peer_sort
                .order(&lines)
                .into_iter()
                .filter(|at| keeps_row::<PeersTable>(&self.peer_filter, &lines[*at]))
                .map(|at| lines[at].peer)
                .collect()
        })
    }

    /// Take up the peers pane's sort as the durable preferences kept it.
    pub(in crate::views::shared_files) fn restore_peer_sort(&mut self, sorts: &TableSorts) {
        self.peer_sort = TableSort::restore(sorts);
    }

    /// A click on the peers header: sort by the column under it. `None` when
    /// the click was not on a header cell.
    pub(in crate::views::shared_files) fn peer_header_click(
        &mut self,
        column: u16,
        row: u16,
    ) -> Option<ViewOutcome> {
        let (area, widths) = self.drawn_peers.header();
        self.peer_sort
            .header_click(area, widths, crate::table::GAP, column, row)
    }
}

#[cfg(test)]
mod tests {
    use ratatui::crossterm::event::KeyCode;

    use super::*;
    use crate::action::Action;
    use crate::config::PrefEdit;
    use crate::fixture::*;
    use crate::state::SharedRow;
    use crate::table_sort::Direction;

    /// Four peers that disagree on every column: `.10` holds a slot for
    /// `b.mkv`, eMule, 50 KB/s; `.9` waits second for `a.iso`, aMule; `.2`
    /// waits first for `b.mkv`, no hello; `.3` holds a slot for `a.iso`,
    /// aMule, 100 KB/s.
    fn four_peers() -> UiState {
        let mut state = UiState::default();
        for (byte, name) in [(1, "b.mkv"), (2, "a.iso")] {
            state.shared.insert(
                file_hash(byte),
                SharedRow {
                    file_hash: file_hash(byte),
                    path: Some(std::path::Path::new("/dl").join(name)),
                    file_size: Some(1),
                    withheld: None,
                },
            );
        }
        let peers = [
            (
                10,
                UploadState::Uploading { file: file_hash(1) },
                Some(emule_qt()),
            ),
            (
                9,
                UploadState::Queued {
                    rank: 2,
                    file: file_hash(2),
                },
                Some(amule_233()),
            ),
            (
                2,
                UploadState::Queued {
                    rank: 1,
                    file: file_hash(1),
                },
                None,
            ),
            (
                3,
                UploadState::Uploading { file: file_hash(2) },
                Some(amule_233()),
            ),
        ];
        for (octet, upload, software) in peers {
            let peer = peer_endpoint(octet);
            state.upload_peers.insert(
                peer,
                UploadPeer {
                    peer,
                    state: upload,
                    software,
                },
            );
        }
        for (octet, kbps) in [(10, 50.0), (3, 100.0)] {
            state
                .rates
                .upload_bps
                .insert(peer_endpoint(octet), kbps * 1024.0);
        }
        state
    }

    #[test]
    fn what_the_pane_does_not_read_rebuilds_nothing() {
        let mut state = four_peers();
        let view = SharedView::default();
        let order = view.peer_order(&state);

        state.log_flash(crate::words::Sentence::for_test("elsewhere"), now());

        assert!(Arc::ptr_eq(&order, &view.peer_order(&state)));
    }

    fn octets(view: &SharedView, state: &UiState) -> Vec<u8> {
        view.ordered_peers(state)
            .iter()
            .map(|peer| {
                (0..=255)
                    .find(|octet| peer_endpoint(*octet) == peer.peer)
                    .expect("a fixture peer")
            })
            .collect()
    }

    #[test]
    fn every_peer_column_orders_by_its_value_with_the_pane_focused() {
        let state = four_peers();
        let mut view = SharedView::default();
        view.handle_key(press(KeyCode::Char('f')), &state); // every peer
        view.handle_key(press(KeyCode::Tab), &state);
        assert_eq!(octets(&view, &state), [2, 3, 9, 10]);
        let expect = [
            // eMule before aMule by family rank; no hello last either way.
            (PeerColumn::Software, [10, 3, 9, 2], [3, 9, 10, 2]),
            // Slot-holders, then the queue in its order.
            (PeerColumn::State, [3, 10, 2, 9], [9, 2, 3, 10]),
            (PeerColumn::Speed, [3, 10, 2, 9], [10, 3, 2, 9]),
            (PeerColumn::File, [3, 9, 2, 10], [2, 10, 3, 9]),
            (PeerColumn::Peer, [2, 3, 9, 10], [10, 9, 3, 2]),
        ];
        for (column, natural, reversed) in expect {
            assert!(
                matches!(
                    view.handle_key(press(KeyCode::Char('s')), &state),
                    ViewOutcome::Emit(Action::Preference(PrefEdit::TableSort {
                        table: "upload_peers",
                        ..
                    }))
                ),
                "{column:?}"
            );
            assert_eq!(view.peer_sort.column(), column);
            assert_eq!(octets(&view, &state), natural, "{column:?} natural");
            view.handle_key(press(KeyCode::Char('S')), &state);
            assert_eq!(octets(&view, &state), reversed, "{column:?} reversed");
            view.handle_key(press(KeyCode::Char('S')), &state);
        }
        assert_eq!(
            view.sort,
            TableSort::default(),
            "the files table kept its sort"
        );
    }

    #[test]
    fn the_peer_cursor_follows_its_peer_as_the_queue_moves() {
        let mut state = four_peers();
        let mut view = SharedView::default();
        view.handle_key(press(KeyCode::Char('f')), &state);
        view.handle_key(press(KeyCode::Tab), &state);
        while view.peer_sort.column() != PeerColumn::State {
            view.handle_key(press(KeyCode::Char('s')), &state);
        }
        assert_eq!(view.peer_sort.direction(), Direction::Ascending);
        view.handle_key(press(KeyCode::Char('G')), &state); // onto .9, last
        assert_eq!(view.peer_ids(&state)[view.peers_selected], peer_endpoint(9));

        // .9 moves to the head of the queue, ahead of .2.
        state
            .upload_peers
            .get_mut(&peer_endpoint(9))
            .expect("peer")
            .state = UploadState::Queued {
            rank: 0,
            file: file_hash(2),
        };
        view.handle_key(press(KeyCode::Char('x')), &state); // any key re-places
        assert_eq!(octets(&view, &state), [3, 10, 9, 2]);
        assert_eq!(view.peer_ids(&state)[view.peers_selected], peer_endpoint(9));
    }
}
