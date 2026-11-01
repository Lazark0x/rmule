//! The Shared Files view (spec §3.5): a shared-file table over an
//! upload-peers pane. This is the aMule-correct home for uploads — they live
//! here, not in Transfers.
//!
//! The upload peers' **Speed** is real: each slot-holder's monotonic
//! `bytes_sent` differenced and smoothed by [`crate::rates`]. A *queued* peer
//! holds no slot, so it has no counter and reads `—`.
//!
//! # The download directory
//!
//! Every shared directory (ADR-0101, "Shared Directories") has a line in
//! the strip above the files table, with its state and what lies under it;
//! `[` / `]` filter the table to one. The first scan of a download directory
//! that already holds files, and a directory being added, ask here as a
//! modal before anything under them is offered: `y` shares, `n` keeps it
//! private.
//!
//! # Extra binding
//!
//! Beyond the global keys, **`a`** toggles the upload-peers "active
//! uploads only" filter (default **on**). It is surfaced in the peers-pane
//! title (`active only` / `all`) and reported to the integrator for the help
//! overlay.
use std::time::Instant;

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Position, Rect};
use ratatui::style::Style;
use ratatui::widgets::Paragraph;

use rmule_primitives::FileHash;

use super::{View, ViewOutcome, rate_cell};
use crate::row_filter::RowFilter;
use crate::row_selection::tags::Tags;
use crate::row_selection::viewport::Viewport;
use crate::state::UiState;
use crate::table::Drawn;
use crate::table_sort::{Memo, RowCursor, RowMove, TableSort};
use crate::theme::Theme;
use crate::views::panes::{self, Zoomed};
use crate::wrap::{clamp_u16, wrap_text};
use menu::{Confirm, FileMenu, draw_confirm};
use sort::SharedTable;

mod files;
mod menu;
mod peers;
pub(crate) mod scan;
mod sort;
mod strip;

/// The Shared Files view. Holds view state only — every datum lives in
/// [`UiState`] (ADR-0069).
pub struct SharedView {
    focus: Pane,
    /// `z`: the focused pane has the whole tab.
    zoomed: bool,
    /// The files table's order.
    sort: TableSort<SharedTable>,
    /// `/`: the files it keeps.
    filter: RowFilter,
    /// `/` over the peers.
    peer_filter: RowFilter,
    /// The rows `Space` tagged.
    tags: Tags<FileHash>,
    /// The table's lines, in that order.
    lines_memo: Memo<sort::LinesKey, sort::SharedLine>,
    /// The selected file, by hash.
    cursor: RowCursor<FileHash>,
    /// The selected file's position in the current order — `cursor`
    /// re-placed before every key and draw.
    files_selected: usize,
    peers_selected: usize,
    /// The peers pane's order.
    peer_sort: TableSort<peers::sort::PeersTable>,
    /// The peers' endpoints, in that order.
    peers_memo: Memo<peers::sort::OrderKey, rmule_primitives::PeerEndpoint>,
    /// The selected upload peer, by endpoint; `peers_selected` is its
    /// position in the current order.
    peer_cursor: RowCursor<rmule_primitives::PeerEndpoint>,
    /// What part of each table, and of the directory strip, is on screen.
    files_viewport: Viewport,
    peers_viewport: Viewport,
    strip_viewport: Viewport,
    /// "Active uploads only" (spec §3.5): default on; `f` toggles.
    active_only: bool,
    /// Row menu on the FILES table (spec §3.5), when open.
    menu: Option<FileMenu>,
    /// Unshare confirmation modal, when open (one of the three destructive
    /// confirms).
    confirm: Option<Confirm>,
    /// The disclosure questions this view answered (`ScanConsent::asked`),
    /// so each closes before core's next scan edge clears it, and a later
    /// question about the same directory is still asked.
    answered: std::collections::BTreeSet<u64>,
    /// What part of a disclosure question is on screen, in a frame too
    /// short for it.
    consent_viewport: std::cell::Cell<Viewport>,
    /// The directory the strip filters the files table to; `None` shows
    /// every shared file.
    dir_filter: Option<std::path::PathBuf>,
    /// Pane areas cached at draw time for click hit-testing.
    files_area: Rect,
    peers_area: Rect,
    /// Both tables as last drawn, for clicks.
    drawn_files: Drawn,
    drawn_peers: Drawn,
}

impl Default for SharedView {
    fn default() -> Self {
        Self {
            lines_memo: Memo::default(),
            focus: Pane::Files,
            zoomed: false,
            sort: TableSort::default(),
            filter: RowFilter::default(),
            peer_filter: RowFilter::default(),
            tags: Tags::default(),
            cursor: RowCursor::default(),
            files_selected: 0,
            peers_selected: 0,
            peer_sort: TableSort::default(),
            peers_memo: Memo::default(),
            peer_cursor: RowCursor::default(),
            files_viewport: Viewport::default(),
            peers_viewport: Viewport::default(),
            strip_viewport: Viewport::default(),
            active_only: true,
            menu: None,
            confirm: None,
            answered: std::collections::BTreeSet::new(),
            consent_viewport: std::cell::Cell::default(),
            dir_filter: None,
            files_area: Rect::default(),
            peers_area: Rect::default(),
            drawn_files: Drawn::default(),
            drawn_peers: Drawn::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pane {
    Files,
    Peers,
}

/// The files table's share of the tab.
const FILES_SHARE: u16 = 55;

/// Zero counts render dim (honest "nothing yet"); positive counts read normal.
fn num_style(value: u64, theme: &Theme) -> Style {
    if value > 0 {
        Style::new().fg(theme.fg)
    } else {
        theme.dim_text()
    }
}

/// A dim message centered in `area`, wrapped over as many rows as it needs
/// rather than clipped.
fn render_empty(frame: &mut Frame, area: Rect, text: &str, theme: &Theme) {
    let lines = wrap_text(text, usize::from(area.width));
    let height = clamp_u16(lines.len()).min(area.height);
    let top = area.y + area.height.saturating_sub(height) / 2;
    frame.render_widget(
        Paragraph::new(lines.join("\n"))
            .style(theme.dim_text())
            .centered(),
        Rect::new(area.x, top, area.width, height),
    );
}

impl SharedView {
    fn handle_pane_key(&mut self, key: KeyEvent, state: &UiState) -> ViewOutcome {
        self.clamp_selection(state);
        let files = self.focus == Pane::Files && !state.shared.is_empty();
        let peers = self.focus == Pane::Peers && !state.upload_peers.is_empty();
        let filtered = match self.focus {
            Pane::Files => self.filter.key(&key, files),
            Pane::Peers => self.peer_filter.key(&key, peers),
        };
        if let Some(outcome) = filtered {
            self.clamp_selection(state);
            return outcome;
        }
        if let Some(movement) = RowMove::of(key.code) {
            self.move_selection(state, movement);
            return ViewOutcome::Redraw;
        }
        if files {
            let ids = self.file_ids(state);
            if let Some(outcome) = self.tags.key(key.code, &ids, &mut self.cursor) {
                self.clamp_selection(state);
                return outcome;
            }
        }
        match key.code {
            KeyCode::Char('s') if files => self.sort.key(true),
            KeyCode::Char('S') if files => self.sort.key(false),
            KeyCode::Char('s') if peers => self.peer_sort.key(true),
            KeyCode::Char('S') if peers => self.peer_sort.key(false),
            // Two panes: Tab and Shift-Tab both toggle table ↔ peers.
            KeyCode::Tab | KeyCode::BackTab => {
                self.focus = match self.focus {
                    Pane::Files => Pane::Peers,
                    Pane::Peers => Pane::Files,
                };
                ViewOutcome::Redraw
            }
            KeyCode::Char('z') => {
                self.zoomed = !self.zoomed;
                ViewOutcome::Redraw
            }
            // `x` is the row's way out everywhere; it asks first.
            KeyCode::Char('x') if files => {
                let targets = self.targets(state);
                if targets.is_empty() {
                    return ViewOutcome::Ignored;
                }
                self.ask_unshare(targets);
                ViewOutcome::Redraw
            }
            KeyCode::Char('f') => {
                self.active_only = !self.active_only;
                self.clamp_selection(state);
                ViewOutcome::Redraw
            }
            KeyCode::Char('m') | KeyCode::Enter => self.open_file_menu(state),
            // The strip's sub-entries (ADR-0073: `[` / `]` move between a
            // tab's sub-entries and mean nothing else).
            KeyCode::Char('[') if !state.diagnostics.shared_directories.is_empty() => {
                self.step_directory(state, false);
                self.clamp_selection(state);
                ViewOutcome::Redraw
            }
            KeyCode::Char(']') if !state.diagnostics.shared_directories.is_empty() => {
                self.step_directory(state, true);
                self.clamp_selection(state);
                ViewOutcome::Redraw
            }
            _ => ViewOutcome::Ignored,
        }
    }

    /// What an action takes: the tagged files still shared, else the file
    /// under the cursor. A Partial Share is its download's, so none is here.
    pub(super) fn targets(&mut self, state: &UiState) -> Vec<FileHash> {
        self.tags
            .keep(|file_hash| state.shared.contains_key(file_hash));
        self.tags
            .targets(self.selected_row(state).map(|row| row.file_hash))
    }

    /// Move the focused pane's cursor.
    fn move_selection(&mut self, state: &UiState, movement: RowMove) {
        match self.focus {
            Pane::Files => {
                let page = self.files_viewport.page();
                self.cursor.apply(&self.file_ids(state), movement, page);
            }
            Pane::Peers => {
                let page = self.peers_viewport.page();
                let ids = self.peer_ids(state);
                self.peer_cursor.apply(&ids, movement, page);
            }
        }
        self.clamp_selection(state);
    }

    /// Put the files selection back on its file wherever the order now has
    /// it, and keep the peers selection inside the filtered list.
    fn clamp_selection(&mut self, state: &UiState) {
        self.files_selected = self.cursor.place(&self.file_ids(state)).unwrap_or(0);
        self.peers_selected = self.peer_cursor.place(&self.peer_ids(state)).unwrap_or(0);
    }

    /// The oldest disclosure question this view has not answered.
    pub(crate) fn pending_consent<'a>(
        &self,
        state: &'a UiState,
    ) -> Option<&'a crate::state::ScanConsent> {
        scan::open_consent(state, &self.answered, false)
    }
}

impl View for SharedView {
    /// Offer one key to the view. Modals capture first; otherwise
    /// the focused pane navigates. Anything unclaimed bubbles to the globals.
    fn handle_key(&mut self, key: KeyEvent, state: &UiState) -> ViewOutcome {
        if let Some(consent) = scan::open_consent(state, &self.answered, false) {
            return scan::consent_key(
                key,
                consent,
                (&mut self.answered, &mut self.consent_viewport),
            );
        }
        if self.confirm.is_some() {
            return self.handle_confirm_key(key);
        }
        if self.menu.is_some() {
            return self.handle_menu_key(key, state);
        }
        self.handle_pane_key(key, state)
    }

    /// A paste into the Row Filter that holds the keyboard.
    fn handle_paste(&mut self, text: &str, _state: &UiState) -> ViewOutcome {
        let filter = match self.focus {
            Pane::Files => &mut self.filter,
            Pane::Peers => &mut self.peer_filter,
        };
        filter.paste(text).unwrap_or(ViewOutcome::Ignored)
    }

    /// Whether a Row Filter holds the keyboard: a question over it reads key
    /// codes alone, so no chord may reach it as its letter.
    fn text_open(&self, state: &UiState) -> bool {
        let filter = match self.focus {
            Pane::Files => &self.filter,
            Pane::Peers => &self.peer_filter,
        };
        self.menu.is_none()
            && self.confirm.is_none()
            && self.pending_consent(state).is_none()
            && filter.typing()
    }

    /// A wheel notch at (`column`, `row`), read as `key` on the pane under the
    /// pointer; the focus stays where it is. A modal takes it as a key.
    fn handle_wheel(
        &mut self,
        (column, row): (u16, u16),
        key: KeyEvent,
        state: &UiState,
    ) -> ViewOutcome {
        let under = if self.menu.is_some() || self.confirm.is_some() {
            None
        } else if crate::views::pane_hit(self.files_area, column, row) {
            Some(Pane::Files)
        } else if crate::views::pane_hit(self.peers_area, column, row) {
            Some(Pane::Peers)
        } else {
            None
        };
        let Some(under) = under else {
            return self.handle_key(key, state);
        };
        let focus = std::mem::replace(&mut self.focus, under);
        let outcome = self.handle_key(key, state);
        self.focus = focus;
        outcome
    }

    /// Render the view (spec §3.5): files table over the upload-peers pane,
    /// with the row menu / confirm modal on top when open.
    /// Click routing (ADR-0072, Row Selection): rows select + focus in either
    /// pane. The row menu takes its clicks; a confirm keeps to the keyboard.
    fn handle_click(&mut self, column: u16, row: u16, state: &UiState) -> ViewOutcome {
        if self.confirm.is_none() && self.menu.is_some() {
            return self.click_menu(column, row, state);
        }
        if self.confirm.is_some() {
            return ViewOutcome::Ignored;
        }
        if let Some(outcome) = self.header_click(column, row) {
            self.focus = Pane::Files;
            return outcome;
        }
        if let Some(outcome) = self.peer_header_click(column, row) {
            self.focus = Pane::Peers;
            return outcome;
        }
        if let Some(index) = self.drawn_files.hit(column, row) {
            self.focus = Pane::Files;
            self.cursor.select(&self.file_ids(state), index);
            self.clamp_selection(state);
            return ViewOutcome::Redraw;
        }
        if let Some(index) = self.drawn_peers.hit(column, row) {
            self.focus = Pane::Peers;
            self.peer_cursor.select(&self.peer_ids(state), index);
            self.clamp_selection(state);
            return ViewOutcome::Redraw;
        }
        if crate::views::pane_hit(self.files_area, column, row) {
            self.focus = Pane::Files;
            return ViewOutcome::Redraw;
        }
        if crate::views::pane_hit(self.peers_area, column, row) {
            self.focus = Pane::Peers;
            return ViewOutcome::Redraw;
        }
        ViewOutcome::Ignored
    }

    /// Render one frame into `area` (spec §3.5): shared files over upload
    /// peers. Caches both pane rects for click hit-testing.
    fn draw(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
        _now: Instant, // no time-varying content; kept for the view contract
    ) -> Option<Position> {
        self.clamp_selection(state);
        // No upload activity is said on one line, and the files keep the rest.
        let idle = state.upload_peers.is_empty().then_some(3);
        let zoomed = self.zoomed.then_some(match self.focus {
            Pane::Files => Zoomed::First,
            Pane::Peers => Zoomed::Second,
        });
        let (files, peers) = panes::split(area, FILES_SHARE, idle, zoomed);
        self.files_area = files;
        self.peers_area = peers;
        self.drawn_files = Drawn::default();
        self.drawn_peers = Drawn::default();
        if !files.is_empty() {
            self.draw_files(frame, files, state, theme);
        }
        if !peers.is_empty() {
            self.draw_peers(frame, peers, state, theme);
        }
        if self.menu.is_some() {
            self.draw_menu(frame, area, state, theme);
        }
        if let Some(confirm) = &self.confirm {
            draw_confirm(frame, area, confirm, state, theme);
        }
        if let Some(consent) = self.pending_consent(state) {
            scan::draw_consent(frame, area, consent, theme, &self.consent_viewport);
            return None;
        }
        match self.focus {
            Pane::Files => self.drawn_files.caret,
            Pane::Peers => self.drawn_peers.caret,
        }
    }
}

#[cfg(test)]
mod tests;
