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
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::widgets::Paragraph;

use rmule_primitives::FileHash;

use super::{DrawnRows, ViewOutcome, rate_cell};
use crate::row_selection::viewport::{BAR_W, Viewport};
use crate::state::UiState;
use crate::table_sort::{RowCursor, RowMove, TableSort};
use crate::theme::Theme;
use crate::wrap::{TableColumns, clamp_u16, greedy_widths, wrap_text};
use menu::{Confirm, FileMenu, draw_confirm};
use sort::SharedTable;

mod files;
mod menu;
mod peers;
pub(crate) mod scan;
mod sort;
mod strip;

/// The two-cell selection gutter every table row carries.
const GUTTER_W: usize = 2;

/// The Shared Files view. Holds view state only — every datum lives in
/// [`UiState`] (ADR-0069).
pub struct SharedView {
    focus: Pane,
    /// The files table's order.
    sort: TableSort<SharedTable>,
    /// The selected file, by hash.
    cursor: RowCursor<FileHash>,
    /// The selected file's position in the current order — `cursor`
    /// re-placed before every key and draw.
    files_selected: usize,
    peers_selected: usize,
    /// The peers pane's order.
    peer_sort: TableSort<peers::sort::PeersTable>,
    /// The selected upload peer, by endpoint; `peers_selected` is its
    /// position in the current order.
    peer_cursor: RowCursor<rmule_primitives::PeerEndpoint>,
    /// What part of each table, and of the directory strip, is on screen.
    files_viewport: Viewport,
    peers_viewport: Viewport,
    strip_viewport: Viewport,
    /// "Active uploads only" (spec §3.5): default on; `a` toggles.
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
    /// The files header as last drawn, and its column widths: a click there
    /// sorts.
    header_area: Rect,
    header_cols: Vec<usize>,
    /// The peers header as last drawn, and its column widths.
    peer_header_area: Rect,
    peer_header_cols: Vec<usize>,
    /// Both tables' rows as last drawn, for row clicks.
    file_rows: DrawnRows,
    peer_rows: DrawnRows,
}

impl Default for SharedView {
    fn default() -> Self {
        Self {
            focus: Pane::Files,
            sort: TableSort::default(),
            cursor: RowCursor::default(),
            files_selected: 0,
            peers_selected: 0,
            peer_sort: TableSort::default(),
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
            header_area: Rect::default(),
            header_cols: Vec::new(),
            peer_header_area: Rect::default(),
            peer_header_cols: Vec::new(),
            file_rows: DrawnRows::default(),
            peer_rows: DrawnRows::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pane {
    Files,
    Peers,
}

/// Column widths for a pane's table: the greedy column absorbs everything
/// the fixed ones leave over, after the selection gutter and the Viewport's
/// bar column while it has a `bar`, and no header is split.
fn table_widths(area: Rect, bar: bool, table: &TableColumns<'_>) -> Vec<usize> {
    let bar = if bar { usize::from(BAR_W) } else { 0 };
    greedy_widths(
        usize::from(area.width).saturating_sub(GUTTER_W + bar),
        table,
        1,
    )
}

fn pane_border(theme: &Theme, focused: bool) -> Style {
    if focused {
        Style::new().fg(theme.accent) // accent border = focus
    } else {
        theme.chrome()
    }
}

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
    /// Offer one key to the view. Modals capture first; otherwise
    /// the focused pane navigates. Anything unclaimed bubbles to the globals.
    pub fn handle_key(&mut self, key: KeyEvent, state: &UiState) -> ViewOutcome {
        if key.kind == KeyEventKind::Release {
            return ViewOutcome::Ignored;
        }
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

    fn handle_pane_key(&mut self, key: KeyEvent, state: &UiState) -> ViewOutcome {
        self.clamp_selection(state);
        let files = self.focus == Pane::Files && !state.shared.is_empty();
        let peers = self.focus == Pane::Peers && !self.visible_peers(state).is_empty();
        if let Some(movement) = RowMove::of(key.code) {
            self.move_selection(state, movement);
            return ViewOutcome::Redraw;
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
            KeyCode::Char('a') => {
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

    /// Move the focused pane's cursor.
    fn move_selection(&mut self, state: &UiState, movement: RowMove) {
        match self.focus {
            Pane::Files => self.cursor.apply(&self.file_ids(state), movement),
            Pane::Peers => self.peer_cursor.apply(&self.peer_ids(state), movement),
        }
        self.clamp_selection(state);
    }

    /// Put the files selection back on its file wherever the order now has
    /// it, and keep the peers selection inside the filtered list.
    fn clamp_selection(&mut self, state: &UiState) {
        self.files_selected = self.cursor.place(&self.file_ids(state)).unwrap_or(0);
        self.peers_selected = self.peer_cursor.place(&self.peer_ids(state)).unwrap_or(0);
    }

    /// Render the view (spec §3.5): files table over the upload-peers pane,
    /// with the row menu / confirm modal on top when open.
    /// Click routing (ADR-0072, Row Selection): rows select + focus in either
    /// pane. Modals stay keyboard-only in v1.
    pub fn handle_click(&mut self, column: u16, row: u16, state: &UiState) -> ViewOutcome {
        if self.menu.is_some() || self.confirm.is_some() {
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
        if let Some(index) = self.file_rows.hit(column, row) {
            self.focus = Pane::Files;
            self.cursor.select(&self.file_ids(state), index);
            self.clamp_selection(state);
            return ViewOutcome::Redraw;
        }
        if let Some(index) = self.peer_rows.hit(column, row) {
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
    pub fn draw(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
        _now: Instant, // no time-varying content; kept for the view contract
    ) {
        self.clamp_selection(state);
        let rows =
            Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).split(area);
        self.files_area = rows[0];
        self.peers_area = rows[1];
        self.draw_files(frame, rows[0], state, theme);
        self.draw_peers(frame, rows[1], state, theme);
        if self.menu.is_some() {
            self.draw_menu(frame, area, state, theme);
        }
        if let Some(confirm) = &self.confirm {
            draw_confirm(frame, area, confirm, theme);
        }
        if let Some(consent) = self.pending_consent(state) {
            scan::draw_consent(frame, area, consent, theme, &self.consent_viewport);
        }
    }

    /// The oldest disclosure question this view has not answered.
    pub(crate) fn pending_consent<'a>(
        &self,
        state: &'a UiState,
    ) -> Option<&'a crate::state::ScanConsent> {
        scan::open_consent(state, &self.answered, false)
    }
}

#[cfg(test)]
mod tests;
