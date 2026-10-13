//! Transfers view (spec §3.2): the third tab, as in aMule.
//!
//! A 62/38 vertical split — a downloads table over a sources pane for the
//! selected download — plus the row-action menu, the cancel confirm, and the
//! file-details modal. Rendering is pure (`UiState` + view state + injected
//! `now` → widgets) so every screen goldens under `TestBackend`; key handling
//! is a pure state machine over the same view state.
//!
//! ## Core-gap degrades (rendered honestly, spec §1's "no dead UI")
//!
//! **File** and **Size** read the real name and exact byte size once a row's
//! `DownloadQueued`/`DownloadRecovered` edge has landed (ADR-0078) —
//! from [`crate::state::DownloadRow::metadata`], not a diagnostics-levels
//! join, so a recovered-but-not-yet-resumed download (no live task, so no
//! diagnostics row to join against) still shows its name. A row whose edge
//! has not landed yet, or whose metadata is `Unknown`-origin with an empty
//! name (a backfilled junk link), falls back honestly to the short-hash
//! stand-in instead of inventing a name; **Size** falls back to
//! `≈ part_count × ED2K_PART_SIZE` in the same "no edge yet" case.
//!
//! **Progress** is a real positional chunk map (ADR-0079): the
//! snapshot's per-index `parts` vector, bucketed to the cell's width by
//! `chunk_bar`. Core opens every row's map at the file's part count, all
//! missing, so only a row whose diagnostics have not reached the view yet (an
//! empty vector — *unknown*, not *nothing done*) keeps the flat dim rendering.
//!
//! What the snapshot still does not carry is any verified-byte fact
//! finer-grained than the part map. So:
//!
//! - **Done %** divides verified bytes (`verified_parts × ED2K_PART_SIZE`,
//!   capped at the exact size) by the exact size when metadata supplies one;
//!   otherwise it falls back to the old part-count ratio.
//!
//! Both **Speed** columns are real: the download's own from its
//! monotonic `received_bytes` total, a source row's from the `bytes_received`
//! its worker slot carries while receiving — both differenced and smoothed by
//! [`crate::rates`], never computed here.
//!
//! ## Wiring degrades (documented, real commands where they exist)
//!
//! - `Pause`, `Resume` and `Cancel…` emit real
//!   [`rmule_core::DownloadCommand`]s; `Resume` needs a core, so on a
//!   UI-only run it flashes instead.
//! - `L` opens the Add-link form: a pasted file link becomes a download
//!   through the same reader and command `rmule-cli add` and the Search
//!   tab's Download use.
//! - `Copy eD2k link` builds the canonical link once a row's
//!   metadata names the file; it stays greyed-with-reason only while that
//!   fact is genuinely absent (see above).
use std::time::Instant;

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Text;
use ratatui::widgets::{Block, Paragraph, TableState};
use rmule_core::DownloadId;
use rmule_core::diagnostics::DownloadDiagnostics;

use crate::action::Action;
use crate::row_selection::viewport::{BAR_W, Viewport};
use crate::state::{DownloadStatus, UiState};
use crate::table_sort::{RowCursor, RowMove, TableSort};
use crate::theme::Theme;
use crate::views::{DrawnRows, ViewOutcome};
use crate::wrap::{TableColumns, clamp_u16, greedy_widths, wrapped_lines};
use menu::{MenuAction, pause_toggle_action};
use sort::DownloadsTable;
use sources::sort::{SourceKey, SourcesTable};

mod add_link;
mod chunks;
mod clear;
mod confirm;
mod details;
mod downloads;
mod link;
mod menu;
mod sort;
mod sources;

/// Inter-column spacing shared by both tables, and the width of the selection
/// symbol they render in the gutter.
const COL_SPACING: u16 = 1;
const SYMBOL_W: u16 = 2;

/// Which pane holds selection focus; the focused pane wears the accent border
/// (every pane's focus cue). Row actions always target the selected *download*, whichever
/// pane has focus.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Pane {
    #[default]
    Table,
    Sources,
}

impl Pane {
    fn toggled(self) -> Self {
        match self {
            Pane::Table => Pane::Sources,
            Pane::Sources => Pane::Table,
        }
    }
}

/// The view's modal machine (spec §3.2 row menu + confirm + details). At most
/// one is up; `Esc`/`q` closes it, and while it is up the view captures input
/// (mirrors chrome's help-overlay exclusivity) rather than leaking keys to the
/// globals underneath.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum Overlay {
    #[default]
    None,
    /// Row action menu; `cursor` names an action, never a place in the list,
    /// and only ever rests on an enabled item (greyed items are skipped,
    /// never landed on).
    Menu { cursor: MenuAction },
    /// The one destructive confirm in this view: cancel deletes the
    /// part file.
    ConfirmCancel,
    /// File-details modal (spec §3.2).
    Details,
    /// "Clear all completed": asks first, since it takes every completed row
    /// off the list at once.
    ConfirmClearCompleted { counted: Vec<DownloadId> },
}

/// Transfers view state (ADR-0069: components hold view state only — data
/// lives in [`UiState`]).
#[derive(Default)]
pub struct TransfersView {
    /// The downloads table's order.
    sort: TableSort<DownloadsTable>,
    /// The selected download, by id; `table_state`'s index is its position
    /// in the current order, re-placed before every key and draw.
    cursor: RowCursor<DownloadId>,
    /// Download-row selection (the downloads table); its offset is the
    /// Viewport's.
    table_state: TableState,
    /// What part of the downloads table is on screen.
    viewport: Viewport,
    /// The sources pane's order, one for every download's sources.
    source_sort: TableSort<SourcesTable>,
    /// The selected source, by its peer; `sources_state`'s index is its
    /// position in the current order, re-placed before every key and draw.
    source_cursor: RowCursor<SourceKey>,
    /// Source-row selection (the sources pane); its offset is the
    /// Viewport's.
    sources_state: TableState,
    /// What part of the sources pane is on screen.
    source_viewport: Viewport,
    focus: Pane,
    overlay: Overlay,
    /// The Add-link form (`L`), modal over everything while it is up.
    add_link: Option<add_link::AddLink>,
    /// Pane areas cached at draw time for click hit-testing.
    table_area: Rect,
    sources_area: Rect,
    /// The downloads header as last drawn, and its column widths: a click
    /// there sorts.
    header_area: Rect,
    header_cols: Vec<usize>,
    /// The sources header as last drawn, and its column widths.
    source_header_area: Rect,
    source_header_cols: Vec<usize>,
    /// Both tables' rows as last drawn, for row clicks.
    rows: DrawnRows,
    source_rows: DrawnRows,
}

fn selected_id(ids: &[DownloadId], table_state: &TableState) -> Option<DownloadId> {
    ids.get(table_state.selected()?).copied()
}

/// Column widths for a bordered table drawn at `area`: the flex column takes
/// what the fixed ones leave over, after the border pair, the selection
/// symbol, the Viewport's bar column while it has a `bar`, and the
/// inter-column spacing.
fn table_widths(area: Rect, bar: bool, table: &TableColumns<'_>) -> Vec<usize> {
    let bar = if bar { BAR_W } else { 0 };
    let total = usize::from(
        area.width
            .saturating_sub(2)
            .saturating_sub(SYMBOL_W)
            .saturating_sub(bar),
    );
    greedy_widths(total, table, usize::from(COL_SPACING))
}

fn pane_block(
    width: u16,
    (title, hint): (&str, &str),
    focused: bool,
    theme: &Theme,
) -> Block<'static> {
    let border = if focused {
        Style::new().fg(theme.accent)
    } else {
        theme.chrome()
    };
    let title_style = if focused {
        Style::new().fg(theme.accent).add_modifier(Modifier::BOLD)
    } else {
        theme.dim_text()
    };
    crate::views::title::titled(
        Block::bordered().border_style(border),
        width,
        (title, title_style),
        (hint, theme.dim_text()),
    )
}

/// A dim message centered in `area` (empty/degrade states), wrapped over as
/// many rows as it needs rather than clipped.
fn draw_centered(frame: &mut Frame, area: Rect, text: &str, style: Style) {
    if area.height == 0 || area.width == 0 {
        return;
    }
    let lines = wrapped_lines(text, usize::from(area.width), style);
    let height = clamp_u16(lines.len()).min(area.height);
    let top = area.y + (area.height.saturating_sub(height)) / 2;
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(style).centered(),
        Rect::new(area.x, top, area.width, height),
    );
}

impl TransfersView {
    /// A view with the first row selected and no modal open.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Handle one key the globals did not claim. Returns [`ViewOutcome`]:
    /// `Emit` to hand the app a command/flash, `Redraw` when view state
    /// changed (or an open modal swallowed the key), `Ignored` to bubble on.
    pub fn handle_key(&mut self, key: KeyEvent, state: &UiState) -> ViewOutcome {
        // Kitty keyboard may report releases/repeats; only presses act.
        if key.kind == KeyEventKind::Release {
            return ViewOutcome::Ignored;
        }
        if self.add_link.is_some() {
            return self.handle_add_link_key(key, state);
        }
        let ids = self.download_ids(state);
        self.clamp(&ids, state);

        match self.overlay.clone() {
            Overlay::None => self.handle_base(key, state, &ids),
            Overlay::Menu { cursor } => self.handle_menu(key, state, &ids, cursor),
            Overlay::ConfirmCancel => self.handle_confirm(key, &ids),
            Overlay::Details => self.handle_details(key),
            Overlay::ConfirmClearCompleted { counted } => self.handle_confirm_clear(key, &counted),
        }
    }

    fn handle_base(&mut self, key: KeyEvent, state: &UiState, ids: &[DownloadId]) -> ViewOutcome {
        let sources = self.source_keys(state, selected_id(ids, &self.table_state));
        if let Some(movement) = RowMove::of(key.code) {
            return self.move_selection(movement, ids, &sources);
        }
        match key.code {
            KeyCode::Tab | KeyCode::BackTab => {
                self.focus = self.focus.toggled();
                ViewOutcome::Redraw
            }
            KeyCode::Char('s') if self.focus == Pane::Table && !ids.is_empty() => {
                self.sort.key(true)
            }
            KeyCode::Char('S') if self.focus == Pane::Table && !ids.is_empty() => {
                self.sort.key(false)
            }
            KeyCode::Char('s') if self.focus == Pane::Sources && !sources.is_empty() => {
                self.source_sort.key(true)
            }
            KeyCode::Char('S') if self.focus == Pane::Sources && !sources.is_empty() => {
                self.source_sort.key(false)
            }
            KeyCode::Char('m') | KeyCode::Enter => {
                // Pinned: a row that re-orders under an open menu is still
                // the one it acts on.
                match self.selected_row_status(state, ids) {
                    Some((_, status)) if self.cursor.pin(ids).is_some() => {
                        self.overlay = Overlay::Menu {
                            cursor: menu::first_action(status),
                        };
                        ViewOutcome::Redraw
                    }
                    _ => ViewOutcome::Ignored,
                }
            }
            KeyCode::Char('C') => self.clear_completed_key(state),
            KeyCode::Char('L') => self.open_add_link(),
            KeyCode::Char('p') => match self.selected_row_status(state, ids) {
                Some((id, status)) => ViewOutcome::Emit(pause_toggle_action(status, id, state)),
                None => ViewOutcome::Ignored,
            },
            // The menu's Preview (ADR-0114): the app reads the row as the
            // menu does, and flashes the reason the menu greys a blocked
            // row with.
            KeyCode::Char('v') if self.focus == Pane::Table => {
                match self.selected_row_status(state, ids) {
                    Some((id, _)) => ViewOutcome::Emit(Action::Preview(id)),
                    None => ViewOutcome::Ignored,
                }
            }
            _ => ViewOutcome::Ignored,
        }
    }

    fn move_selection(
        &mut self,
        movement: RowMove,
        ids: &[DownloadId],
        sources: &[SourceKey],
    ) -> ViewOutcome {
        match self.focus {
            Pane::Table => {
                let before = self.cursor.place(ids);
                self.cursor.apply(ids, movement);
                self.table_selected(before, ids);
            }
            Pane::Sources => {
                self.source_cursor.apply(sources, movement);
                self.sources_state.select(self.source_cursor.place(sources));
            }
        }
        ViewOutcome::Redraw
    }

    /// The operator moved the table cursor from `before`: follow it, and
    /// start a newly selected download's sources list at its top.
    fn table_selected(&mut self, before: Option<usize>, ids: &[DownloadId]) {
        let after = self.cursor.place(ids);
        self.table_state.select(after);
        if after != before {
            self.source_cursor.reset();
            self.sources_state.select(Some(0));
        }
    }

    /// Keep selections inside the live data (rows churn between keystrokes):
    /// the table's on its download and the sources pane's on its source,
    /// wherever the orders put them.
    fn clamp(&mut self, ids: &[DownloadId], state: &UiState) {
        self.table_state.select(self.cursor.place(ids));
        let sources = self.source_keys(state, selected_id(ids, &self.table_state));
        self.sources_state
            .select(self.source_cursor.place(&sources));
    }

    fn selected_diag<'a>(
        &self,
        state: &'a UiState,
        ids: &[DownloadId],
    ) -> Option<&'a DownloadDiagnostics> {
        let id = selected_id(ids, &self.table_state)?;
        state.diagnostics.downloads.get(&id)
    }

    fn selected_row_status(
        &self,
        state: &UiState,
        ids: &[DownloadId],
    ) -> Option<(DownloadId, DownloadStatus)> {
        let id = selected_id(ids, &self.table_state)?;
        Some((id, state.downloads.get(&id)?.status))
    }

    /// Row-click select (ADR-0072, Row Selection), against the pane areas cached
    /// by the last draw. Modals stay keyboard-only in v1.
    pub fn handle_click(&mut self, column: u16, row: u16, state: &UiState) -> ViewOutcome {
        if !matches!(self.overlay, Overlay::None) || self.add_link.is_some() {
            return ViewOutcome::Ignored;
        }
        let ids = self.download_ids(state);
        if let Some(outcome) = self.header_click(column, row) {
            self.focus = Pane::Table;
            return outcome;
        }
        if let Some(outcome) = self.source_header_click(column, row) {
            self.focus = Pane::Sources;
            return outcome;
        }
        if let Some(index) = self.rows.hit(column, row) {
            self.focus = Pane::Table;
            let before = self.cursor.place(&ids);
            self.cursor.select(&ids, index);
            self.table_selected(before, &ids);
            return ViewOutcome::Redraw;
        }
        if let Some(index) = self.source_rows.hit(column, row) {
            self.focus = Pane::Sources;
            let sources = self.source_keys(state, selected_id(&ids, &self.table_state));
            if index < sources.len() {
                self.source_cursor.select(&sources, index);
                self.sources_state
                    .select(self.source_cursor.place(&sources));
            }
            return ViewOutcome::Redraw;
        }
        if crate::views::pane_hit(self.table_area, column, row) {
            self.focus = Pane::Table;
            return ViewOutcome::Redraw;
        }
        if crate::views::pane_hit(self.sources_area, column, row) {
            self.focus = Pane::Sources;
            return ViewOutcome::Redraw;
        }
        ViewOutcome::Ignored
    }

    /// Render one frame of the view into `area` (spec §3.2).
    pub fn draw(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
        now: Instant,
    ) {
        let lines = self.sorted_lines(state);
        let ids: Vec<DownloadId> = lines.iter().map(|line| line.id).collect();
        self.clamp(&ids, state);

        let [table_area, sources_area] =
            Layout::vertical([Constraint::Percentage(62), Constraint::Percentage(38)]).areas(area);
        self.table_area = table_area;
        self.sources_area = sources_area;
        self.draw_downloads(frame, table_area, state, theme, &lines);
        self.draw_sources(frame, sources_area, state, theme, &ids, now);

        match &self.overlay {
            Overlay::None => {}
            Overlay::Menu { cursor } => self.draw_menu(frame, area, state, theme, &ids, *cursor),
            Overlay::ConfirmCancel => self.draw_confirm(frame, area, state, theme, &ids),
            Overlay::Details => self.draw_details(frame, area, state, theme, &ids),
            Overlay::ConfirmClearCompleted { counted } => {
                self.draw_confirm_clear(frame, area, counted, theme)
            }
        }
        self.draw_add_link(frame, area, theme);
    }
}

#[cfg(test)]
impl TransfersView {
    /// Put the cursor on display row `index`, as the operator would.
    fn select_row(&mut self, state: &UiState, index: usize) {
        let ids = self.download_ids(state);
        self.cursor.select(&ids, index);
        self.table_state.select(self.cursor.place(&ids));
    }
}

#[cfg(test)]
mod tests;
