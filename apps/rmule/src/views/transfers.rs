//! Transfers view (spec §3.2): the third tab, as in aMule.
//!
//! A downloads table and a sources pane for the selected download, shared out
//! by `crate::views::panes`, plus the row-action menu, the cancel confirm,
//! and the file-details modal. Rendering is pure (`UiState` + view state + injected
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
//!   [`rmule_core::DownloadCommand`]s.
//! - `L` opens the Add-link form: a pasted file link becomes a download
//!   through the same reader and command `rmule-cli add` and the Search
//!   tab's Download use.
//! - `Copy eD2k link` builds the canonical link once a row's
//!   metadata names the file; it stays greyed-with-reason only while that
//!   fact is genuinely absent (see above).
use std::time::Instant;

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Position, Rect};
use ratatui::style::Style;
use ratatui::text::Text;
use ratatui::widgets::{Block, Paragraph};
use rmule_core::DownloadId;
use rmule_core::diagnostics::DownloadDiagnostics;

use self::menu::{MenuAction, pause_toggle_action};
use crate::action::Action;
use crate::row_filter::RowFilter;
use crate::row_selection::tags::Tags;
use crate::row_selection::viewport::Viewport;
use crate::state::{DownloadStatus, UiState};
use crate::table::Drawn;
use crate::table_sort::{Memo, RowCursor, RowMove, TableSort};
use crate::theme::Theme;
use crate::views::ViewOutcome;
use crate::views::panes::{self, Zoomed};
use crate::wrap::{clamp_u16, wrap_text, wrapped_lines};
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

/// The downloads table's share of the tab.
const SHARE: u16 = 62;

/// Which pane holds selection focus; the focused pane wears the focus border
/// ([`Theme::pane`], every pane's focus cue). Row actions always target the selected *download*, whichever
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
    /// part file. It holds the downloads it asks about, so a row that moves
    /// under it stays the one the answer acts on.
    ConfirmCancel { targets: Vec<DownloadId> },
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
    /// `/`: the downloads it keeps.
    filter: RowFilter,
    /// `/` over the sources pane.
    source_filter: RowFilter,
    /// The rows `Space` tagged.
    tags: Tags<DownloadId>,
    /// The table's lines under that sort and filter.
    lines_memo: Memo<(u64, TableSort<DownloadsTable>, u64), sort::DownloadLine>,
    /// The selected download, by id.
    cursor: RowCursor<DownloadId>,
    /// That download's position in the current order, re-placed before every
    /// key and draw.
    selected: Option<usize>,
    /// What part of the downloads table is on screen.
    viewport: Viewport,
    /// The sources pane's order, one for every download's sources.
    source_sort: TableSort<SourcesTable>,
    /// The selected source, by its peer.
    source_cursor: RowCursor<SourceKey>,
    /// That source's position in the current order, re-placed before every
    /// key and draw.
    source_selected: Option<usize>,
    /// What part of the sources pane is on screen.
    source_viewport: Viewport,
    /// Where the row menu is, and what part of it is on screen.
    menu_place: crate::views::menu::Place,
    /// What part of the details modal is on screen, in a frame too short for
    /// it; back to its first line each time it opens.
    details_viewport: std::cell::Cell<Viewport>,
    /// What part of a confirm is on screen, in a frame too short for it;
    /// back to its first line each time one opens.
    confirm_viewport: std::cell::Cell<Viewport>,
    focus: Pane,
    /// `z`: the focused pane has the whole tab.
    zoomed: bool,
    overlay: Overlay,
    /// The Add-link form (`L`), modal over everything while it is up.
    add_link: Option<add_link::AddLink>,
    /// A form left while its links wait for a download dir; `L` brings it
    /// back.
    parked_link: Option<add_link::AddLink>,
    /// Pane areas cached at draw time for click hit-testing.
    table_area: Rect,
    sources_area: Rect,
    /// Both tables as last drawn, for clicks.
    drawn: Drawn,
    source_drawn: Drawn,
}

fn selected_id(ids: &[DownloadId], selected: Option<usize>) -> Option<DownloadId> {
    ids.get(selected?).copied()
}

fn pane_block(
    width: u16,
    (title, hint): (&str, &str),
    focused: bool,
    theme: &Theme,
) -> Block<'static> {
    crate::views::title::titled(
        theme.pane(focused),
        width,
        (title, theme.pane_title(focused)),
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
        if self.add_link.is_some() {
            return self.handle_add_link_key(key, state);
        }
        let ids = self.download_ids(state);
        self.clamp(&ids, state);

        match self.overlay.clone() {
            Overlay::None => self.handle_base(key, state, &ids),
            Overlay::Menu { cursor } => self.handle_menu(key, state, &ids, cursor),
            Overlay::ConfirmCancel { targets } => self.handle_confirm(key, &targets),
            Overlay::Details => self.handle_details(key),
            Overlay::ConfirmClearCompleted { counted } => self.handle_confirm_clear(key, &counted),
        }
    }

    fn handle_base(&mut self, key: KeyEvent, state: &UiState, ids: &[DownloadId]) -> ViewOutcome {
        let sources = self.source_keys(state, selected_id(ids, self.selected));
        let filtered = match self.focus {
            Pane::Table => self.filter.key(&key, !state.downloads.is_empty()),
            Pane::Sources => self.source_filter.key(&key, !sources.is_empty()),
        };
        if let Some(outcome) = filtered {
            return outcome;
        }
        if let Some(movement) = RowMove::of(key.code) {
            return self.move_selection(movement, ids, &sources);
        }
        if self.focus == Pane::Table
            && let Some(outcome) = self.tags.key(key.code, ids, &mut self.cursor)
        {
            return outcome;
        }
        match key.code {
            KeyCode::Tab | KeyCode::BackTab => {
                self.focus = self.focus.toggled();
                ViewOutcome::Redraw
            }
            KeyCode::Char('z') => {
                self.zoomed = !self.zoomed;
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
                        self.menu_place.reset();
                        self.overlay = Overlay::Menu {
                            cursor: menu::first_action(status),
                        };
                        ViewOutcome::Redraw
                    }
                    _ => ViewOutcome::Ignored,
                }
            }
            // `x` is the row's way out everywhere: here, its cancel. Greyed
            // in the menu, so a completed row asks nothing.
            KeyCode::Char('x') => {
                self.cursor.pin(ids);
                let targets = menu::cancellable(self.targets(state, ids), state);
                if targets.is_empty() {
                    return match self.selected {
                        Some(_) => ViewOutcome::Emit(Action::Flash(
                            crate::words::download::NOTHING_TO_CANCEL,
                        )),
                        None => ViewOutcome::Ignored,
                    };
                }
                self.ask_cancel(targets);
                ViewOutcome::Redraw
            }
            KeyCode::Char('d') => match self.selected_row_status(state, ids) {
                Some(_) => {
                    self.cursor.pin(ids);
                    self.overlay = Overlay::Details;
                    self.details_viewport.take();
                    ViewOutcome::Redraw
                }
                None => ViewOutcome::Ignored,
            },
            KeyCode::Char('C') => self.clear_completed_key(state),
            KeyCode::Char('L') => self.open_add_link(state),
            KeyCode::Char('p') if !self.tags.is_empty() => {
                let targets = self.targets(state, ids);
                ViewOutcome::Emit(menu::pause_or_resume(&targets, state))
            }
            KeyCode::Char('p') => match self.selected_row_status(state, ids) {
                Some((id, status)) => ViewOutcome::Emit(pause_toggle_action(status, id)),
                None => ViewOutcome::Ignored,
            },
            KeyCode::Char('P') if !ids.is_empty() => {
                ViewOutcome::Emit(menu::pause_or_resume(ids, state))
            }
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
                self.cursor.apply(ids, movement, self.viewport.page());
                self.table_selected(before, ids);
            }
            Pane::Sources => {
                let page = self.source_viewport.page();
                self.source_cursor.apply(sources, movement, page);
                self.source_selected = self.source_cursor.place(sources);
            }
        }
        ViewOutcome::Redraw
    }

    /// The operator moved the table cursor from `before`: follow it, and
    /// start a newly selected download's sources list at its top.
    fn table_selected(&mut self, before: Option<usize>, ids: &[DownloadId]) {
        let after = self.cursor.place(ids);
        self.selected = after;
        if after != before {
            self.source_cursor.reset();
            self.source_selected = Some(0);
        }
    }

    /// Keep selections inside the live data (rows churn between keystrokes):
    /// the table's on its download and the sources pane's on its source,
    /// wherever the orders put them.
    fn clamp(&mut self, ids: &[DownloadId], state: &UiState) {
        self.selected = self.cursor.place(ids);
        let sources = self.source_keys(state, selected_id(ids, self.selected));
        self.source_selected = self.source_cursor.place(&sources);
    }

    /// What an action takes: the tagged downloads still listed, else the one
    /// under the cursor.
    pub(super) fn targets(&mut self, state: &UiState, ids: &[DownloadId]) -> Vec<DownloadId> {
        self.tags.keep(|id| state.downloads.contains_key(id));
        self.tags.targets(selected_id(ids, self.selected))
    }

    fn selected_diag<'a>(
        &self,
        state: &'a UiState,
        ids: &[DownloadId],
    ) -> Option<&'a DownloadDiagnostics> {
        let id = selected_id(ids, self.selected)?;
        state.diagnostics.downloads.get(&id)
    }

    fn selected_row_status(
        &self,
        state: &UiState,
        ids: &[DownloadId],
    ) -> Option<(DownloadId, DownloadStatus)> {
        let id = selected_id(ids, self.selected)?;
        Some((id, state.downloads.get(&id)?.status))
    }

    /// A wheel notch at (`column`, `row`), read as `key` on the pane under the
    /// pointer; the focus stays where it is. A modal or a field takes it as a
    /// key.
    pub fn handle_wheel(
        &mut self,
        (column, row): (u16, u16),
        key: KeyEvent,
        state: &UiState,
    ) -> ViewOutcome {
        let under = if !matches!(self.overlay, Overlay::None) || self.add_link.is_some() {
            None
        } else if crate::views::pane_hit(self.table_area, column, row) {
            Some(Pane::Table)
        } else if crate::views::pane_hit(self.sources_area, column, row) {
            Some(Pane::Sources)
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

    /// Row-click select (ADR-0072, Row Selection), against the pane areas cached
    /// by the last draw. The row menu takes its clicks; other modals keep to
    /// the keyboard.
    pub fn handle_click(&mut self, column: u16, row: u16, state: &UiState) -> ViewOutcome {
        let ids = self.download_ids(state);
        if self.add_link.is_none() && matches!(self.overlay, Overlay::Menu { .. }) {
            return self.click_menu((column, row), state, &ids);
        }
        if !matches!(self.overlay, Overlay::None) || self.add_link.is_some() {
            return ViewOutcome::Ignored;
        }
        if let Some(outcome) = self.header_click(column, row) {
            self.focus = Pane::Table;
            return outcome;
        }
        if let Some(outcome) = self.source_header_click(column, row) {
            self.focus = Pane::Sources;
            return outcome;
        }
        if let Some(index) = self.drawn.hit(column, row) {
            self.focus = Pane::Table;
            let before = self.cursor.place(&ids);
            self.cursor.select(&ids, index);
            self.table_selected(before, &ids);
            return ViewOutcome::Redraw;
        }
        if let Some(index) = self.source_drawn.hit(column, row) {
            self.focus = Pane::Sources;
            let sources = self.source_keys(state, selected_id(&ids, self.selected));
            if index < sources.len() {
                self.source_cursor.select(&sources, index);
                self.source_selected = self.source_cursor.place(&sources);
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
    ) -> Option<Position> {
        let lines = self.sorted_lines(state);
        let ids: Vec<DownloadId> = lines.iter().map(|line| line.id).collect();
        self.clamp(&ids, state);

        // A pane with nothing to list says so in the lines that takes, and
        // the downloads keep the rest.
        let idle = self.idle_sources_text(state, &ids, now).map(|text| {
            let width = usize::from(area.width.saturating_sub(2)).max(1);
            clamp_u16(wrap_text(&text, width).len()).saturating_add(2)
        });
        let zoomed = self.zoomed.then_some(match self.focus {
            Pane::Table => Zoomed::First,
            Pane::Sources => Zoomed::Second,
        });
        let (table_area, sources_area) = panes::split(area, SHARE, idle, zoomed);
        self.table_area = table_area;
        self.sources_area = sources_area;
        self.drawn = Drawn::default();
        self.source_drawn = Drawn::default();
        if !table_area.is_empty() {
            self.draw_downloads(frame, table_area, state, theme, &lines);
        }
        if !sources_area.is_empty() {
            self.draw_sources(frame, sources_area, state, theme, &ids, now);
        }
        let filter_caret = match self.focus {
            Pane::Table => self.drawn.caret,
            Pane::Sources => self.source_drawn.caret,
        };

        match &self.overlay {
            Overlay::None => {}
            Overlay::Menu { cursor } => self.draw_menu(frame, area, state, theme, &ids, *cursor),
            Overlay::ConfirmCancel { targets } => {
                self.draw_confirm(frame, area, state, theme, targets);
            }
            Overlay::Details => self.draw_details(frame, area, state, theme, &ids),
            Overlay::ConfirmClearCompleted { counted } => {
                self.draw_confirm_clear(frame, area, counted, theme)
            }
        }
        self.draw_add_link(frame, area, theme).or(filter_caret)
    }

    /// Whether the Add-link form or a Row Filter holds the keyboard.
    pub(crate) fn text_open(&self) -> bool {
        self.add_link.is_some()
            || (matches!(self.overlay, Overlay::None) && self.focused_filter().typing())
    }

    fn focused_filter(&self) -> &RowFilter {
        match self.focus {
            Pane::Table => &self.filter,
            Pane::Sources => &self.source_filter,
        }
    }
}

#[cfg(test)]
impl TransfersView {
    /// The selected row's place, as the last key left it.
    pub(crate) const fn selected_row(&self) -> Option<usize> {
        self.selected
    }

    /// A view sorted by name, the order most tests state their rows in.
    pub(crate) fn by_name() -> Self {
        let mut view = Self::new();
        view.sort.click(sort::DownloadColumn::File);
        view
    }

    /// Put the cursor on display row `index`, as the operator would.
    fn select_row(&mut self, state: &UiState, index: usize) {
        let ids = self.download_ids(state);
        self.cursor.select(&ids, index);
        self.selected = self.cursor.place(&ids);
    }
}

#[cfg(test)]
mod tests;
