//! The Searches view (spec §3.3): a query input line with
//! a method selector and a search-options row, the strip of **Held Searches**
//! under it, over a source-count-tinted results table (Name · Size · Sources ·
//! Type) of the current one — a file the operator already knows marked in
//! place of its tint — plus a per-row action menu and the confirm a known
//! file's Download asks.
//!
//! View state only (ADR-0069): the search *data* lives in [`UiState::searches`]
//! (folded from `SearchEvent`); this component holds focus, the typed query, the
//! selected method, the typed constraints, the held searches with their queries
//! and cursors, the results' **Table Sort** (one for every held search), and the
//! row-menu cursor.
//!
//! **Search options.** aMule's extended-search panel offers five
//! constraints — file type, min/max size, availability, extension
//! (`SearchDlg.cpp:455-494`) — and every one of them is a term in the request's
//! expression tree. They live here as `Filters`, summarised on one line under
//! the query when idle and expanded into an editor by `o`.
//!
//! **The two methods are not a choice.** A `StartSearch` fans out to *both*
//! surfaces at once (ADR-0051 + ADR-0062: the TCP search, the global-UDP sweep,
//! and a Kad keyword walk feed one merged result set), so the Kad slot renders
//! greyed-with-reason — not because it is missing, but because it is never
//! *not* running. Global-UDP has no slot at all: no reachable server answers
//! `0x98`, so offering it would be offering nothing.
use std::time::Instant;

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::widgets::TableState;

use rmule_core::{CoreCommand, SearchCommand};
use rmule_primitives::{Ed2kText, KeywordQuery};

use super::ViewOutcome;
use crate::action::Action;
use crate::row_selection::viewport::Viewport;
use crate::state::UiState;
use crate::table_sort::{RowMove, TableSort, TableSorts};
use crate::theme::Theme;
use filters::Filters;
use held::HeldSearches;
use menu::{draw_menu, menu_step};
use method::SearchMethod;
use readd::ReAdd;
use sort::ResultsTable;

mod filters;
mod held;
mod input;
mod menu;
mod method;
mod more;
mod no_core;
mod readd;
mod related;
mod results;
mod sort;

/// The Searches view (spec §3.3). Constructed once and offered every key while
/// its tab is active; renders from [`UiState`] each frame.
#[derive(Default)]
pub struct SearchesView {
    /// `/` focuses the query line; `Esc` returns to the results pane.
    input_focused: bool,
    query: String,
    method: SearchMethod,
    /// Drawing state only: the row the current Held Search's cursor was
    /// placed on each frame, and the Viewport's offset.
    results_state: TableState,
    /// What part of the results table is on screen.
    viewport: Viewport,
    /// The results' order. Per table and durable, not per search.
    sort: TableSort<ResultsTable>,
    /// Every search of the run, each with its query and its own cursor.
    held: HeldSearches,
    /// `Some(cursor)` while the row-action menu is open; `cursor` indexes a
    /// *selectable* `menu::MenuItem` (the greyed one is never a resting spot).
    menu: Option<usize>,
    /// The confirm a known file's Download opened (ADR-0100), while it is up.
    readd: Option<ReAdd>,
    /// The typed constraints. They persist across expansions and across
    /// searches — an operator who narrowed to "Videos ≥ 700 MB" means it for the
    /// next query too, until they say otherwise.
    filters: Filters,
    /// `true` while the filter editor is expanded and holding focus; the
    /// editor's own cursor lives in [`Filters`]'s shared form.
    filters_open: bool,
    /// Pane areas cached at draw time for click hit-testing.
    input_area: Rect,
    results_area: Rect,
    /// The header row, from the first column's left edge, and its column
    /// widths: a click there sorts.
    header_area: Rect,
    header_cols: Vec<usize>,
    /// The table's rows region and each display row's drawn height.
    rows_area: Rect,
    row_heights: Vec<u16>,
}

impl SearchesView {
    /// A view with an empty query, the results pane focused, and no menu open.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Take up the results' sort as the durable preferences kept it.
    pub fn restore_sort(&mut self, sorts: &TableSorts) {
        self.sort = TableSort::restore(sorts);
    }

    /// Handle one key. Returns [`ViewOutcome::Ignored`] for keys that are not
    /// the view's, so the app loop can fall through to the global bindings —
    /// except while the query input is focused, where every printable is text
    /// and only non-text control keys bubble (a focused input's keys never
    /// reach the globals, so `h`/`l`/`q`/`1`–`4` are characters here).
    pub fn handle_key(&mut self, key: KeyEvent, state: &UiState) -> ViewOutcome {
        self.held.bind(state);
        // 0. The re-add confirm is modal over everything.
        if self.readd.is_some() {
            return self.handle_readd_key(key, state);
        }
        // 1. The row-action menu is modal: it captures every key until closed.
        if let Some(cursor) = self.menu {
            return match key.code {
                KeyCode::Esc => {
                    self.menu = None;
                    ViewOutcome::Redraw
                }
                KeyCode::Char('j') | KeyCode::Down => {
                    self.menu = Some(menu_step(cursor, 1, state));
                    ViewOutcome::Redraw
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    self.menu = Some(menu_step(cursor, -1, state));
                    ViewOutcome::Redraw
                }
                KeyCode::Enter => self.activate_menu(state),
                // Modal swallows the rest so nothing leaks to the globals.
                _ => ViewOutcome::Redraw,
            };
        }

        // 2. The expanded filter editor is modal in the same sense the query
        //    input is: printables are text, so binding letters never leak.
        if self.filters_open {
            return self.handle_filter_key(key, state);
        }

        // 3. Focused query input: every printable is text.
        if self.input_focused {
            return match key.code {
                KeyCode::Esc => {
                    self.input_focused = false;
                    ViewOutcome::Redraw
                }
                // Tab/Shift-Tab (spec: the global two-pane cycle) leave
                // the input for the results pane; there are only two panes
                // here, so either direction lands on the same one, matching
                // Shared Files' two-pane toggle.
                KeyCode::Tab | KeyCode::BackTab => {
                    self.input_focused = false;
                    ViewOutcome::Redraw
                }
                KeyCode::Enter => self.commit_query(state),
                KeyCode::Backspace => {
                    self.query.pop();
                    ViewOutcome::Redraw
                }
                KeyCode::Left | KeyCode::Right => self.cycle_method(),
                KeyCode::Char(c) => {
                    self.query.push(c);
                    ViewOutcome::Redraw
                }
                // Remaining non-text control keys (function keys, …) bubble.
                _ => ViewOutcome::Ignored,
            };
        }

        // 4. Results pane (input unfocused): navigation, the strip, row menu,
        //    stop and close.
        let has_results = self
            .held
            .current_pane(state)
            .is_some_and(|pane| !pane.results.is_empty());
        if has_results && let Some(movement) = RowMove::of(key.code) {
            let ids = self.result_ids(state);
            return self.with_cursor(|cursor| cursor.apply(&ids, movement));
        }
        match key.code {
            KeyCode::Char('/') => {
                self.input_focused = true;
                ViewOutcome::Redraw
            }
            // Two panes (input, results): Tab and Shift-Tab both cross to
            // the input, mirroring `/`.
            KeyCode::Tab | KeyCode::BackTab => {
                self.input_focused = true;
                ViewOutcome::Redraw
            }
            KeyCode::Char('o') => {
                self.filters.form.error = None;
                self.filters.form.focus_first();
                self.filters_open = true;
                ViewOutcome::Redraw
            }
            // `[` / `]` move between the Held Searches and mean nothing else,
            // anywhere (ADR-0073): with none held they do nothing.
            KeyCode::Char('[') if !self.held.is_empty() => self.step_held(-1),
            KeyCode::Char(']') if !self.held.is_empty() => self.step_held(1),
            KeyCode::Char('s') if has_results => self.sort.key(true),
            KeyCode::Char('S') if has_results => self.sort.key(false),
            KeyCode::Char('m') | KeyCode::Enter if has_results => {
                self.open_menu(state);
                ViewOutcome::Redraw
            }
            // `n`: the next page from the entry's server (ADR-0036).
            KeyCode::Char('n') if !self.held.is_empty() => self.ask_more(state),
            KeyCode::Char('x') => self.stop_or_close(state),
            // Everything else (h/l/1–6/c/p/?/q) is a global binding; `[`/`]`
            // with no search held bubble to globals that do not bind them.
            _ => ViewOutcome::Ignored,
        }
    }

    fn commit_query(&mut self, state: &UiState) -> ViewOutcome {
        let phrase = self.query.trim();
        if phrase.is_empty() {
            return ViewOutcome::Redraw; // nothing to commit; stay focused.
        }
        // No core to send through: held as an entry that says so,
        // the query left in the input.
        if let Some(reason) = no_core::absent(state) {
            let phrase = phrase.to_string();
            self.held.open_unsent(&phrase, None, self.method, reason);
            return ViewOutcome::Redraw;
        }
        // A search names no server: core sends each leg where it can
        // — Kad at once, the server leg on the operator's session — so a
        // Kad-only operator searches too. Only a run with no session config
        // (no core to speak for) cannot.
        if state.session.is_none() {
            return ViewOutcome::Emit(Action::Flash(crate::words::app::CORE_NOT_ATTACHED));
        }
        let query = match KeywordQuery::new(Ed2kText::from_utf8(phrase)) {
            Ok(query) => query,
            Err(error) => {
                return ViewOutcome::Emit(Action::Flash(crate::words::search::invalid_query(
                    &error,
                )));
            }
        };
        // A filter that cannot be parsed is refused *here* too: `Enter` on the
        // query line must not quietly drop a constraint the operator can still
        // see on the summary row.
        match self.filters.apply(query) {
            Ok(query) => {
                // A new entry every time, the same text twice included: the
                // one it came from stays as it was, to compare against.
                // The entry holds the id the search is sent under, so every
                // outcome core reports finds it by id.
                let query = query.into();
                let search_id = rmule_core::SearchId::mint();
                self.held.open(&query, self.method, search_id);
                ViewOutcome::Emit(Action::Command(CoreCommand::Search(
                    SearchCommand::StartSearch { search_id, query },
                )))
            }
            Err(reason) => {
                ViewOutcome::Emit(Action::Flash(crate::words::search::invalid_filter(&reason)))
            }
        }
    }

    /// Click routing (ADR-0072, Row Selection): the query line focuses the input,
    /// a results header sorts by its column, a results row selects it (both
    /// unfocus the input). Menu stays keyboard-only in v1.
    pub fn handle_click(&mut self, column: u16, row: u16, state: &UiState) -> ViewOutcome {
        self.held.bind(state);
        // The row menu and the filter editor both hold keyboard focus; a click
        // must not yank it out from under either.
        if self.menu.is_some() || self.filters_open || self.readd.is_some() {
            return ViewOutcome::Ignored;
        }
        if let Some(index) = self.held.hit(column, row) {
            self.input_focused = false;
            self.held.select(index);
            self.show_current_query();
            return ViewOutcome::Redraw;
        }
        if crate::views::pane_hit(self.input_area, column, row) {
            self.input_focused = true;
            return ViewOutcome::Redraw;
        }
        if let Some(outcome) = self.header_click(column, row) {
            self.input_focused = false;
            return outcome;
        }
        if let Some(index) = self.row_at(column, row) {
            self.input_focused = false;
            let ids = self.result_ids(state);
            return self.with_cursor(|cursor| cursor.select(&ids, index));
        }
        ViewOutcome::Ignored
    }

    /// Render the view into `area` (spec §3.3).
    pub fn draw(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
        now: Instant,
    ) {
        let _ = now; // the searches view has no time-based rendering (yet).
        self.held.bind(state);
        // The input block grows with its wrapped content instead of clipping a
        // long query or the method line's deferral tag.
        let input_h = self.input_height(usize::from(area.width.saturating_sub(2)), theme);
        let strip_h = u16::from(held::strip_shown(&self.held, state));
        let [input_area, strip_area, results_area] = Layout::vertical([
            Constraint::Length(input_h.min(area.height)),
            Constraint::Length(strip_h),
            Constraint::Min(0),
        ])
        .areas(area);
        self.input_area = input_area;
        self.results_area = results_area;

        self.draw_input(frame, input_area, theme);
        self.held.draw(frame, strip_area, state, theme);
        self.draw_results(frame, results_area, state, theme);

        if let Some(cursor) = self.menu {
            draw_menu(frame, area, cursor, state, theme);
        }
        self.draw_readd(frame, area, theme);
    }
}

#[cfg(test)]
mod tests;
