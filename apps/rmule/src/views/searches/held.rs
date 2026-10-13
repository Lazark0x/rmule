//! The **Held Searches** (ADR-0073, Held Searches): every search of the run,
//! kept side by side as a strip of entries under the query input.
//!
//! Core echoes no query text, so an entry is opened here, with what the view
//! sent and the id it chose for it (ADR-0034, "Every outcome names its
//! search"), the moment the query is committed. Every outcome core reports
//! names that id, so nothing is matched by order: the results and status stay
//! in [`UiState::searches`] under it, a refusal in [`UiState::refused_searches`].
//! A search the view did not send (another front end on the same core) is held
//! as an entry with no query. An entry adds only the query, the method and its
//! own cursor. Nothing here is written anywhere.

mod kind;

use std::collections::BTreeSet;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use rmule_core::{CoreCommand, SearchCommand, SearchId};
use rmule_primitives::{FileHash, SearchQuery};

pub(super) use kind::HeldKind;

use super::method::SearchMethod;
use super::sort::ResultId;
use super::{SearchesView, ViewOutcome};
use crate::action::Action;
use crate::row_selection::viewport::Viewport;
use crate::state::{SearchPane, SearchStatus, UiState};
use crate::table_sort::RowCursor;
use crate::theme::Theme;
use crate::wrap::clamp_u16;

/// A label keeps this many characters of its query; a longer one ends in `…`.
/// Capped labels are exempt from the no-truncation rule, as the tab bar is:
/// the query input always shows the current entry's query whole.
const LABEL_CHARS: usize = 20;
/// Shown where entries lie beyond the strip's left or right edge.
const MORE_LEFT: &str = "‹ ";
const MORE_RIGHT: &str = " ›";

/// One search the tab is keeping.
#[derive(Clone, Debug)]
pub(super) struct HeldSearch {
    /// The id the view chose for the search when it sent it.
    pub(super) id: SearchId,
    /// What was sent — the only record of it, and in memory only. For a
    /// Related-Files Search, the file's name; empty when none was known.
    pub(super) query: String,
    pub(super) kind: HeldKind,
    pub(super) method: SearchMethod,
    /// The selection in this search's results.
    pub(super) cursor: RowCursor<ResultId>,
}

/// The strip: its entries in the order they were opened, and which is current.
#[derive(Debug, Default)]
pub(super) struct HeldSearches {
    pub(super) entries: Vec<HeldSearch>,
    current: usize,
    /// The newest id core has shown; an id at or below it is never held
    /// again.
    newest_seen: Option<SearchId>,
    /// The ids the operator closed: a late event naming one opens nothing,
    /// even when `newest_seen` has not reached it yet.
    closed: BTreeSet<SearchId>,
    /// What part of the strip is on screen, in entries: it scrolls only when
    /// the current entry would leave the view.
    viewport: Viewport,
    /// Each drawn entry's columns on the strip row, for click hit-testing.
    hits: Vec<(Rect, usize)>,
}

impl HeldSearches {
    /// Open an entry for a query just sent under `id`: at the right end, and
    /// current.
    pub(super) fn open(&mut self, query: &SearchQuery, method: SearchMethod, id: SearchId) {
        let (query, kind) = match query {
            SearchQuery::Keywords(query) => {
                (query.phrase().to_display_string(), HeldKind::Keywords)
            }
            SearchQuery::RelatedFiles(query) => (
                query.file_name().to_display_string(),
                HeldKind::Related {
                    file: query.file_hash(),
                    refused: None,
                },
            ),
        };
        self.entries.push(HeldSearch {
            id,
            query,
            kind,
            method,
            cursor: RowCursor::default(),
        });
        self.current = self.entries.len() - 1;
    }

    /// Hold a search that was never sent, saying `why`: at the right end,
    /// and current. It is under an id no core ever saw, so nothing can
    /// answer it.
    pub(super) fn open_unsent(
        &mut self,
        query: &str,
        related: Option<FileHash>,
        method: SearchMethod,
        why: String,
    ) {
        self.entries.push(HeldSearch {
            id: SearchId::mint(),
            query: query.to_string(),
            kind: HeldKind::NotSent { why, related },
            method,
            cursor: RowCursor::default(),
        });
        self.current = self.entries.len() - 1;
    }

    /// Take in what core has shown since last looked, each by the id it
    /// names: a refusal settles its entry, and a search no entry holds — one
    /// the view did not send — is held as an entry with no query rather than
    /// hidden.
    pub(super) fn bind(&mut self, state: &UiState) {
        for entry in &mut self.entries {
            if let HeldKind::Related { refused, .. } = &mut entry.kind
                && refused.is_none()
            {
                *refused = state.refused_searches.get(&entry.id).copied();
            }
        }
        let newest_seen = self.newest_seen;
        let closed = &self.closed;
        let fresh: Vec<SearchId> = state
            .searches
            .keys()
            .copied()
            .filter(|id| newest_seen.is_none_or(|seen| *id > seen) && !closed.contains(id))
            .collect();
        for id in fresh {
            self.newest_seen = Some(id);
            if self.entries.iter().all(|entry| entry.id != id) {
                self.entries.push(HeldSearch {
                    id,
                    query: String::new(),
                    kind: HeldKind::Keywords,
                    method: SearchMethod::default(),
                    cursor: RowCursor::default(),
                });
            }
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(super) fn current(&self) -> Option<&HeldSearch> {
        self.entries.get(self.current)
    }

    pub(super) fn current_mut(&mut self) -> Option<&mut HeldSearch> {
        self.entries.get_mut(self.current)
    }

    /// The current entry's id.
    pub(super) fn current_id(&self) -> Option<SearchId> {
        self.current().map(|entry| entry.id)
    }

    /// The current entry's results and status, once core has any.
    pub(super) fn current_pane<'a>(&self, state: &'a UiState) -> Option<&'a SearchPane> {
        self.current_id().and_then(|id| state.searches.get(&id))
    }

    /// `[` / `]`: move `delta` entries, clamped at either end. `true` when the
    /// current entry changed.
    pub(super) fn step(&mut self, delta: isize) -> bool {
        let Some(last) = self.entries.len().checked_sub(1) else {
            return false;
        };
        let next = self.current.saturating_add_signed(delta).min(last);
        let moved = next != self.current;
        self.current = next;
        moved
    }

    /// The entry drawn at (`column`, `row`), if a click landed on one.
    pub(super) fn hit(&self, column: u16, row: u16) -> Option<usize> {
        self.hits
            .iter()
            .find(|(area, _)| crate::views::pane_hit(*area, column, row))
            .map(|(_, index)| *index)
    }

    /// Make the entry at `index` current (a click on it).
    pub(super) fn select(&mut self, index: usize) {
        if index < self.entries.len() {
            self.current = index;
        }
    }

    /// Close the current entry; the right neighbour becomes current, else the
    /// left. Returns the closed search's id, whose results can now go.
    pub(super) fn close_current(&mut self) -> Option<SearchId> {
        if self.current >= self.entries.len() {
            return None;
        }
        let closed = self.entries.remove(self.current);
        self.closed.insert(closed.id);
        if self.current >= self.entries.len() {
            self.current = self.entries.len().saturating_sub(1);
        }
        Some(closed.id)
    }

    /// Draw the strip into the one-row `area`, scrolled so the current entry
    /// shows, with a marker on each side that hides entries.
    pub(super) fn draw(&mut self, frame: &mut Frame, area: Rect, state: &UiState, theme: &Theme) {
        self.hits.clear();
        if area.width == 0 || area.height == 0 {
            return;
        }
        // The dropped-rows note takes the strip's right end when there is room
        // for it beside the current entry; entries keep the rest.
        let mut area = area;
        if let Some(note) = unattributed_note(state) {
            let note_width = u16::try_from(Span::raw(&note).width()).unwrap_or(u16::MAX);
            let room = if self.entries.is_empty() {
                note_width
            } else {
                note_width.saturating_add(NOTE_MIN_ENTRIES)
            };
            if area.width >= room {
                let note_area = Rect::new(area.right() - note_width, area.y, note_width, 1);
                frame.render_widget(
                    Paragraph::new(Line::from(Span::styled(note, theme.dim_text()))),
                    note_area,
                );
                area.width -= note_width;
            }
        }
        if self.entries.is_empty() {
            return;
        }
        let texts: Vec<String> = self
            .entries
            .iter()
            .enumerate()
            .map(|(index, entry)| entry_text(entry, state, index == self.current))
            .collect();
        let widths: Vec<u16> = texts
            .iter()
            .map(|text| clamp_u16(Span::raw(text).width()))
            .collect();
        // While the entries outgrow the strip, both markers and the count
        // keep their room at its ends, and the entries share the rest.
        let fits = widths.iter().map(|w| usize::from(*w)).sum::<usize>() <= usize::from(area.width);
        let room = if fits {
            area.width
        } else {
            let at = self.current.min(texts.len() - 1);
            let count = crate::words::viewport::count(at + 1, texts.len());
            let ends = Span::raw(MORE_LEFT).width()
                + Span::raw(MORE_RIGHT).width()
                + Span::raw(&count).width()
                + 2;
            area.width.saturating_sub(clamp_u16(ends))
        };
        self.viewport
            .follow(self.current, texts.len(), room, |index| widths[index]);
        let shown = self.viewport.shown();
        let (first, last) = (shown.start, shown.end.saturating_sub(1));

        let mut spans = Vec::new();
        let mut x = area.x;
        let mut push = |spans: &mut Vec<Span<'static>>, text: String, style: Style| -> Rect {
            let width = u16::try_from(Span::raw(&text).width()).unwrap_or(u16::MAX);
            let at = Rect::new(x, area.y, width.min(area.right().saturating_sub(x)), 1);
            x = x.saturating_add(width);
            spans.push(Span::styled(text, style));
            at
        };
        if first > 0 {
            push(&mut spans, MORE_LEFT.to_string(), theme.dim_text());
        }
        for (index, text) in texts.iter().enumerate().take(last + 1).skip(first) {
            let style = if index == self.current {
                Style::new().fg(theme.accent).add_modifier(Modifier::BOLD)
            } else {
                theme.dim_text()
            };
            let at = push(&mut spans, text.clone(), style);
            self.hits.push((at, index));
        }
        if last + 1 < texts.len() {
            push(&mut spans, MORE_RIGHT.to_string(), theme.dim_text());
        }
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
        if self.viewport.overflows() {
            self.viewport.draw_count(frame, area, theme);
        }
    }
}

impl SearchesView {
    /// A view that has sent `query`, under the id `1` more than the entries it
    /// already holds — the ids the test fixtures fold events under.
    #[cfg(test)]
    pub(crate) fn having_sent(mut self, query: &str) -> Self {
        let sent =
            rmule_primitives::KeywordQuery::new(rmule_primitives::Ed2kText::from_utf8(query))
                .expect("a valid test query");
        let id = crate::fixture::search_id(self.held.entries.len() as u64 + 1);
        self.held.open(&sent.into(), SearchMethod::default(), id);
        self.query = query.to_string();
        self
    }

    /// The query the input shows for the current entry.
    #[cfg(test)]
    pub(crate) fn shown_query(&self) -> &str {
        &self.query
    }

    /// Focus is on the results, not the query input or a modal.
    #[cfg(test)]
    pub(crate) fn results_focused(&self) -> bool {
        !self.input_focused && self.menu.is_none() && !self.filters_open && self.readd.is_none()
    }

    /// Act on the current entry's cursor; with no entry there is none to move.
    pub(super) fn with_cursor(
        &mut self,
        act: impl FnOnce(&mut RowCursor<ResultId>),
    ) -> ViewOutcome {
        if let Some(entry) = self.held.current_mut() {
            act(&mut entry.cursor);
        }
        ViewOutcome::Redraw
    }

    /// `[` / `]`: the neighbouring held search, its query in the input.
    pub(super) fn step_held(&mut self, delta: isize) -> ViewOutcome {
        if self.held.step(delta) {
            self.show_current_query();
        }
        ViewOutcome::Redraw
    }

    /// The input shows the current entry's query and method; with no entry
    /// left, the empty prompt. A Related-Files entry leaves the input empty:
    /// its file is no keywords to edit, and the query line names it instead.
    pub(super) fn show_current_query(&mut self) {
        match self.held.current() {
            Some(entry) if entry.kind.related_file().is_some() => {
                self.query.clear();
                self.method = entry.method;
            }
            Some(entry) => {
                self.query.clone_from(&entry.query);
                self.method = entry.method;
            }
            None => {
                self.query.clear();
                self.method = SearchMethod::default();
            }
        }
    }

    /// `x`: a running search stops and keeps what arrived; a stopped or
    /// complete one closes, and its results go with it.
    pub(super) fn stop_or_close(&mut self, state: &UiState) -> ViewOutcome {
        let Some(entry) = self.held.current() else {
            return ViewOutcome::Ignored;
        };
        let search_id = entry.id;
        // Refused before it started, or never sent: nothing runs and nothing
        // arrived. So too once the core has stopped: nothing runs any more.
        if entry.kind.never_started() || super::no_core::absent(state).is_some() {
            self.held.close_current();
            self.show_current_query();
            return ViewOutcome::Emit(Action::ForgetSearch(search_id));
        }
        if !state.searches.contains_key(&search_id) {
            return ViewOutcome::Emit(Action::Flash(crate::words::search::NOT_STARTED));
        }
        let running = state
            .searches
            .get(&search_id)
            .is_some_and(|pane| pane.status.is_live());
        if running {
            return ViewOutcome::Emit(Action::Command(CoreCommand::Search(
                SearchCommand::CancelSearch { search_id },
            )));
        }
        let closed = self.held.close_current();
        self.show_current_query();
        match closed {
            Some(search_id) => ViewOutcome::Emit(Action::ForgetSearch(search_id)),
            None => ViewOutcome::Redraw,
        }
    }
}

/// The strip keeps at least this many columns for its entries before it gives
/// the rest to the dropped-rows note.
const NOTE_MIN_ENTRIES: u16 = 24;

/// Whether the strip has anything to draw: entries, or rows core dropped.
pub(super) fn strip_shown(held: &HeldSearches, state: &UiState) -> bool {
    !held.is_empty() || unattributed_note(state).is_some()
}

/// The rows core dropped because they answered no running search (ADR-0034,
/// Search Attribution), counted over the run — said only once there are some.
fn unattributed_note(state: &UiState) -> Option<String> {
    match state.diagnostics.session.search_rows_unattributed_total {
        0 => None,
        1 => Some(" 1 row answered no running search and was dropped ".to_string()),
        n => Some(format!(
            " {n} rows answered no running search and were dropped "
        )),
    }
}

/// An entry as the strip draws it: ` label · count ` with a trailing `…` while
/// the search still runs, bracketed when current — so the current entry reads
/// without colour too.
fn entry_text(entry: &HeldSearch, state: &UiState, current: bool) -> String {
    let label = match entry.kind.related_file() {
        // A file whose name is not known yet is labelled by its hash.
        Some(hash) if entry.query.trim().is_empty() => {
            format!(
                "~{}",
                label(&crate::words::units::short_hex(hash.as_bytes()))
            )
        }
        Some(_) => format!("~{}", label(&entry.query)),
        None => label(&entry.query),
    };
    let pane = state.searches.get(&entry.id);
    let count = pane.map_or_else(|| "—".to_string(), |pane| pane.results.len().to_string());
    let running = !entry.kind.never_started()
        && state.core_alive
        && pane.is_none_or(|pane| pane.status == SearchStatus::Running);
    let running = if running { "…" } else { "" };
    let (open, close) = if current { ('[', ']') } else { (' ', ' ') };
    format!("{open}{label} · {count}{running}{close}")
}

/// The query capped at [`LABEL_CHARS`] characters; `—` for a search the view
/// did not send.
fn label(query: &str) -> String {
    let query = query.trim();
    if query.is_empty() {
        return "—".to_string();
    }
    if query.chars().count() > LABEL_CHARS {
        let kept: String = query.chars().take(LABEL_CHARS).collect();
        format!("{kept}…")
    } else {
        query.to_string()
    }
}

#[cfg(test)]
mod tests;
