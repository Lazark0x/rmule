//! The results table: name, size, sources and type, tinted by how many
//! sources a result reports — or, for a file the operator already knows, by
//! its **Known-File Mark** — in the order its **Table Sort** gives (see
//! `sort`).
//!
//! A cell says what the result actually carries — the type falls back to a
//! dash when neither name nor tag classifies the file, rather than guessing.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Paragraph};

use rmule_primitives::{Ed2kText, SearchResult};

use super::SearchesView;
use super::sort::ResultsTable;
use crate::state::{KnownFileMark, KnownFileMarks, SearchPane, SearchStatus, UiState};
use crate::table::{self, Cell, Rows, Table};
use crate::table_sort::SortedTable;
use crate::theme::Theme;
use crate::views::human_size;
use crate::wrap::{clamp_u16, display_width, wrap_text};

/// Results table columns: Name · Size · Sources · Type. `Name` is greedy: its
/// entry is the room it keeps before other columns give way to it, and it
/// takes everything the others leave over.
const RESULT_COLS: [usize; 4] = [30, 9, 7, 8];
const RESULT_FLEX: usize = 0;
/// The bounded columns and the most each asks for beyond its floor when a value
/// drawn is wider: Size, Sources, Type.
const RESULT_CAPS: [(usize, usize); 3] = [(1, 12), (2, 16), (3, 14)];
/// The order the results table's columns give way in: Type, Size, then
/// Sources, which is what a result is picked by. Name never gives way.
const RESULT_GIVE_WAY: [usize; 3] = [3, 1, 2];

/// Source-count tint (spec §3.3 inventory parity): ≥100 green, ≥10 normal fg,
/// else dim.
fn source_tint(count: u32, theme: &Theme) -> Color {
    if count >= 100 {
        theme.good
    } else if count >= 10 {
        theme.fg
    } else {
        theme.dim
    }
}

/// A marked row's look (ADR-0100): the mark's colour in place of the source
/// tint, and an attribute as the second cue, so the mark survives a monochrome
/// terminal and never reads as a source count.
fn mark_style(mark: &KnownFileMark, theme: &Theme) -> Style {
    match mark {
        KnownFileMark::Downloading { .. } => Style::new()
            .fg(theme.mark_downloading)
            .add_modifier(Modifier::BOLD),
        KnownFileMark::Failed { .. } => Style::new()
            .fg(theme.mark_failed)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        KnownFileMark::Have { .. } => Style::new().fg(theme.mark_have).add_modifier(Modifier::DIM),
        KnownFileMark::Withheld { .. } => Style::new()
            .fg(theme.mark_withheld)
            .add_modifier(Modifier::UNDERLINED),
        KnownFileMark::Had { .. } => Style::new()
            .fg(theme.mark_had)
            .add_modifier(Modifier::ITALIC),
        KnownFileMark::Cancelled => Style::new()
            .fg(theme.mark_cancelled)
            .add_modifier(Modifier::CROSSED_OUT),
    }
}

/// The source count aMule tints on: the server-reported availability when
/// present, else the concrete peer-source list length.
pub(super) fn result_source_count(result: &SearchResult) -> u32 {
    result
        .reported_availability()
        .unwrap_or_else(|| u32::try_from(result.sources().len()).unwrap_or(u32::MAX))
}

/// The *Sources* cell, aMule's format (`SearchListCtrl.cpp:217-222`): the
/// reported availability, then the complete-source count in parentheses when
/// the counterparty sent a non-zero one — `42 (7)`.
///
/// aMule appends a third `[n]` group for the distinct clients advertising the
/// file, but only ever on a *grouped parent* row; rmule's result set is flat
/// (one row per `(hash, size)`), so the group has no analogue and is left out
/// rather than printed as a `[1]` on every row.
fn result_sources_text(result: &SearchResult) -> String {
    let count = result_source_count(result);
    match result.complete_sources() {
        Some(complete) if complete > 0 => format!("{count} ({complete})"),
        _ => count.to_string(),
    }
}

/// The row's type: its file class (name first, `FT_FILETYPE` tag as the
/// fallback — see [`SearchResult::file_class`]), else the raw tag string when
/// the counterparty sent a term rmule does not know (information the server did
/// send beats nothing), else `None` for a genuinely unclassifiable row — no
/// extension, or one outside aMule's table.
pub(super) fn result_type(result: &SearchResult) -> Option<String> {
    result.file_class().map_or_else(
        || result.file_type().map(Ed2kText::to_display_string),
        |class| Some(crate::words::search::file_class_words(class).to_string()),
    )
}

/// The *Type* cell: [`result_type`], or `—` for an unclassifiable row.
fn result_type_text(result: &SearchResult) -> String {
    result_type(result).unwrap_or_else(|| "—".to_string())
}

fn results_title(
    pane: Option<&SearchPane>,
    more: Option<rmule_core::ServerMoreResults>,
    core_alive: bool,
    related: bool,
    reconnecting: bool,
) -> String {
    let Some(pane) = pane else {
        return " Results ".to_string();
    };
    let status = match &pane.status {
        // Nothing will answer it: the core that ran it is gone.
        SearchStatus::Running | SearchStatus::WaitingForConnection if !core_alive => {
            crate::words::search::STOPPED_WITH_THE_ENGINE_TITLE.to_string()
        }
        SearchStatus::WaitingForConnection if reconnecting => {
            "Waiting for the reconnect · sent when it lands".to_string()
        }
        SearchStatus::WaitingForConnection => {
            "Waiting for a connection · sent when you connect".to_string()
        }
        SearchStatus::Running => {
            let running = match pane.waiting_for_turn {
                Some(send_in) => format!(
                    "Waiting its turn on this server · sent in {} s",
                    crate::state::seconds(send_in)
                ),
                None => "Running…".to_string(),
            };
            // Each leg by name: one may wait while the others run.
            match pane.legs {
                Some(legs) => format!(
                    "{running} · {}",
                    crate::state::legs_line(legs, related, reconnecting)
                ),
                None => running,
            }
        }
        SearchStatus::Completed { total } => match pane.legs {
            // A leg that never ran, was never sent or was never answered is
            // said, so a Kad-less or server-less completion does not read as
            // a full one.
            Some(legs)
                if short_of_full(legs.server)
                    || (!related && (short_of_full(legs.sweep) || short_of_full(legs.kad))) =>
            {
                format!(
                    "Completed · {total} · {}",
                    crate::state::legs_line(legs, related, reconnecting)
                )
            }
            _ => format!("Completed · {total}"),
        },
        SearchStatus::Cancelled => "Cancelled".to_string(),
        SearchStatus::Failed {
            reason: rmule_core::SearchFailure::RelatedSearchNotOffered,
        } => "Refused".to_string(),
        SearchStatus::Failed { reason } => {
            format!("Failed · {}", crate::state::search_failure_words(*reason))
        }
    };
    let status = match super::more::status_clause(more, pane.more_ended) {
        Some(clause) => format!("{status} · {clause}"),
        None => status,
    };
    if pane.skipped > 0 {
        format!(" Results · {status} · {} skipped ", pane.skipped)
    } else {
        format!(" Results · {status} ")
    }
}

/// Whether a settled leg ended without saying what it would have.
const fn short_of_full(leg: rmule_core::SearchLegState) -> bool {
    use rmule_core::SearchLegState as L;
    match leg {
        L::NotRun | L::NotSent(_) | L::Unanswered | L::WalkStopped => true,
        L::WaitingForSession | L::WaitingForKad | L::Sent | L::Settled => false,
    }
}

impl SearchesView {
    pub(super) fn draw_results(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
    ) {
        let pane = self.held.current_pane(state);
        let more = self
            .held
            .current_id()
            .and_then(|search_id| super::more::offered(state, search_id));
        // The results pane is the active (accent-bordered) pane whenever the
        // input is unfocused and neither the menu nor the filter editor is up.
        let active = !self.input_focused && self.menu.is_none() && !self.filters_open;
        let border = if active { theme.accent } else { theme.dim };
        let title = self.current_not_sent().map_or_else(
            || {
                let related = self
                    .held
                    .current()
                    .is_some_and(|held| held.kind.related_file().is_some());
                results_title(
                    pane,
                    more,
                    state.core_alive,
                    related,
                    state.reconnect.is_some(),
                )
            },
            |_| " Results · Not sent ".to_string(),
        );
        let reopen = if self.held.can_reopen() {
            "  u reopen"
        } else {
            ""
        };
        let hint = if let Some(pane) = pane {
            let x = if pane.status.is_live() && state.core_alive {
                "x stop"
            } else {
                "x close"
            };
            let sort = if pane.results.is_empty() {
                ""
            } else {
                "  Space tag  s sort  S reverse  z zoom"
            };
            let next = if more.is_some_and(|more| more.asks_left > 0) {
                "  n more"
            } else {
                ""
            };
            let menu = if pane.results.is_empty() {
                ""
            } else {
                "Enter menu  / filter  "
            };
            format!(" {menu}[ ] search  {x}{next}{sort}{reopen} ")
        } else if self.current_refused() || self.current_not_sent().is_some() {
            format!(" [ ] search  x close{reopen} ")
        } else {
            reopen.to_string()
        };
        let block = crate::views::title::titled_first_key(
            Block::bordered().border_style(Style::new().fg(border)),
            area.width,
            (&title, Style::new().fg(theme.fg)),
            (&hint, theme.dim_text()),
        );
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if inner.width == 0 || inner.height == 0 {
            return;
        }

        // Nothing to click until a table is drawn.
        self.drawn = table::Drawn::default();
        match pane {
            Some(pane) if !pane.results.is_empty() => {
                self.draw_table(frame, area, inner, state, theme);
            }
            _ => {
                let message = self
                    .not_sent_message()
                    .or_else(|| self.related_message(pane))
                    .unwrap_or_else(|| {
                        match pane {
                            None if self.input_focused => crate::words::search::TYPE_A_QUERY,
                            None => crate::words::search::PRESS_SLASH,
                            Some(pane) => match pane.status {
                                SearchStatus::Running | SearchStatus::WaitingForConnection
                                    if !state.core_alive =>
                                {
                                    crate::words::search::STOPPED_WITH_THE_ENGINE
                                }
                                SearchStatus::WaitingForConnection => {
                                    "waiting for a connection — press c on a server in Networks (1) to connect"
                                }
                                SearchStatus::Running => "searching…",
                                SearchStatus::Completed { .. } => "no results",
                                SearchStatus::Cancelled => "search cancelled",
                                SearchStatus::Failed { .. } => "search failed",
                            },
                        }
                        .to_string()
                    });
                let lines = wrap_text(&message, usize::from(inner.width));
                let height = clamp_u16(lines.len()).min(inner.height);
                let rows = Rect::new(
                    inner.x,
                    inner.y + inner.height.saturating_sub(height) / 2,
                    inner.width,
                    height,
                );
                frame.render_widget(
                    Paragraph::new(lines.join("\n"))
                        .style(theme.dim_text())
                        .centered(),
                    rows,
                );
            }
        }
    }

    /// The results table in `area`, the inside of the bordered `pane`.
    fn draw_table(
        &mut self,
        frame: &mut Frame,
        pane: Rect,
        area: Rect,
        state: &UiState,
        theme: &Theme,
    ) {
        let ids = self.result_ids(state);
        let selected = self
            .held
            .current_mut()
            .and_then(|entry| entry.cursor.place(&ids));
        self.selected = selected;
        let results = self.ordered(state);

        let key = self.order_key(state);
        let wants = self.wants_memo.get(key, || {
            let mut wants = vec![0; 4];
            for (index, cap) in RESULT_CAPS {
                let widest = results
                    .iter()
                    .map(|result| match index {
                        1 => display_width(&human_size(result.file_size())),
                        2 => display_width(&result_sources_text(result)),
                        _ => display_width(&result_type_text(result)),
                    })
                    .max()
                    .unwrap_or(0);
                wants[index] = widest.min(cap);
            }
            wants
        });
        let marks = KnownFileMarks::of(state);
        // The tint — or the mark — colours the whole row (inventory parity).
        let cells = |index: usize, _: &[usize]| {
            let result = results[index];
            let tint = marks
                .get(result.file_hash(), result.file_size())
                .map_or_else(
                    || Style::new().fg(source_tint(result_source_count(result), theme)),
                    |mark| mark_style(mark, theme),
                );
            vec![
                Cell::new(result.primary_name().to_display_string(), tint),
                Cell::new(human_size(result.file_size()), tint),
                Cell::new(result_sources_text(result), tint),
                Cell::new(result_type_text(result), tint),
            ]
        };
        let header_style = Style::new().fg(theme.dim).add_modifier(Modifier::BOLD);
        let table = Table::of(
            &self.sort,
            &RESULT_COLS,
            RESULT_FLEX,
            &RESULT_GIVE_WAY,
            header_style,
        )
        .wants(&wants)
        .empty(crate::words::app::NO_MATCH);
        let entry = self.held.current();
        let tagged = |index: usize| {
            entry.is_some_and(|entry| entry.tags.contains(&ResultsTable::identity(results[index])))
        };
        let total = self
            .held
            .current_pane(state)
            .map_or(0, |pane| pane.results.len());
        let rows = Rows {
            count: results.len(),
            selected,
            focused: !self.input_focused,
            cells: &cells,
            marker: None,
            tagged: Some(&tagged),
            filter: entry.map(|entry| (&entry.filter, total)),
        };
        self.drawn = table::draw(
            frame,
            (pane, area),
            &table,
            &rows,
            &mut self.viewport,
            theme,
        );
    }
}

#[cfg(test)]
mod tests;
