//! The results table: name, size, sources and type, tinted by how many
//! sources a result reports — or, for a file the operator already knows, by
//! its **Known-File Mark** — in the order its **Table Sort** gives (see
//! `sort`).
//!
//! A cell says what the result actually carries — the type falls back to a
//! dash when neither name nor tag classifies the file, rather than guessing.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, HighlightSpacing, Paragraph, Row, Table};

use rmule_primitives::{Ed2kText, SearchResult};

use super::SearchesView;
use super::sort::ResultsTable;
use crate::row_selection::{MARKER, selection_style, viewport};
use crate::state::{KnownFileMark, KnownFileMarks, SearchPane, SearchStatus, UiState};
use crate::table_sort::{SortedTable, header_label, header_widths};
use crate::theme::Theme;
use crate::views::say_gave_way;
use crate::wrap::{TableColumns, clamp_u16, gave_way, greedy_widths, wrap_text, wrapped_cell};

/// Results table columns: Name · Size · Sources · Type. `Name` is greedy
/// Its declared width is ignored and it takes everything the others
/// leave over; when the pane is too narrow even for those, they shrink and
/// every cell wraps. Nothing is ever clipped.
const RESULT_COLS: [usize; 4] = [20, 11, 12, 10];
const RESULT_FLEX: usize = 0;
/// The bounded columns and the most each asks for beyond its floor when a value
/// drawn is wider: Size, Sources, Type.
const RESULT_CAPS: [(usize, usize); 3] = [(1, 12), (2, 16), (3, 14)];
/// The order the results table's columns give way in when the pane cannot
/// hold every header: Type, Sources, then Size. Name never gives way.
const RESULT_GIVE_WAY: [usize; 3] = [3, 2, 1];
const COL_SPACING: u16 = 1;
/// [`COL_SPACING`] as the header hit-test counts it.
pub(super) const COL_SPACING_CELLS: usize = COL_SPACING as usize;
const SYMBOL_W: u16 = 2;

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

/// Human-readable file size (binary units, one decimal above bytes).
fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
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
            let mut stopped = super::no_core::STOPPED_WITH_THE_CORE.to_string();
            if let Some(first) = stopped.get_mut(..1) {
                first.make_ascii_uppercase();
            }
            stopped
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
        let hint = if let Some(pane) = pane {
            let x = if pane.status.is_live() && state.core_alive {
                "x stop"
            } else {
                "x close"
            };
            let sort = if pane.results.is_empty() {
                ""
            } else {
                "  s sort  S reverse"
            };
            let next = if more.is_some_and(|more| more.asks_left > 0) {
                "  n more"
            } else {
                ""
            };
            format!(" [ ] search  {x}{next}{sort} ")
        } else if self.current_refused() || self.current_not_sent().is_some() {
            " [ ] search  x close ".to_string()
        } else {
            String::new()
        };
        let block = crate::views::title::titled(
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
        self.header_area = Rect::default();
        self.rows_area = Rect::default();
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
                            None => "press / and type a query",
                            Some(pane) => match pane.status {
                                SearchStatus::Running | SearchStatus::WaitingForConnection
                                    if !state.core_alive =>
                                {
                                    super::no_core::STOPPED_WITH_THE_CORE
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
        self.results_state.select(selected);
        let results = self.ordered(state);

        // The Name column is greedy and wraps: a 200-character filename grows
        // its row instead of being cut. Widths are computed rather than
        // left to `Constraint::Fill` so an over-narrow pane shrinks the fixed
        // columns instead of collapsing the name column to nothing.
        let headers = header_widths(&self.sort);
        let mut wants = [0; 4];
        for (index, cap) in RESULT_CAPS {
            let widest = results
                .iter()
                .map(|result| match index {
                    1 => format_size(result.file_size()).chars().count(),
                    2 => result_sources_text(result).chars().count(),
                    _ => result_type_text(result).chars().count(),
                })
                .max()
                .unwrap_or(0);
            wants[index] = widest.min(cap);
        }
        let cols_at = |bar: bool| {
            let bar = if bar { viewport::BAR_W } else { 0 };
            greedy_widths(
                usize::from(area.width.saturating_sub(SYMBOL_W).saturating_sub(bar)),
                &TableColumns {
                    floors: &RESULT_COLS,
                    wants: &wants,
                    headers: &headers,
                    flex: RESULT_FLEX,
                    give_way: &RESULT_GIVE_WAY,
                },
                usize::from(COL_SPACING),
            )
        };
        // The selected result's values in the columns that gave way.
        let off_screen_at = |cols: &[usize]| {
            selected
                .and_then(|index| results.get(index))
                .map_or_else(Vec::new, |result| {
                    let values = [
                        result.primary_name().to_display_string(),
                        format_size(result.file_size()),
                        result_sources_text(result),
                        result_type_text(result),
                    ];
                    crate::views::off_screen::hidden(
                        ResultsTable::COLUMNS.iter().map(|c| c.label),
                        &values,
                        cols,
                    )
                })
        };
        // The arrow is part of the header's text, and every column is at
        // least as wide as its header with the arrow, so a header is one line.
        let header_style = Style::new().fg(theme.dim).add_modifier(Modifier::BOLD);
        let header_at = |cols: &[usize]| -> (Row<'static>, u16) {
            let (cells, heights): (Vec<_>, Vec<u16>) = ResultsTable::COLUMNS
                .iter()
                .zip(cols)
                .map(|(column, width)| {
                    let label = header_label(column.label, self.sort.arrow(column.column));
                    wrapped_cell(&label, *width, header_style, column.kind.right_aligned())
                })
                .unzip();
            let height = heights.into_iter().max().unwrap_or(1);
            (Row::new(cells).style(header_style).height(height), height)
        };
        let marks = KnownFileMarks::of(state);
        let row_at = |result: &SearchResult, cols: &[usize]| -> (Row<'static>, u16) {
            let tint = marks
                .get(result.file_hash(), result.file_size())
                .map_or_else(
                    || Style::new().fg(source_tint(result_source_count(result), theme)),
                    |mark| mark_style(mark, theme),
                );
            let (name, name_h) = wrapped_cell(
                &result.primary_name().to_display_string(),
                cols[0],
                tint,
                false,
            );
            let (size, size_h) =
                wrapped_cell(&format_size(result.file_size()), cols[1], tint, true);
            let (sources, sources_h) =
                wrapped_cell(&result_sources_text(result), cols[2], tint, true);
            let (ftype, type_h) = wrapped_cell(&result_type_text(result), cols[3], tint, false);
            let height = name_h.max(size_h).max(sources_h).max(type_h);
            (
                Row::new(vec![name, size, sources, ftype])
                    // The tint — or the mark — applies to the whole row
                    // (inventory parity).
                    .style(tint)
                    .height(height),
                height,
            )
        };
        let bar = viewport::needs_bar(results.len(), area.height.saturating_sub(1), || {
            let cols = cols_at(false);
            let room = area
                .height
                .saturating_sub(crate::views::off_screen::height(
                    area,
                    &off_screen_at(&cols),
                ))
                .saturating_sub(header_at(&cols).1);
            let drawn: u32 = results
                .iter()
                .map(|result| u32::from(row_at(result, &cols).1))
                .sum();
            drawn > u32::from(room)
        });
        let cols = cols_at(bar);
        let area = crate::views::off_screen::draw(frame, area, &off_screen_at(&cols), theme);
        let (header, header_h) = header_at(&cols);
        let (list, bar) = viewport::split(area, bar);
        self.header_area = Rect::new(
            list.x.saturating_add(SYMBOL_W),
            list.y,
            list.width.saturating_sub(SYMBOL_W),
            header_h.min(list.height),
        );
        self.rows_area = Rect::new(
            list.x,
            list.y.saturating_add(header_h),
            list.width,
            list.height.saturating_sub(header_h),
        );
        let (rows, heights): (Vec<Row>, Vec<u16>) =
            results.iter().map(|result| row_at(result, &cols)).unzip();
        let first = self.viewport.follow(
            selected.unwrap_or(0),
            heights.len(),
            list.height.saturating_sub(header_h),
            |index| heights[index],
        );
        *self.results_state.offset_mut() = first;
        self.row_heights = heights;

        let widths: Vec<Constraint> = cols
            .iter()
            .map(|width| Constraint::Length(clamp_u16(*width)))
            .collect();
        self.header_cols = cols;
        let table = Table::new(rows, widths)
            .header(header)
            .column_spacing(COL_SPACING)
            .row_highlight_style(selection_style(theme, !self.input_focused))
            .highlight_symbol(MARKER)
            // The symbol's gutter is always there, so the header's column
            // edges — and a click on them — do not move with the selection.
            .highlight_spacing(HighlightSpacing::Always);
        frame.render_stateful_widget(table, list, &mut self.results_state);
        let foot = self.viewport.draw(frame, pane, bar, theme);
        say_gave_way(
            frame,
            foot,
            &gave_way(
                ResultsTable::COLUMNS.iter().map(|c| c.label),
                &self.header_cols,
            ),
            theme,
        );
    }
}

#[cfg(test)]
mod tests;
