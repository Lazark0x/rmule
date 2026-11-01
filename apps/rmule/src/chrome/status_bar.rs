//! The status bar (spec §3.1): one row, the bottom border, that answers "is
//! everything fine?" at any width.
//!
//! The rates are the app's main live number, so they sit first, in fixed cells,
//! and nothing displaces them: a note or a flash takes what is left of the row
//! and gives up its middle rather than its place. Every other segment carries a
//! claim on the row and is dropped whole when its claim comes up short, because
//! half a number reads as a number nobody measured. The bar takes no rows from
//! the frame, so nothing it says moves a table.
//!
//! The row has two anchors: the left one starts with the rates, the right one
//! ends with the way to help, and the count between them that can change a
//! digit is the tally, on the right, so it moves nothing but itself.

use std::time::Instant;

use ratatui::style::Style;
use ratatui::text::{Line, Span};

use super::{ChromeState, spans_width};
use crate::rates::{RATE_CELLS, SHORT_RATE_CELLS, format_rate, format_rate_short};
use crate::state::{Ed2kConnection, NOTE_AGE_SHOWN, Tally, TallyPart, UiState};
use crate::table::cut_middle;
use crate::theme::Theme;
use crate::words::app as words;
use crate::wrap::display_width;

/// The status bar laid out for one frame width: the two ends of the bottom
/// border. They never meet, so the border shows between them.
pub(super) struct StatusBar {
    pub(super) left: Line<'static>,
    pub(super) right: Line<'static>,
}

/// Cells a segment pays to sit beside another: ` │ `.
const SEPARATOR_CELLS: usize = 3;

/// Cells the right end costs before its first segment: the space that closes
/// the row, and the border left showing between the two ends.
const RIGHT_END_CELLS: usize = 2;

/// A note shortened below this says too little to be worth the row.
const NOTE_FLOOR: usize = 12;

/// What is left of the row, handed out by claim.
struct Row {
    room: usize,
}

impl Row {
    /// A segment that is shown whole or not at all.
    fn whole(&mut self, segment: Vec<Span<'static>>) -> Option<Vec<Span<'static>>> {
        let cells = spans_width(&segment) + SEPARATOR_CELLS;
        (cells <= self.room).then(|| {
            self.room -= cells;
            segment
        })
    }

    /// The segment that opens the right end, which pays for that end.
    fn right_end(&mut self, segment: Vec<Span<'static>>) -> Option<Vec<Span<'static>>> {
        let cells = spans_width(&segment) + RIGHT_END_CELLS;
        (cells <= self.room).then(|| {
            self.room -= cells;
            segment
        })
    }

    /// The first form of a segment that fits whole.
    fn first_fit(&mut self, forms: Vec<Vec<Span<'static>>>) -> Option<Vec<Span<'static>>> {
        forms.into_iter().find_map(|form| self.whole(form))
    }

    /// Text that gives up its middle to stay, down to `floor` cells for the
    /// text; `kept` stays whole behind it.
    fn shortened(
        &mut self,
        text: &str,
        kept: &str,
        style: Style,
        floor: usize,
    ) -> Option<Vec<Span<'static>>> {
        let wanted = display_width(text) + display_width(kept);
        let room = self.room.checked_sub(SEPARATOR_CELLS)?;
        let cells = wanted.min(room);
        let text_cells = cells.checked_sub(display_width(kept))?;
        if text_cells < floor.min(display_width(text)) {
            return None;
        }
        self.room -= cells + SEPARATOR_CELLS;
        let shown = cut_middle(text, text_cells);
        Some(vec![Span::styled(format!("{shown}{kept}"), style)])
    }
}

/// The rates in fixed cells: a digit changing moves nothing, and a frame too
/// narrow for the full form reads the short one. Dim until a direction
/// actually moves bytes. Both directions are differenced from the session's
/// monotonic byte totals (ADR-0077), so ▲ meters every byte the serve activity
/// hands out, a transfer's tail after its row retires included.
fn rates(state: &UiState, theme: &Theme, budget: usize) -> Vec<Span<'static>> {
    let style = |value: f64| {
        if value > 0.0 {
            Style::new().fg(theme.fg)
        } else {
            theme.dim_text()
        }
    };
    let (down, up) = (state.rates.down_total_bps, state.rates.up_total_bps);
    let full = 2 * (RATE_CELLS + 2) + 1;
    if budget >= full + 2 {
        return vec![
            Span::styled(format!("▼ {:>RATE_CELLS$}", format_rate(down)), style(down)),
            Span::raw(" "),
            Span::styled(format!("▲ {:>RATE_CELLS$}", format_rate(up)), style(up)),
        ];
    }
    let short = |bps: f64| format!("{:>SHORT_RATE_CELLS$}", format_rate_short(bps));
    vec![
        Span::styled(format!("▼{}", short(down)), style(down)),
        Span::raw(" "),
        Span::styled(format!("▲{}", short(up)), style(up)),
    ]
}

/// The connected server's users and files, as it last reported them (aMule's
/// status bar): the connected endpoint's row of the server list level. Dashes
/// while no server is connected or it has said nothing.
fn users(state: &UiState, theme: &Theme) -> Vec<Span<'static>> {
    let reported = state
        .diagnostics
        .connected_server
        .as_ref()
        .and_then(|endpoint| {
            state
                .diagnostics
                .servers
                .iter()
                .find(|row| &row.server.endpoint == endpoint)
        });
    let (users_n, files_n) = reported.map_or((None, None), |row| (row.users, row.files));
    let style = if users_n.is_some() {
        Style::new().fg(theme.fg)
    } else {
        theme.dim_text()
    };
    vec![Span::styled(
        format!(
            "Users: {} · Files: {}",
            crate::views::short_count(users_n),
            crate::views::short_count(files_n)
        ),
        style,
    )]
}

/// The connection dots, aMule's arrow colours: green, yellow, and for no
/// session dim when that is the operator's choice, red when one was lost. Kad
/// wears the same grades and the Networks panel's words, off the same facts.
fn connection(state: &UiState, theme: &Theme) -> Vec<Span<'static>> {
    let live = Style::new().fg(theme.fg);
    let (dot, label, style) = match &state.ed2k {
        Ed2kConnection::Connected { client_id } if client_id.is_high_id() => {
            (theme.good, words::ED2K_HIGH_ID.to_string(), live)
        }
        Ed2kConnection::Connected { .. } => (theme.warn, words::ED2K_LOW_ID.to_string(), live),
        Ed2kConnection::Connecting { .. } => (theme.warn, words::ED2K_CONNECTING.to_string(), live),
        // A lost session core is re-making: not off, on its way back.
        Ed2kConnection::Disconnected | Ed2kConnection::Lost if state.reconnect.is_some() => {
            let attempt = state.reconnect.as_ref().map_or(0, |r| r.step.attempt);
            (theme.warn, words::ed2k_reconnecting(attempt), live)
        }
        Ed2kConnection::Lost => (theme.bad, words::ED2K_LOST.to_string(), live),
        Ed2kConnection::Disconnected => (theme.dim, words::ED2K_OFF.to_string(), theme.dim_text()),
    };
    let (word, kad_style) = crate::views::kad_word(state, theme);
    vec![
        Span::styled("●", Style::new().fg(dot)),
        Span::styled(label, style),
        Span::raw(" "),
        Span::styled("●", Style::new().fg(crate::views::kad_dot(state, theme))),
        Span::styled(word, kad_style),
    ]
}

/// The tally in one form, or nothing when no download has anything to count.
fn tally(tally: Tally, short: bool, theme: &Theme) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    for (part, count) in tally.parts() {
        if count == 0 {
            continue;
        }
        if !spans.is_empty() {
            spans.push(Span::styled(words::tally_gap(short), theme.dim_text()));
        }
        let style = match part {
            TallyPart::Active => Style::new().fg(theme.fg),
            TallyPart::Failed => Style::new().fg(theme.bad),
            TallyPart::Done => Style::new().fg(theme.good),
        };
        spans.push(Span::styled(words::tally_part(part, count, short), style));
    }
    spans
}

/// One end of the border from its segments.
fn joined(segments: Vec<Vec<Span<'static>>>, theme: &Theme) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    for (index, segment) in segments.into_iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled(" │ ", theme.chrome()));
        }
        spans.extend(segment);
    }
    spans
}

/// Fit the bar to `width`. Claims on the row, strongest first: the rates, which
/// are never refused; a flash or a stopped core, which are what the operator
/// must read now and give up only their middle; the way to help; the
/// connection; the tally; the note, shortened to what is left; the server's
/// users.
pub(super) fn render(
    state: &UiState,
    chrome: &ChromeState,
    theme: &Theme,
    now: Instant,
    width: u16,
) -> StatusBar {
    let budget = usize::from(width.saturating_sub(2));
    let rates = rates(state, theme, budget);
    let opening_space = 1;
    let mut row = Row {
        room: budget.saturating_sub(spans_width(&rates) + opening_space),
    };

    let urgent = if let Some(flash) = chrome.flash_text(now) {
        let flash = format!("✱ {flash}");
        row.shortened(&flash, "", theme.flash(), 1)
    } else if state.core_alive {
        None
    } else {
        row.shortened(
            words::CORE_STOPPED.as_str(),
            "",
            theme.flash().fg(theme.bad),
            1,
        )
    };
    let help = row.right_end(vec![
        Span::styled(words::HELP_KEY, Style::new().fg(theme.accent)),
        Span::styled(words::HELP_HINT, theme.dim_text()),
    ]);
    let connection = row.whole(connection(state, theme));
    let counts = state.tally();
    let tally = if counts.is_empty() {
        None
    } else {
        row.first_fit(vec![
            tally(counts, false, theme),
            tally(counts, true, theme),
        ])
    };
    let note = state
        .standing_note(now)
        .filter(|_| urgent.is_none() && state.core_alive)
        .and_then(|note| {
            let age = note.age(now);
            let aged = (age >= NOTE_AGE_SHOWN).then(|| words::note_age(age));
            let kept = aged.as_ref().map_or("", |aged| aged.as_str());
            row.shortened(note.as_str(), kept, Style::new().fg(theme.fg), NOTE_FLOOR)
        });
    // Never in the connection's place: it says which server it is reading.
    let users = connection
        .as_ref()
        .and_then(|_| row.whole(users(state, theme)));

    let mut left = vec![Span::raw(" ")];
    left.extend(joined(
        std::iter::once(Some(rates))
            .chain([connection, users, urgent.or(note)])
            .flatten()
            .collect(),
        theme,
    ));
    let mut right = joined([tally, help].into_iter().flatten().collect(), theme);
    if !right.is_empty() {
        right.push(Span::raw(" "));
    }
    StatusBar {
        left: Line::from(left),
        right: Line::from(right),
    }
}

#[cfg(test)]
mod tests;
