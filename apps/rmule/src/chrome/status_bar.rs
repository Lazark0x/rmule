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
use crate::theme::Theme;
use crate::words::app as words;
use crate::table::cut_middle;
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
mod tests {
    use super::super::draw_frame;
    use super::render as status_bar;
    use super::*;
    use crate::action::Action;
    use crate::fixture::*;
    use crate::golden::assert_golden;
    use crate::state::NOTE_STANDS;
    use crate::words::Sentence;
    use std::time::Duration;

    /// Both ends of the border, as they read.
    fn read(bar: &StatusBar) -> String {
        format!("{} {}", bar.left, bar.right)
    }

    fn cells(bar: &StatusBar) -> usize {
        bar.left.width() + bar.right.width()
    }

    #[test]
    fn golden_chrome_cold_start_shows_every_degrade_segment() {
        assert_golden("chrome_cold", 80, 24, |frame| {
            draw_frame(
                frame,
                &UiState::default(),
                &ChromeState::default(),
                &Theme::default_dark(),
                now(),
            );
        });
    }

    #[test]
    fn golden_chrome_connected_with_rates_and_notable() {
        assert_golden("chrome_connected", 80, 24, |frame| {
            draw_frame(
                frame,
                &connected_state(),
                &ChromeState::default(),
                &Theme::default_dark(),
                now(),
            );
        });
    }

    /// The users segment is the connected server's own report — the row of
    /// the server list whose endpoint the session is connected to — and
    /// dashes while no server is connected, never another row's figures.
    #[test]
    fn users_and_files_are_the_connected_servers_report() {
        let theme = Theme::default_dark();
        let chrome = ChromeState::default();
        let users = |state: &UiState| {
            status_bar(state, &chrome, &theme, now(), 120)
                .left
                .spans
                .into_iter()
                .find(|span| span.content.starts_with("Users"))
                .expect("a users segment")
                .content
                .into_owned()
        };
        let mut state = listed_servers();
        assert_eq!(users(&state), "Users: 1M · Files: 24M");
        state.diagnostics.connected_server = None;
        assert_eq!(users(&state), "Users: — · Files: —", "not connected");
        state.diagnostics.connected_server =
            Some(state.diagnostics.servers[1].server.endpoint.clone());
        assert_eq!(users(&state), "Users: 9812 · Files: 431k");
        state.diagnostics.connected_server =
            Some(state.diagnostics.servers[2].server.endpoint.clone());
        assert_eq!(
            users(&state),
            "Users: — · Files: —",
            "a server that said nothing"
        );
    }

    /// ▲ is a real meter (the session up-total, differenced by the bridge),
    /// never a placeholder zero: it carries the synthesized number and stops
    /// rendering dim once bytes actually move.
    #[test]
    fn the_up_arrow_carries_the_synthesized_upload_rate() {
        let theme = Theme::default_dark();
        let chrome = ChromeState::default();
        let up_span = |bps: f64| {
            let mut state = connected_state();
            state.rates.up_total_bps = bps;
            status_bar(&state, &chrome, &theme, now(), 120)
                .left
                .spans
                .into_iter()
                .find(|span| span.content.starts_with('▲'))
                .expect("an ▲ segment")
        };
        let idle = up_span(0.0);
        assert_eq!(idle.content, "▲   0.0 KB/s");
        assert_eq!(idle.style.fg, Some(theme.dim), "nothing served ⇒ dim");
        let busy = up_span(45.6 * 1024.0);
        assert_eq!(busy.content, "▲  45.6 KB/s");
        assert_eq!(busy.style.fg, Some(theme.fg), "a live meter reads normal");
    }

    #[test]
    fn golden_chrome_both_meters_live() {
        let mut state = connected_state();
        state.rates.up_total_bps = 45.6 * 1024.0;
        state.notable = Some(Sentence::for_test("upload slot granted").into());
        assert_golden("chrome_rates_both", 80, 24, |frame| {
            draw_frame(
                frame,
                &state,
                &ChromeState::default(),
                &Theme::default_dark(),
                now(),
            );
        });
    }

    /// The bar's first rule: no note, no flash and no width takes the rates
    /// off it, and nothing it says outgrows its one row.
    #[test]
    fn the_rates_stay_on_the_bar_at_every_width_with_every_note() {
        let theme = Theme::default_dark();
        let t0 = now();
        let mut noted = connected_state();
        noted.notable = Some(
            Sentence::for_test("no download dir yet: press 6, then set Download dir in Settings")
                .into(),
        );
        let mut stopped = connected_state();
        stopped.core_alive = false;
        let mut flashed = ChromeState::default();
        flashed.update(&Action::Flash(LONG_FLASH), t0);
        let quiet = ChromeState::default();

        for (state, chrome) in [
            (&noted, &quiet),
            (&noted, &flashed),
            (&stopped, &quiet),
            (&connected_state(), &quiet),
        ] {
            for width in 18u16..=140 {
                let bar = status_bar(state, chrome, &theme, t0, width);
                let text = read(&bar);
                assert!(text.contains('▼') && text.contains('▲'), "{width}: {text}");
                assert!(
                    cells(&bar) <= usize::from(width - 2),
                    "overflows at {width}: {text}"
                );
            }
        }
    }

    /// A long flash stays on the row: its middle goes, both ends stay, and
    /// the frame gives the table every row it had.
    #[test]
    fn a_flash_takes_no_rows_and_keeps_both_ends() {
        let t0 = now();
        let mut chrome = ChromeState::default();
        chrome.update(&Action::Flash(LONG_FLASH), t0);
        let at80 = read(&status_bar(
            &connected_state(),
            &chrome,
            &Theme::default_dark(),
            t0,
            80,
        ));
        assert!(at80.contains('…'), "{at80}");
        let whole = LONG_FLASH;
        let first_word = whole.split(' ').next().expect("a word");
        assert!(at80.contains(first_word), "{at80}");
        let last_word = whole.rsplit(' ').next().expect("a word");
        assert!(at80.contains(last_word), "{at80}");

        let content = |chrome: &ChromeState| {
            let mut rect = ratatui::layout::Rect::default();
            crate::golden::render_to_lines(80, 24, |frame| {
                rect = draw_frame(
                    frame,
                    &connected_state(),
                    chrome,
                    &Theme::default_dark(),
                    t0,
                );
            });
            rect
        };
        assert_eq!(content(&chrome), content(&ChromeState::default()));
    }

    /// A note past its minute says how old it is, and the age survives the
    /// note being shortened.
    #[test]
    fn a_note_past_a_minute_says_its_age_until_it_leaves() {
        let theme = Theme::default_dark();
        let chrome = ChromeState::default();
        let t0 = now();
        let mut state = connected_state();
        state.apply(Action::Note(Sentence::for_test("search completed")), t0);
        let at = |offset: Duration| read(&status_bar(&state, &chrome, &theme, t0 + offset, 120));
        assert!(at(Duration::from_secs(59)).contains("search completed"));
        assert!(!at(Duration::from_secs(59)).contains("ago"));
        assert!(at(Duration::from_secs(180)).contains("search completed · 3m ago"));
        assert!(!at(NOTE_STANDS).contains("search completed"));
    }

    /// Nothing right of the rates shifts when a rate gains a digit, and the
    /// tally changing a digit moves only itself.
    #[test]
    fn a_digit_changing_moves_no_other_value() {
        let theme = Theme::default_dark();
        let chrome = ChromeState::default();
        let column = |state: &UiState, needle: &str| {
            let bar = status_bar(state, &chrome, &theme, now(), 140);
            let text = bar.left.to_string();
            text.find(needle)
                .map(|at| crate::wrap::display_width(&text[..at]))
                .expect("on the bar")
        };
        let mut before = connected_state();
        before.rates.down_total_bps = 9.9 * 1024.0;
        let mut after = connected_state();
        after.rates.down_total_bps = 10.0 * 1024.0;
        for needle in ["▲", "●eD2k", "Users"] {
            assert_eq!(column(&before, needle), column(&after, needle), "{needle}");
        }
    }

    /// Off is dim when it is where the operator left things, red when a
    /// session was lost or Kad ended on its own: a resting app shows no alarm.
    #[test]
    fn a_chosen_off_is_dim_and_a_lost_one_is_red() {
        let theme = Theme::default_dark();
        let chrome = ChromeState::default();
        let dots = |state: &UiState| {
            status_bar(state, &chrome, &theme, now(), 120)
                .left
                .spans
                .into_iter()
                .filter(|span| span.content == "●")
                .map(|span| span.style.fg)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            dots(&UiState::default()),
            [Some(theme.dim), Some(theme.dim)]
        );
        let lost = UiState {
            ed2k: Ed2kConnection::Lost,
            kad_lost: true,
            ..UiState::default()
        };
        assert_eq!(dots(&lost), [Some(theme.bad), Some(theme.bad)]);
    }

    /// The status dot reads the same facts the Networks panel does, in its
    /// words, so the two can never contradict each other.
    #[test]
    fn the_kad_dot_tracks_the_runtime_facts_the_bridge_polled() {
        let theme = Theme::default_dark();
        let chrome = ChromeState::default();
        let bar = |state: &UiState| read(&status_bar(state, &chrome, &theme, now(), 120));
        assert!(bar(&connected_state()).contains("Kad: off"), "no node");
        assert!(bar(&with_kad(false)).contains("Kad: joining"));
        assert!(bar(&with_kad(true)).contains("Kad: running"));
    }

    /// The connection says the dial, and no frame claims a session at once.
    #[test]
    fn a_dial_reads_connecting() {
        let theme = Theme::default_dark();
        let chrome = ChromeState::default();
        let state = UiState {
            ed2k: Ed2kConnection::Connecting {
                server: rmule_primitives::ServerEndpoint::new("192.0.2.7", 4661).expect("endpoint"),
            },
            ..UiState::default()
        };
        let text = read(&status_bar(&state, &chrome, &theme, now(), 120));
        assert!(text.contains("eD2k connecting…"), "{text}");
        assert!(
            !text.contains("off ●") && !text.contains("HighID"),
            "{text}"
        );
    }

    /// The tally answers the check-in: words where the row has room, glyphs
    /// at the default terminal, and no failure is ever dropped for a note.
    #[test]
    fn the_tally_counts_active_failed_and_done() {
        use crate::state::DownloadStatus;
        let theme = Theme::default_dark();
        let chrome = ChromeState::default();
        let mut state = three_downloads();
        for (row, status) in state.downloads.values_mut().zip([
            DownloadStatus::Downloading,
            DownloadStatus::Failed,
            DownloadStatus::Completed,
        ]) {
            row.status = status;
        }
        state.notable = Some(Sentence::for_test("a note of no great length at all").into());
        let wide = read(&status_bar(&state, &chrome, &theme, now(), 140));
        assert!(wide.contains("1 active · 1 failed · 1 done"), "{wide}");
        let at80 = read(&status_bar(&state, &chrome, &theme, now(), 80));
        assert!(at80.contains("1↓ 1✗ 1✓"), "{at80}");
        assert!(!read(&status_bar(&UiState::default(), &chrome, &theme, now(), 80)).contains('✓'));
    }

    #[test]
    fn the_segments_give_way_in_their_order() {
        let theme = Theme::default_dark();
        let t0 = now();
        let state = connected_state();
        let chrome = ChromeState::default();
        // Roomy: every segment.
        let wide = read(&status_bar(&state, &chrome, &theme, t0, 120));
        assert!(
            wide.contains("Users:")
                && wide.contains("KB/s")
                && wide.contains("eD2k")
                && wide.contains("download completed"),
            "{wide}"
        );
        // 80 columns: the users counter drops first.
        let at80 = read(&status_bar(&state, &chrome, &theme, t0, 80));
        assert!(!at80.contains("Users:"), "users drop first: {at80:?}");
        assert!(at80.contains("eD2k") && at80.contains("? help"), "{at80:?}");
        // Very narrow: the rates and the way to help are what is left.
        let at40 = read(&status_bar(&state, &chrome, &theme, t0, 40));
        assert!(at40.contains("KB/s") && at40.contains("? help"), "{at40:?}");
        assert!(!at40.contains("eD2k"), "{at40:?}");
    }

    #[test]
    fn golden_status_bar_keeps_an_overlong_flash_on_its_row() {
        let t0 = now();
        let mut chrome = ChromeState::default();
        chrome.update(&Action::Flash(LONG_FLASH), t0);
        assert_golden("chrome_flash_narrow", 44, 12, |frame| {
            draw_frame(
                frame,
                &connected_state(),
                &chrome,
                &Theme::default_dark(),
                t0,
            );
        });
    }
}
