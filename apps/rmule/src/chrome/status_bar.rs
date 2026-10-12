//! The status bar (spec §3.1): connection, meters, the info feed and the
//! flash, fitted to a width budget.
//!
//! Segments carry a priority, and the lowest-priority segment is the first to
//! be dropped when the frame narrows — the bar never clips a segment in place,
//! because half a rate reads as a number nobody measured. An overlong flash
//! wraps above the border rather than pushing the rest out.

use std::time::Instant;

use ratatui::style::Style;
use ratatui::text::{Line, Span};

use super::{ChromeState, spans_width};
use crate::rates::format_rate;
use crate::state::{Ed2kConnection, UiState};
use crate::theme::Theme;
use crate::wrap::wrap_text;

/// The status bar laid out for one frame width: what the bottom border shows,
/// plus any wrapped info rows that did not fit on it.
pub(super) struct StatusBar {
    pub(super) border: Line<'static>,
    /// Info text too wide for the border, wrapped for the rows above it.
    pub(super) overflow: Vec<Line<'static>>,
}

/// The 4 aMule status segments (spec §3.1): info/flash · users · rates ·
/// connection dots (prototype-compact: `●eD2k HighID ●Kad off`). Segments
/// without core backing render their designed degrade text — visible
/// absence, never invented numbers.
///
/// # No-truncation adaptation
///
/// The bar sits on a single border row, so it cannot simply grow. Instead the
/// segments are *priority-ordered* — info (1) > connection (4) > rates (3) >
/// users (2) — and whole low-priority segments are dropped until the line
/// fits. Dropping a whole segment is visible absence (the same discipline the
/// menus use); clipping a string is a silent lie. If the info text alone still
/// overflows, it leaves the border entirely and wraps onto the rows above it
/// ([`crate::chrome::draw_frame`] shrinks the content rect to match), so no glyph is ever cut.
pub(super) fn render(
    state: &UiState,
    chrome: &ChromeState,
    theme: &Theme,
    now: Instant,
    width: u16,
) -> StatusBar {
    let sep = || Span::styled(" │ ", theme.chrome());
    let sep_w = 3usize;

    // (2) the connected server's users and files, as it last reported them
    // (aMule's status bar): the connected endpoint's row of the server list
    // level. Dashes while no server is connected or it has said nothing.
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
    let users_style = if users_n.is_some() {
        Style::new().fg(theme.fg)
    } else {
        theme.dim_text()
    };
    let users = vec![Span::styled(
        format!(
            "Users: {} · Files: {}",
            crate::views::short_count(users_n),
            crate::views::short_count(files_n)
        ),
        users_style,
    )];

    // (3) bridge-synthesized rates: both directions are differenced from the
    // session's monotonic byte totals (ADR-0077), so ▲ meters every byte the
    // serve activity hands out — including a transfer's tail after its row
    // retires. Dim until a direction actually moves bytes.
    let down = state.rates.down_total_bps;
    let up = state.rates.up_total_bps;
    let rate_style = |value: f64| {
        if value > 0.0 {
            Style::new().fg(theme.fg)
        } else {
            theme.dim_text()
        }
    };
    let rates = vec![
        Span::styled(format!("▼ {}", format_rate(down)), rate_style(down)),
        Span::raw(" "),
        Span::styled(format!("▲ {}", format_rate(up)), rate_style(up)),
    ];

    // (4) connection dots, aMule arrow-color parity: green/yellow/red =
    // HighID/LowID/off — and the same three grades for Kad, off the one
    // runtime fact core reports (see `views::networks::draw_kad`). The
    // dot must never disagree with the Networks panel: both read
    // `diagnostics.kad`.
    let mut connection: Vec<Span<'static>> = Vec::new();
    match state.ed2k {
        Ed2kConnection::Connected { client_id } => {
            let (dot, label) = if client_id.is_high_id() {
                (theme.good, "HighID")
            } else {
                (theme.warn, "LowID")
            };
            connection.push(Span::styled("●", Style::new().fg(dot)));
            connection.push(Span::styled(
                format!("eD2k {label}"),
                Style::new().fg(theme.fg),
            ));
        }
        // A lost session core is re-making: not off — on its way back.
        Ed2kConnection::Disconnected if state.reconnect.is_some() => {
            let attempt = state.reconnect.as_ref().map_or(0, |r| r.step.attempt);
            connection.push(Span::styled("●", Style::new().fg(theme.warn)));
            connection.push(Span::styled(
                format!("eD2k reconnecting ({attempt})"),
                Style::new().fg(theme.fg),
            ));
        }
        Ed2kConnection::Disconnected => {
            connection.push(Span::styled("●", Style::new().fg(theme.bad)));
            connection.push(Span::styled("eD2k off", theme.dim_text()));
        }
    }
    connection.push(Span::raw(" "));
    let (kad_dot, kad_label, kad_style) = match state.diagnostics.kad {
        None => (theme.bad, "Kad off ", theme.dim_text()),
        Some(kad) if kad.contact_responded => {
            (theme.good, "Kad joined ", Style::new().fg(theme.fg))
        }
        Some(_) => (theme.warn, "Kad no contact ", Style::new().fg(theme.fg)),
    };
    connection.push(Span::styled("●", Style::new().fg(kad_dot)));
    connection.push(Span::styled(kad_label, kad_style));

    // (1) info label: the flash beats the last notable core fact.
    let (info_text, info_style) = if let Some(flash) = chrome.flash_text(now) {
        (format!("✱ {flash}"), theme.flash())
    } else if !state.core_alive {
        (
            crate::words::app::CORE_STOPPED.as_str().to_string(),
            theme.flash().fg(theme.bad),
        )
    } else if let Some(notable) = &state.notable {
        (notable.as_str().to_string(), Style::new().fg(theme.fg))
    } else {
        ("—".to_string(), theme.dim_text())
    };

    let budget = usize::from(width.saturating_sub(2));
    // Rendered left→right after the info label, dropped front-first (users,
    // then rates, then the connection dots) as the line runs out.
    let tail = [users, rates, connection];
    let tail_w = tail.each_ref().map(|segment| spans_width(segment));
    let info_w = info_text.chars().count() + 1; // the leading space

    for dropped in 0..=tail.len() {
        let kept = &tail[dropped..];
        let used = info_w + tail_w[dropped..].iter().sum::<usize>() + sep_w * kept.len();
        if used <= budget {
            let mut spans = vec![Span::styled(format!(" {info_text}"), info_style)];
            for segment in kept {
                spans.push(sep());
                spans.extend(segment.iter().cloned());
            }
            return StatusBar {
                border: Line::from(spans),
                overflow: Vec::new(),
            };
        }
    }

    // The info text alone cannot share the border: it wraps above instead, and
    // the fixed segments reclaim the whole border row.
    let overflow = wrap_text(&info_text, budget)
        .into_iter()
        .map(|line| Line::from(Span::styled(line, info_style)))
        .collect();
    for dropped in 0..=tail.len() {
        let kept = &tail[dropped..];
        let used =
            1 + tail_w[dropped..].iter().sum::<usize>() + sep_w * kept.len().saturating_sub(1);
        if used <= budget {
            let mut spans = vec![Span::raw(" ")];
            for (index, segment) in kept.iter().enumerate() {
                if index > 0 {
                    spans.push(sep());
                }
                spans.extend(segment.iter().cloned());
            }
            return StatusBar {
                border: Line::from(spans),
                overflow,
            };
        }
    }
    StatusBar {
        border: Line::default(),
        overflow,
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
    use crate::state::UiState;

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

    /// ▲ is a real meter (the session up-total, differenced by the bridge),
    /// never a placeholder zero: it carries the synthesized number and
    /// The users segment is the connected server's own report — the row of
    /// the server list whose endpoint the session is connected to — and
    /// dashes while no server is connected, never another row's figures.
    #[test]
    fn users_and_files_are_the_connected_servers_report() {
        let theme = Theme::default_dark();
        let chrome = ChromeState::default();
        let users = |state: &UiState| {
            status_bar(state, &chrome, &theme, now(), 120)
                .border
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

    /// stops rendering dim once bytes actually move.
    #[test]
    fn the_up_arrow_carries_the_synthesized_upload_rate() {
        let theme = Theme::default_dark();
        let chrome = ChromeState::default();
        let up_span = |bps: f64| {
            let mut state = connected_state();
            state.rates.up_total_bps = bps;
            status_bar(&state, &chrome, &theme, now(), 120)
                .border
                .spans
                .into_iter()
                .find(|span| span.content.starts_with('▲'))
                .expect("an ▲ segment")
        };
        let idle = up_span(0.0);
        assert_eq!(idle.content, "▲ 0.0 KB/s");
        assert_eq!(idle.style.fg, Some(theme.dim), "nothing served ⇒ dim");
        let busy = up_span(45.6 * 1024.0);
        assert_eq!(busy.content, "▲ 45.6 KB/s");
        assert_eq!(busy.style.fg, Some(theme.fg), "a live meter reads normal");
    }

    #[test]
    fn golden_chrome_both_meters_live() {
        let mut state = connected_state();
        state.rates.up_total_bps = 45.6 * 1024.0;
        state.notable = Some(crate::words::Sentence::for_test("upload slot granted"));
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

    #[test]
    fn the_status_bar_never_clips_and_keeps_the_whole_info_text() {
        let theme = Theme::default_dark();
        let t0 = now();
        let mut chrome = ChromeState::default();
        chrome.update(&Action::Flash(LONG_FLASH), t0);
        let expected = format!("✱ {LONG_FLASH}");

        for width in 20u16..=140 {
            let bar = status_bar(&connected_state(), &chrome, &theme, t0, width);
            let budget = usize::from(width.saturating_sub(2));
            assert!(
                bar.border.width() <= budget,
                "border line overflows at {width}: {} > {budget}",
                bar.border.width()
            );
            // The info text survives whole — on the border, or wrapped above it.
            let carried: String = if bar.overflow.is_empty() {
                bar.border.to_string()
            } else {
                for line in &bar.overflow {
                    assert!(line.width() <= budget, "overflow line overflows at {width}");
                }
                bar.overflow.iter().map(ToString::to_string).collect()
            };
            let rejoined: String = carried.chars().filter(|c| !c.is_whitespace()).collect();
            let wanted: String = expected.chars().filter(|c| !c.is_whitespace()).collect();
            assert!(
                rejoined.contains(&wanted),
                "info text was cut at width {width}: {carried:?}"
            );
        }
    }

    /// The status dot reads the same `diagnostics.kad` the Networks panel
    /// does, so the two can never contradict each other.
    #[test]
    fn the_kad_dot_tracks_the_runtime_facts_the_bridge_polled() {
        use rmule_core::diagnostics::{DiagnosticsSnapshot, KadRuntimeDiagnostics};

        let theme = Theme::default_dark();
        let t0 = now();
        let chrome = ChromeState::default();
        let with_kad = |contact_responded: Option<bool>| UiState {
            diagnostics: DiagnosticsSnapshot {
                kad: contact_responded.map(|contact_responded| KadRuntimeDiagnostics {
                    contact_responded,
                    contacts: 0,
                    keywords_stored: 0,
                    node_id: rmule_core::KadId::from_bytes([0x11; 16]),
                    firewall: rmule_core::diagnostics::KadFirewallVerdict::Firewalled,
                    firewall_check: rmule_core::diagnostics::KadFirewallCheck::NotYetRun,
                    udp: rmule_core::diagnostics::KadUdpVerdict::Unverified,
                    traffic: rmule_core::diagnostics::KadTraffic::default(),
                }),
                ..DiagnosticsSnapshot::default()
            },
            ..connected_state()
        };
        let bar = |state: &UiState| {
            status_bar(state, &chrome, &theme, t0, 120)
                .border
                .to_string()
        };
        assert!(bar(&with_kad(None)).contains("Kad off"), "no node ⇒ off");
        assert!(bar(&with_kad(Some(false))).contains("Kad no contact"));
        assert!(bar(&with_kad(Some(true))).contains("Kad joined"));
    }

    #[test]
    fn the_lowest_priority_segment_is_the_first_to_go() {
        let theme = Theme::default_dark();
        let t0 = now();
        let state = connected_state();
        let chrome = ChromeState::default();
        // Roomy: all four segments.
        let wide = status_bar(&state, &chrome, &theme, t0, 120)
            .border
            .to_string();
        assert!(wide.contains("Users:") && wide.contains("KB/s") && wide.contains("eD2k"));
        // 80 columns: the degrade-only users counter drops first.
        let at80 = status_bar(&state, &chrome, &theme, t0, 80)
            .border
            .to_string();
        assert!(
            !at80.contains("Users:"),
            "users segment drops first: {at80:?}"
        );
        assert!(at80.contains("KB/s") && at80.contains("eD2k"), "{at80:?}");
        // Very narrow: the info label outranks every fixed segment.
        let at40 = status_bar(&state, &chrome, &theme, t0, 40)
            .border
            .to_string();
        assert_eq!(
            at40.trim(),
            "download completed",
            "info is last to go: {at40:?}"
        );

        // …unless the info cannot fit at all — then it wraps above the border
        // and the fixed segments reclaim the row.
        let mut flashed = ChromeState::default();
        flashed.update(&Action::Flash(LONG_FLASH), t0);
        let spilled = status_bar(&state, &flashed, &theme, t0, 44);
        assert!(
            !spilled.overflow.is_empty(),
            "an unfittable info text spills"
        );
        assert!(
            spilled.border.to_string().contains("eD2k"),
            "the border is reclaimed: {:?}",
            spilled.border.to_string()
        );
    }

    #[test]
    fn golden_status_bar_wraps_an_overlong_flash_above_the_border() {
        let t0 = now();
        let mut chrome = ChromeState::default();
        chrome.update(&Action::Flash(LONG_FLASH), t0);
        assert_golden("chrome_status_wrap_narrow", 44, 12, |frame| {
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
