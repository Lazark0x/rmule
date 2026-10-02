//! The Kad panel (spec §3.4): the runtime facts core reports — contact
//! responded, live contact count, node id, the ADR-0058 firewall verdicts and
//! why they read as they do, and the size of the keyword index this node
//! stores for others.
//!
//! Without a node the rows dash rather than claim zeros. §3.4's traffic is
//! two rows, Received and Sent: the rate the bridge meters from core's wire
//! byte totals, then the session total itself.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};

use rmule_core::diagnostics::{
    KadFirewallCheck, KadFirewallVerdict, KadRuntimeDiagnostics, KadUdpVerdict,
};

use crate::rates::format_rate;

use crate::state::UiState;
use crate::theme::Theme;
use crate::views::human_size;
use crate::wrap::labeled_lines;

/// The TCP firewall row: the verdict, then why — whether a check has run,
/// and how many of the two connect-backs openness needs the last one drew.
/// A fresh node's `firewalled` is a default, not a finding, and reads so.
pub(super) fn firewall_text(kad: &KadRuntimeDiagnostics) -> String {
    let needed = KadFirewallCheck::ACKS_FOR_OPEN;
    let why = match kad.firewall_check {
        KadFirewallCheck::NotYetRun => "not checked yet".to_owned(),
        KadFirewallCheck::Running { acks } | KadFirewallCheck::Ended { acks } => {
            format!("{acks}/{needed} dial-backs")
        }
    };
    let verdict = match kad.firewall {
        KadFirewallVerdict::Open => "open",
        KadFirewallVerdict::Checking => "checking",
        KadFirewallVerdict::Firewalled => "firewalled",
    };
    format!("{verdict} · {why}")
}

/// The UDP self-check's verdict: open on the port a helper reached, or what
/// the helpers concluded.
pub(super) fn udp_text(verdict: KadUdpVerdict) -> String {
    match verdict {
        KadUdpVerdict::Open { port } => format!("open · port {port}"),
        KadUdpVerdict::Firewalled => "firewalled · helpers failed".to_owned(),
        KadUdpVerdict::Unverified => "unverified · no helper yet".to_owned(),
    }
}

/// One direction of Kad traffic: its metered rate (a dash until the bridge
/// has metered an echo), then its wire bytes this session.
pub(super) fn traffic_text(bps: Option<f64>, bytes: u64) -> String {
    let rate = bps.map_or_else(|| "—".to_owned(), format_rate);
    format!("{rate} · {}", human_size(bytes))
}

/// The Kad panel — the live runtime facts, and a reasoned dash for the rest.
///
/// `DiagnosticsSnapshot::kad` is core's Kad vocabulary (ADR-0067): `None` until
/// `EnableKad` started a node, then the join observable (aMule's `HasHadContact` — the *Joined* row and the status
/// dot), the live routing-table size, the node's own Kad ID, the ADR-0058
/// verdicts with the TCP check's connect-back count, and the keyword index's
/// size.
pub(super) fn draw_kad(frame: &mut Frame, area: Rect, state: &UiState, theme: &Theme) {
    let kad_state = state.diagnostics.kad_state;
    // `K` is hinted only with a core to send it to (No dead UI).
    let hint = if state.session.is_some() {
        crate::words::kad::switch_hint(kad_state)
    } else {
        ""
    };
    let block = Block::bordered().border_style(theme.chrome());
    let block = crate::views::title::titled(
        block,
        area.width,
        (" Kad ", Style::new().fg(theme.fg)),
        (hint, theme.dim_text()),
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height == 0 || inner.width == 0 {
        return;
    }
    let width = usize::from(inner.width);
    let kad = state.diagnostics.kad;

    // Dot colour is aMule's own arrow parity, applied to the one fact we have:
    // red = no node, yellow = running but nobody has answered, green = joined.
    // The grade is never colour-only — the *Joined* row spells it out.
    let dot = match kad {
        None => theme.bad,
        Some(k) if k.contact_responded => theme.good,
        Some(_) => theme.warn,
    };
    let live = Style::new().fg(theme.fg);
    let contact = kad.is_some_and(|k| k.contact_responded);
    let word = crate::words::kad::state_word(kad_state, contact);
    let mut lines = vec![Line::from(vec![
        Span::styled("● ", Style::new().fg(dot)),
        match kad_state {
            rmule_core::diagnostics::KadState::Off => Span::styled(word, theme.dim_text()),
            _ => Span::styled(word, live),
        },
    ])];

    let joined = match kad {
        None => "— (node not started)",
        Some(k) if k.contact_responded => "yes",
        // Only a received datagram flips the flag, so "not yet" is the whole
        // claim: nobody has answered *us* — never that the node is failing.
        Some(_) => "not yet",
    };
    let never = || "— (never run)".to_owned();
    let firewall = kad.as_ref().map_or_else(never, firewall_text);
    let udp = kad.map_or_else(never, |k| udp_text(k.udp));
    let contacts = kad.map_or_else(|| "—".to_owned(), |k| k.contacts.to_string());
    let keywords = kad.map_or_else(|| "—".to_owned(), |k| k.keywords_stored.to_string());
    let node_id = kad.map_or_else(|| "—".to_owned(), |k| short_kad_id(k.node_id));
    let rates = state.rates.kad;
    let received = kad.map_or_else(
        || "—".to_owned(),
        |k| {
            let t = k.traffic;
            traffic_text(rates.map(|r| r.in_bps), t.bytes_in)
        },
    );
    let sent = kad.map_or_else(
        || "—".to_owned(),
        |k| {
            let t = k.traffic;
            traffic_text(rates.map(|r| r.out_bps), t.bytes_out)
        },
    );
    let fact_style = if kad.is_some() {
        live
    } else {
        theme.dim_text()
    };
    lines.extend(kad_kv(theme, "Joined", joined, fact_style, width));
    lines.extend(kad_kv(theme, "Contacts", &contacts, fact_style, width));
    lines.extend(kad_kv(theme, "Firewall", &firewall, fact_style, width));
    lines.extend(kad_kv(theme, "UDP", &udp, fact_style, width));
    lines.extend(kad_kv(theme, "Keywords", &keywords, fact_style, width));
    lines.extend(kad_kv(theme, "Node id", &node_id, fact_style, width));
    lines.extend(kad_kv(theme, "Received", &received, fact_style, width));
    lines.extend(kad_kv(theme, "Sent", &sent, fact_style, width));
    frame.render_widget(Paragraph::new(lines), inner);
}

/// The node's Kad ID in the short hex form every hash and id takes.
fn short_kad_id(id: rmule_core::KadId) -> String {
    crate::words::units::short_hex(id.as_bytes())
}

/// One Kad key-value row, wrapping under its value column.
fn kad_kv(
    theme: &Theme,
    label: &str,
    value: &str,
    value_style: Style,
    width: usize,
) -> Vec<Line<'static>> {
    labeled_lines(
        Span::styled(format!("{label:<9} "), theme.dim_text()),
        value,
        value_style,
        width.saturating_sub(10).max(1),
    )
}
#[cfg(test)]
mod tests {

    use crate::golden::assert_golden;

    use crate::views::networks::*;

    use crate::fixture::*;
    #[test]
    fn golden_networks_kad_live() {
        let state = with_kad(true);
        let mut view = NetworksView::new();
        let now = Instant::now();
        assert_golden("networks_kad_live", 78, 21, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now);
        });
    }

    /// The three honest grades of the one Kad fact core reports: no node,
    /// running-but-unanswered, joined. The dot colour carries aMule's arrow
    /// parity and the *Joined* row carries the same grade as text, so nothing
    /// is communicated by colour alone.
    #[test]
    fn the_kad_panel_grades_no_node_awaiting_contact_and_joined() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let theme = Theme::default_dark();
        for (state, dot_color, status, joined) in [
            (
                UiState::default(),
                theme.bad,
                "Kad: off",
                "Joined    — (node not started)",
            ),
            (
                with_kad(false),
                theme.warn,
                "Kad: joining",
                "Joined    not yet",
            ),
            (with_kad(true), theme.good, "Kad: running", "Joined    yes"),
        ] {
            let mut view = NetworksView::new();
            let mut terminal = Terminal::new(TestBackend::new(78, 21)).expect("terminal");
            terminal
                .draw(|frame| {
                    view.draw(
                        frame,
                        Rect::new(0, 0, 78, 21),
                        &state,
                        &theme,
                        Instant::now(),
                    );
                })
                .expect("draw");
            let buffer = terminal.backend().buffer();
            // The Kad panel sits at the bottom right; its first inner column
            // is one past the log pane's right edge.
            let x0 = view.log_area.right() + 1;
            let y0 = view.log_area.y + 1;
            let row = |y: u16| -> String {
                (x0..buffer.area.right())
                    .map(|x| buffer.cell((x, y)).map_or(" ", |cell| cell.symbol()))
                    .collect()
            };
            let dot = buffer.cell((x0, y0)).expect("kad dot");
            assert_eq!(dot.symbol(), "●");
            assert_eq!(dot.style().fg, Some(dot_color), "dot colour for '{joined}'");
            assert!(
                row(y0).contains(status),
                "status row '{}' lacks '{status}'",
                row(y0)
            );
            assert!(
                row(y0 + 1).contains(joined),
                "fact row '{}' lacks '{joined}'",
                row(y0 + 1)
            );
        }
    }

    /// The Kad panel facts render live from the snapshot — contact count,
    /// firewall verdict, short node id — and keep their honest dash while no
    /// node runs. The keyword row keeps its dash either way (no core surface).
    /// Every row is a fact core reported — the firewall verdict with why,
    /// the UDP verdict, the keyword index — and without a node every row
    /// dashes rather than claiming a zero.
    #[test]
    fn the_kad_panel_renders_the_runtime_facts_and_dashes_without_a_node() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        use rmule_core::diagnostics::{KadFirewallCheck, KadFirewallVerdict, KadUdpVerdict};

        let theme = Theme::default_dark();
        let checked = |firewall, acks, udp| {
            let mut state = with_kad(true);
            let kad = state.diagnostics.kad.as_mut().expect("node");
            kad.firewall = firewall;
            kad.firewall_check = KadFirewallCheck::Ended { acks };
            kad.udp = udp;
            kad.keywords_stored = 12;
            state
        };
        for (state, rows) in [
            (
                UiState::default(),
                [
                    "Contacts  —",
                    "Firewall  — (never run)",
                    "UDP       — (never run)",
                    "Keywords  —",
                    "Node id   —",
                ],
            ),
            (
                with_kad(true),
                [
                    "Contacts  54",
                    "Firewall  firewalled · not checked yet",
                    "UDP       unverified · no helper yet",
                    "Keywords  0",
                    "Node id   2E2E2E2E2E…",
                ],
            ),
            (
                checked(KadFirewallVerdict::Firewalled, 1, KadUdpVerdict::Firewalled),
                [
                    "Contacts  54",
                    "Firewall  firewalled · 1/2 dial-backs",
                    "UDP       firewalled · helpers failed",
                    "Keywords  12",
                    "Node id   2E2E2E2E2E…",
                ],
            ),
            (
                checked(
                    KadFirewallVerdict::Open,
                    2,
                    KadUdpVerdict::Open { port: 4672 },
                ),
                [
                    "Contacts  54",
                    "Firewall  open · 2/2 dial-backs",
                    "UDP       open · port 4672",
                    "Keywords  12",
                    "Node id   2E2E2E2E2E…",
                ],
            ),
        ] {
            let mut view = NetworksView::new();
            let mut terminal = Terminal::new(TestBackend::new(78, 21)).expect("terminal");
            terminal
                .draw(|frame| {
                    view.draw(
                        frame,
                        Rect::new(0, 0, 78, 21),
                        &state,
                        &theme,
                        Instant::now(),
                    );
                })
                .expect("draw");
            let buffer = terminal.backend().buffer();
            let x0 = view.log_area.right() + 1;
            let y0 = view.log_area.y + 1;
            let row = |y: u16| -> String {
                (x0..buffer.area.right())
                    .map(|x| buffer.cell((x, y)).map_or(" ", |cell| cell.symbol()))
                    .collect()
            };
            for (offset, expect) in (2u16..).zip(rows) {
                assert!(
                    row(y0 + offset).contains(expect),
                    "row '{}' lacks '{expect}'",
                    row(y0 + offset)
                );
            }
        }
    }
}
