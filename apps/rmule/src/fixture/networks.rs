//! The Networks tab's fixtures: the server table and Kad panel states, and typing into a field.

use std::time::{Duration, Instant};

use ratatui::crossterm::event::KeyCode;
use rmule_core::diagnostics::{DiagnosticsSnapshot, KadRuntimeDiagnostics, ServerDiagnostics};
use rmule_core::{CoreEvent, DownloadEvent, ManagedServer, ServerPriority};
use rmule_primitives::{ClientId, Ed2kText, ServerEndpoint};

use crate::action::Action;
use crate::state::{Ed2kConnection, UiState};
use crate::views::networks::NetworksView;

use super::{download_id, press, session};

/// Type `text` into the focused field of `view`, one key press at a time.
pub(crate) fn typed(view: &mut NetworksView, state: &UiState, text: &str) {
    for c in text.chars() {
        view.handle_key(press(KeyCode::Char(c)), state);
    }
}

/// A server endpoint from a host and port, panicking on a malformed pair.
pub(crate) fn endpoint(host: &str, port: u16) -> ServerEndpoint {
    ServerEndpoint::new(host, port).expect("endpoint")
}

/// A listed row with the durable fields set and no dynamics measured.
pub(crate) fn listed(host: &str, port: u16, name: &str) -> ServerDiagnostics {
    let mut server = ManagedServer::listed(endpoint(host, port));
    server.name = Ed2kText::from_utf8(name);
    ServerDiagnostics::listed(server)
}

/// The mixed server table every table golden and most Networks behaviour
/// tests read: a connected row with full dynamics, a static high-priority
/// row, a dead row whose pings kept failing past the limit, and an unnamed
/// row that has said nothing.
pub(crate) fn listed_servers() -> UiState {
    let mut first = listed("10.0.0.1", 4661, "eDonkey Prime");
    first.server.description = Ed2kText::from_utf8("Main hub, no fakes");
    first.ping = Some(Duration::from_millis(42));
    first.users = Some(1_204_331);
    first.files = Some(24_507_112);
    first.age = Some(Duration::from_secs(12));
    first.server.figures = Some(rmule_core::ServerFigures {
        udp_flags: Some(rmule_primitives::ServerUdpFlags::from_bits(0x0000_073B)),
        ..rmule_core::ServerFigures::answered(1_700_000_000)
    });
    first.server.grants = Some(rmule_core::ServerGrantsReport {
        tcp_flags: rmule_primitives::ServerTcpFlags::from_bits(0x0000_0559),
        reported_at: 1_700_000_000,
    });
    first.grants_age = Some(Duration::from_secs(14 * 60));
    first.health = rmule_core::ServerHealth::Answered;

    let mut second = listed("10.0.0.2", 4242, "Static Pin");
    second.server.description = Ed2kText::from_utf8("Operator pinned");
    second.server.is_static = true;
    second.server.priority = ServerPriority::High;
    second.ping = Some(Duration::from_millis(1_200));
    second.users = Some(9_812);
    second.files = Some(431_004);
    second.age = Some(Duration::from_secs(2 * 3_600));
    second.health = rmule_core::ServerHealth::Answered;

    let mut third = listed("172.16.9.9", 5000, "Flaky Mirror");
    third.server.fail_count = 7;
    third.server.priority = ServerPriority::Low;
    third.health = rmule_core::ServerHealth::Dead;
    third.dead_since = Some(rmule_core::DeadSince::For(Duration::from_secs(45 * 60)));

    let fourth = listed("192.168.4.4", 4661, "");

    UiState {
        ed2k: Ed2kConnection::Connected {
            client_id: ClientId::from_u32(ClientId::LOW_ID_THRESHOLD),
        },
        diagnostics: DiagnosticsSnapshot {
            servers: vec![first, second, third, fourth],
            connected_server: Some(endpoint("10.0.0.1", 4661)),
            ..DiagnosticsSnapshot::default()
        },
        session: Some(session()),
        ..UiState::default()
    }
}

/// [`listed_servers`] whose Kad node is running, as the bridge's
/// `DumpDiagnostics` poll reports it.
pub(crate) fn with_kad(contact_responded: bool) -> UiState {
    let mut state = listed_servers();
    state.diagnostics.kad_state = rmule_core::diagnostics::KadState::Running;
    state.diagnostics.kad = Some(KadRuntimeDiagnostics {
        contact_responded,
        contacts: 54,
        keywords_stored: 0,
        node_id: rmule_core::KadId::from_bytes([0x2E; 16]),
        firewall: rmule_core::diagnostics::KadFirewallVerdict::Firewalled,
        firewall_check: rmule_core::diagnostics::KadFirewallCheck::NotYetRun,
        udp: rmule_core::diagnostics::KadUdpVerdict::Unverified,
        traffic: rmule_core::diagnostics::KadTraffic {
            datagrams_in: 840,
            bytes_in: 96 * 1024,
            datagrams_out: 612,
            bytes_out: 64 * 1024,
        },
    });
    state.rates.kad = Some(crate::rates::KadRates {
        in_bps: 1.5 * 1024.0,
        out_bps: 1024.0,
        dgrams_in_bps: 5.2,
        dgrams_out_bps: 3.1,
    });
    state
}

/// A long name and a long description at the 80-column design floor have
/// nowhere to go but down. Nothing is clipped and no ellipsis appears
/// The identity columns are at their floors, so the wrap is the
/// tightest the table ever renders without the shrink path.
pub(crate) fn long_row() -> UiState {
    let mut row = listed(
        "198.51.100.200",
        4661,
        "Der Grosse Deutsche Donkey Server Nummer Zwei",
    );
    row.server.description =
        Ed2kText::from_utf8("No fakes, no adverts, moderated around the clock");
    row.users = Some(120_000);
    UiState {
        diagnostics: DiagnosticsSnapshot {
            servers: vec![row, listed("10.0.0.5", 4661, "Second")],
            ..DiagnosticsSnapshot::default()
        },
        ..UiState::default()
    }
}

/// The core's longest log line — a storage-integrity failure reads over 100
/// characters, wider than the log pane at any sane frame width. Returns
/// the base instant so the caller's `now` is exact, not merely close.
pub(crate) fn long_failure() -> (UiState, Instant) {
    let base = Instant::now();
    let mut state = UiState::default();
    state.apply(
        Action::Core(CoreEvent::Download(DownloadEvent::PartVerified {
            download_id: download_id(1),
            part_index: 3,
        })),
        base,
    );
    state.apply(
        Action::Core(CoreEvent::Download(DownloadEvent::DownloadFailed {
            download_id: download_id(1),
            reason: rmule_core::DownloadFailure::StorageIntegrityFailed(
                rmule_core::StorageIntegrityFault::PartFileMissing,
            ),
        })),
        base,
    );
    (state, base)
}
