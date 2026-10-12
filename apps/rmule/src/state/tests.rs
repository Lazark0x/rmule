//! Unit tests for the pure UI-state spine: how lifecycle edges and level snapshots fold.

use rmule_core::{CoreCommandRejectReason, DownloadEvent};

use crate::action::Action;

use super::*;
use crate::fixture::{download_event, download_id, file_hash, unnamed_metadata};

#[test]
fn snapshot_frames_replace_levels_and_stamp_injected_time() {
    let mut state = UiState::default();
    let now = Instant::now();
    let rates = TransferRates {
        down_total_bps: 1234.5,
        ..TransferRates::default()
    };
    let dirty = state.apply(
        Action::Snapshot(BridgeSnapshot {
            diagnostics: DiagnosticsSnapshot::default(),
            rates: rates.clone(),
            taken_at: now,
        }),
        now,
    );
    assert!(dirty);
    assert_eq!(state.rates, rates);
    assert_eq!(state.last_snapshot_at, Some(now));
}

#[test]
fn core_closed_flips_liveness_and_says_so() {
    let mut state = UiState::default();
    assert!(state.core_alive);
    let dirty = state.apply(Action::CoreClosed, Instant::now());
    assert!(dirty);
    assert!(!state.core_alive);
    assert_eq!(state.notable.as_deref(), Some("core stopped"));
}

#[test]
fn core_closed_appends_a_stopped_log_line() {
    let mut state = UiState::default();
    state.apply(Action::CoreClosed, Instant::now());
    assert_eq!(
        state.log.back().map(|line| line.text.as_str()),
        Some("core stopped")
    );
}

#[test]
fn a_core_event_is_logged_before_it_folds() {
    let mut state = UiState::default();
    let dirty = state.apply(
        Action::Core(download_event(DownloadEvent::DownloadQueued {
            download_id: download_id(1),
            file_hash: file_hash(7),
            metadata: unnamed_metadata(),
            file_path: crate::fixture::part_file(),
        })),
        Instant::now(),
    );
    assert!(dirty, "a logged event always repaints the log pane");
    assert_eq!(state.log.back().unwrap().text, "download queued");
    // …and the fold still ran: the row exists.
    assert_eq!(
        state.downloads[&download_id(1)].status,
        DownloadStatus::Waiting
    );
}

#[test]
fn spine_irrelevant_edges_do_not_dirty_the_frame() {
    let mut state = UiState::default();
    let peer = rmule_primitives::PeerEndpoint::V4(rmule_primitives::Ipv4Endpoint::new(
        std::net::Ipv4Addr::new(10, 0, 0, 1),
        4662,
    ));
    let dirty = fold(
        &mut state,
        download_event(DownloadEvent::PeerRetired {
            download_id: download_id(1),
            peer,
            reason: rmule_core::PeerRetirementReason::PeerDisconnected,
        }),
    );
    assert!(!dirty, "no visible spine fact changed");
}

#[test]
fn rejections_reach_the_info_feed() {
    let mut state = UiState::default();
    let dirty = fold(
        &mut state,
        CoreEvent::CommandRejected {
            reason: CoreCommandRejectReason::UnknownDownload,
        },
    );
    assert!(dirty);
    assert!(
        state
            .notable
            .as_deref()
            .is_some_and(|s| s == "refused: that download is no longer known"),
    );
}

/// A Kad rejection caused by the client-UDP bind names the port and the
/// OS's reason plainly (ADR-0057) instead of falling back to
/// a Debug dump of the nested `KadUnavailableReason` — and in the TUI's
/// words for the OS's reason, not the standard library's.
#[test]
fn a_kad_unavailable_rejection_from_the_udp_bind_names_the_port_and_the_reason() {
    let mut state = UiState::default();
    let dirty = fold(
        &mut state,
        CoreEvent::CommandRejected {
            reason: CoreCommandRejectReason::KadUnavailable(
                rmule_core::KadUnavailableReason::UdpUnbound {
                    port: 4672,
                    kind: std::io::ErrorKind::AddrInUse,
                },
            ),
        },
    );
    assert!(dirty);
    assert_eq!(
        state.notable.as_deref(),
        Some("Kad refused: UDP port 4672 could not be bound (another program holds the port)")
    );
}

/// A refused add names why the file never reached Transfers, not the
/// reason's Debug spelling.
#[test]
fn a_refused_add_names_its_cause() {
    for (reason, text) in [
        (
            CoreCommandRejectReason::DuplicateDownload,
            "download refused: this file is already in Transfers",
        ),
        (
            CoreCommandRejectReason::DownloadPathConflict,
            "download refused: a file of that name is already in the download dir",
        ),
    ] {
        let mut state = UiState::default();
        assert!(fold(&mut state, CoreEvent::CommandRejected { reason }));
        assert_eq!(state.notable.as_deref(), Some(text));
    }
}

/// The client-UDP bind failure's own start event (ADR-0057)
/// reaches the info feed with the same plain wording the log pane uses.
#[test]
fn a_client_udp_bind_failure_reaches_the_info_feed() {
    let mut state = UiState::default();
    let dirty = fold(
        &mut state,
        CoreEvent::ClientUdpBindFailed {
            port: 4672,
            kind: std::io::ErrorKind::AddrInUse,
        },
    );
    assert!(dirty);
    assert_eq!(
        state.notable.as_deref(),
        Some(
            "UDP port 4672 could not be bound (another program holds the port) — Kad, reask and NAT traversal are off until restart"
        )
    );
}

/// A **Half-Bound Pair** reaches the info feed too — the
/// case an operator is *most* likely to miss, because everything else
/// about the node reads healthy. The TUI words it — the role, the missing
/// family, the OS's reason and what that costs — not the type's `Display`.
#[test]
fn a_half_bound_client_udp_pair_reaches_the_info_feed() {
    let mut state = UiState::default();
    let dirty = fold(
        &mut state,
        CoreEvent::SocketBoundWithoutFamily {
            half_bound: rmule_core::HalfBound {
                role: rmule_core::PairRole::ClientUdp,
                missing: rmule_primitives::AddressFamily::V4,
                kind: std::io::ErrorKind::AddrInUse,
            },
        },
    );
    assert!(dirty);
    assert_eq!(
        state.notable.as_deref(),
        Some(
            "the client UDP socket came up without IPv4 (another program holds the port): Kad, NAT traversal and the IPv4 UDP advert are off until restart"
        )
    );
}

/// A listener that never bound says so in words in the status bar, not as a
/// `Debug` dump of an `io::ErrorKind`.
#[test]
fn a_held_listen_port_reaches_the_info_feed_in_words() {
    let mut state = UiState::default();
    let dirty = fold(
        &mut state,
        CoreEvent::Serve(rmule_core::ServeEvent::ServingFailed {
            reason: rmule_core::ServeStartFailure::Bind(std::io::ErrorKind::AddrInUse),
        }),
    );
    assert!(dirty);
    assert_eq!(
        state.notable.as_deref(),
        Some(
            "not serving: the eD2k listen port is in use by another program or a second rmule — serving is off until that port is free or another is chosen"
        )
    );
}
