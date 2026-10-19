//! The Statistics tab's fixture: one busy session that every counter row reads.

use std::collections::BTreeMap;
use std::time::Instant;

use rmule_core::diagnostics::{
    DiagnosticsSnapshot, KadRuntimeDiagnostics, SessionCounters, UploadDiagnostics,
};
use rmule_core::{CoreEvent, DownloadEvent, DownloadId, DownloadMetadata, ServeEvent};
use rmule_primitives::ClientId;

use crate::action::Action;
use crate::state::UiState;

use super::{amule_233, emule_qt, file_hash, peer_endpoint, rate_ticks};

/// A busy session: two downloads (one on the wire), a served peer plus a
/// queued one, two shares, a HighID login, a joined Kad node — then 90
/// data ticks of the fixture ramp so the graphs carry real shape.
pub(crate) fn busy(base: Instant) -> UiState {
    let mut state = UiState::default();
    for (n, on_wire) in [(1u64, true), (2, false)] {
        state.apply(
            Action::Core(CoreEvent::Download(DownloadEvent::DownloadQueued {
                download_id: DownloadId::from_u64(n),
                file_hash: file_hash(n as u8),
                metadata: DownloadMetadata::unnamed(1024),
                file_path: crate::fixture::part_file(),
            })),
            base,
        );
        if on_wire {
            state.apply(
                Action::Core(CoreEvent::Download(DownloadEvent::PeerSlotGranted {
                    download_id: DownloadId::from_u64(n),
                    peer: peer_endpoint(1),
                })),
                base,
            );
        }
    }
    // The session edge, not the per-download echo: `ServerConnection` is
    // the single writer of `UiState::ed2k`.
    state.apply(
        Action::Core(CoreEvent::ServerConnection(
            rmule_core::ServerConnectionEvent::Connected {
                server: rmule_primitives::ServerEndpoint::new("10.0.0.1", 4661).expect("endpoint"),
                client_id: ClientId::from_u32(ClientId::LOW_ID_THRESHOLD),
            },
        )),
        base,
    );
    for byte in [7u8, 8] {
        state.apply(
            Action::Core(CoreEvent::Serve(ServeEvent::FileShared {
                file_hash: file_hash(byte),
            })),
            base,
        );
    }
    state.apply(
        Action::Core(CoreEvent::Serve(ServeEvent::UploadSlotGranted {
            peer: peer_endpoint(5),
            file_hash: file_hash(7),
            software: Some(amule_233()),
            road: rmule_core::GrantRoad::Linked,
        })),
        base,
    );
    state.apply(
        Action::Core(CoreEvent::Serve(ServeEvent::PeerQueued {
            peer: peer_endpoint(6),
            rank: 2,
            file_hash: file_hash(1),
            software: Some(emule_qt()),
        })),
        base,
    );

    let mut uploads = BTreeMap::new();
    uploads.insert(
        peer_endpoint(5),
        UploadDiagnostics {
            peer: peer_endpoint(5),
            file_hash: file_hash(7),
            started_at: base,
            bytes_sent: 4096,
        },
    );
    let levels = DiagnosticsSnapshot {
        uploads,
        kad: Some(KadRuntimeDiagnostics {
            contact_responded: true,
            contacts: 0,
            keywords_stored: 0,
            node_id: rmule_core::KadId::from_bytes([0x11; 16]),
            firewall: rmule_core::diagnostics::KadFirewallVerdict::Firewalled,
            firewall_check: rmule_core::diagnostics::KadFirewallCheck::NotYetRun,
            udp: rmule_core::diagnostics::KadUdpVerdict::Unverified,
            traffic: rmule_core::diagnostics::KadTraffic {
                datagrams_in: 840,
                bytes_in: 96 * 1024,
                datagrams_out: 612,
                bytes_out: 64 * 1024,
            },
        }),
        session: SessionCounters::default(),
        ..DiagnosticsSnapshot::default()
    };
    rate_ticks(&mut state, base, 90, &levels);
    // `rate_ticks` writes the byte totals alone; the refused-hello count
    // rides the last level as core would carry it.
    state.diagnostics.session.peer_hellos_refused_total = 3;
    // `rate_ticks` hand-feeds byte rates only; the Kad datagram rate
    // is set directly, as `with_kad`'s fixture sets the Kad byte rate.
    state.rates.kad = Some(crate::rates::KadRates {
        in_bps: 1.5 * 1024.0,
        out_bps: 1024.0,
        dgrams_in_bps: 5.2,
        dgrams_out_bps: 3.1,
    });
    state
}
