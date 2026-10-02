//! What a front-end reads while a download runs (ADR-0028): the per-worker
//! phase trail a [`WorkerEntry`] keeps, and the snapshot a
//! [`DiagnosticsState`] hands out — a clone that later mutation cannot reach
//! back into, with the session byte totals that outlive a transfer row.

use std::net::Ipv4Addr;

use rmule_core::diagnostics::{DiagnosticsState, WorkerEntry, WorkerPhase, WorkerSlot};
use rmule_core::{DownloadId, DownloadMetadata};
use rmule_primitives::{FileHash, Ipv4Endpoint, PeerEndpoint};

#[test]
fn worker_entry_transition_updates_phase_and_bumps_count() {
    let mut entry = WorkerEntry::new(WorkerSlot::from_usize(0));

    entry.attach_peer(PeerEndpoint::V4(Ipv4Endpoint::new(
        Ipv4Addr::new(1, 2, 3, 4),
        4662,
    )));
    entry.transition(WorkerPhase::Connecting);
    entry.transition(WorkerPhase::HandshakingPeer);

    assert_eq!(entry.phase(), &WorkerPhase::HandshakingPeer);
    assert_eq!(entry.transition_count(), 2);
    assert_eq!(entry.peer_endpoint().unwrap().port(), 4662);
}

#[test]
fn diagnostics_state_snapshot_is_an_independent_clone() {
    let state = DiagnosticsState::new();
    let id = DownloadId::from_u64(7);
    state.ensure_download(
        id,
        FileHash::from_bytes([0u8; 16]),
        DownloadMetadata::unnamed(0),
    );
    state.update_worker(id, WorkerSlot::from_usize(0), |entry| {
        entry.transition(WorkerPhase::Connecting);
    });

    let snap = state.snapshot();

    state.update_worker(id, WorkerSlot::from_usize(0), |entry| {
        entry.transition(WorkerPhase::HandshakingPeer);
    });

    let workers = &snap.downloads[&id].workers;
    assert_eq!(
        workers[&WorkerSlot::from_usize(0)].phase(),
        &WorkerPhase::Connecting,
        "snapshot must not observe writes that happened after it was taken",
    );
    assert!(snap.taken_at.is_some());
}

/// A shared file's serve counters are keyed by the file, not the peer: bytes
/// of one file served to two peers sum into its row, another file keeps its
/// own, and the rows outlive every upload that fed them — what the Shared
/// Files table reads after the peers have gone.
#[test]
fn a_shared_files_counters_sum_over_its_peers_and_outlive_them() {
    let state = DiagnosticsState::new();
    let film = FileHash::from_bytes([0xF1; 16]);
    let song = FileHash::from_bytes([0x50; 16]);
    let a = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 1), 4662));
    let b = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 2), 4662));

    state.count_upload_request(film);
    state.count_upload_request(film);
    state.count_upload_request(song);
    state.open_upload(a, film);
    state.open_upload(b, film);
    state.add_sent_bytes(a, film, 300);
    state.add_sent_bytes(b, film, 200);
    state.add_sent_bytes(a, song, 50);
    state.close_upload(a);
    state.close_upload(b);

    let files = state.snapshot().shared_files;
    assert_eq!(files[&film].requests, 2);
    assert_eq!(files[&film].transferred, 500);
    assert_eq!(files[&song].requests, 1);
    assert_eq!(files[&song].transferred, 50);
}

/// The monotonic guarantee of the **Transfer Byte Counters** (ADR-0077): the
/// per-transfer rows are transient — they retire with the transfer — but the
/// session totals only ever grow, so a consumer polling slower than transfers
/// finish still sees every byte that crossed the wire.
#[test]
fn session_byte_totals_survive_transfer_row_teardown() {
    let state = DiagnosticsState::new();
    let id = DownloadId::from_u64(11);
    let file = FileHash::from_bytes([0xAB; 16]);
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 7), 4662));

    state.ensure_download(id, file, DownloadMetadata::unnamed(0));
    state.add_received_bytes(id, 1_000);
    state.open_upload(peer, file);
    state.add_sent_bytes(peer, file, 400);
    state.add_sent_bytes(peer, file, 600);

    let live = state.snapshot();
    assert_eq!(live.downloads[&id].received_bytes, 1_000);
    assert_eq!(live.uploads[&peer].bytes_sent, 1_000);
    assert_eq!(live.session.down_bytes_total, 1_000);
    assert_eq!(live.session.up_bytes_total, 1_000);

    state.remove_download(id);
    state.close_upload(peer);

    let after = state.snapshot();
    assert!(after.downloads.is_empty(), "the download row retired");
    assert!(after.uploads.is_empty(), "the upload row retired");
    assert_eq!(after.session.down_bytes_total, 1_000);
    assert_eq!(after.session.up_bytes_total, 1_000);

    // A straggler block for a torn-down download counts for the session
    // instead of vanishing with its row.
    state.add_received_bytes(id, 7);
    assert_eq!(state.snapshot().session.down_bytes_total, 1_007);
}
