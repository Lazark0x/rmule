//! The Transfers tab's fixtures: download rows, workers, diagnostics and the states built from them.

use std::collections::BTreeMap;
use std::time::Instant;

use rmule_core::diagnostics::{
    ClientSoftware, DiagnosticsSnapshot, DownloadDiagnostics, SessionCounters, WorkerEntry,
    WorkerPhase, WorkerSlot,
};
use rmule_core::{DownloadEvent, DownloadId, DownloadMetadata, DownloadMetadataOrigin, SourceWait};
use rmule_primitives::{ED2K_PART_SIZE, Ed2kText, PeerEndpoint};

use crate::rates::TransferRates;
use crate::state::{DownloadRow, DownloadStatus, UiState};

use super::{amule_233, download_id, file_hash, part_map, peer_endpoint};

/// One download row at `status`, with no metadata yet.
pub(crate) fn download_row(
    status: DownloadStatus,
    hash_byte: u8,
    part_count: usize,
) -> DownloadRow {
    DownloadRow {
        file_hash: Some(file_hash(hash_byte)),
        status,
        part_count: Some(part_count),
        verified_bytes: 0,
        metadata: None,
        file_path: None,
        failure: None,
        source_wait: None,
    }
}

/// A named, exact-size metadata fact (ADR-0078) for a fixture row. An
/// empty `name` models the `Unknown`-origin backfilled-junk-link case:
/// the size is still exact, only the name is unknown.
pub(crate) fn metadata(name: &str, size: u64, origin: DownloadMetadataOrigin) -> DownloadMetadata {
    DownloadMetadata {
        name: Ed2kText::from_utf8(name),
        size,
        origin,
    }
}

/// `entry` once its peer's hello has named its client.
pub(crate) fn identified(mut entry: WorkerEntry, software: ClientSoftware) -> WorkerEntry {
    entry.identify(software);
    entry
}

/// `entry` dialed from its download's **Source Seeds** (ADR-0109).
pub(crate) fn remembered(mut entry: WorkerEntry) -> WorkerEntry {
    entry.mark_remembered();
    entry
}

/// One worker slot in `phase`, optionally attached to `peer`.
pub(crate) fn worker(slot: usize, phase: WorkerPhase, peer: Option<PeerEndpoint>) -> WorkerEntry {
    let mut entry = WorkerEntry::new(WorkerSlot::from_usize(slot));
    if let Some(peer) = peer {
        entry.attach_peer(peer);
    }
    entry.transition(phase);
    entry
}

/// A diagnostics row whose part map is written positionally (ADR-0079):
/// `parts` is a `V`/`I`/`M` pattern, one glyph per part. An empty pattern
/// is the honest "row opened, scheduler has not settled yet" case.
pub(crate) fn diag(
    download_id: DownloadId,
    hash_byte: u8,
    parts: &str,
    received_bytes: u64,
    workers: Vec<WorkerEntry>,
) -> DownloadDiagnostics {
    DownloadDiagnostics {
        download_id,
        file_hash: file_hash(hash_byte),
        metadata: DownloadMetadata::unnamed(0),
        started_at: Instant::now(),
        parts: part_map(parts),
        retired_peers: 0,
        workers: workers.into_iter().map(|w| (w.slot(), w)).collect(),
        received_bytes,
        known_sources: 0,
        dials_ended: 0,
        dial_ends: Default::default(),
        reask_replies_ignored: 0,
    }
}

/// Three downloads: an active one (selected) with two workers — the idle one
/// dialed from a remembered seed — a paused one, and a completed one. Rates are metered for the active row and for
/// the one worker actually receiving — its idle neighbour has none, so the
/// sources pane dashes that cell.
///
/// Their metadata spans the fallback matrix on purpose: download_id(1)
/// carries a real name + exact size (the edge has landed), download_id(2) carries
/// none at all (edge not landed yet — the honest-fallback case), and
/// download_id(3) carries an exact size but an empty name (`Unknown` origin, a
/// backfilled junk link) — proving the two fallbacks are independent.
///
/// Their part maps span the positional matrix the same way:
/// download_id(1) is scattered mid-download (its in-flight parts are 4 and 7, and
/// part 4 is the one its receiving worker holds), download_id(2) has *no map yet*
/// (row opened, scheduler not settled — the empty-vector fallback), and
/// download_id(3) is complete.
pub(crate) fn three_downloads() -> UiState {
    let mut downloads = BTreeMap::new();
    let mut active = download_row(DownloadStatus::Downloading, 0x07, 10);
    active.metadata = Some(metadata(
        "bunny.mp4",
        92_000_000,
        DownloadMetadataOrigin::Link,
    ));
    downloads.insert(download_id(1), active);
    downloads.insert(
        download_id(2),
        download_row(DownloadStatus::Paused, 0xAB, 3),
    );
    let mut completed = download_row(DownloadStatus::Completed, 0x5C, 5);
    completed.metadata = Some(metadata("", 45_000_000, DownloadMetadataOrigin::Unknown));
    downloads.insert(download_id(3), completed);

    let mut diags = BTreeMap::new();
    diags.insert(
        download_id(1),
        diag(
            download_id(1),
            0x07,
            "VVMVIMVIMM",
            4 * ED2K_PART_SIZE + 40_000,
            vec![
                identified(
                    worker(
                        0,
                        WorkerPhase::ReceivingPart {
                            part_index: 4,
                            bytes_received: 40_000,
                        },
                        Some(peer_endpoint(1)),
                    ),
                    amule_233(),
                ),
                remembered(worker(
                    1,
                    WorkerPhase::WaitingForSlot,
                    Some(peer_endpoint(2)),
                )),
            ],
        ),
    );
    diags.insert(
        download_id(2),
        diag(download_id(2), 0xAB, "", ED2K_PART_SIZE, vec![]),
    );
    diags.insert(
        download_id(3),
        diag(download_id(3), 0x5C, "VVVVV", 5 * ED2K_PART_SIZE, vec![]),
    );

    // The sources each run knows: eight for the active one (one of them
    // receiving), none left for the paused one, one for the completed one.
    for (id, known) in [(1, 8), (2, 0), (3, 1)] {
        diags.get_mut(&download_id(id)).expect("diag").known_sources = known;
    }

    let mut download_bps = BTreeMap::new();
    download_bps.insert(download_id(1), 123.4 * 1024.0);
    let mut download_avg_bps = BTreeMap::new();
    download_avg_bps.insert(download_id(1), 123.4 * 1024.0);
    let mut source_bps = BTreeMap::new();
    source_bps.insert((download_id(1), WorkerSlot::from_usize(0)), 98.7 * 1024.0);

    UiState {
        downloads,
        diagnostics: DiagnosticsSnapshot {
            kad_state: rmule_core::diagnostics::KadState::Off,
            downloads: diags,
            uploads: BTreeMap::new(),
            shared_files: BTreeMap::new(),
            session: SessionCounters {
                down_bytes_total: 10 * ED2K_PART_SIZE + 40_000,
                up_bytes_total: 0,
                ..SessionCounters::default()
            },
            servers: Vec::new(),
            status_sweep_unheard: false,
            share_announcement: None,
            addresses: Vec::new(),
            mappings: Vec::new(),
            connected_server: None,
            connected_server_grants: rmule_core::ServerGrants::default(),
            search_more_results: None,
            taken_at: None,
            kad: None,
            kad_tasks_live: 0,
            shared_directories: Vec::new(),
            natt_own_mapping: None,
            client_udp_bind_failure: None,
            half_bound_pairs: Vec::new(),
        },
        rates: TransferRates {
            download_bps,
            download_avg_bps,
            source_bps,
            down_total_bps: 123.4 * 1024.0,
            ..TransferRates::default()
        },
        ..UiState::default()
    }
}

/// One download, named `name`, isolated from [`three_downloads`]'s other
/// rows so a "no ellipsis anywhere" check is not confused by their honest
/// short-hash stand-ins — those legitimately render one, unrelated to
/// wrap.
pub(crate) fn state_with_named_download(name: &str) -> UiState {
    let mut named = download_row(DownloadStatus::Downloading, 0x44, 10);
    named.metadata = Some(metadata(name, 92_000_000, DownloadMetadataOrigin::Link));
    let mut downloads = BTreeMap::new();
    downloads.insert(download_id(1), named);

    let mut diags = BTreeMap::new();
    diags.insert(
        download_id(1),
        diag(
            download_id(1),
            0x44,
            "VVMVIMVIMM",
            4 * ED2K_PART_SIZE,
            vec![],
        ),
    );

    UiState {
        downloads,
        diagnostics: DiagnosticsSnapshot {
            kad_state: rmule_core::diagnostics::KadState::Off,
            downloads: diags,
            uploads: BTreeMap::new(),
            shared_files: BTreeMap::new(),
            session: SessionCounters::default(),
            servers: Vec::new(),
            status_sweep_unheard: false,
            share_announcement: None,
            addresses: Vec::new(),
            mappings: Vec::new(),
            connected_server: None,
            connected_server_grants: rmule_core::ServerGrants::default(),
            search_more_results: None,
            taken_at: None,
            kad: None,
            kad_tasks_live: 0,
            shared_directories: Vec::new(),
            natt_own_mapping: None,
            client_udp_bind_failure: None,
            half_bound_pairs: Vec::new(),
        },
        ..UiState::default()
    }
}

// The downloads table splits its pane 8 ways and only gets 62% of the
// frame height (unlike the Searches results table, which is one
// borderless table over nearly the whole frame) — a wrapped row taller
// than its pane's visible rows does not partially render, ratatui's
// `Table` drops it entirely. 120×30 gives the File column and the pane
// enough room that the 200-char name's wrapped row actually fits.
/// Frame width the long-name wrap golden is taken at.
pub(crate) const WRAP_LONG_NAME_W: u16 = 120;
/// Frame height that same golden is taken at.
pub(crate) const WRAP_LONG_NAME_H: u16 = 30;

/// [`three_downloads`] with the first two runs out of sources (ADR-0051's
/// amendment): the first asked while its session was up, then lost the
/// session with Kad off; the second waits on Kad alone.
pub(crate) fn waiting_downloads() -> UiState {
    let mut state = three_downloads();
    if let Some(diag) = state.diagnostics.downloads.get_mut(&download_id(1)) {
        diag.workers.clear();
    }
    for (id, reason) in [
        (1, SourceWait::Asking),
        (1, SourceWait::NoSession),
        (2, SourceWait::KadAlone),
    ] {
        crate::state::fold(
            &mut state,
            super::download_event(DownloadEvent::WaitingForSources {
                download_id: download_id(id),
                reason,
            }),
        );
    }
    state
}
