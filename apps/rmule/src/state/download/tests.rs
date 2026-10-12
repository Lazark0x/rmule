//! Unit tests for the download rows and the fold arm that maintains them.

use rmule_core::{DownloadEvent, DownloadLifecycle};

use super::*;
use crate::fixture::{download_event, download_id, file_hash, search_result, unnamed_metadata};
use crate::state::fold;

#[test]
fn a_queued_download_appears_waiting_with_its_hash() {
    let mut state = UiState::default();
    let dirty = fold(
        &mut state,
        download_event(DownloadEvent::DownloadQueued {
            download_id: download_id(1),
            file_hash: file_hash(7),
            metadata: unnamed_metadata(),
        }),
    );
    assert!(dirty);
    let row = &state.downloads[&download_id(1)];
    assert_eq!(row.status, DownloadStatus::Waiting);
    assert_eq!(row.file_hash, Some(file_hash(7)));
    assert_eq!(state.notable.as_deref(), Some("download queued"));
}

#[test]
fn a_queued_downloads_metadata_lands_on_its_row() {
    let mut state = UiState::default();
    let metadata = rmule_core::DownloadMetadata {
        name: rmule_primitives::Ed2kText::from_utf8("bunny.mp4"),
        size: 123_456,
        origin: rmule_core::DownloadMetadataOrigin::Link,
    };
    fold(
        &mut state,
        download_event(DownloadEvent::DownloadQueued {
            download_id: download_id(1),
            file_hash: file_hash(7),
            metadata: metadata.clone(),
        }),
    );
    assert_eq!(
        state.downloads[&download_id(1)].metadata.as_ref(),
        Some(&metadata)
    );
}

#[test]
fn a_recovered_downloads_hash_and_metadata_ride_the_edge_not_a_levels_join() {
    // `DownloadRecovered` carries both facts directly
    // (ADR-0078) — a recovered-but-not-yet-resumed download has no live
    // task, so no diagnostics row exists to join against; the edge is the
    // only path.
    let mut state = UiState::default();
    let metadata = rmule_core::DownloadMetadata {
        name: rmule_primitives::Ed2kText::from_utf8("recovered.iso"),
        size: 555_000,
        origin: rmule_core::DownloadMetadataOrigin::RecoveredLink,
    };
    fold(
        &mut state,
        download_event(DownloadEvent::DownloadRecovered {
            download_id: download_id(1),
            state: DownloadLifecycle::Active,
            failure: None,
            file_hash: file_hash(7),
            metadata: metadata.clone(),
        }),
    );
    let row = &state.downloads[&download_id(1)];
    assert_eq!(row.file_hash, Some(file_hash(7)));
    assert_eq!(row.metadata.as_ref(), Some(&metadata));
}

/// Search→transfer continuity: the name a search result showed
/// is the same name `DownloadQueued`'s edge carries once the download
/// starts, because both ride the same `Ed2kFileLink` — the fold does not
/// re-derive or retype it.
#[test]
fn a_queued_downloads_name_matches_the_search_result_it_came_from() {
    let result = search_result("bunny.mp4", 12);
    let file = result.to_file_link();
    let metadata = rmule_core::DownloadMetadata::from_link(&file);

    let mut state = UiState::default();
    fold(
        &mut state,
        download_event(DownloadEvent::DownloadQueued {
            download_id: download_id(1),
            file_hash: file_hash(7),
            metadata,
        }),
    );

    let row_metadata = state.downloads[&download_id(1)]
        .metadata
        .as_ref()
        .expect("metadata folded");
    assert_eq!(
        row_metadata.name.to_display_string(),
        result.primary_name().to_display_string(),
    );
    assert_eq!(row_metadata.size, result.file_size());
}

#[test]
fn slot_grant_marks_the_row_downloading() {
    let mut state = UiState::default();
    fold(
        &mut state,
        download_event(DownloadEvent::DownloadQueued {
            download_id: download_id(1),
            file_hash: file_hash(7),
            metadata: unnamed_metadata(),
        }),
    );
    let peer = rmule_primitives::PeerEndpoint::V4(rmule_primitives::Ipv4Endpoint::new(
        std::net::Ipv4Addr::new(10, 0, 0, 1),
        4662,
    ));
    let dirty = fold(
        &mut state,
        download_event(DownloadEvent::PeerSlotGranted {
            download_id: download_id(1),
            peer,
        }),
    );
    assert!(dirty);
    assert_eq!(
        state.downloads[&download_id(1)].status,
        DownloadStatus::Downloading
    );
}

/// A run with no connection reads No connection, not Failed, and the
/// lookup that answers once a connection exists moves it back to Waiting.
#[test]
fn a_download_waiting_for_a_connection_reads_so_until_a_lookup_answers() {
    let mut state = UiState::default();
    fold(
        &mut state,
        download_event(DownloadEvent::DownloadQueued {
            download_id: download_id(1),
            file_hash: file_hash(7),
            metadata: unnamed_metadata(),
        }),
    );
    fold(
        &mut state,
        download_event(DownloadEvent::WaitingForConnection {
            download_id: download_id(1),
        }),
    );
    assert_eq!(
        state.downloads[&download_id(1)].status,
        DownloadStatus::NoConnection
    );
    fold(
        &mut state,
        download_event(DownloadEvent::SourcesFound {
            download_id: download_id(1),
            total: 1,
            usable_high_id: 1,
        }),
    );
    assert_eq!(
        state.downloads[&download_id(1)].status,
        DownloadStatus::Waiting
    );
}

#[test]
fn pause_and_resume_round_trip_through_the_status_column() {
    let mut state = UiState::default();
    fold(
        &mut state,
        download_event(DownloadEvent::DownloadQueued {
            download_id: download_id(1),
            file_hash: file_hash(7),
            metadata: unnamed_metadata(),
        }),
    );
    fold(
        &mut state,
        download_event(DownloadEvent::DownloadPaused {
            download_id: download_id(1),
        }),
    );
    assert_eq!(
        state.downloads[&download_id(1)].status,
        DownloadStatus::Paused
    );
    fold(
        &mut state,
        download_event(DownloadEvent::DownloadResumed {
            download_id: download_id(1),
        }),
    );
    assert_eq!(
        state.downloads[&download_id(1)].status,
        DownloadStatus::Waiting
    );
}

#[test]
fn completion_keeps_the_row_and_cancellation_removes_it() {
    let mut state = UiState::default();
    for n in [1, 2] {
        fold(
            &mut state,
            download_event(DownloadEvent::DownloadQueued {
                download_id: download_id(n),
                file_hash: file_hash(7),
                metadata: unnamed_metadata(),
            }),
        );
    }
    fold(
        &mut state,
        download_event(DownloadEvent::DownloadCompleted {
            download_id: download_id(1),
            final_path: "/downloads/file.bin".into(),
        }),
    );
    fold(
        &mut state,
        download_event(DownloadEvent::DownloadCancelled {
            download_id: download_id(2),
        }),
    );
    assert_eq!(
        state.downloads[&download_id(1)].status,
        DownloadStatus::Completed
    );
    assert!(!state.downloads.contains_key(&download_id(2)));
    assert_eq!(state.notable.as_deref(), Some("download cancelled"));
}

#[test]
fn recovered_rows_map_the_persisted_lifecycle() {
    let mut state = UiState::default();
    let cases = [
        (1, DownloadLifecycle::Active, DownloadStatus::Waiting),
        (2, DownloadLifecycle::Paused, DownloadStatus::Paused),
        (3, DownloadLifecycle::Queued, DownloadStatus::Waiting),
    ];
    for (n, lifecycle, expected) in cases {
        fold(
            &mut state,
            download_event(DownloadEvent::DownloadRecovered {
                download_id: download_id(n),
                state: lifecycle,
                failure: None,
                file_hash: file_hash(7),
                metadata: unnamed_metadata(),
            }),
        );
        assert_eq!(state.downloads[&download_id(n)].status, expected);
    }
    // A cancelled record recovers to no row at all.
    let dirty = fold(
        &mut state,
        download_event(DownloadEvent::DownloadRecovered {
            download_id: download_id(9),
            state: DownloadLifecycle::Cancelled,
            failure: None,
            file_hash: file_hash(7),
            metadata: unnamed_metadata(),
        }),
    );
    assert!(!dirty);
    assert!(!state.downloads.contains_key(&download_id(9)));
}

/// A Restart of a failed row says which of the two core did and what it
/// cost, and the row leaves Failed either way.
#[test]
fn a_restart_says_whether_it_continued_or_started_over() {
    use rmule_core::{DownloadFailure, RestartOutcome, StorageIntegrityFault};
    let restarted = |outcome: RestartOutcome| {
        let mut state = UiState::default();
        fold(
            &mut state,
            download_event(DownloadEvent::DownloadFailed {
                download_id: download_id(1),
                reason: DownloadFailure::NoUsableSources,
            }),
        );
        fold(
            &mut state,
            download_event(DownloadEvent::DownloadRestarted {
                download_id: download_id(1),
                outcome,
            }),
        );
        let row = &state.downloads[&download_id(1)];
        assert_eq!(row.status, DownloadStatus::Waiting);
        assert!(row.failure.is_none());
        state.notable.expect("a restart note")
    };

    let over = restarted(RestartOutcome::StartedOver {
        fault: StorageIntegrityFault::PartFileMissing,
        dropped_parts: 3,
        dropped_bytes: 3 * ED2K_PART_SIZE,
    });
    assert_eq!(
        over,
        "download 1 restarted: nothing on disk to continue from (its part file is missing), \
         starting from 0 %; 3 checked parts (27.8 MB) fetched again"
    );

    let kept = restarted(RestartOutcome::Continued {
        kept_parts: 2,
        kept_bytes: 2 * ED2K_PART_SIZE,
        dropped_parts: 1,
        dropped_bytes: ED2K_PART_SIZE,
    });
    assert_eq!(
        kept,
        "download 1 restarted: continuing from 2 checked parts (18.6 MB); \
         1 checked part damaged (9.3 MB) dropped, fetched again"
    );
}

/// A second link's sources joining a running download answer the paste in
/// the status feed, by the download's name.
#[test]
fn a_second_links_sources_are_told_by_the_downloads_name() {
    let mut state = crate::fixture::three_downloads();
    fold(
        &mut state,
        download_event(DownloadEvent::LinkSourcesAdded {
            download_id: download_id(1),
            named: 2,
            admitted: 2,
            new: 0,
        }),
    );
    assert_eq!(
        state.notable.as_deref(),
        Some("already downloading bunny.mp4; 0 new sources from the link")
    );
}
