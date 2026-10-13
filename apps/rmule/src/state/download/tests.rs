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
            file_path: crate::fixture::part_file(),
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
            file_path: crate::fixture::part_file(),
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
            file_path: crate::fixture::part_file(),
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
            file_path: crate::fixture::part_file(),
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
            file_path: crate::fixture::part_file(),
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
            file_path: crate::fixture::part_file(),
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
            file_path: crate::fixture::part_file(),
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
                file_path: crate::fixture::part_file(),
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
        (4, DownloadLifecycle::Completing, DownloadStatus::Completing),
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
                file_path: crate::fixture::part_file(),
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
            file_path: crate::fixture::part_file(),
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

/// The row holds where core said the bytes lie: the `.part` the queued edge
/// named, then the finished file the completion edge named.
#[test]
fn a_queued_rows_file_path_is_its_part_until_completion_names_the_file() {
    let mut state = UiState::default();
    let part = crate::fixture::rooted("films/bunny.mp4.part");
    let finished = crate::fixture::rooted("films/bunny.mp4");
    fold(
        &mut state,
        download_event(DownloadEvent::DownloadQueued {
            download_id: download_id(1),
            file_hash: file_hash(7),
            metadata: unnamed_metadata(),
            file_path: part.clone(),
        }),
    );
    assert_eq!(state.downloads[&download_id(1)].file_path, Some(part));
    fold(
        &mut state,
        download_event(DownloadEvent::DownloadCompleted {
            download_id: download_id(1),
            final_path: finished.clone(),
        }),
    );
    assert_eq!(state.downloads[&download_id(1)].file_path, Some(finished));
}

/// A recovered row holds the path its edge named, whatever the lifecycle.
#[test]
fn a_recovered_rows_file_path_is_the_one_its_edge_named() {
    let mut state = UiState::default();
    let finished = crate::fixture::rooted("films/done.mkv");
    fold(
        &mut state,
        download_event(DownloadEvent::DownloadRecovered {
            download_id: download_id(2),
            state: DownloadLifecycle::Completed,
            failure: None,
            file_hash: file_hash(9),
            metadata: unnamed_metadata(),
            file_path: finished.clone(),
        }),
    );
    assert_eq!(state.downloads[&download_id(2)].file_path, Some(finished));
}

/// A run on a disk that holds no holes (ADR-0111) is said once, by the
/// download's name and its part file's directory: the status note now, and
/// the Networks log for after the next note replaces it.
#[test]
fn a_hole_less_destination_sets_the_note_and_logs_its_line() {
    use std::time::Instant;

    use crate::action::Action;

    let mut state = crate::fixture::three_downloads();
    state.apply(
        Action::Core(download_event(DownloadEvent::HoleLessDestination {
            download_id: download_id(1),
            directory: PathBuf::from("/srv/rmule/Temp"),
        })),
        Instant::now(),
    );
    assert_eq!(
        state.notable.as_deref(),
        Some(
            "bunny.mp4: its part file lies in /srv/rmule/Temp; this disk holds no holes, so \
             the part file takes its full length on disk up to its last verified part; the \
             download goes on — downloads started with the Temp Directory on another disk \
             avoid this"
        )
    );
    assert_eq!(
        state.log.back().expect("the edge's log line").text,
        "its part file lies in /srv/rmule/Temp; this disk holds no holes, so the part file \
         takes its full length on disk up to its last verified part; downloads started with \
         the Temp Directory on another disk avoid this"
    );
}

/// A completion move's steps fold into the Completing status, each said on
/// the status bar by the download's name; the move ends Completed, and a
/// Pause that stopped it leaves the row Paused (ADR-0115).
#[test]
fn completing_edges_hold_the_row_completing_until_it_completes_or_pauses() {
    use rmule_core::CompletionStep;

    let mut state = UiState::default();
    let named = rmule_core::DownloadMetadata {
        name: rmule_primitives::Ed2kText::from_utf8("film.mkv"),
        size: 1_000,
        origin: rmule_core::DownloadMetadataOrigin::Link,
    };
    fold(
        &mut state,
        download_event(DownloadEvent::DownloadQueued {
            download_id: download_id(1),
            file_hash: file_hash(7),
            metadata: named,
            file_path: crate::fixture::part_file(),
        }),
    );
    let to = std::path::PathBuf::from("/dl/film (1).mkv");
    let completing = |step| {
        download_event(DownloadEvent::Completing {
            download_id: download_id(1),
            to: to.clone(),
            step,
        })
    };
    assert!(fold(
        &mut state,
        completing(CompletionStep::WaitingForRelease)
    ));
    assert_eq!(
        state.downloads[&download_id(1)].status,
        DownloadStatus::Completing
    );
    assert_eq!(
        state.notable.as_deref(),
        Some(
            "film.mkv: waiting for the file to be released; it completes once the program \
             holding it lets go"
        )
    );
    fold(&mut state, completing(CompletionStep::Copying));
    assert_eq!(
        state.notable.as_deref(),
        Some("film.mkv: copying the finished file to the disk it goes to")
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
    fold(&mut state, completing(CompletionStep::QueuedForCopy));
    fold(
        &mut state,
        download_event(DownloadEvent::DownloadCompleted {
            download_id: download_id(1),
            final_path: to.clone(),
        }),
    );
    let row = &state.downloads[&download_id(1)];
    assert_eq!(row.status, DownloadStatus::Completed);
    assert_eq!(row.file_path.as_deref(), Some(to.as_path()));
}
