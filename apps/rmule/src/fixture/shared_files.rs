//! The Shared Files tab's fixtures: served files, their edges and the metered session.

use rmule_core::{CoreEvent, ServeEvent};

use crate::state::UiState;

use super::{amule_233, emule_qt, file_hash, now, peer_endpoint};

/// Fold one serve edge into `state`, discarding the dirty hint.
fn serve_fold(state: &mut UiState, event: ServeEvent) {
    crate::state::fold(state, CoreEvent::Serve(event));
}

/// Two shared files; one peer uploading file 1, two peers queued; one
/// source-exchange ask answered for file 1; a data tick has counted file 1's
/// three upload requests and 1 MiB served this run, twelve and 4 MiB all
/// time. Core has not answered the File History yet, so neither file's name
/// is known.
pub(crate) fn served_files() -> UiState {
    let mut state = UiState {
        last_snapshot_at: Some(now()),
        ..UiState::default()
    };
    state.diagnostics.shared_files.insert(
        file_hash(1),
        rmule_core::diagnostics::SharedFileCounters {
            requests: 3,
            accepted: 1,
            transferred: 1_048_576,
            all_time: rmule_core::diagnostics::ShareTotals {
                requests: 12,
                accepted: 5,
                transferred: 4 * 1_048_576,
            },
        },
    );
    serve_fold(
        &mut state,
        ServeEvent::FileShared {
            file_hash: file_hash(1),
        },
    );
    serve_fold(
        &mut state,
        ServeEvent::FileShared {
            file_hash: file_hash(2),
        },
    );
    serve_fold(
        &mut state,
        ServeEvent::UploadSlotGranted {
            peer: peer_endpoint(1),
            file_hash: file_hash(1),
            software: Some(amule_233()),
        },
    );
    serve_fold(
        &mut state,
        ServeEvent::PeerQueued {
            peer: peer_endpoint(2),
            rank: 1,
            file_hash: file_hash(1),
            software: Some(emule_qt()),
        },
    );
    serve_fold(
        &mut state,
        ServeEvent::PeerQueued {
            peer: peer_endpoint(3),
            rank: 2,
            file_hash: file_hash(1),
            software: None,
        },
    );
    serve_fold(
        &mut state,
        ServeEvent::SourcesServed {
            peer: peer_endpoint(9),
            file_hash: file_hash(1),
            count: 4,
        },
    );
    state
}

/// [`served_files`] plus the data tick's synthesized upload rates:
/// the slot holder is metered, the queued peers are not — they hold no
/// slot, so core keeps no byte counter for them.
pub(crate) fn metered() -> UiState {
    let mut state = served_files();
    state
        .rates
        .upload_bps
        .insert(peer_endpoint(1), 123.4 * 1024.0);
    state.rates.up_total_bps = 123.4 * 1024.0;
    state
}

/// [`served_files`] placed by a File History answer in two shared
/// directories — file 1 under the download directory, file 2 under an added
/// one whose watch could not start — and a third directory still being
/// added.
pub(crate) fn shared_directories() -> UiState {
    use std::path::PathBuf;

    use rmule_core::{DirectoryRole, DirectoryState, ScanPhase, SharedDirectoryDiagnostics};

    let mut state = served_files();
    for (tag, path, size) in [
        (1, "/home/u/Downloads/album.flac", 41_943_040),
        (2, "/srv/media/films/film.mkv", 734_003_200),
    ] {
        if let Some(row) = state.shared.get_mut(&file_hash(tag)) {
            row.path = Some(PathBuf::from(path));
            row.file_size = Some(size);
        }
    }
    state.diagnostics.shared_directories = vec![
        SharedDirectoryDiagnostics {
            dir: PathBuf::from("/home/u/Downloads"),
            role: DirectoryRole::DownloadDirectory,
            state: DirectoryState::Scan(ScanPhase::Watching { settling: 0 }),
        },
        SharedDirectoryDiagnostics {
            dir: PathBuf::from("/srv/media"),
            role: DirectoryRole::Added,
            state: DirectoryState::Scan(ScanPhase::Unwatched {
                reason: rmule_core::WatchFault::Limit,
            }),
        },
        SharedDirectoryDiagnostics {
            dir: PathBuf::from("/srv/books"),
            role: DirectoryRole::Adding,
            state: DirectoryState::Scan(ScanPhase::Hashing {
                done: 36,
                total: 100,
                current: PathBuf::from("/srv/books/atlas.pdf"),
            }),
        },
    ];
    state
}
