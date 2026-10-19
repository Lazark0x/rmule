//! Unit tests for the share set and upload-side peers: their folds and the words the operator reads.

use std::path::PathBuf;

/// The finished pass says how many files it carried to a new path,
/// in its place between kept and hashed.
#[test]
fn the_scan_finished_line_counts_what_it_carried() {
    let line = crate::words::scan::line(&ScanEvent::Finished {
        dir: PathBuf::from("/downloads"),
        summary: rmule_core::ScanSummary {
            trusted: 4,
            hashed: 2,
            carried: 3,
            dropped: 1,
            skipped: 0,
            unreadable: 2,
        },
    });
    assert_eq!(
        line,
        "/downloads scanned: 4 kept, 3 carried, 2 hashed, 1 dropped, 0 skipped, 2 unreadable"
    );
}

use rmule_core::ServeEvent;
use rmule_core::file_history::{Ed2kIdentity, FileHistory, HistoryPart, SharedFileFact};

use super::*;
use crate::fixture::{file_hash, peer_endpoint, serve_event};
use crate::state::fold;

fn only_shared(state: &UiState) -> &SharedRow {
    state.shared.values().next().expect("one shared row")
}

fn history(files: &[(u8, &str, u64)]) -> CoreEventHistory {
    CoreEventHistory(FileHistory {
        shared: files
            .iter()
            .map(|(hash, path, size)| SharedFileFact {
                identity: Ed2kIdentity::new(file_hash(*hash), *size),
                path: PathBuf::from(path),
                withheld: None,
            })
            .collect(),
        ..FileHistory::default()
    })
}

/// A File History answer as the bus carries it.
struct CoreEventHistory(FileHistory);

impl CoreEventHistory {
    fn fold_into(self, state: &mut UiState) {
        fold(
            state,
            rmule_core::CoreEvent::FileHistory { history: self.0 },
        );
    }
}

#[test]
fn sharing_inserts_a_row_and_unsharing_removes_it_keeping_the_notes() {
    let mut state = UiState::default();
    assert!(fold(
        &mut state,
        serve_event(ServeEvent::FileShared {
            file_hash: file_hash(1)
        })
    ));
    assert_eq!(state.notable.as_deref(), Some("file shared"));
    let row = only_shared(&state);
    assert_eq!(row.file_hash, file_hash(1));
    assert_eq!(row.name(), None, "no name until core says where it lies");

    fold(
        &mut state,
        serve_event(ServeEvent::FileUnshared {
            file_hash: file_hash(1),
        }),
    );
    assert!(state.shared.is_empty());
    assert_eq!(state.notable.as_deref(), Some("file unshared"));
}

/// The share set is the registry as core last read it: the answer seeds a
/// row per entry with its name and size — the files an earlier run shared
/// included — fills in a row an edge opened, and drops one the registry no
/// longer holds.
#[test]
fn a_file_history_answer_makes_the_share_set_the_registrys() {
    let mut state = UiState::default();
    for hash in [2, 9] {
        fold(
            &mut state,
            serve_event(ServeEvent::FileShared {
                file_hash: file_hash(hash),
            }),
        );
    }
    history(&[
        (1, "/dl/film.mkv", 734_003_200),
        (2, "/dl/films/song.mp3", 4_194_304),
    ])
    .fold_into(&mut state);

    let rows: Vec<(Option<String>, Option<u64>)> = state
        .shared
        .values()
        .map(|row| (row.name(), row.file_size))
        .collect();
    assert_eq!(
        rows,
        [
            (Some("film.mkv".to_string()), Some(734_003_200)),
            (Some("song.mp3".to_string()), Some(4_194_304)),
        ]
    );
}

/// Uploading is read off the upload peers, so it counts slot holders
/// whatever order their grants and the file's row arrived in, and a
/// re-queue or a release takes the peer out of it.
#[test]
fn uploading_counts_the_files_slot_holders_now() {
    let mut state = UiState::default();
    let grant = |peer| {
        serve_event(ServeEvent::UploadSlotGranted {
            peer: peer_endpoint(peer),
            file_hash: file_hash(1),
            software: None,
            road: rmule_core::GrantRoad::Linked,
        })
    };
    assert!(fold(&mut state, grant(1)));
    assert!(fold(&mut state, grant(2)));
    history(&[(1, "/dl/film.mkv", 1)]).fold_into(&mut state);
    assert_eq!(
        state.uploading_now(file_hash(1)),
        2,
        "grants before the row"
    );

    fold(
        &mut state,
        serve_event(ServeEvent::PeerQueued {
            peer: peer_endpoint(1),
            rank: 5,
            file_hash: file_hash(1),
            software: None,
        }),
    );
    assert_eq!(state.uploading_now(file_hash(1)), 1, "re-queued");
    assert!(fold(
        &mut state,
        serve_event(ServeEvent::UploadSlotReleased {
            peer: peer_endpoint(2)
        }),
    ));
    assert_eq!(state.uploading_now(file_hash(1)), 0, "released");
    // Releasing a peer we never had changes nothing.
    assert!(!fold(
        &mut state,
        serve_event(ServeEvent::UploadSlotReleased {
            peer: peer_endpoint(7)
        }),
    ));
}

#[test]
fn queuing_records_the_peers_rank_and_file() {
    let mut state = UiState::default();
    assert!(fold(
        &mut state,
        serve_event(ServeEvent::PeerQueued {
            peer: peer_endpoint(2),
            rank: 3,
            file_hash: file_hash(4),
            software: None,
        }),
    ));
    assert!(matches!(
        state.upload_peers.values().next().unwrap().state,
        UploadState::Queued { rank: 3, file } if file == file_hash(4),
    ));
}

/// A waiter back on a new link is the same row at its new address, still at
/// its rank, and no row is left at the old one.
#[test]
fn a_relinked_waiter_keeps_its_row_at_its_new_link() {
    let mut state = UiState::default();
    fold(
        &mut state,
        serve_event(ServeEvent::PeerQueued {
            peer: peer_endpoint(2),
            rank: 1,
            file_hash: file_hash(4),
            software: None,
        }),
    );
    assert!(fold(
        &mut state,
        serve_event(ServeEvent::WaiterRelinked {
            from: peer_endpoint(2),
            to: peer_endpoint(3),
        }),
    ));
    assert!(!state.upload_peers.contains_key(&peer_endpoint(2)));
    let row = &state.upload_peers[&peer_endpoint(3)];
    assert_eq!(row.peer, peer_endpoint(3));
    assert!(matches!(
        row.state,
        UploadState::Queued { rank: 1, file } if file == file_hash(4),
    ));
}

/// A waiter rmule dials back to its held slot reads so — not uploading yet —
/// until the grant lands on the dialed link, its row moved there; a dial that
/// ends unsent takes the row with the place.
#[test]
fn a_dialled_back_waiter_reads_dialling_back_until_its_grant_or_its_failure() {
    let mut state = UiState::default();
    let dialing = || {
        serve_event(ServeEvent::UploadDialBack {
            peer: peer_endpoint(2),
            file_hash: file_hash(4),
            software: None,
        })
    };
    assert!(fold(&mut state, dialing()));
    assert!(matches!(
        state.upload_peers[&peer_endpoint(2)].state,
        UploadState::DialingBack { file } if file == file_hash(4),
    ));
    assert_eq!(state.uploading_now(file_hash(4)), 0);

    fold(
        &mut state,
        serve_event(ServeEvent::WaiterRelinked {
            from: peer_endpoint(2),
            to: peer_endpoint(3),
        }),
    );
    fold(
        &mut state,
        serve_event(ServeEvent::UploadSlotGranted {
            peer: peer_endpoint(3),
            file_hash: file_hash(4),
            software: None,
            road: rmule_core::GrantRoad::DialedBack,
        }),
    );
    assert_eq!(state.upload_peers.len(), 1, "one row, at the dialed link");
    assert_eq!(state.uploading_now(file_hash(4)), 1);

    let mut state = UiState::default();
    fold(&mut state, dialing());
    assert!(fold(
        &mut state,
        serve_event(ServeEvent::UploadDialBackFailed {
            peer: peer_endpoint(2),
            cause: rmule_core::DialBackEnd::Lapsed,
        }),
    ));
    assert!(state.upload_peers.is_empty());
}

#[test]
fn queue_full_notes_without_creating_a_peer_row() {
    let mut state = UiState::default();
    assert!(fold(
        &mut state,
        serve_event(ServeEvent::UploadQueueFull {
            peer: peer_endpoint(3)
        }),
    ));
    assert_eq!(
        state.notable.as_deref(),
        Some("upload queue full: a peer was turned away")
    );
    assert!(state.upload_peers.is_empty());
}

#[test]
fn a_withheld_row_keeps_its_place_says_why_and_is_offered_again() {
    let mut state = UiState::default();
    history(&[(1, "/Volumes/Backup/film.mkv", 7)]).fold_into(&mut state);
    let since = std::time::SystemTime::UNIX_EPOCH;
    fold(
        &mut state,
        serve_event(ServeEvent::FileWithheld {
            file_hash: file_hash(1),
            reason: WithheldReason::FolderMissing,
            since,
        }),
    );
    assert_eq!(
        only_shared(&state).withheld,
        Some(Withheld {
            reason: WithheldReason::FolderMissing,
            since,
        })
    );
    assert_eq!(
        state.notable.as_deref(),
        Some("a shared file is no longer offered: its folder is missing — an unplugged disk?")
    );
    fold(
        &mut state,
        serve_event(ServeEvent::FileOffered {
            file_hash: file_hash(1),
        }),
    );
    assert_eq!(only_shared(&state).withheld, None);
    assert_eq!(state.shared.len(), 1);
}

/// A part core could not read keeps the last answer's rows, and the
/// operator is told the marks may be out of date.
#[test]
fn a_file_history_part_that_could_not_be_read_keeps_the_last_answer_and_says_so() {
    let mut state = UiState::default();
    history(&[(1, "/dl/film.mkv", 734_003_200)]).fold_into(&mut state);
    CoreEventHistory(FileHistory {
        unread: vec![HistoryPart::Shared, HistoryPart::Had],
        ..FileHistory::default()
    })
    .fold_into(&mut state);
    assert_eq!(only_shared(&state).name(), Some("film.mkv".to_string()));
    let history = state.file_history.as_ref().expect("the answer is kept");
    assert_eq!(history.shared.len(), 1, "the Have marks stay drawn");
    assert_eq!(
        state.notable.as_deref(),
        Some(
            "search marks may be missing or out of date: the shared files and \
             the files once shared could not be read (see the run log)"
        )
    );
}

/// A refused add and a refused remove read differently, each with its
/// reason; a remove says how many files left and that they stay on disk.
#[test]
fn the_list_edges_read_as_what_happened_to_the_directory() {
    use rmule_core::{DirectoryRefusal, ScanEvent};
    let line = |event| crate::words::scan::line(&event).as_str().to_string();
    assert_eq!(
        line(ScanEvent::DirectoryRefused {
            dir: PathBuf::from("/home/u"),
            reason: DirectoryRefusal::HomeDirectory,
        }),
        "/home/u not shared: it is your home directory — share a folder inside it"
    );
    assert_eq!(
        line(ScanEvent::DirectoryRefused {
            dir: PathBuf::from("/home/u/Downloads"),
            reason: DirectoryRefusal::DownloadDirectory,
        }),
        "/home/u/Downloads not removed: it is the download directory — change that above, under Paths"
    );
    assert_eq!(
        line(ScanEvent::DirectoryRemoved {
            dir: PathBuf::from("/srv/media"),
            files: 1,
        }),
        "/srv/media no longer shared: 1 file left the offer, still on disk"
    );
}

/// A Partial Share is its download's: core's edges open and close it, a File
/// History answer — the registry's — leaves it be, and it is named by the
/// download it belongs to.
#[test]
fn a_partial_share_outlives_a_registry_answer_and_ends_on_its_withdrawal() {
    let mut state = crate::fixture::partially_served();
    assert_eq!(
        state.notable.as_deref(),
        Some("a download offers the parts it has verified")
    );
    history(&[(1, "/dl/film.mkv", 734_003_200)]).fold_into(&mut state);
    let download = state
        .partial_download(file_hash(3))
        .expect("the share is its download's");
    assert_eq!(
        download
            .metadata
            .as_ref()
            .map(|m| m.name.to_display_string()),
        Some("album.flac".to_string())
    );
    assert!(
        !state.shared.contains_key(&file_hash(3)),
        "never a registry row"
    );

    fold(
        &mut state,
        serve_event(ServeEvent::PartialWithdrawn {
            file_hash: file_hash(3),
            cause: rmule_core::PartialEnd::Completed,
        }),
    );
    assert!(state.partial_download(file_hash(3)).is_none());
    assert_eq!(
        state.notable.as_deref(),
        Some("a download finished and is shared whole")
    );
}
