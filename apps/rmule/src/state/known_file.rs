//! The **Known-File Marks** (ADR-0100): what the operator's own history says
//! about a search result's file, keyed by the eD2k identity — hash and size.
//!
//! Two halves feed them. The download edges already folded into
//! [`UiState::downloads`] say what is downloading now and what failed; the
//! **File History**
//! core answers with says what is shared and readable (Have), what is shared
//! but cannot be read now (Withheld), what was shared and has left the disk
//! (Had) and what was cancelled. A mark
//! is computed from both at the moment it is drawn, so a download started from
//! the table marks its row in every held search as soon as core queues it.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;

use rmule_core::file_history::Ed2kIdentity;
use rmule_core::{DownloadFailure, DownloadId, WithheldReason};
use rmule_primitives::FileHash;

use super::{DownloadStatus, UiState};

/// At most one per result, by this precedence (ADR-0100).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KnownFileMark {
    /// A download of the file is running, waiting or paused: its row is in
    /// Transfers, and the store refuses a second.
    Downloading {
        /// The name the download runs under.
        name: String,
    },
    /// A download of the file failed and still holds its place (ADR-0094,
    /// "Failed"): a re-add restarts that download, keeping what it holds.
    Failed {
        /// The download to restart.
        download_id: DownloadId,
        /// The name it ran under.
        name: String,
        /// Why its run failed, when this session saw it fail.
        reason: Option<DownloadFailure>,
    },
    /// The file is in the Shared File Registry — on disk now.
    Have {
        /// Where it lies.
        path: PathBuf,
    },
    /// The file is in the Shared File Registry but rmule cannot read it now
    /// (ADR-0106, "The registry against the disk"): neither on disk for
    /// certain nor gone, and offered to nobody meanwhile.
    Withheld {
        /// Where the registry says it lies.
        path: PathBuf,
        /// Why it cannot be read.
        reason: WithheldReason,
        /// When rmule noticed.
        since: SystemTime,
    },
    /// The file was in the Shared File Registry and has left the disk.
    Had {
        /// The name it had when it left — the operator's own, which the
        /// result's need not be.
        name: String,
        /// When it was found gone.
        found_gone: SystemTime,
    },
    /// A download of the file was cancelled before it completed.
    Cancelled,
}

impl KnownFileMark {
    /// Higher wins when one file holds two marks.
    const fn rank(&self) -> u8 {
        match self {
            Self::Downloading { .. } => 5,
            Self::Failed { .. } => 4,
            Self::Have { .. } => 3,
            Self::Withheld { .. } => 2,
            Self::Had { .. } => 1,
            Self::Cancelled => 0,
        }
    }
}

/// Every mark the state holds, by file identity.
#[derive(Debug, Default)]
pub struct KnownFileMarks(HashMap<Ed2kIdentity, KnownFileMark>);

impl KnownFileMarks {
    /// The marks as `state` holds them now.
    #[must_use]
    pub fn of(state: &UiState) -> Self {
        let mut marks = Self::default();
        if let Some(history) = &state.file_history {
            for file in &history.cancelled {
                marks.offer(*file, KnownFileMark::Cancelled);
            }
            for file in &history.had {
                marks.offer(
                    file.identity,
                    KnownFileMark::Had {
                        name: file.name.clone(),
                        found_gone: file.found_gone,
                    },
                );
            }
            for file in &history.shared {
                let path = file.path.clone();
                let mark = match file.withheld {
                    None => KnownFileMark::Have { path },
                    Some(held) => KnownFileMark::Withheld {
                        path,
                        reason: held.reason,
                        since: held.since,
                    },
                };
                marks.offer(file.identity, mark);
            }
        }
        for (id, row) in &state.downloads {
            let (Some(hash), Some(metadata)) = (row.file_hash, &row.metadata) else {
                continue;
            };
            let name = metadata.name.to_display_string();
            let mark = match row.status {
                DownloadStatus::Waiting
                | DownloadStatus::NoConnection
                | DownloadStatus::Downloading
                | DownloadStatus::Paused
                // An active download's mark while it completes (ADR-0115).
                | DownloadStatus::Completing => KnownFileMark::Downloading { name },
                DownloadStatus::Failed => KnownFileMark::Failed {
                    download_id: *id,
                    name,
                    reason: row.failure.clone(),
                },
                DownloadStatus::Completed => continue,
            };
            marks.offer(Ed2kIdentity::new(hash, metadata.size), mark);
        }
        marks
    }

    /// The mark on the file `hash` of `size`, if any.
    #[must_use]
    pub fn get(&self, hash: FileHash, size: u64) -> Option<&KnownFileMark> {
        self.0.get(&Ed2kIdentity::new(hash, size))
    }

    fn offer(&mut self, file: Ed2kIdentity, mark: KnownFileMark) {
        match self.0.get(&file) {
            Some(held) if held.rank() >= mark.rank() => {}
            _ => {
                self.0.insert(file, mark);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rmule_core::file_history::{Ed2kIdentity, FileHistory, HadFile, SharedFileFact};
    use rmule_core::{DownloadEvent, DownloadMetadata, DownloadMetadataOrigin};
    use rmule_primitives::Ed2kText;

    use super::*;
    use crate::fixture::{download_event, download_id};
    use crate::state::fold;

    fn hash(byte: u8) -> FileHash {
        FileHash::from_bytes([byte; 16])
    }

    fn queued(state: &mut UiState, n: u64, byte: u8, size: u64) {
        fold(
            state,
            download_event(DownloadEvent::DownloadQueued {
                download_id: download_id(n),
                file_hash: hash(byte),
                metadata: DownloadMetadata {
                    name: Ed2kText::from_utf8("file.bin"),
                    size,
                    origin: DownloadMetadataOrigin::Link,
                },
                file_path: crate::fixture::part_file(),
            }),
        );
    }

    fn history(shared: &[(u8, u64)], had: &[(u8, u64)], cancelled: &[(u8, u64)]) -> FileHistory {
        FileHistory {
            had: had
                .iter()
                .map(|(byte, size)| HadFile {
                    identity: Ed2kIdentity::new(hash(*byte), *size),
                    name: "kept as.bin".into(),
                    found_gone: SystemTime::UNIX_EPOCH,
                })
                .collect(),
            shared: shared
                .iter()
                .map(|(byte, size)| SharedFileFact {
                    identity: Ed2kIdentity::new(hash(*byte), *size),
                    path: PathBuf::from("/srv/have.bin"),
                    withheld: None,
                })
                .collect(),
            cancelled: cancelled
                .iter()
                .map(|(byte, size)| Ed2kIdentity::new(hash(*byte), *size))
                .collect(),
            unread: Vec::new(),
        }
    }

    #[test]
    fn downloading_outranks_have_outranks_had_outranks_cancelled() {
        // File 1 holds all four marks, file 2 the lower three, file 3 the
        // lower two, file 4 only the last.
        let mut state = UiState {
            file_history: Some(history(
                &[(1, 10), (2, 20)],
                &[(1, 10), (2, 20), (3, 30)],
                &[(1, 10), (2, 20), (3, 30), (4, 40)],
            )),
            ..UiState::default()
        };
        queued(&mut state, 1, 1, 10);
        let marks = KnownFileMarks::of(&state);
        assert!(matches!(
            marks.get(hash(1), 10),
            Some(KnownFileMark::Downloading { .. })
        ));
        assert_eq!(
            marks.get(hash(2), 20),
            Some(&KnownFileMark::Have {
                path: PathBuf::from("/srv/have.bin")
            })
        );
        assert_eq!(
            marks.get(hash(3), 30),
            Some(&KnownFileMark::Had {
                name: "kept as.bin".into(),
                found_gone: SystemTime::UNIX_EPOCH,
            })
        );
        assert_eq!(marks.get(hash(4), 40), Some(&KnownFileMark::Cancelled));
        assert_eq!(marks.get(hash(4), 41), None, "identity is hash and size");
    }

    #[test]
    fn a_withheld_row_is_not_have_and_outranks_had() {
        let mut history = history(&[(1, 10)], &[(1, 10)], &[]);
        history.shared[0].withheld = Some(rmule_core::Withheld {
            reason: rmule_core::WithheldReason::Missing,
            since: SystemTime::UNIX_EPOCH,
        });
        let state = UiState {
            file_history: Some(history),
            ..UiState::default()
        };
        assert_eq!(
            KnownFileMarks::of(&state).get(hash(1), 10),
            Some(&KnownFileMark::Withheld {
                path: PathBuf::from("/srv/have.bin"),
                reason: rmule_core::WithheldReason::Missing,
                since: SystemTime::UNIX_EPOCH,
            })
        );
    }

    #[test]
    fn a_download_marks_its_file_when_queued_and_not_once_it_completes() {
        let mut state = UiState::default();
        assert_eq!(KnownFileMarks::of(&state).get(hash(4), 40), None);
        queued(&mut state, 7, 4, 40);
        assert!(matches!(
            KnownFileMarks::of(&state).get(hash(4), 40),
            Some(KnownFileMark::Downloading { name }) if name == "file.bin"
        ));
        fold(
            &mut state,
            download_event(DownloadEvent::DownloadCompleted {
                download_id: download_id(7),
                final_path: "/downloads/file.bin".into(),
            }),
        );
        assert_eq!(
            KnownFileMarks::of(&state).get(hash(4), 40),
            None,
            "a completed file is Have once the registry says so"
        );
    }

    /// A failed download is not Downloading — its re-add restarts it —
    /// and it outranks Have, since the store refuses a new download of the
    /// file while the failed one holds its place. A resume makes it
    /// Downloading again.
    #[test]
    fn a_failed_download_marks_failed_above_have_until_it_resumes() {
        let mut state = UiState {
            file_history: Some(history(&[(4, 40)], &[], &[])),
            ..UiState::default()
        };
        queued(&mut state, 7, 4, 40);
        fold(
            &mut state,
            download_event(DownloadEvent::DownloadFailed {
                download_id: download_id(7),
                reason: rmule_core::DownloadFailure::StorageIntegrityFailed(
                    rmule_core::StorageIntegrityFault::PartFileMissing,
                ),
            }),
        );
        assert_eq!(
            KnownFileMarks::of(&state).get(hash(4), 40),
            Some(&KnownFileMark::Failed {
                download_id: download_id(7),
                name: "file.bin".into(),
                reason: Some(rmule_core::DownloadFailure::StorageIntegrityFailed(
                    rmule_core::StorageIntegrityFault::PartFileMissing,
                )),
            })
        );
        fold(
            &mut state,
            download_event(DownloadEvent::DownloadResumed {
                download_id: download_id(7),
            }),
        );
        assert!(matches!(
            KnownFileMarks::of(&state).get(hash(4), 40),
            Some(KnownFileMark::Downloading { .. })
        ));
    }
}
