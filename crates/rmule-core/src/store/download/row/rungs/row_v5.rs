//! **The version-5 row and the rung that names it**: the download row as
//! record version 5 (store versions 9 to 14) wrote it, its frozen failure
//! reason, and store version 14 → 15, which gives every row its Download
//! Name (ADR-0115, step 2) and no Kad AICH root (ADR-0038).

use std::path::Path;

use rmule_primitives::{Ed2kText, FileHash, ServerEndpoint};
use rmule_store::redb::TableDefinition;
use rmule_store::{Indexed, Packed, Record, StoreError, WriteTransaction};
use serde::{Deserialize, Serialize};

use super::StorageIntegrityFaultV4;
use super::row_enums::{DownloadLifecycleV5, DownloadMetadataOriginV1, VerificationAuthorityV1};
use crate::store::download::row::{DOWNLOADS, DownloadRow, PartPathSlot};
use crate::{DownloadFailure, StorageIntegrityFault};

/// The row as record version 5 wrote it, before it kept the Download Name.
/// Its part path is the slot's stored text. Compiled only for the rungs.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct DownloadRowV5 {
    pub(super) file_hash: FileHash,
    pub(super) file_size: u64,
    pub(super) canonical_link: String,
    pub(super) source_hint: Option<ServerEndpoint>,
    pub(super) final_path: String,
    pub(super) part_path: String,
    pub(super) lifecycle: DownloadLifecycleV5,
    pub(super) verification_authority: Option<VerificationAuthorityV1>,
    pub(super) file_name: Ed2kText,
    pub(super) metadata_origin: DownloadMetadataOriginV1,
    pub(super) failure: Option<DownloadFailureV5>,
}

impl Record for DownloadRowV5 {
    const NAME: &'static str = "download";
    const VERSION: u32 = 5;
}

/// An index-free view of the table for the rungs: the index entries are
/// keyed by values no rung changes, so they stay as they were.
pub(super) static DOWNLOADS_V5: Indexed<u64, DownloadRowV5> = Indexed::new("download", &[]);

/// [`DownloadFailure`] as record version 5 encoded it, by declaration order:
/// version 4's codes with the completion move's appended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum DownloadFailureV5 {
    NoUsableSources,
    HashSetMismatch,
    Cancelled,
    Paused,
    ServerDisconnected,
    ServerFiltered,
    SourceLookupTimedOut,
    PeerDisconnected,
    PartVerificationFailed,
    StorageIntegrityFailed(StorageIntegrityFaultV4),
    FinalPathTaken,
    CompletedFileNotMoved { os_code: Option<i32> },
    StoreFailed,
    CompletionCopyFailed { os_code: Option<i32> },
}

impl DownloadFailureV5 {
    /// The reason as the live row keeps it: every code the same.
    const fn grown(self) -> DownloadFailure {
        match self {
            Self::NoUsableSources => DownloadFailure::NoUsableSources,
            Self::HashSetMismatch => DownloadFailure::HashSetMismatch,
            Self::Cancelled => DownloadFailure::Cancelled,
            Self::Paused => DownloadFailure::Paused,
            Self::ServerDisconnected => DownloadFailure::ServerDisconnected,
            Self::ServerFiltered => DownloadFailure::ServerFiltered,
            Self::SourceLookupTimedOut => DownloadFailure::SourceLookupTimedOut,
            Self::PeerDisconnected => DownloadFailure::PeerDisconnected,
            Self::PartVerificationFailed => DownloadFailure::PartVerificationFailed,
            Self::StorageIntegrityFailed(fault) => {
                DownloadFailure::StorageIntegrityFailed(match fault {
                    StorageIntegrityFaultV4::PartFileMissing => {
                        StorageIntegrityFault::PartFileMissing
                    }
                    StorageIntegrityFaultV4::PartFileUnreadable { os_code } => {
                        StorageIntegrityFault::PartFileUnreadable { os_code }
                    }
                    StorageIntegrityFaultV4::NoPartHolds { recorded, first } => {
                        StorageIntegrityFault::NoPartHolds {
                            recorded,
                            first: first.grown(),
                        }
                    }
                })
            }
            Self::FinalPathTaken => DownloadFailure::FinalPathTaken,
            Self::CompletedFileNotMoved { os_code } => {
                DownloadFailure::CompletedFileNotMoved { os_code }
            }
            Self::StoreFailed => DownloadFailure::StoreFailed,
            Self::CompletionCopyFailed { os_code } => {
                DownloadFailure::CompletionCopyFailed { os_code }
            }
        }
    }
}

/// The downloads' half of store version 14 → 15 (ADR-0115, step 2): every
/// row keeps a Download Name, read from the name it was placed under, and
/// holds no Kad AICH root, since none was kept before (ADR-0038). A row
/// a placement numbered before the rung keeps that number in its name:
/// nothing on the row tells a number rmule added from one the command gave.
pub(crate) fn grow_from_v14(txn: &WriteTransaction) -> Result<(), StoreError> {
    let old = DOWNLOADS_V5.iter(txn)?;
    txn.delete_table(TableDefinition::<u64, Packed<DownloadRowV5>>::new(
        "download",
    ))?;
    DOWNLOADS.create(txn)?;
    for (key, row) in old {
        let name = placed_name(&row.final_path, &row.part_path);
        let grown = DownloadRow {
            file_hash: row.file_hash,
            file_size: row.file_size,
            canonical_link: row.canonical_link,
            source_hint: row.source_hint,
            final_path: row.final_path,
            part_path: PartPathSlot::from_stored(row.part_path),
            lifecycle: row.lifecycle.grown(),
            verification_authority: row
                .verification_authority
                .map(VerificationAuthorityV1::grown),
            file_name: row.file_name,
            metadata_origin: row.metadata_origin.grown(),
            failure: row.failure.map(DownloadFailureV5::grown),
            name,
            kad_aich_root: None,
        };
        DOWNLOADS.set(txn, &key, &grown)?;
    }
    Ok(())
}

/// The name a row was placed under: its part file's name less `.part`,
/// since a placement names the two alike and a completion move changes only
/// the final path; or the final path's file name for a part path named any
/// other way or given up.
fn placed_name(final_path: &str, part_path: &str) -> String {
    let file_name = |path: &str| {
        Path::new(path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
    };
    file_name(part_path)
        .and_then(|name| name.strip_suffix(".part").map(str::to_owned))
        .filter(|name| !name.is_empty())
        .or_else(|| file_name(final_path))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
