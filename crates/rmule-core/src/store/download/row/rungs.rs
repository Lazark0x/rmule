//! **How an older store's download rows climb** (ADR-0083's ladder): the row
//! shapes earlier store versions wrote, and the rungs that grow them into
//! today's [`DownloadRow`](super::DownloadRow).
//!
//! A frozen row shape embeds only frozen enums: its bytes decode by variant
//! position, so a live enum that gains or reorders a variant must not reach
//! a shape whose bytes are already on disk. Each frozen enum converts into
//! the live one, and its encoding is pinned by test. The enums every shape
//! embeds unchanged live in `row_enums`.

use rmule_primitives::{Ed2kText, FileHash, PartHash, ServerEndpoint};
use rmule_store::redb::TableDefinition;
use rmule_store::{Indexed, Packed, Record, StoreError, UpgradeStep, WriteTransaction};
use serde::{Deserialize, Serialize};

use crate::PartFault;

mod row_enums;
mod row_v5;

use row_enums::{DownloadLifecycleV1, DownloadMetadataOriginV1, VerificationAuthorityV1};
pub(crate) use row_v5::grow_from_v14;
use row_v5::{DOWNLOADS_V5, DownloadFailureV5, DownloadRowV5};

/// The row as record version 1 wrote it, before the failure reason was kept.
/// Compiled only for [`UPGRADE_FROM_V5`].
#[derive(Debug, Serialize, Deserialize)]
struct DownloadRowV1 {
    file_hash: FileHash,
    file_size: u64,
    canonical_link: String,
    server: ServerEndpoint,
    final_path: String,
    part_path: String,
    lifecycle: DownloadLifecycleV1,
    verification_authority: Option<VerificationAuthorityV1>,
    file_name: Ed2kText,
    metadata_origin: DownloadMetadataOriginV1,
}

impl Record for DownloadRowV1 {
    const NAME: &'static str = "download";
    const VERSION: u32 = 1;
}

/// An index-free view of the table for the rung: the index entries are keyed
/// by values no rung changes, so they stay as they were.
static DOWNLOADS_V1: Indexed<u64, DownloadRowV1> = Indexed::new("download", &[]);

#[cfg(test)]
mod declared_v1;
#[cfg(test)]
mod declared_v5;
#[cfg(test)]
pub(crate) use declared_v1::{schema_v1, seed_v1};
#[cfg(test)]
pub(crate) use declared_v5::{schema_v5_rows, seed_v5};

/// The row as record version 2 wrote it: its failure reason a bare code, the
/// storage-integrity one without the fault it now carries. Compiled only for
/// the rungs.
#[derive(Debug, Serialize, Deserialize)]
struct DownloadRowV2 {
    file_hash: FileHash,
    file_size: u64,
    canonical_link: String,
    server: ServerEndpoint,
    final_path: String,
    part_path: String,
    lifecycle: DownloadLifecycleV1,
    verification_authority: Option<VerificationAuthorityV1>,
    file_name: Ed2kText,
    metadata_origin: DownloadMetadataOriginV1,
    failure: Option<DownloadFailureV2>,
}

impl Record for DownloadRowV2 {
    const NAME: &'static str = "download";
    const VERSION: u32 = 2;
}

/// [`DownloadFailure`](crate::DownloadFailure) as store version 6 encoded it, by declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum DownloadFailureV2 {
    NoUsableSources,
    HashSetMismatch,
    Cancelled,
    Paused,
    ServerDisconnected,
    ServerFiltered,
    SourceLookupTimedOut,
    PeerDisconnected,
    PartVerificationFailed,
    StorageIntegrityFailed,
}

impl DownloadFailureV2 {
    /// The reason as version 7 keeps it. The storage-integrity code had no
    /// fault to carry, so it becomes no reason — the row stays `Failed`, and
    /// the next restart finds the fault again.
    const fn grown(self) -> Option<DownloadFailureV3> {
        Some(match self {
            Self::NoUsableSources => DownloadFailureV3::NoUsableSources,
            Self::HashSetMismatch => DownloadFailureV3::HashSetMismatch,
            Self::Cancelled => DownloadFailureV3::Cancelled,
            Self::Paused => DownloadFailureV3::Paused,
            Self::ServerDisconnected => DownloadFailureV3::ServerDisconnected,
            Self::ServerFiltered => DownloadFailureV3::ServerFiltered,
            Self::SourceLookupTimedOut => DownloadFailureV3::SourceLookupTimedOut,
            Self::PeerDisconnected => DownloadFailureV3::PeerDisconnected,
            Self::PartVerificationFailed => DownloadFailureV3::PartVerificationFailed,
            Self::StorageIntegrityFailed => return None,
        })
    }
}

/// Index-free views of the row table for the rungs: the index entries are
/// keyed by values no rung changes, so they stay as they were.
static DOWNLOADS_V2: Indexed<u64, DownloadRowV2> = Indexed::new("download", &[]);

/// Store version 5 → 6 (ADR-0094, "Failed"): every download row gains a
/// failure reason. A row failed before the rung has none to give, so it reads
/// `None` — the one case where the Failed mark still cannot say why. A
/// version-5 build refuses the store: it would fail a download without
/// keeping why.
pub(crate) const UPGRADE_FROM_V5: UpgradeStep = UpgradeStep {
    from: 5,
    run: keep_no_failure_reason,
};

fn keep_no_failure_reason(txn: &WriteTransaction) -> Result<(), StoreError> {
    let old = DOWNLOADS_V1.iter(txn)?;
    txn.delete_table(TableDefinition::<u64, Packed<DownloadRowV1>>::new(
        "download",
    ))?;
    DOWNLOADS_V2.create(txn)?;
    for (key, row) in old {
        let grown = DownloadRowV2 {
            file_hash: row.file_hash,
            file_size: row.file_size,
            canonical_link: row.canonical_link,
            server: row.server,
            final_path: row.final_path,
            part_path: row.part_path,
            lifecycle: row.lifecycle,
            verification_authority: row.verification_authority,
            file_name: row.file_name,
            metadata_origin: row.metadata_origin,
            failure: None,
        };
        DOWNLOADS_V2.insert(txn, &key, &grown)?;
    }
    Ok(())
}

/// Store version 6 → 7 (ADR-0094, "Damaged parts"): the storage-integrity
/// failure carries its fault (which check, on which part, expected and
/// found). A row failed with the bare code has no fault to give, so its reason
/// reads `None`; every other reason is kept. A version-6 build refuses the
/// store: it could not read the fault.
pub(crate) const UPGRADE_FROM_V6: UpgradeStep = UpgradeStep {
    from: 6,
    run: keep_failure_codes,
};

fn keep_failure_codes(txn: &WriteTransaction) -> Result<(), StoreError> {
    let old = DOWNLOADS_V2.iter(txn)?;
    txn.delete_table(TableDefinition::<u64, Packed<DownloadRowV2>>::new(
        "download",
    ))?;
    DOWNLOADS_V3.create(txn)?;
    for (key, row) in old {
        let grown = DownloadRowV3 {
            file_hash: row.file_hash,
            file_size: row.file_size,
            canonical_link: row.canonical_link,
            server: row.server,
            final_path: row.final_path,
            part_path: row.part_path,
            lifecycle: row.lifecycle,
            verification_authority: row.verification_authority,
            file_name: row.file_name,
            metadata_origin: row.metadata_origin,
            failure: row.failure.and_then(DownloadFailureV2::grown),
        };
        DOWNLOADS_V3.insert(txn, &key, &grown)?;
    }
    Ok(())
}

/// The row as record version 3 wrote it: an unreadable part file's fault
/// carried the OS's message as text. Compiled only for the rungs.
#[derive(Debug, Serialize, Deserialize)]
struct DownloadRowV3 {
    file_hash: FileHash,
    file_size: u64,
    canonical_link: String,
    server: ServerEndpoint,
    final_path: String,
    part_path: String,
    lifecycle: DownloadLifecycleV1,
    verification_authority: Option<VerificationAuthorityV1>,
    file_name: Ed2kText,
    metadata_origin: DownloadMetadataOriginV1,
    failure: Option<DownloadFailureV3>,
}

impl Record for DownloadRowV3 {
    const NAME: &'static str = "download";
    const VERSION: u32 = 3;
}

/// [`DownloadFailure`](crate::DownloadFailure) as store version 7 encoded it, by declaration order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum DownloadFailureV3 {
    NoUsableSources,
    HashSetMismatch,
    Cancelled,
    Paused,
    ServerDisconnected,
    ServerFiltered,
    SourceLookupTimedOut,
    PeerDisconnected,
    PartVerificationFailed,
    StorageIntegrityFailed(StorageIntegrityFaultV3),
}

/// [`StorageIntegrityFault`](crate::StorageIntegrityFault) as store version 7 encoded it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum StorageIntegrityFaultV3 {
    PartFileMissing,
    PartFileUnreadable(String),
    NoPartHolds { recorded: u32, first: PartFaultV3 },
}

/// [`PartFault`] as store versions 7 to 14 encoded it, by declaration order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum PartFaultV3 {
    Short {
        part_index: u32,
        expected_end: u64,
        found_len: u64,
    },
    HashMismatch {
        part_index: u32,
        expected: PartHash,
        found: PartHash,
    },
}

impl PartFaultV3 {
    const fn grown(self) -> PartFault {
        match self {
            Self::Short {
                part_index,
                expected_end,
                found_len,
            } => PartFault::Short {
                part_index,
                expected_end,
                found_len,
            },
            Self::HashMismatch {
                part_index,
                expected,
                found,
            } => PartFault::HashMismatch {
                part_index,
                expected,
                found,
            },
        }
    }
}

impl DownloadFailureV3 {
    /// The reason as version 8 keeps it: an unreadable part file keeps the
    /// OS's error number its message named, and nothing else of the text.
    fn grown(self) -> DownloadFailureV4 {
        match self {
            Self::NoUsableSources => DownloadFailureV4::NoUsableSources,
            Self::HashSetMismatch => DownloadFailureV4::HashSetMismatch,
            Self::Cancelled => DownloadFailureV4::Cancelled,
            Self::Paused => DownloadFailureV4::Paused,
            Self::ServerDisconnected => DownloadFailureV4::ServerDisconnected,
            Self::ServerFiltered => DownloadFailureV4::ServerFiltered,
            Self::SourceLookupTimedOut => DownloadFailureV4::SourceLookupTimedOut,
            Self::PeerDisconnected => DownloadFailureV4::PeerDisconnected,
            Self::PartVerificationFailed => DownloadFailureV4::PartVerificationFailed,
            Self::StorageIntegrityFailed(fault) => {
                DownloadFailureV4::StorageIntegrityFailed(match fault {
                    StorageIntegrityFaultV3::PartFileMissing => {
                        StorageIntegrityFaultV4::PartFileMissing
                    }
                    StorageIntegrityFaultV3::PartFileUnreadable(message) => {
                        StorageIntegrityFaultV4::PartFileUnreadable {
                            os_code: StorageIntegrityFaultV3::os_code_in_v7_message(&message),
                        }
                    }
                    StorageIntegrityFaultV3::NoPartHolds { recorded, first } => {
                        StorageIntegrityFaultV4::NoPartHolds { recorded, first }
                    }
                })
            }
        }
    }
}

/// [`DownloadFailure`](crate::DownloadFailure) as store version 8 encoded it, by declaration order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum DownloadFailureV4 {
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
}

/// [`StorageIntegrityFault`](crate::StorageIntegrityFault) as store versions 8 to 14 encoded it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum StorageIntegrityFaultV4 {
    PartFileMissing,
    PartFileUnreadable { os_code: Option<i32> },
    NoPartHolds { recorded: u32, first: PartFaultV3 },
}

impl DownloadFailureV4 {
    /// The reason as record version 5 keeps it: every code the same.
    const fn grown(self) -> DownloadFailureV5 {
        match self {
            Self::NoUsableSources => DownloadFailureV5::NoUsableSources,
            Self::HashSetMismatch => DownloadFailureV5::HashSetMismatch,
            Self::Cancelled => DownloadFailureV5::Cancelled,
            Self::Paused => DownloadFailureV5::Paused,
            Self::ServerDisconnected => DownloadFailureV5::ServerDisconnected,
            Self::ServerFiltered => DownloadFailureV5::ServerFiltered,
            Self::SourceLookupTimedOut => DownloadFailureV5::SourceLookupTimedOut,
            Self::PeerDisconnected => DownloadFailureV5::PeerDisconnected,
            Self::PartVerificationFailed => DownloadFailureV5::PartVerificationFailed,
            Self::StorageIntegrityFailed(fault) => DownloadFailureV5::StorageIntegrityFailed(fault),
        }
    }
}

impl StorageIntegrityFaultV3 {
    /// The OS error number a version-7 row's message names — "… (os error 13)"
    /// — if it names one. Version 7 wrote the rendered `io::Error`; this is
    /// the only reader of that text, and it lives for this rung alone.
    fn os_code_in_v7_message(message: &str) -> Option<i32> {
        let (_, tail) = message.rsplit_once("(os error ")?;
        tail.strip_suffix(')')?.parse().ok()
    }
}

static DOWNLOADS_V3: Indexed<u64, DownloadRowV3> = Indexed::new("download", &[]);

/// Store version 7 → 8: an unreadable part file's fault keeps the OS's
/// error number, not its message, so a front end words it. A version-7 build
/// refuses the store: it could not read the fault.
pub(crate) const UPGRADE_FROM_V7: UpgradeStep = UpgradeStep {
    from: 7,
    run: keep_os_codes,
};

fn keep_os_codes(txn: &WriteTransaction) -> Result<(), StoreError> {
    let old = DOWNLOADS_V3.iter(txn)?;
    txn.delete_table(TableDefinition::<u64, Packed<DownloadRowV3>>::new(
        "download",
    ))?;
    DOWNLOADS_V4.create(txn)?;
    for (key, row) in old {
        let grown = DownloadRowV4 {
            file_hash: row.file_hash,
            file_size: row.file_size,
            canonical_link: row.canonical_link,
            server: row.server,
            final_path: row.final_path,
            part_path: row.part_path,
            lifecycle: row.lifecycle,
            verification_authority: row.verification_authority,
            file_name: row.file_name,
            metadata_origin: row.metadata_origin,
            failure: row.failure.map(DownloadFailureV3::grown),
        };
        DOWNLOADS_V4.insert(txn, &key, &grown)?;
    }
    Ok(())
}

/// The row as record version 4 wrote it: the server the link was found on
/// required. Compiled only for the rungs.
#[derive(Debug, Serialize, Deserialize)]
struct DownloadRowV4 {
    file_hash: FileHash,
    file_size: u64,
    canonical_link: String,
    server: ServerEndpoint,
    final_path: String,
    part_path: String,
    lifecycle: DownloadLifecycleV1,
    verification_authority: Option<VerificationAuthorityV1>,
    file_name: Ed2kText,
    metadata_origin: DownloadMetadataOriginV1,
    failure: Option<DownloadFailureV4>,
}

impl Record for DownloadRowV4 {
    const NAME: &'static str = "download";
    const VERSION: u32 = 4;
}

static DOWNLOADS_V4: Indexed<u64, DownloadRowV4> = Indexed::new("download", &[]);

/// The downloads' half of store version 8 → 9: the server a row names
/// becomes an optional source hint, so a download can start with no server
/// at all. Every row keeps the server it named, now as its hint.
pub(crate) fn grow_from_v8(txn: &WriteTransaction) -> Result<(), StoreError> {
    let old = DOWNLOADS_V4.iter(txn)?;
    txn.delete_table(TableDefinition::<u64, Packed<DownloadRowV4>>::new(
        "download",
    ))?;
    DOWNLOADS_V5.create(txn)?;
    for (key, row) in old {
        let grown = DownloadRowV5 {
            file_hash: row.file_hash,
            file_size: row.file_size,
            canonical_link: row.canonical_link,
            source_hint: Some(row.server),
            final_path: row.final_path,
            part_path: row.part_path,
            lifecycle: row.lifecycle.grown(),
            verification_authority: row.verification_authority,
            file_name: row.file_name,
            metadata_origin: row.metadata_origin,
            failure: row.failure.map(DownloadFailureV4::grown),
        };
        DOWNLOADS_V5.insert(txn, &key, &grown)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
