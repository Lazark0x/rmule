//! **What a download is, durably**: the four record kinds the download seam
//! owns, the indexes declared on them, the id counter that mints primary keys,
//! and the total conversions between a stored row and the domain's
//! [`DurableDownloadRecord`] / [`VerifiedPartRecord`].
//!
//! Nothing here opens a transaction of its own — every function is handed one —
//! so the record shapes and the write ordering stay separable concerns. The
//! rows carry the domain's own enums, encoded by their declaration order: a
//! variant added anywhere but the end, or reordered, changes the record's
//! shape and must bump the row's [`Record::VERSION`] like any other field change
//! (ADR-0083), which is what makes the engine refuse the older table.

mod part_path;
mod rungs;

pub(super) use part_path::PartPathSlot;
pub(crate) use rungs::{UPGRADE_FROM_V5, UPGRADE_FROM_V6, UPGRADE_FROM_V7, grow_from_v8};
#[cfg(test)]
pub(crate) use rungs::{schema_v1, seed_v1};

use rmule_primitives::{
    Ed2kFileLink, Ed2kLink, Ed2kText, FileHash, PartHash, ServerEndpoint, UserHash,
};
use rmule_store::{Children, Indexed, MultimapIndex, Record, Sequence, UniqueIndex};
use serde::{Deserialize, Serialize};

use crate::durable::DurableDownloadRecordInput;
use crate::{
    DownloadFailure, DownloadId, DownloadLifecycle, DownloadMetadata, DownloadMetadataOrigin,
    DownloadPaths, DurableDownloadRecord, VerificationAuthority, VerifiedPartRecord,
};

/// One download as the store holds it, keyed by its [`DownloadId`]'s `u64`.
/// Paths are kept as text because the part path is also a unique index value;
/// a path that is not valid UTF-8 is stored lossily.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct DownloadRow {
    pub file_hash: FileHash,
    pub file_size: u64,
    pub canonical_link: String,
    /// The server the link was found on, `None` for a Kad-only start:
    /// a hint, never dialed.
    pub source_hint: Option<ServerEndpoint>,
    pub final_path: String,
    pub part_path: PartPathSlot,
    pub lifecycle: DownloadLifecycle,
    pub verification_authority: Option<VerificationAuthority>,
    pub file_name: Ed2kText,
    pub metadata_origin: DownloadMetadataOrigin,
    /// Why the last run failed: set with the `Failed` lifecycle, cleared by
    /// any other (ADR-0094, "Failed"). A code, never a sentence.
    pub failure: Option<DownloadFailure>,
}

impl Record for DownloadRow {
    const NAME: &'static str = "download";
    const VERSION: u32 = 5;
}

/// One hash-checked part on disk, keyed by `(download id, part index)` so a
/// download's parts are one contiguous key range in part order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct VerifiedPartRow {
    pub offset: u64,
    pub len: u64,
    pub part_hash: PartHash,
}

impl Record for VerifiedPartRow {
    const NAME: &'static str = "download.verified_part";
    const VERSION: u32 = 1;
}

/// One peer-supplied part hash, keyed by `(download id, part index)` — the
/// provisional authority's ordered set, read back as a key range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ProvisionalPartHashRow {
    pub part_hash: PartHash,
}

impl ProvisionalPartHashRow {
    pub(super) const fn of(part_hash: &PartHash) -> Self {
        Self {
            part_hash: *part_hash,
        }
    }
}

impl Record for ProvisionalPartHashRow {
    const NAME: &'static str = "download.provisional_part_hash";
    const VERSION: u32 = 1;
}

/// One peer this download distrusts, keyed by `(download id, ordinal)`: it
/// served this file bad data (ADR-0090 "Source ownership"). Kept by
/// User Hash, not address, so the distrust follows the peer to a new one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct DistrustedPeerRow {
    pub user_hash: [u8; UserHash::BYTE_LEN],
}

impl Record for DistrustedPeerRow {
    const NAME: &'static str = "download.distrusted_peer";
    const VERSION: u32 = 1;
}

/// At most one row may write a given `.part` file, so the store refuses the
/// second before anything lands.
pub(super) static PART_PATH: UniqueIndex<&'static str, u64, DownloadRow> =
    UniqueIndex::new("download.part_path", |row| row.part_path.index_text());

/// eD2k file identity is the file hash plus its size. Multimap, not unique: a
/// terminal row keeps its identity, so a completed download does not block a
/// second attempt at the same file — the duplicate rule reads the lifecycles.
pub(super) static IDENTITY: MultimapIndex<([u8; FileHash::BYTE_LEN], u64), u64, DownloadRow> =
    MultimapIndex::new("download.identity", |row| {
        (*row.file_hash.as_bytes(), row.file_size)
    });

pub(super) static DOWNLOADS: Indexed<u64, DownloadRow> =
    Indexed::new("download", &[&PART_PATH, &IDENTITY]);

pub(super) static VERIFIED_PARTS: Children<u64, VerifiedPartRow> =
    Children::new("download.verified_part");

pub(super) static PROVISIONAL_HASHES: Children<u64, ProvisionalPartHashRow> =
    Children::new("download.provisional_part_hash");

/// The counter minting download ids.
pub(super) static DOWNLOAD_IDS: Sequence = Sequence::new("download");

impl DownloadRow {
    /// The row a `create_download` writes: every fact taken from the caller's
    /// link, source hint and paths, queued and unverified.
    pub(super) fn new(
        file: &Ed2kFileLink,
        source_hint: Option<&ServerEndpoint>,
        paths: &DownloadPaths,
    ) -> Self {
        let metadata = DownloadMetadata::from_link(file);
        // A link set that is not the file's own is never recorded: the
        // row's authority and its canonical link agree with the run's.
        let file = Ed2kFileLink {
            part_hash_set: crate::hashing::proven_link_hash_set(file),
            ..file.clone()
        };
        Self {
            file_hash: file.file_hash,
            file_size: metadata.size,
            canonical_link: Ed2kLink::File(file.clone()).to_string(),
            source_hint: source_hint.cloned(),
            final_path: paths.final_path().to_string_lossy().into_owned(),
            part_path: PartPathSlot::held(paths.part_path()),
            lifecycle: DownloadLifecycle::Queued,
            verification_authority: file
                .part_hash_set
                .as_ref()
                .map(|_| VerificationAuthority::LinkPartHashSet),
            file_name: metadata.name,
            metadata_origin: metadata.origin,
            failure: None,
        }
    }

    /// Whether a second row for this file's identity would race this one.
    /// Terminal rows (completed, cancelled) do not.
    pub(super) const fn is_live(&self) -> bool {
        matches!(
            self.lifecycle,
            DownloadLifecycle::Queued
                | DownloadLifecycle::Active
                | DownloadLifecycle::Paused
                | DownloadLifecycle::Failed
        )
    }

    /// Give up the `.part` path a terminal row still names, so a new row may
    /// write it; the slot stays unique by the row's key.
    pub(super) fn release_part_path(&mut self, key: u64) {
        self.part_path = PartPathSlot::released(key);
    }

    /// Whether a caller could still resume this row — the live set minus
    /// `Active`, which belongs to a run that is already on the wire.
    pub(super) const fn is_resumable(&self) -> bool {
        matches!(
            self.lifecycle,
            DownloadLifecycle::Queued | DownloadLifecycle::Paused | DownloadLifecycle::Failed
        )
    }

    /// Where this download's bytes live: the two paths it was created with.
    pub(super) fn paths(&self) -> DownloadPaths {
        DownloadPaths::new(
            self.final_path.clone().into(),
            self.part_path.index_text().into(),
        )
    }

    /// The domain record this row stands for, under the id it is keyed by.
    pub(super) fn to_record(&self, id: DownloadId) -> DurableDownloadRecord {
        DurableDownloadRecord::new(DurableDownloadRecordInput {
            id,
            file_hash: self.file_hash,
            metadata: DownloadMetadata {
                name: self.file_name.clone(),
                size: self.file_size,
                origin: self.metadata_origin,
            },
            canonical_link: self.canonical_link.clone(),
            source_hint: self.source_hint.clone(),
            paths: self.paths(),
            lifecycle: self.lifecycle,
            verification_authority: self.verification_authority,
            failure: self.failure.clone(),
        })
    }
}

impl VerifiedPartRow {
    pub(super) const fn from_record(part: VerifiedPartRecord) -> Self {
        Self {
            offset: part.offset,
            len: part.len,
            part_hash: part.part_hash,
        }
    }

    pub(super) const fn to_record(self, part_index: u32) -> VerifiedPartRecord {
        VerifiedPartRecord {
            part_index,
            offset: self.offset,
            len: self.len,
            part_hash: self.part_hash,
        }
    }
}

pub(super) static DISTRUSTED_PEERS: Children<u64, DistrustedPeerRow> =
    Children::new("download.distrusted_peer");

#[cfg(test)]
mod tests;
