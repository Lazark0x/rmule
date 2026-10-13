//! The durable [`DownloadRepository`]: every download row, its verified parts
//! and its provisional part hashes in the shared [`Store`], composed with the
//! [`ContentFileStore`](crate::ContentFileStore) for the bytes themselves.
//!
//! The record shapes, their indexes and the id counter live in [`row`]; this
//! module is the transaction boundaries. Three writes are atomic by
//! construction rather than by convention (ADR-0083): a create checks its two
//! guards, mints its id and writes the row and both index entries in one
//! transaction; a provisional hash set writes its children and flips the row's
//! authority in one; a lifecycle move reads the current state and writes the
//! next in one. Every method takes `&self`, so a handle is shared, not locked.

mod row;
mod seeds;

pub(crate) use row::{UPGRADE_FROM_V5, UPGRADE_FROM_V6, UPGRADE_FROM_V7, grow_from_v8};
#[cfg(test)]
pub(crate) use row::{schema_v1, seed_v1};
pub use seeds::LoadedSeeds;
pub(crate) use seeds::UPGRADE_FROM_V12;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rmule_primitives::{Ed2kFileLink, PartHash, ServerEndpoint, UserHash};
use rmule_store::{Readable, Store};

use super::Schema;
use crate::content::{Revalidation, revalidate_verified_parts};
use crate::file_history::Ed2kIdentity;
use crate::storage::{DownloadRepository, ResolvedAuthority, resolve_hash_authority};
use crate::{
    CoreError, DownloadFailure, DownloadId, DownloadLifecycle, DownloadPaths,
    DurableDownloadRecord, PartFault, VerificationAuthority, VerifiedPartRecord,
};
use row::{
    DISTRUSTED_PEERS, DOWNLOAD_IDS, DOWNLOADS, DistrustedPeerRow, DownloadRow, IDENTITY, PART_PATH,
    PROVISIONAL_HASHES, ProvisionalPartHashRow, VERIFIED_PARTS, VerifiedPartRow,
};

/// The tables this seam owns, for the store-wide [`Schema`] core assembles
/// before [`Store::open`].
#[must_use]
pub(crate) fn schema() -> Schema {
    Schema::new()
        .indexed(&DOWNLOADS)
        .children(&VERIFIED_PARTS)
        .children(&PROVISIONAL_HASHES)
        .children(&DISTRUSTED_PEERS)
        .children(&seeds::SOURCE_SEEDS)
}

/// The tables this seam owned at store version 12, before the seeds table.
#[cfg(test)]
pub(crate) fn schema_v12() -> Schema {
    Schema::new()
        .indexed(&DOWNLOADS)
        .children(&VERIFIED_PARTS)
        .children(&PROVISIONAL_HASHES)
        .children(&DISTRUSTED_PEERS)
}

/// The durable [`DownloadRepository`]: download rows, verified parts and
/// provisional part hashes in the shared store, part bytes in the content
/// files the rows name. Every method takes `&self` and a clone reaches the
/// same store, so a caller that hands one to core can keep another.
#[derive(Clone, Debug)]
pub struct DurableDownloadRepository {
    store: Arc<Store>,
}

impl DurableDownloadRepository {
    /// A repository over the already-open store. The tables were created by
    /// [`Store::open`] against this module's schema.
    #[must_use]
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    /// Drop the record of each part in `damaged`, the parts revalidation
    /// found no longer holding, so they are fetched again: Resume's effect,
    /// and the Offer Check's (ADR-0113).
    ///
    /// # Errors
    /// [`CoreError::UnknownDownload`] when the row is gone, or
    /// [`CoreError::Repository`].
    pub(crate) fn drop_parts(
        &self,
        id: DownloadId,
        damaged: &[PartFault],
    ) -> Result<(), CoreError> {
        if damaged.is_empty() {
            return Ok(());
        }
        self.store.write(|txn| {
            require_row(txn, id)?;
            for fault in damaged {
                VERIFIED_PARTS
                    .table()
                    .remove(txn, &(id.as_u64(), fault.part_index()))?;
            }
            Ok(())
        })
    }

    /// Record one part as hash-checked and on disk. Upserts on part index, so
    /// re-verifying a part after a repair replaces its child rather than
    /// duplicating it.
    ///
    /// # Errors
    /// [`CoreError::UnknownDownload`] when the row is gone, or
    /// [`CoreError::Repository`].
    pub fn record_verified_part(
        &self,
        id: DownloadId,
        part: VerifiedPartRecord,
    ) -> Result<(), CoreError> {
        self.store.write(|txn| {
            require_row(txn, id)?;
            Ok(VERIFIED_PARTS.put(
                txn,
                id.as_u64(),
                part.part_index,
                &VerifiedPartRow::from_record(part),
            )?)
        })
    }

    /// Where one download's bytes live, without assembling the rest of the
    /// record around them — what the two content-file methods need.
    /// Distrust `peer` for the download's life: it served this file bad data
    /// (ADR-0090 "Source ownership"). A peer already distrusted is left
    /// as it is.
    ///
    /// # Errors
    /// [`CoreError::UnknownDownload`] when the row is gone, or
    /// [`CoreError::Repository`].
    pub fn distrust_peer(&self, id: DownloadId, peer: UserHash) -> Result<(), CoreError> {
        self.store.write(|txn| {
            require_row(txn, id)?;
            let mut held: Vec<DistrustedPeerRow> = DISTRUSTED_PEERS
                .list(txn, id.as_u64())?
                .into_iter()
                .map(|(_, row)| row)
                .collect();
            let row = DistrustedPeerRow {
                user_hash: *peer.as_bytes(),
            };
            if held.contains(&row) {
                return Ok(());
            }
            held.push(row);
            Ok(DISTRUSTED_PEERS.replace(txn, id.as_u64(), held)?)
        })
    }

    /// Every peer the download distrusts, for a resumed run to start from.
    ///
    /// # Errors
    /// [`CoreError::UnknownDownload`] when the row is gone, or
    /// [`CoreError::Repository`].
    pub fn distrusted_peers(&self, id: DownloadId) -> Result<Vec<UserHash>, CoreError> {
        self.store.read(|txn| {
            require_row(txn, id)?;
            Ok(DISTRUSTED_PEERS
                .list(txn, id.as_u64())?
                .into_iter()
                .map(|(_, row)| UserHash::from_bytes(row.user_hash))
                .collect())
        })
    }

    /// Every part path a download row names, with whether its download is
    /// live (queued, active, completing, paused or failed) — for the
    /// **Download Directory Scan**, which skips rmule's own part files by
    /// these paths, not by a suffix (ADR-0102, "Part files are known by their
    /// download rows"). A completing row's destination is listed as live
    /// beside its part path until the row is `Completed`: the move puts the
    /// finished file there before its registry row is written, and the scan
    /// never reads it first (ADR-0115). A part path a terminal row gave up to
    /// a new row is not listed.
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the store read fails.
    pub fn part_files(&self) -> Result<Vec<(PathBuf, bool)>, CoreError> {
        self.store.read(|txn| {
            Ok(DOWNLOADS
                .iter(txn)?
                .into_iter()
                .flat_map(|(_, row)| {
                    let live = row.is_live();
                    let part = row.part_path.held_path().map(|path| (path.into(), live));
                    let destination = (row.lifecycle == DownloadLifecycle::Completing)
                        .then(|| (PathBuf::from(&row.final_path), true));
                    part.into_iter().chain(destination)
                })
                .collect())
        })
    }

    /// Mark the download failed and keep why, in one write (ADR-0094,
    /// "Failed"): the reason outlives the run and the process, so the Failed
    /// mark can name it after a restart.
    ///
    /// # Errors
    /// [`CoreError::UnknownDownload`] when the row is gone, and
    /// [`CoreError::InvalidLifecycleTransition`] from a terminal lifecycle.
    pub fn fail(&self, id: DownloadId, reason: DownloadFailure) -> Result<(), CoreError> {
        self.store.write(|txn| {
            let mut row = read_row(txn, id)?;
            if !row.lifecycle.can_transition_to(DownloadLifecycle::Failed) {
                return Err(CoreError::InvalidLifecycleTransition);
            }
            row.lifecycle = DownloadLifecycle::Failed;
            row.failure = Some(reason);
            Ok(DOWNLOADS.update(txn, &id.as_u64(), &row).map(|_| ())?)
        })
    }

    /// Store `Completing` and the destination the completion move chose, in
    /// one write, before anything moves (ADR-0115): from `Active`, or on a
    /// row already completing whose destination a free name moved. The row
    /// names the one file the move may put at that path.
    ///
    /// # Errors
    /// [`CoreError::UnknownDownload`] when the row is gone, and
    /// [`CoreError::InvalidLifecycleTransition`] from any lifecycle but
    /// `Active` and `Completing`.
    pub fn set_completing(&self, id: DownloadId, destination: &Path) -> Result<(), CoreError> {
        self.store.write(|txn| {
            let mut row = read_row(txn, id)?;
            if !matches!(
                row.lifecycle,
                DownloadLifecycle::Active | DownloadLifecycle::Completing
            ) {
                return Err(CoreError::InvalidLifecycleTransition);
            }
            row.lifecycle = DownloadLifecycle::Completing;
            row.failure = None;
            row.final_path = destination.to_string_lossy().into_owned();
            Ok(DOWNLOADS.update(txn, &id.as_u64(), &row).map(|_| ())?)
        })
    }

    /// Drop the verified-part records of `parts`, which the part file no
    /// longer holds (ADR-0094, "The run holds its part file"), and
    /// return the records dropped, so the caller can say what they cost.
    ///
    /// # Errors
    /// [`CoreError::UnknownDownload`] when the row is gone, or
    /// [`CoreError::Repository`].
    pub fn drop_verified_parts(
        &self,
        id: DownloadId,
        parts: &[u32],
    ) -> Result<Vec<VerifiedPartRecord>, CoreError> {
        self.store.write(|txn| {
            require_row(txn, id)?;
            let mut dropped = Vec::new();
            for (index, row) in VERIFIED_PARTS.list(txn, id.as_u64())? {
                if parts.contains(&index) {
                    VERIFIED_PARTS.table().remove(txn, &(id.as_u64(), index))?;
                    dropped.push(row.to_record(index));
                }
            }
            Ok(dropped)
        })
    }

    /// Drop every verified part of a running download and the provisional
    /// hash set a peer supplied, returning the parts dropped: its finished
    /// file did not hash and no part could be named (ADR-0093, "Finalize with
    /// lost parts"), so what it recorded is wrong and is fetched again.
    ///
    /// # Errors
    /// [`CoreError::UnknownDownload`] when the row is gone, or
    /// [`CoreError::Repository`].
    pub fn drop_every_part(&self, id: DownloadId) -> Result<Vec<VerifiedPartRecord>, CoreError> {
        self.store.write(|txn| {
            let mut row = read_row(txn, id)?;
            let key = id.as_u64();
            let dropped = VERIFIED_PARTS
                .list(txn, key)?
                .into_iter()
                .map(|(index, part)| part.to_record(index))
                .collect();
            VERIFIED_PARTS.clear(txn, key)?;
            PROVISIONAL_HASHES.clear(txn, key)?;
            if row.verification_authority == Some(VerificationAuthority::PeerHashSet) {
                row.verification_authority = None;
                DOWNLOADS.update(txn, &key, &row)?;
            }
            Ok(dropped)
        })
    }

    /// **Start over** a failed download (ADR-0094): discard what is recorded
    /// — its verified parts and the provisional hash set a peer supplied — and
    /// keep its identity, its row and its final path. The row stays `Failed`
    /// with its reason until the run that follows begins. The `.part` file is
    /// the caller's to remove.
    ///
    /// # Errors
    /// [`CoreError::UnknownDownload`] when there is no such row, and
    /// [`CoreError::InvalidLifecycleTransition`] when it is not `Failed`: a
    /// running, paused or queued download still holds what it recorded.
    pub fn discard_progress(&self, id: DownloadId) -> Result<(), CoreError> {
        self.store.write(|txn| {
            let mut row = read_row(txn, id)?;
            if row.lifecycle != DownloadLifecycle::Failed {
                return Err(CoreError::InvalidLifecycleTransition);
            }
            let key = id.as_u64();
            VERIFIED_PARTS.clear(txn, key)?;
            PROVISIONAL_HASHES.clear(txn, key)?;
            if row.verification_authority == Some(VerificationAuthority::PeerHashSet) {
                row.verification_authority = None;
            }
            Ok(DOWNLOADS.update(txn, &key, &row).map(|_| ())?)
        })
    }

    /// Forget a completed download (ADR-0093, "Clearing a completed
    /// download"): its row, its verified parts, its provisional hashes and its
    /// distrusted peers leave in one transaction. The file it finished is the
    /// **Shared File Registry**'s, not this row's, so nothing on disk or in
    /// the registry moves.
    ///
    /// # Errors
    /// [`CoreError::UnknownDownload`] when there is no such row, and
    /// [`CoreError::InvalidLifecycleTransition`] when the row is not
    /// `Completed`: any other still holds its file's place or its mark.
    pub fn clear_completed(&self, id: DownloadId) -> Result<(), CoreError> {
        self.store.write(|txn| {
            if read_row(txn, id)?.lifecycle != DownloadLifecycle::Completed {
                return Err(CoreError::InvalidLifecycleTransition);
            }
            let key = id.as_u64();
            DOWNLOADS.remove(txn, &key)?;
            VERIFIED_PARTS.clear(txn, key)?;
            PROVISIONAL_HASHES.clear(txn, key)?;
            DISTRUSTED_PEERS.clear(txn, key)?;
            seeds::forget(txn, key)?;
            Ok(())
        })
    }

    /// Every download Transfers lists, as the last process left it, in
    /// ascending order: each that still holds its file's place, and each
    /// completed one until the operator clears it (ADR-0093, "Clearing a
    /// completed download"). A cancelled one is not listed.
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the store read fails.
    pub fn listed_downloads(&self) -> Result<Vec<DurableDownloadRecord>, CoreError> {
        self.store.read(|txn| {
            Ok(DOWNLOADS
                .iter(txn)?
                .into_iter()
                .filter(|(_, row)| row.lifecycle != DownloadLifecycle::Cancelled)
                .map(|(key, row)| row.to_record(DownloadId::from_u64(key)))
                .collect())
        })
    }

    /// Every completed download's id, in ascending order.
    ///
    /// # Errors
    /// [`CoreError::Repository`] when the store read fails.
    pub fn completed_downloads(&self) -> Result<Vec<DownloadId>, CoreError> {
        self.store.read(|txn| {
            Ok(DOWNLOADS
                .iter(txn)?
                .into_iter()
                .filter(|(_, row)| row.lifecycle == DownloadLifecycle::Completed)
                .map(|(key, _)| DownloadId::from_u64(key))
                .collect())
        })
    }
}

/// The row under `id`, or [`CoreError::UnknownDownload`].
fn read_row(txn: &impl Readable, id: DownloadId) -> Result<DownloadRow, CoreError> {
    DOWNLOADS
        .get(txn, &id.as_u64())?
        .ok_or(CoreError::UnknownDownload)
}

/// Refuse a child write whose parent is gone, without decoding the parent.
fn require_row(txn: &impl Readable, id: DownloadId) -> Result<(), CoreError> {
    if DOWNLOADS.contains(txn, &id.as_u64())? {
        Ok(())
    } else {
        Err(CoreError::UnknownDownload)
    }
}

/// The download's provisional hashes in part order. Assumes the row was
/// already checked for existence.
fn read_provisional(txn: &impl Readable, id: DownloadId) -> Result<Vec<PartHash>, CoreError> {
    Ok(PROVISIONAL_HASHES
        .list(txn, id.as_u64())?
        .into_iter()
        .map(|(_, hash)| hash.part_hash)
        .collect())
}

/// Every resumable row on `txn`, in ascending id order.
fn resumable_records(txn: &impl Readable) -> Result<Vec<DurableDownloadRecord>, CoreError> {
    Ok(DOWNLOADS
        .iter(txn)?
        .into_iter()
        .filter(|(_, row)| row.is_resumable())
        .map(|(key, row)| row.to_record(DownloadId::from_u64(key)))
        .collect())
}

impl DownloadRepository for DurableDownloadRepository {
    /// Mint a row for `file` and return it with the id it was given. Refuses
    /// with [`CoreError::PathConflict`] when the destination exists or another
    /// row already writes that `.part`, and with
    /// [`CoreError::DuplicateDownloadIdentity`] when a live row already holds
    /// the same hash and size. Both guards, the id and the row share one
    /// transaction, so a refused create leaves nothing behind.
    ///
    /// A completed or cancelled row writes no `.part` any more, so it gives
    /// its `.part` path up to the new row rather than refuse it: re-adding a
    /// file once cancelled, to the same place, is a new download (ADR-0100,
    /// "Adding a marked file").
    fn create_download(
        &self,
        file: &Ed2kFileLink,
        source_hint: Option<&ServerEndpoint>,
        paths: &DownloadPaths,
    ) -> Result<DurableDownloadRecord, CoreError> {
        if paths.final_path().exists() {
            return Err(CoreError::PathConflict);
        }
        let new = DownloadRow::new(file, source_hint, paths);
        self.store.write(|txn| {
            if let Some(holder) =
                DOWNLOADS.by_unique(txn, &PART_PATH, new.part_path.index_text())?
            {
                let mut row = read_row(txn, DownloadId::from_u64(holder))?;
                if row.is_live() {
                    return Err(CoreError::PathConflict);
                }
                row.release_part_path(holder);
                DOWNLOADS.update(txn, &holder, &row)?;
            }
            let identity = (*new.file_hash.as_bytes(), new.file_size);
            for other in DOWNLOADS.by_multi(txn, &IDENTITY, identity)? {
                if DOWNLOADS.get(txn, &other)?.is_some_and(|row| row.is_live()) {
                    return Err(CoreError::DuplicateDownloadIdentity);
                }
            }

            let id = DownloadId::from_u64(DOWNLOAD_IDS.next(txn)?);
            DOWNLOADS.insert(txn, &id.as_u64(), &new)?;
            Ok(new.to_record(id))
        })
    }

    /// Read one row back, or [`CoreError::UnknownDownload`] when there is none.
    fn load_download(&self, id: DownloadId) -> Result<DurableDownloadRecord, CoreError> {
        self.store.read(|txn| Ok(read_row(txn, id)?.to_record(id)))
    }

    /// Every queued, paused or failed row, in ascending id order. Completed
    /// and cancelled rows are excluded — nothing can resume them.
    fn list_resumable(&self) -> Result<Vec<DurableDownloadRecord>, CoreError> {
        self.store.read(resumable_records)
    }

    fn list_cancelled(&self) -> Result<Vec<Ed2kIdentity>, CoreError> {
        self.store.read(|txn| {
            Ok(DOWNLOADS
                .iter(txn)?
                .into_iter()
                .filter(|(_, row)| row.lifecycle == DownloadLifecycle::Cancelled)
                .map(|(_, row)| Ed2kIdentity::new(row.file_hash, row.file_size))
                .collect())
        })
    }

    /// Move a row's lifecycle, rejecting a transition the state machine
    /// forbids with [`CoreError::InvalidLifecycleTransition`] — completed and
    /// cancelled rows never move again.
    fn set_lifecycle(&self, id: DownloadId, state: DownloadLifecycle) -> Result<(), CoreError> {
        self.store.write(|txn| {
            let mut row = read_row(txn, id)?;
            if !row.lifecycle.can_transition_to(state) {
                return Err(CoreError::InvalidLifecycleTransition);
            }
            row.lifecycle = state;
            // A reason belongs to the failure it explains; every other
            // lifecycle has none (`fail` writes both together).
            row.failure = None;
            // A finished or dropped download keeps no peers (ADR-0109,
            // "Source Seeds"): they leave in the move that ends it.
            if !row.is_live() {
                seeds::forget(txn, id.as_u64())?;
            }
            Ok(DOWNLOADS.update(txn, &id.as_u64(), &row).map(|_| ())?)
        })
    }

    /// The download's verified parts in ascending part order — what a resume
    /// re-hashes and then skips fetching.
    fn verified_parts(&self, id: DownloadId) -> Result<Vec<VerifiedPartRecord>, CoreError> {
        self.store.read(|txn| {
            require_row(txn, id)?;
            Ok(VERIFIED_PARTS
                .list(txn, id.as_u64())?
                .into_iter()
                .map(|(part_index, part)| part.to_record(part_index))
                .collect())
        })
    }

    /// Store a peer-supplied part hash set for the download: the children,
    /// the row's new authority and the drop of every verified part the set
    /// disproves land in one transaction, so no reader can see a
    /// half-recorded set or a part the set in force refutes. A part written
    /// while no set was held was recorded with the hash of its own bytes; one
    /// whose recorded hash is not the set's at its index is dropped and
    /// returned, to be fetched again (ADR-0113). Refused with
    /// [`CoreError::ProvisionalAuthorityConflict`] when the row already
    /// verifies under the link's own set, which always wins, or when a
    /// *different* set is already recorded.
    fn record_provisional_part_hashes(
        &self,
        id: DownloadId,
        hashes: &[PartHash],
    ) -> Result<Vec<VerifiedPartRecord>, CoreError> {
        self.store.write(|txn| {
            let mut row = read_row(txn, id)?;
            if row.verification_authority == Some(VerificationAuthority::LinkPartHashSet) {
                return Err(CoreError::ProvisionalAuthorityConflict);
            }
            let existing = read_provisional(txn, id)?;
            if !existing.is_empty() {
                return if existing == hashes {
                    Ok(Vec::new())
                } else {
                    Err(CoreError::ProvisionalAuthorityConflict)
                };
            }

            PROVISIONAL_HASHES.replace(
                txn,
                id.as_u64(),
                hashes.iter().map(ProvisionalPartHashRow::of),
            )?;
            row.verification_authority = Some(VerificationAuthority::PeerHashSet);
            DOWNLOADS.update(txn, &id.as_u64(), &row)?;
            let mut disproved = Vec::new();
            for (index, part) in VERIFIED_PARTS.list(txn, id.as_u64())? {
                let part = part.to_record(index);
                if hashes.get(index as usize) != Some(&part.part_hash) {
                    VERIFIED_PARTS.table().remove(txn, &(id.as_u64(), index))?;
                    disproved.push(part);
                }
            }
            Ok(disproved)
        })
    }

    /// The stored peer-supplied hashes in part order, empty when none were
    /// recorded.
    fn provisional_part_hashes(&self, id: DownloadId) -> Result<Vec<PartHash>, CoreError> {
        self.store.read(|txn| {
            require_row(txn, id)?;
            read_provisional(txn, id)
        })
    }

    fn hash_authority(&self, id: DownloadId) -> Result<ResolvedAuthority, CoreError> {
        self.store.read(|txn| {
            let row = read_row(txn, id)?;
            let provisional = read_provisional(txn, id)?;
            Ok(resolve_hash_authority(&row.canonical_link, &provisional))
        })
    }

    fn live_downloads(&self) -> Result<Vec<DurableDownloadRecord>, CoreError> {
        self.store.read(|txn| {
            let mut live = Vec::new();
            for (key, row) in DOWNLOADS.iter(txn)? {
                if row.is_live() {
                    live.push(row.to_record(DownloadId::from_u64(key)));
                }
            }
            Ok(live)
        })
    }

    async fn revalidate(&self, id: DownloadId) -> Result<Revalidation, CoreError> {
        let record = self.load_download(id)?;
        let parts = self.verified_parts(id)?;
        let revalidation = revalidate_verified_parts(record.paths(), &parts).await;
        if let Revalidation::Restored { damaged, .. } = &revalidation {
            self.drop_parts(id, damaged)?;
        }
        Ok(revalidation)
    }
}
