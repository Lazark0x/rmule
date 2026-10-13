//! Persisting what a download earned: one verified part written through the
//! run's **Held Part File** and recorded against the download, and the
//! repair a finished file that does not hash asks for. Fallible effects, so
//! the sans-I/O brain asks for them as decisions and resumes on the result;
//! the completion move itself is the runner's (ADR-0115).
//!
//! The part file is the operator's to delete (ADR-0094, "The run holds its
//! part file"). A run that finds the file at its path gone, replaced
//! or cut short says what that cost ([`DownloadEvent::PartFileLost`]), drops
//! the verified parts it lost, and never writes into a file nobody can reach:
//! gone or replaced fails the download, cut short repairs it in place — the
//! run asks again and fetches the lost parts, keeping every part that holds.
//! The completion move's check repairs the same way when the whole file does
//! not hash.

use ed2k::digest::Digest;
use rmule_primitives::{Ed2kFileLink, PartHash};
use tokio::sync::mpsc;

use crate::adapters::{PeerTransferService, SourceLookupService};
use crate::content::{
    HeldPartFile, HeldWriteError, HoleVerdict, PartFileChange, Revalidation, probe_holes,
};
use crate::download::runner::RunnerContext;
use crate::durable::VerifiedPartRecord;
use crate::error::{DownloadFailure, StorageIntegrityFault};
use crate::hashing::{ResolvedHashSet, part_hash_on_arrival, verify_part_bytes};
use crate::service::{CoreEvent, DownloadEvent, DownloadId, PartsLost, send_download_event};
use crate::storage::DownloadRepository;

/// Why a part was not persisted.
pub(super) enum PersistError {
    /// The brain's own affair: the bytes did not verify, or the write failed.
    Rejected(DownloadFailure),
    /// The run ends with this failure: the part file changed under it (what
    /// that cost is already said and dropped; a repair, when the run was
    /// marked for one, is not a failure the operator sees), or the Durable
    /// Store could not record the part.
    Ended(DownloadFailure),
}

/// Open the run's part file and hold it (ADR-0094): created for a download
/// with nothing recorded, opened as it is otherwise. A repaired run keeps the
/// handle it already holds. A newly held file publishes the run-start
/// Allocated Bytes reading, then the run's Hole Probe runs beside the
/// `.part` and publishes its verdict (ADR-0111); no verdict refuses the run.
/// A `HoleLess` one is also told as [`DownloadEvent::HoleLessDestination`],
/// so once per run.
pub(super) async fn hold_part_file<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
) -> Result<(), DownloadFailure> {
    let mut held = runner.part_file.lock().await;
    if held.is_some() {
        return Ok(());
    }
    let store_failed = |_| DownloadFailure::StoreFailed;
    let record = runner
        .rt
        .store
        .load_download(download_id)
        .map_err(store_failed)?;
    let parts = runner
        .rt
        .store
        .verified_parts(download_id)
        .map_err(store_failed)?;
    let part_path = record.paths().part_path();
    match HeldPartFile::hold(part_path, recorded_end(&parts)).await {
        Ok((file, allocated)) => {
            *held = Some(file);
            let diagnostics = &runner.rt.diagnostics;
            diagnostics.part_file_read(download_id, allocated);
            let verdict = probe_holes(part_path).await;
            diagnostics.hole_probed(download_id, verdict);
            // A probe that answered named a file, so its path has a parent.
            if verdict == HoleVerdict::HoleLess
                && let Some(directory) = part_path.parent()
            {
                send_download_event(
                    &runner.rt.evt_tx,
                    DownloadEvent::HoleLessDestination {
                        download_id,
                        directory: directory.to_path_buf(),
                    },
                )
                .await;
            }
            Ok(())
        }
        Err(HeldWriteError::Changed(_)) => Err(DownloadFailure::StorageIntegrityFailed(
            StorageIntegrityFault::PartFileMissing,
        )),
        Err(HeldWriteError::Io(error)) => {
            tracing::warn!(%error, "the part file could not be opened");
            Err(DownloadFailure::StorageIntegrityFailed(
                StorageIntegrityFault::PartFileUnreadable {
                    os_code: error.raw_os_error(),
                },
            ))
        }
    }
}

/// How often a run that waits — for a connection, or for sources with no
/// worker and no callback out — looks at its part file: one `stat` of
/// the path and one of the held handle, per waiting download, each second.
/// A part file deleted while the run waits is said within the second, not
/// when the next part arrives.
pub(crate) const WAITING_PART_FILE_CHECK: std::time::Duration = std::time::Duration::from_secs(1);

/// Look at the held part file between parts: when the run leaves a
/// wait, and on the tick while it waits. A change is said and costs what it
/// costs, as at a part boundary; the run ends with the failure it answers.
pub(super) async fn check_held_part_file<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
) -> Result<(), DownloadFailure> {
    let mut held = runner.part_file.lock().await;
    if let Some(part_file) = held.as_mut()
        && let Err(change) = part_file.check().await
    {
        return Err(part_file_changed(runner, download_id, part_file, change).await);
    }
    Ok(())
}

/// Where the highest recorded part ends.
fn recorded_end(parts: &[VerifiedPartRecord]) -> u64 {
    parts
        .iter()
        .map(|part| part.offset.saturating_add(part.len))
        .max()
        .unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn persist_streamed_part<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    file: &Ed2kFileLink,
    resolved: &ResolvedHashSet,
    part_index: u32,
    offset: u64,
    bytes: &[u8],
    file_hash_only_parts: &mut Vec<u32>,
    evt_tx: &mpsc::Sender<CoreEvent>,
) -> Result<(), PersistError>
where
    S: SourceLookupService,
    P: PeerTransferService,
{
    let (part_hash, verified) =
        if let Some(expected) = part_hash_on_arrival(resolved, file, part_index) {
            verify_part_bytes(expected, bytes).map_err(PersistError::Rejected)?;
            (expected, true)
        } else if resolved.hashes.is_empty() {
            (
                PartHash::from_bytes(ed2k::Ed2kBlue::digest(bytes).into()),
                false,
            )
        } else {
            return Err(PersistError::Rejected(
                DownloadFailure::PartVerificationFailed,
            ));
        };
    let record = VerifiedPartRecord {
        part_index,
        offset,
        len: bytes.len() as u64,
        part_hash,
    };
    write_through_held(runner, download_id, record, bytes).await?;
    if verified {
        tracing::info!(
            download_id = download_id.as_u64(),
            part_index,
            "part verified",
        );
        send_download_event(
            evt_tx,
            DownloadEvent::PartVerified {
                download_id,
                part_index,
            },
        )
        .await;
    } else {
        file_hash_only_parts.push(part_index);
    }
    Ok(())
}

/// Write `bytes` through the held part file and record the part — or, when
/// the file at the path is not the one held, say what that cost.
async fn write_through_held<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    record: VerifiedPartRecord,
    bytes: &[u8],
) -> Result<(), PersistError> {
    let rejected = || PersistError::Rejected(DownloadFailure::PartVerificationFailed);
    let mut held = runner.part_file.lock().await;
    let file = held.as_mut().ok_or_else(rejected)?;
    match file.write_part(record.offset, bytes).await {
        Ok(allocated) => {
            runner.rt.diagnostics.part_file_read(download_id, allocated);
            runner
                .rt
                .store
                .record_verified_part(download_id, record)
                .map_err(|error| {
                    tracing::warn!(%error, "a verified part could not be recorded");
                    PersistError::Ended(DownloadFailure::StoreFailed)
                })
        }
        Err(HeldWriteError::Io(error)) => {
            tracing::warn!(%error, "a verified part could not be written to the part file");
            Err(rejected())
        }
        Err(HeldWriteError::Changed(change)) => Err(PersistError::Ended(
            part_file_changed(runner, download_id, file, change).await,
        )),
    }
}

/// The part file changed under the run: drop the verified parts it lost, say
/// what that cost, and answer the failure the run ends with. A file cut short
/// marks the run for repair; a file gone or replaced fails the download. The
/// change is told even when the store cannot say which parts were lost: then
/// no count is told, and the download fails as a store failure.
pub(super) async fn part_file_changed<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    held: &mut HeldPartFile,
    change: PartFileChange,
) -> DownloadFailure {
    let dropped = runner
        .rt
        .store
        .verified_parts(download_id)
        .and_then(|recorded| {
            let lost: Vec<u32> = recorded
                .iter()
                .filter(|part| match change {
                    PartFileChange::Gone | PartFileChange::Replaced => true,
                    PartFileChange::Truncated { len } => part.offset.saturating_add(part.len) > len,
                })
                .map(|part| part.part_index)
                .collect();
            let dropped = runner.rt.store.drop_verified_parts(download_id, &lost)?;
            runner.rt.diagnostics.parts_lost(download_id, &lost);
            Ok(dropped)
        });
    let lost = match &dropped {
        Ok(dropped) => PartsLost::Counted {
            parts: u32::try_from(dropped.len()).unwrap_or(u32::MAX),
            bytes: dropped.iter().map(|part| part.len).sum::<u64>(),
        },
        Err(error) => {
            tracing::warn!(
                download_id = download_id.as_u64(),
                %change,
                %error,
                "the part file changed and the store could not say what that cost",
            );
            PartsLost::NotCounted
        }
    };
    if let PartsLost::Counted { parts, bytes } = lost {
        tracing::warn!(
            download_id = download_id.as_u64(),
            %change,
            parts_lost = parts,
            bytes_lost = bytes,
            "the part file changed under the running download",
        );
    }
    send_download_event(
        &runner.rt.evt_tx,
        DownloadEvent::PartFileLost {
            download_id,
            found: change,
            lost,
        },
    )
    .await;
    if dropped.is_err() {
        return DownloadFailure::StoreFailed;
    }
    match change {
        PartFileChange::Truncated { .. } => {
            let still = match runner.rt.store.verified_parts(download_id) {
                Ok(still) => still,
                Err(error) => {
                    tracing::warn!(
                        download_id = download_id.as_u64(),
                        %error,
                        "the store could not say which parts still hold",
                    );
                    return DownloadFailure::StoreFailed;
                }
            };
            held.parts_dropped(recorded_end(&still));
            runner.mark_for_repair();
            DownloadFailure::PartVerificationFailed
        }
        PartFileChange::Gone | PartFileChange::Replaced => {
            DownloadFailure::StorageIntegrityFailed(StorageIntegrityFault::PartFileMissing)
        }
    }
}

/// The whole file did not hash (ADR-0094, "Finalize with lost parts"):
/// re-check every recorded part, drop those that fail and fetch them again.
/// When no part can be named — a file verified by its file hash alone —
/// every recorded part is dropped. Only a part file that is gone or
/// unreadable fails the download.
pub(super) async fn repair_at_finalize<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
) -> DownloadFailure {
    match runner.rt.store.revalidate(download_id).await {
        Ok(Revalidation::Condemned(fault)) => DownloadFailure::StorageIntegrityFailed(fault),
        Ok(Revalidation::Restored { damaged, .. }) if !damaged.is_empty() => {
            let lost: Vec<u32> = damaged.iter().map(crate::PartFault::part_index).collect();
            runner.rt.diagnostics.parts_lost(download_id, &lost);
            send_download_event(
                &runner.rt.evt_tx,
                DownloadEvent::DamagedPartsDropped {
                    download_id,
                    damaged,
                },
            )
            .await;
            runner.mark_for_repair();
            DownloadFailure::PartVerificationFailed
        }
        Ok(Revalidation::Restored { .. }) => {
            // Every part holds against its record, yet the file does not hash:
            // the records themselves are wrong (a file-hash-only download, or a
            // peer's hash set that lied consistently). Nothing can be named,
            // so every part and the peer's hash set go.
            let Ok(dropped) = runner.rt.store.drop_every_part(download_id) else {
                return DownloadFailure::StoreFailed;
            };
            let lost: Vec<u32> = dropped.iter().map(|part| part.part_index).collect();
            runner.rt.diagnostics.parts_lost(download_id, &lost);
            send_download_event(
                &runner.rt.evt_tx,
                DownloadEvent::FinishedFileRejected {
                    download_id,
                    parts_dropped: u32::try_from(dropped.len()).unwrap_or(u32::MAX),
                    bytes_dropped: dropped.iter().map(|part| part.len).sum(),
                },
            )
            .await;
            runner.mark_for_repair();
            DownloadFailure::PartVerificationFailed
        }
        Err(_) => DownloadFailure::StoreFailed,
    }
}

/// Keep why a download failed on its row, and tell it. The failure is told
/// either way; a store that could not keep it is told after it
/// ([`DownloadEvent::FailureNotRecorded`]), since the row then keeps the
/// lifecycle it had and the next start reads that one.
pub(crate) async fn record_failure(
    store: &crate::store::download::DurableDownloadRepository,
    evt_tx: &mpsc::Sender<CoreEvent>,
    download_id: DownloadId,
    reason: DownloadFailure,
) {
    let kept = store.fail(download_id, reason.clone());
    tracing::error!(
        download_id = download_id.as_u64(),
        reason = %reason,
        "download failed",
    );
    send_download_event(
        evt_tx,
        DownloadEvent::DownloadFailed {
            download_id,
            reason,
        },
    )
    .await;
    if let Err(error) = kept {
        tracing::warn!(
            download_id = download_id.as_u64(),
            %error,
            "the store could not record why the download failed",
        );
        send_download_event(evt_tx, DownloadEvent::FailureNotRecorded { download_id }).await;
    }
}

#[cfg(test)]
mod tests;
