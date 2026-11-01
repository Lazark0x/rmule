//! Persisting what a download earned: one verified part written through the
//! run's **Held Part File** and recorded against the download, the distrusted
//! peers and the Kad AICH root a resumed run starts with, and the repair a
//! finished file that does not hash asks for. Fallible effects, so
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
//!
//! A local failure is no peer's fault (ADR-0094, "A volume's refusal is a
//! Volume Stop"): a write the volume refuses, a volume under its free-space
//! floor and a path that names nothing over a whole file end the run as a
//! pause, keep every verified part and reach no verdict.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use rmule_primitives::{
    AichHashSet, AichRootHash, Ed2kFileLink, Ed2kLink, PartHash, PartHashSet, UserHash,
};

use crate::assembly::{ArrivedPart, CellHash};
use crate::content::{
    HeldCheckFailed, HeldPartFile, HeldWriteError, HoleVerdict, PartFileChange, Revalidation,
    on_pool, part_link, probe_holes,
};
use crate::download::runner::RunnerContext;
use crate::durable::{DownloadLifecycle, VerifiedPartRecord};
use crate::error::{CoreError, DownloadFailure, StorageIntegrityFault};
use crate::hashing::{ResolvedHashSet, part_hash_on_arrival};
use crate::planning::PartPlan;
use crate::service::{DownloadEvent, DownloadId, PartsLost, VolumeStop, send_download_event};
use crate::storage::DownloadRepository;

/// Why a part was not persisted.
pub(super) enum PersistError {
    /// The brain's own affair: the bytes did not verify.
    Rejected(DownloadFailure),
    /// The run ends with this failure: the part file changed under it (what
    /// that cost is already said and dropped; a repair, when the run was
    /// marked for one, is not a failure the operator sees), the Durable
    /// Store could not record the part, or the volume stopped the run.
    Ended(DownloadFailure),
}

/// Say once that a failed write stopped the store (ADR-0083).
pub(crate) fn tell_store_stop(
    store: &crate::store::download::DurableDownloadRepository,
    evt_tx: &crate::service::Outbox,
) {
    if store.store_stop_to_tell() {
        tracing::warn!("a failed write stopped the store until the next start");
        send_download_event(evt_tx, DownloadEvent::StoreStopped);
    }
}

/// The store refused `what`: the run ends on it, and the cause goes to the Run
/// Log, since `StoreFailed` is all the operator's sentence can name.
pub(crate) fn store_failed(what: &'static str) -> impl Fn(CoreError) -> DownloadFailure {
    move |error| {
        tracing::warn!(%error, "{what}");
        DownloadFailure::StoreFailed
    }
}

/// Keep the link beside the part file, off the run's way (ADR-0083). A line
/// that fails costs only the rescue it would have allowed.
fn keep_link_line(part_path: PathBuf, link: String) {
    tokio::task::spawn_blocking(move || keep_or_warn(&part_path, &link));
}

fn keep_or_warn(part_path: &Path, link: &str) {
    if let Err(error) = part_link::keep(part_path, link) {
        tracing::warn!(%error, "the line beside a part file could not be written");
    }
}

/// The line a run starts with: the set a peer gave an earlier run when the
/// store holds one, or the link when no line stands, which must not replace
/// one that says more.
fn line_for_the_run<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    record: &crate::DurableDownloadRecord,
) {
    match runner.rt.store.provisional_part_hashes(download_id) {
        Ok(hashes) if !hashes.is_empty() => hash_set_learned(runner, download_id, &hashes),
        _ => {
            let part_path = record.paths().part_path().to_path_buf();
            let link = record.canonical_link().to_owned();
            tokio::task::spawn_blocking(move || {
                if part_link::beside(&part_path).is_some_and(|line| !line.exists()) {
                    keep_or_warn(&part_path, &link);
                }
            });
        }
    }
}

/// The run learned its Part Hash Set: the line says so, since a part is
/// verified only under one, and a line without it could prove none of them.
pub(crate) fn hash_set_learned<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    hashes: &[PartHash],
) {
    let Ok(record) = runner.rt.store.load_download(download_id) else {
        return;
    };
    let Ok(mut link) = record.file_link() else {
        return;
    };
    let Ok(set) = PartHashSet::from_hashes(link.size(), hashes.to_vec()) else {
        return;
    };
    link.part_hash_set = Some(set);
    keep_link_line(
        record.paths().part_path().to_path_buf(),
        Ed2kLink::File(link).to_string(),
    );
}

/// Open the run's part file and hold it (ADR-0094): created for a download
/// with nothing recorded, opened as it is otherwise. A repaired run keeps the
/// handle it already holds. A newly held file publishes the run-start
/// Allocated Bytes reading, then — the first time the run holds it — the
/// run's Hole Probe runs beside the `.part` and publishes its verdict
/// (ADR-0111); no verdict refuses the run. A `HoleLess` one is also told as
/// [`DownloadEvent::HoleLessDestination`], so once per run: a run whose
/// finished file did not hash holds the file again and probes nothing.
pub(super) async fn hold_part_file<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
) -> Result<(), DownloadFailure> {
    let mut held = runner.part_file.lock().await;
    if held.is_some() {
        return Ok(());
    }
    let record = runner
        .rt
        .store
        .load_download(download_id)
        .map_err(store_failed("the download's row could not be read"))?;
    let parts = runner
        .rt
        .store
        .verified_parts(download_id)
        .map_err(store_failed("the verified parts could not be read"))?;
    let part_path = record.paths().part_path();
    match HeldPartFile::hold(part_path, recorded_end(&parts)).await {
        Ok((file, allocated)) => {
            // Whatever a leftover held past the file's end never lands
            // (ADR-0115).
            if let Err(error) = file.cut_to(record.file_size()).await {
                tracing::warn!(%error, "the part file could not be cut to the file's size");
                return Err(DownloadFailure::StorageIntegrityFailed(
                    StorageIntegrityFault::PartFileUnreadable {
                        os_code: error.raw_os_error(),
                    },
                ));
            }
            *held = Some(file.recorded_in(runner.rt.store.store_directory()));
            line_for_the_run(runner, download_id, &record);
            let diagnostics = &runner.rt.diagnostics;
            diagnostics.part_file_read(download_id, allocated);
            if runner.hole_probed.swap(true, Ordering::SeqCst) {
                return Ok(());
            }
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
                );
            }
            Ok(())
        }
        Err(
            HeldWriteError::Changed(_)
            | HeldWriteError::PathAbsent
            | HeldWriteError::OutOfSpace { .. },
        ) => Err(DownloadFailure::StorageIntegrityFailed(
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

/// The peers the download's record distrusts, for the run to start with: a
/// resumed run does not dial again a peer that served it bad data. A record
/// the store cannot read ends the start as a store failure — a run that
/// started without it would forget every distrust the download earned.
pub(super) fn distrusted_at_start<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
) -> Result<HashSet<UserHash>, DownloadFailure> {
    runner
        .rt
        .store
        .distrusted_peers(download_id)
        .map(|peers| peers.into_iter().collect())
        .map_err(|error| {
            tracing::warn!(%error, "could not read the download's distrusted peers");
            DownloadFailure::StoreFailed
        })
}

/// The Kad AICH root the download's record keeps, or the contest that ended
/// it, for the run to start under (ADR-0038). A record the store cannot read
/// ends the start as a store failure, as the distrusted peers do: a run that
/// started without it would trust a root its peers already contested.
pub(super) fn kad_aich_root_at_start<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
) -> Result<Option<crate::KadAichRoot>, DownloadFailure> {
    runner
        .rt
        .store
        .load_download(download_id)
        .map(|record| record.kad_aich_root())
        .map_err(|error| {
            tracing::warn!(%error, "could not read the download's Kad AICH root");
            DownloadFailure::StoreFailed
        })
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
        && let Err(failed) = part_file.check().await
    {
        return Err(check_failed(runner, download_id, part_file, failed).await);
    }
    Ok(())
}

/// What a look at the held part file found costs: a change is said and costs
/// what it costs, an absent path over a whole file is a Volume Stop. Answers
/// the failure the run ends with.
pub(super) async fn check_failed<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    held: &mut HeldPartFile,
    failed: HeldCheckFailed,
) -> DownloadFailure {
    match failed {
        HeldCheckFailed::Changed(change) => {
            part_file_changed(runner, download_id, held, change).await
        }
        HeldCheckFailed::PathAbsent => runner.stop_for_volume(VolumeStop::PartFileOutOfReach),
    }
}

/// Where the highest recorded part ends.
fn recorded_end(parts: &[VerifiedPartRecord]) -> u64 {
    parts
        .iter()
        .map(|part| part.offset.saturating_add(part.len))
        .max()
        .unwrap_or(0)
}

/// What a landed part proved: whether its own hash checked it, or only the
/// whole file's will.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Landed {
    /// A part hash the run trusts matched it.
    Verified,
    /// No part hash stands yet: the file hash proves it at completion.
    FileHashOnly,
}

/// What a part's check came to, with what the file held for each cell when
/// the brain will judge by it (ADR-0117 §1).
pub(super) struct PartChecked {
    /// What the part proved, or why it did not land.
    pub(super) result: Result<Landed, PersistError>,
    /// Each cell's hash: read on a failure, and when the part's check asked.
    pub(super) cells: Option<Vec<CellHash>>,
}

/// Why a part stopped short of a verdict, for the lane to carry to the end of
/// the run.
fn ended(failure: DownloadFailure) -> PartChecked {
    PartChecked {
        result: Err(PersistError::Ended(failure)),
        cells: None,
    }
}

/// Check the part `plan` covers from the file, behind every byte written
/// before it, on the blocking pool (ADR-0031), and record it: the file is
/// looked at first, and a read the volume refuses is the volume's fault, no
/// peer's. A part whose bytes fail keeps each cell's hash for the brain.
pub(super) async fn persist_streamed_part<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    file: &Ed2kFileLink,
    resolved: &ResolvedHashSet,
    plan: PartPlan,
    read_cells: bool,
) -> PartChecked
where
    S: Send,
    P: Send,
{
    let part_index = plan.part_index;
    let expected = part_hash_on_arrival(resolved, file, part_index.value());
    let mut held = runner.part_file.lock().await;
    let Some(held) = held.as_mut() else {
        return ended(DownloadFailure::StorageIntegrityFailed(
            StorageIntegrityFault::PartFileMissing,
        ));
    };
    if let Err(failed) = held.check().await {
        return ended(check_failed(runner, download_id, held, failed).await);
    }
    let unnamed = expected.is_none() && !resolved.hashes.is_empty();
    let read = match held.read_part(plan, read_cells || unnamed).await {
        Ok(read) => read,
        Err(error) => return ended(read_refused(runner, &error)),
    };
    let (part_hash, cells) = read;
    let matched = expected.is_none_or(|expected| expected == part_hash);
    if unnamed || !matched {
        let cells = match cells {
            Some(cells) => cells,
            None => match held.read_part(plan, true).await {
                Ok((_, Some(cells))) => cells,
                Ok((_, None)) => Vec::new(),
                Err(error) => return ended(read_refused(runner, &error)),
            },
        };
        return PartChecked {
            result: Err(PersistError::Rejected(
                DownloadFailure::PartVerificationFailed,
            )),
            cells: Some(cells),
        };
    }
    let landed = if expected.is_some() {
        Landed::Verified
    } else {
        Landed::FileHashOnly
    };
    let record = VerifiedPartRecord {
        part_index: part_index.value(),
        offset: plan.offset,
        len: plan.len,
        part_hash,
    };
    // A commit syncs: it holds a pool thread, not a runtime worker.
    let store = Arc::clone(&runner.rt.store);
    let recorded = on_pool(move || store.record_verified_part(download_id, record)).await;
    if let Err(error) = recorded {
        tracing::warn!(%error, "a verified part could not be recorded");
        return ended(DownloadFailure::StoreFailed);
    }
    if landed == Landed::Verified {
        tracing::info!(
            download_id = download_id.as_u64(),
            part_index = part_index.value(),
            "part verified",
        );
        send_download_event(
            &runner.rt.evt_tx,
            DownloadEvent::PartVerified {
                download_id,
                part_index: part_index.value(),
            },
        );
    }
    PartChecked {
        result: Ok(landed),
        cells,
    }
}

/// A read of the run's own file failed: the volume's refusal, no verdict.
fn read_refused<S, P>(runner: &RunnerContext<S, P>, error: &std::io::Error) -> DownloadFailure {
    tracing::warn!(%error, "the part file could not be read back");
    runner.stop_for_volume(VolumeStop::WriteRefused {
        os_code: error.raw_os_error(),
    })
}

/// Write `blocks` through the held part file. What the volume refuses ends the
/// run as a Volume Stop, and a file that changed says what that cost: either
/// way nothing behind these bytes on the lane may run.
pub(super) async fn write_blocks<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    blocks: Vec<(u64, Vec<u8>)>,
) -> Result<(), DownloadFailure>
where
    S: Send,
    P: Send,
{
    let mut held = runner.part_file.lock().await;
    let file = held
        .as_mut()
        .ok_or(DownloadFailure::StorageIntegrityFailed(
            StorageIntegrityFault::PartFileMissing,
        ))?;
    match file.write_blocks(blocks).await {
        Ok(allocated) => {
            runner.rt.diagnostics.part_file_read(download_id, allocated);
            Ok(())
        }
        Err(HeldWriteError::Io(error)) => {
            tracing::warn!(%error, "bytes could not be written to the part file");
            Err(runner.stop_for_volume(VolumeStop::WriteRefused {
                os_code: error.raw_os_error(),
            }))
        }
        Err(HeldWriteError::OutOfSpace { free_bytes }) => {
            tracing::warn!(free_bytes, "the volume is under its free-space floor");
            Err(runner.stop_for_volume(VolumeStop::OutOfSpace { free_bytes }))
        }
        Err(HeldWriteError::PathAbsent) => {
            Err(runner.stop_for_volume(VolumeStop::PartFileOutOfReach))
        }
        Err(HeldWriteError::Changed(change)) => {
            Err(part_file_changed(runner, download_id, file, change).await)
        }
    }
}

/// Commit the checkpoint `parts`, behind every byte they claim: the file's
/// data is synced first, so no row claims a byte the disk does not hold
/// (ADR-0117 §4). A filesystem with no sync to give has nothing more to say.
pub(super) async fn checkpoint<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    parts: Vec<ArrivedPart>,
) -> Result<(), DownloadFailure>
where
    S: Send,
    P: Send,
{
    {
        let held = runner.part_file.lock().await;
        let Some(file) = held.as_ref() else {
            return Ok(());
        };
        match file.sync().await {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Unsupported | std::io::ErrorKind::InvalidInput
                ) =>
            {
                tracing::info!(%error, "the part file was not synced before its checkpoint");
            }
            Err(error) => {
                tracing::warn!(%error, "the part file could not be synced");
                return Err(runner.stop_for_volume(VolumeStop::WriteRefused {
                    os_code: error.raw_os_error(),
                }));
            }
        }
    }
    let store = Arc::clone(&runner.rt.store);
    on_pool(move || store.record_arrived(download_id, parts))
        .await
        .map_err(store_failed("a checkpoint could not be recorded"))
}

/// Judge `plan`'s bytes in the file by `recovery_data` against `root`
/// (ADR-0038): the corrupt blocks it localizes, none when the data is malformed
/// or names none.
pub(super) async fn check_recovery<S, P>(
    runner: &RunnerContext<S, P>,
    file_size: u64,
    plan: PartPlan,
    root: AichRootHash,
    recovery_data: Vec<u8>,
) -> Result<Option<Vec<u16>>, DownloadFailure>
where
    S: Send,
    P: Send,
{
    let held = runner.part_file.lock().await;
    let file = held
        .as_ref()
        .ok_or(DownloadFailure::StorageIntegrityFailed(
            StorageIntegrityFault::PartFileMissing,
        ))?;
    let bytes = file
        .read_bytes(plan)
        .await
        .map_err(|error| read_refused(runner, &error))?;
    let judged = on_pool(move || {
        AichHashSet::verify_part(file_size, plan.offset, &bytes, &recovery_data, root)
    })
    .await;
    Ok(judged.ok())
}

/// The Arrived Checkpoint a run starts from, cut to the file it holds: the
/// one resume path, whatever ended the last run (ADR-0117 §4). A row the store
/// cannot read ends the start as a store failure, as a distrust it cannot read
/// does: a run would only fetch again what it holds, and write over it.
pub(super) async fn arrived_at_start<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
) -> Result<Vec<ArrivedPart>, DownloadFailure> {
    let rows = runner
        .rt
        .store
        .arrived_parts(download_id)
        .map_err(store_failed("the arrived parts could not be read"))?;
    let held = runner.part_file.lock().await;
    let Some(file) = held.as_ref() else {
        return Ok(Vec::new());
    };
    let end = file.len().await.unwrap_or(0);
    Ok(rows.into_iter().map(|row| row.cut_to(end)).collect())
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
    );
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
            // The file it speaks for is gone, so the checkpoint claims nothing.
            if let Err(error) = runner.rt.store.forget_arrived(download_id) {
                tracing::warn!(%error, "the arrived parts could not be dropped");
            }
            DownloadFailure::StorageIntegrityFailed(StorageIntegrityFault::PartFileMissing)
        }
    }
}

/// The whole file did not hash (ADR-0094, "A whole-file hash failing at finalize"):
/// re-check every recorded part, drop those that fail and fetch them again.
/// When no part can be named — a file verified by its file hash alone —
/// every recorded part is dropped. Only a part file that is gone or
/// unreadable fails the download.
pub(super) async fn repair_at_finalize<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
) -> DownloadFailure {
    match crate::download::part_check::walk_recorded(runner, download_id).await {
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
            );
            runner.mark_for_repair();
            DownloadFailure::PartVerificationFailed
        }
        Ok(Revalidation::Restored { .. }) => {
            // Every part holds against its record, yet the file does not hash:
            // the records themselves are wrong (a file-hash-only download, or a
            // peer's hash set that lied consistently). Nothing can be named,
            // so every part and the peer's hash set go.
            let dropped = match runner.rt.store.drop_every_part(download_id) {
                Ok(dropped) => dropped,
                Err(error) => return store_failed("every part could not be dropped")(error),
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
            );
            runner.mark_for_repair();
            DownloadFailure::PartVerificationFailed
        }
        Err(failure) => failure,
    }
}

/// The volume stopped the run: the row is stored `Paused`, and the stop and
/// the pause are told, as an operator's pause is. A store that cannot keep it
/// leaves the row as it was: the next start reads that one, and the volume
/// stops that run too.
pub(super) async fn record_volume_stop<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    stop: VolumeStop,
) {
    let store = &runner.rt.store;
    if let Err(error) = store.set_lifecycle(download_id, DownloadLifecycle::Paused) {
        tracing::warn!(%error, "the store could not record the volume's stop");
    }
    let directory = store.load_download(download_id).ok().and_then(|record| {
        let parent = record.paths().part_path().parent()?;
        Some(parent.to_path_buf())
    });
    tracing::warn!(
        download_id = download_id.as_u64(),
        ?stop,
        "the volume stopped the download"
    );
    let evt_tx = &runner.rt.evt_tx;
    if let Some(directory) = directory {
        send_download_event(
            evt_tx,
            DownloadEvent::VolumeStopped {
                download_id,
                directory,
                stop,
            },
        );
    }
    send_download_event(evt_tx, DownloadEvent::DownloadPaused { download_id });
}

/// Keep why a download failed on its row, and tell it. The failure is told
/// either way; a store that could not keep it is told after it
/// ([`DownloadEvent::FailureNotRecorded`]), since the row then keeps the
/// lifecycle it had and the next start reads that one.
pub(crate) async fn record_failure(
    store: &crate::store::download::DurableDownloadRepository,
    evt_tx: &crate::service::Outbox,
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
    );
    if let Err(error) = kept {
        tracing::warn!(
            download_id = download_id.as_u64(),
            %error,
            "the store could not record why the download failed",
        );
        send_download_event(evt_tx, DownloadEvent::FailureNotRecorded { download_id });
        tell_store_stop(store, evt_tx);
    }
}

#[cfg(test)]
mod tests;
