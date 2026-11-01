//! A resume's **part check** (ADR-0094, "Attach and Resume return at once"):
//! the run's first stage re-reads every recorded part and hashes it against
//! its record, on the blocking pool, under the hashing turn the scans and the
//! Offer Check share and under the run's stop. The actor has stored `Active`
//! and said so before this starts; what the check finds follows. A check that
//! is stopped changes nothing: its walk ends before its next part, and the
//! records stand.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::content::{ContentFileStore, Revalidation, on_pool};
use crate::diagnostics::{DiagnosticsState, PartCheckProgress};
use crate::service::{
    CoreCommandRejectReason, CoreEvent, DownloadEvent, DownloadId, Outbox, RestartOutcome,
    send_download_event,
};
use crate::storage::DownloadRepository;
use crate::store::download::DurableDownloadRepository;
use crate::{
    DownloadFailure, DurableDownloadRecord, PartFault, StorageIntegrityFault, VerifiedPartRecord,
};

use super::RunnerContext;
use super::persist::store_failed;

/// What a resumed run's check starts from.
#[derive(Clone, Debug, Default)]
pub(crate) struct PartCheck {
    /// The operator's Restart of a failed download; `None` for a Resume and
    /// for attach's restore, which never start over (ADR-0094).
    pub(crate) restart: Option<Restart>,
}

/// What a Restart keeps from the failed row its run replaced.
#[derive(Clone, Debug)]
pub(crate) struct Restart {
    /// Why the row failed, for a Restart that fails again to leave it so.
    pub(crate) failure: Option<DownloadFailure>,
    /// Where a part file gone from the row's path would stand had the
    /// download been moved: the name in the current Temp Directory.
    pub(crate) moved_to: Option<PathBuf>,
}

/// Raises the walk's stop flag when the walk's awaiter goes, however it goes:
/// a stop, or quit's abort of the run.
#[derive(Default)]
struct WalkStop(Arc<AtomicBool>);

impl Drop for WalkStop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Takes the part check's level off the row when the walk ends, however it
/// ends.
struct CheckLevel {
    diagnostics: DiagnosticsState,
    download_id: DownloadId,
}

impl Drop for CheckLevel {
    fn drop(&mut self) {
        self.diagnostics.part_check(self.download_id, None);
    }
}

/// Walk `download_id`'s recorded parts under the hashing turn and the run's
/// stop, dropping the record of each part that no longer holds. The row's
/// [`part_check`](crate::diagnostics::DownloadDiagnostics::part_check) level
/// stands from before the turn until the walk ends.
///
/// # Errors
/// The stop's failure, or [`DownloadFailure::StoreFailed`].
pub(super) async fn walk_recorded<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
) -> Result<Revalidation, DownloadFailure> {
    let stop = WalkStop::default();
    let diagnostics = runner.rt.diagnostics.clone();
    let of = runner
        .rt
        .store
        .verified_parts(download_id)
        .map_or(0, |parts| u32::try_from(parts.len()).unwrap_or(u32::MAX));
    let report = move |checked| {
        let level = PartCheckProgress { checked, of };
        diagnostics.part_check(download_id, Some(level));
    };
    report(0);
    let _level = CheckLevel {
        diagnostics: runner.rt.diagnostics.clone(),
        download_id,
    };
    let walked = runner
        .until_stop(async {
            let turn = runner.rt.hash_turn.clone();
            let flag = Arc::clone(&stop.0);
            let Some(_turn) = on_pool(move || turn.take(&flag)).await else {
                return Ok(None);
            };
            runner
                .rt
                .store
                .revalidate(download_id, Arc::clone(&stop.0), report)
                .await
        })
        .await?
        .map_err(store_failed("a download's parts could not be checked"))?;
    // Only a stop raises the flag, and `until_stop` answers a stop first.
    walked.ok_or(DownloadFailure::Cancelled)
}

/// The run's first stage: check the parts, say what held and what did not,
/// and return the indexes of the parts it may go on from. A Restart that
/// found nothing to continue from starts over here.
///
/// # Errors
/// The stop's failure, or what the download fails of: a part file that backs
/// nothing it recorded, or a store that cannot say.
pub(super) async fn first_stage<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    check: PartCheck,
) -> Result<Vec<u32>, DownloadFailure> {
    let rt = &runner.rt;
    let record = rt
        .store
        .load_download(download_id)
        .map_err(store_failed("the download's row could not be read"))?;
    let recorded = rt
        .store
        .verified_parts(download_id)
        .map_err(store_failed("the verified parts could not be read"))?;
    let (recorded_parts, recorded_bytes) = tally(&recorded);
    let restored = match walk_recorded(runner, download_id).await? {
        Revalidation::Restored { progress, damaged } => {
            tell_damaged(&rt.store, &rt.diagnostics, &rt.evt_tx, &record, damaged);
            let kept_parts = u32::try_from(progress.verified_parts()).unwrap_or(u32::MAX);
            let outcome = RestartOutcome::Continued {
                kept_parts,
                kept_bytes: progress.verified_bytes(),
                dropped_parts: recorded_parts.saturating_sub(kept_parts),
                dropped_bytes: recorded_bytes.saturating_sub(progress.verified_bytes()),
            };
            (
                progress.verified_parts(),
                progress.verified_bytes(),
                outcome,
            )
        }
        Revalidation::Condemned(fault) => {
            let Some(restart) = check.restart.as_ref().filter(|_| starts_over(&fault)) else {
                tracing::warn!(
                    download_id = download_id.as_u64(),
                    %fault,
                    "download failed: its part file backs none of its verified parts"
                );
                return Err(DownloadFailure::StorageIntegrityFailed(fault));
            };
            if moved(restart, &fault).await {
                rt.evt_tx.send(CoreEvent::CommandRejected {
                    reason: CoreCommandRejectReason::PartFileMoved,
                });
                return Err(restart
                    .failure
                    .clone()
                    .unwrap_or(DownloadFailure::StorageIntegrityFailed(fault)));
            }
            discard(runner, &record).await?;
            let outcome = RestartOutcome::StartedOver {
                fault,
                dropped_parts: recorded_parts,
                dropped_bytes: recorded_bytes,
            };
            (0, 0, outcome)
        }
    };
    let (verified_parts, verified_bytes, outcome) = restored;
    let parts = rt
        .store
        .verified_parts(download_id)
        .map_err(store_failed("the verified parts could not be read"))?;
    send_download_event(
        &rt.evt_tx,
        DownloadEvent::DownloadProgressRestored {
            download_id,
            verified_parts,
            verified_bytes,
        },
    );
    if check.restart.is_some() {
        tracing::info!(
            download_id = download_id.as_u64(),
            ?outcome,
            "download restarted"
        );
        send_download_event(
            &rt.evt_tx,
            DownloadEvent::DownloadRestarted {
                download_id,
                outcome,
            },
        );
    }
    Ok(parts.iter().map(|part| part.part_index).collect())
}

/// Tell of the parts a check dropped, and rest the part picture on the
/// verified set that is left.
pub(crate) fn tell_damaged(
    store: &DurableDownloadRepository,
    diagnostics: &DiagnosticsState,
    evt_tx: &Outbox,
    record: &DurableDownloadRecord,
    damaged: Vec<PartFault>,
) {
    if damaged.is_empty() {
        return;
    }
    let download_id = record.id();
    let dropped = damaged
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ");
    tracing::warn!(
        download_id = download_id.as_u64(),
        damaged = damaged.len(),
        %dropped,
        "verified parts no longer hold on disk; fetching them again"
    );
    let held = store
        .verified_parts(download_id)
        .map(|parts| parts.iter().map(|part| part.part_index).collect::<Vec<_>>())
        .unwrap_or_default();
    diagnostics.rest_download(
        download_id,
        record.file_hash(),
        record.metadata().clone(),
        &held,
    );
    send_download_event(
        evt_tx,
        DownloadEvent::DamagedPartsDropped {
            download_id,
            damaged,
        },
    );
}

/// Discard what the failed download recorded and the part file its row names,
/// keeping its identity and place, so the run goes on from nothing. Only the
/// run's own check does this: the part file is still nobody's.
async fn discard<S, P>(
    runner: &RunnerContext<S, P>,
    record: &DurableDownloadRecord,
) -> Result<(), DownloadFailure> {
    let rt = &runner.rt;
    rt.store
        .discard_progress(record.id())
        .map_err(store_failed(
            "a failed download's progress could not be discarded",
        ))?;
    if let Err(error) = ContentFileStore::delete_part(record.paths()).await {
        tracing::warn!(%error, "a failed download's part file could not be removed");
    }
    if let Some(lease) = &runner.served {
        lease.started_over();
    }
    rt.diagnostics.rest_download(
        record.id(),
        record.file_hash(),
        record.metadata().clone(),
        &[],
    );
    Ok(())
}

/// Whether the part file a Restart found gone stands in the Temp Directory.
async fn moved(restart: &Restart, fault: &StorageIntegrityFault) -> bool {
    let StorageIntegrityFault::PartFileMissing = fault else {
        return false;
    };
    match restart.moved_to.clone() {
        Some(candidate) => on_pool(move || candidate.is_file()).await,
        None => false,
    }
}

/// How many verified parts `parts` records, and the bytes they hold.
fn tally(parts: &[VerifiedPartRecord]) -> (u32, u64) {
    let count = u32::try_from(parts.len()).unwrap_or(u32::MAX);
    (count, parts.iter().map(|part| part.len).sum())
}

/// Whether a Restart that met `fault` starts over rather than failing again:
/// the part file is gone, or none of what it recorded matches it. A part file
/// that exists but cannot be read may read again once its disk or its
/// permissions are back, so what it holds is not thrown away for it.
const fn starts_over(fault: &StorageIntegrityFault) -> bool {
    match fault {
        StorageIntegrityFault::PartFileMissing | StorageIntegrityFault::NoPartHolds { .. } => true,
        StorageIntegrityFault::PartFileUnreadable { .. } => false,
    }
}
