//! Step 5 of the completion move (ADR-0115), the **Completion Copy**: the
//! part file copied to the destination's volume under a dot-prefixed name,
//! one copy at a time across the core, hashed as it is read, then landed
//! under the destination's name through the Completion Gate.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rmule_primitives::{Ed2kFileLink, FileHash};

use super::copy::{Copied, copy_hashed, copy_path, sync_directory};
use super::{
    Landed, Refusal, free_destination, land, on_pool, refused, remove_quietly, stopped,
    store_destination, tell,
};
use crate::DownloadPaths;
use crate::download::runner::{RunnerContext, stop_reason, wait_until_stop};
use crate::error::{DownloadFailure, FinalizeError};
use crate::service::{CompletionStep, DownloadId};

/// Step 5, the Completion Copy: wait for the core's one copy turn, copy the
/// part file to `.<name>.completing` beside `destination` hashing what it
/// reads, then land the copy under the destination's name — the next free
/// one when a file took it meanwhile, stored first — and sync the directory.
/// Answers where the file landed.
pub(super) async fn copy_into_place<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    file: &Ed2kFileLink,
    row: &DownloadPaths,
    mut destination: PathBuf,
) -> Result<PathBuf, DownloadFailure> {
    let part_path = row.part_path();
    let diagnostics = &runner.rt.diagnostics;
    diagnostics.completion_step(download_id, CompletionStep::QueuedForCopy);
    tell(
        runner,
        download_id,
        &destination,
        CompletionStep::QueuedForCopy,
    )
    .await;
    let mut stop_rx = runner.stop_rx.clone();
    let turn = tokio::select! {
        biased;
        () = wait_until_stop(&mut stop_rx) => return Err(stop_reason(&stop_rx).unwrap_or(DownloadFailure::Cancelled)),
        turn = Arc::clone(&runner.rt.copy_turn).acquire_owned() => turn,
    };
    diagnostics.completion_step(download_id, CompletionStep::Copying);
    tell(runner, download_id, &destination, CompletionStep::Copying).await;
    let copy = copy_path(&destination);
    remove_quietly(copy.clone()).await;
    let copied = copy_answering_stop(runner, download_id, part_path, &copy, file.size).await?;
    if copied != file.file_hash {
        remove_quietly(copy).await;
        tracing::warn!("the bytes copied do not hash to the file; repairing");
        return Err(refused(runner, download_id, FinalizeError::Mismatch).await);
    }
    loop {
        if !runner.completion.begin() {
            remove_quietly(copy).await;
            return Err(stopped(runner).await);
        }
        let landed = land(runner, &copy, &destination).await;
        runner.completion.settle(matches!(landed, Landed::InPlace));
        match landed {
            Landed::InPlace => break,
            Landed::Taken => {
                destination = free_destination(row).await;
                store_destination(runner, download_id, &destination)?;
            }
            Landed::Refused(refusal) => {
                remove_quietly(copy).await;
                let os_code = match refusal {
                    Refusal::InUse { os_code } => Some(os_code),
                    Refusal::Other { os_code } => os_code,
                    Refusal::CrossesDevices => None,
                };
                return Err(DownloadFailure::CompletionCopyFailed { os_code });
            }
        }
    }
    drop(turn);
    if let Some(directory) = destination.parent().map(Path::to_path_buf)
        && let Err(error) = on_pool(move || sync_directory(&directory)).await
    {
        tracing::warn!(%error, "the destination's directory could not be synced");
    }
    Ok(destination)
}

/// Raises its flag when dropped: a run aborted mid-copy stops its copy.
struct RaiseOnDrop(Arc<AtomicBool>);

impl Drop for RaiseOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Copy `from` to `copy` on the blocking pool, publishing the bytes written
/// and answering the run's stop between parts: the hash of what was read.
async fn copy_answering_stop<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    from: &Path,
    copy: &Path,
    size: u64,
) -> Result<FileHash, DownloadFailure> {
    let stop = Arc::new(AtomicBool::new(false));
    let raise = RaiseOnDrop(Arc::clone(&stop));
    let diagnostics = runner.rt.diagnostics.clone();
    let mut task = tokio::task::spawn_blocking({
        let (from, copy, stop) = (from.to_owned(), copy.to_owned(), Arc::clone(&stop));
        move || {
            copy_hashed(&from, &copy, size, &stop, &mut |written| {
                diagnostics.completion_copied(download_id, written);
            })
        }
    });
    let mut stop_rx = runner.stop_rx.clone();
    let copied = tokio::select! {
        biased;
        () = wait_until_stop(&mut stop_rx) => {
            drop(raise);
            let _ = task.await;
            return Err(stop_reason(&stop_rx).unwrap_or(DownloadFailure::Cancelled));
        }
        copied = &mut task => copied,
    };
    let failed = |os_code| {
        tracing::warn!(
            ?os_code,
            "the finished file could not be copied to its volume"
        );
        DownloadFailure::CompletionCopyFailed { os_code }
    };
    match copied {
        Ok(Ok(Copied::Whole(hash))) => Ok(hash),
        Ok(Ok(Copied::Stopped)) => Err(stopped(runner).await),
        Ok(Err(error)) => Err(failed(error.raw_os_error())),
        Err(_) => Err(failed(None)),
    }
}
