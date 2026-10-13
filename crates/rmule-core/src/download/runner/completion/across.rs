//! Step 5 of the completion move (ADR-0115), the **Completion Copy**: the
//! part file copied to the destination's volume under a dot-prefixed name,
//! one copy at a time across the core, hashed as it is read, then landed
//! under the destination's name through the Completion Gate.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rmule_primitives::{Ed2kFileLink, FileHash};

use super::copy::{Copied, copy_hashed, copy_path, sync_directory};
use super::{land_free, on_pool, refused, remove_quietly, stopped, tell};
use crate::DownloadPaths;
use crate::download::runner::RunnerContext;
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
    tell(
        runner,
        download_id,
        &destination,
        CompletionStep::QueuedForCopy,
    )
    .await;
    let turn = runner
        .until_stop(Arc::clone(&runner.rt.copy_turn).acquire_owned())
        .await?;
    tell(runner, download_id, &destination, CompletionStep::Copying).await;
    let copy = copy_path(&destination);
    remove_quietly(copy.clone()).await;
    let copied = copy_answering_stop(runner, download_id, part_path, &copy, file.size).await?;
    if copied != file.file_hash {
        remove_quietly(copy).await;
        tracing::warn!("the bytes copied do not hash to the file; repairing");
        return Err(refused(runner, download_id, FinalizeError::Mismatch).await);
    }
    match land_free(runner, download_id, row, &copy, &mut destination).await {
        Ok(Ok(())) => {}
        Ok(Err(refusal)) => {
            remove_quietly(copy).await;
            return Err(DownloadFailure::CompletionCopyFailed {
                os_code: refusal.os_code(),
            });
        }
        Err(failure) => {
            remove_quietly(copy).await;
            return Err(failure);
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
    let copied = match runner.until_stop(&mut task).await {
        Ok(copied) => copied,
        Err(failure) => {
            drop(raise);
            let _ = task.await;
            return Err(failure);
        }
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
