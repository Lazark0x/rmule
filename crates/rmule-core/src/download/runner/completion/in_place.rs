//! Steps 6 and 7 of the completion move (ADR-0115): the finished file is in
//! place, so the run points its Served Download at it and reports it to the
//! core actor until its registry row is written; only then is the part file
//! deleted — waiting while a program holds it — and `Completed` stored.

use std::path::Path;
use std::sync::Arc;

use tokio::sync::oneshot;

use super::{Backoff, FinalFileInPlace, Refusal, on_pool, tell, wait_or_stop};
use crate::content::ContentFileStore;
use crate::download::runner::{RunnerContext, served};
use crate::error::DownloadFailure;
use crate::service::{CompletionStep, DownloadEvent, DownloadId, send_download_event};
use crate::storage::DownloadRepository;
use crate::{DownloadLifecycle, DownloadPaths};

/// Steps 6 and 7: point the Served Download at the finished file, report it
/// in place until the actor has written its row, then delete the part file
/// and store `Completed`.
pub(super) async fn finish<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    paths: &DownloadPaths,
) -> Result<(), DownloadFailure> {
    let final_path = paths.final_path();
    served::in_place(runner, download_id, final_path).await;
    report_in_place(runner, download_id, final_path).await?;
    delete_part(runner, download_id, paths).await?;
    let mut backoff = Backoff::new();
    let mut waiting = false;
    while let Err(error) = runner
        .rt
        .store
        .set_lifecycle(download_id, DownloadLifecycle::Completed)
    {
        tracing::warn!(%error, "the store could not record the completed download; retrying");
        if !waiting {
            waiting = true;
            tell(
                runner,
                download_id,
                final_path,
                CompletionStep::WaitingForStore,
            )
            .await;
        }
        wait_or_stop(runner, backoff.next()).await?;
    }
    tracing::info!(download_id = download_id.as_u64(), "download completed");
    send_download_event(
        &runner.rt.evt_tx,
        DownloadEvent::DownloadCompleted {
            download_id,
            final_path: final_path.to_path_buf(),
        },
    )
    .await;
    Ok(())
}

/// Step 6: report the finished file in place at `path`, again on the
/// backoff while the actor could not write its row.
async fn report_in_place<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    path: &Path,
) -> Result<(), DownloadFailure> {
    let mut backoff = Backoff::new();
    let mut waiting = false;
    loop {
        let (written, answer) = oneshot::channel();
        let report = FinalFileInPlace {
            download_id,
            run: runner.run,
            path: path.to_path_buf(),
            written,
        };
        // An actor that is gone takes no report: the row stays `Completing`
        // and the next start resolves it.
        if runner.rt.in_place_tx.send(report).await.is_err() {
            return Err(DownloadFailure::Cancelled);
        }
        let written = runner
            .until_stop(answer)
            .await?
            .map_err(|_| DownloadFailure::Cancelled)?;
        if written {
            return Ok(());
        }
        if !waiting {
            waiting = true;
            tell(runner, download_id, path, CompletionStep::WaitingForStore).await;
        }
        wait_or_stop(runner, backoff.next()).await?;
    }
}

/// Step 7's delete: the part file and the Hole Probe's file beside it, the
/// delete waiting while a program holds the part file.
async fn delete_part<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    paths: &DownloadPaths,
) -> Result<(), DownloadFailure> {
    let mut backoff = Backoff::new();
    let mut waiting = false;
    loop {
        let fs = Arc::clone(&runner.rt.completion_fs);
        let part = paths.part_path().to_path_buf();
        match on_pool(move || fs.remove(&part)).await {
            Ok(()) => break,
            Err(Refusal::InUse { .. }) => {
                if !waiting {
                    waiting = true;
                    let step = CompletionStep::WaitingForRelease;
                    tell(runner, download_id, paths.final_path(), step).await;
                }
                wait_or_stop(runner, backoff.next()).await?;
            }
            // The finished file is in place and its row written: a part file
            // that cannot go is the operator's to remove.
            Err(refusal) => {
                tracing::warn!(
                    ?refusal,
                    "the part file could not be deleted after completion"
                );
                break;
            }
        }
    }
    if let Err(error) = ContentFileStore::delete_part(paths).await {
        tracing::warn!(%error, "the hole probe's file could not be deleted");
    }
    Ok(())
}
