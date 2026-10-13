//! The **completion move** (ADR-0115): the run's last step, after the
//! scheduling brain's last decision. The run checks the part file against the
//! file hash, names the destination — the row's final path or the first free
//! `stem (n).ext` beside it — and stores `Completing` with it before anything
//! moves. It renames the part file onto the destination; while another
//! program holds the file it waits and retries; across volumes it makes the
//! **Completion Copy**. With the finished file in place it points its Served
//! Download at it and reports to the core actor, which writes the registry
//! row and ends the Served Download in one step; only then is the part file
//! deleted and `Completed` stored.
//!
//! Download State holds no clock and takes no part: every wait here is the
//! run's own, answering its stop between attempts. The part file is never
//! deleted before the finished file is in place, and a stop that arrives
//! after that is refused at the **Completion Gate**.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rmule_primitives::Ed2kFileLink;
use tokio::sync::oneshot;

use super::{RunnerContext, served, stop_reason, wait_until_stop};
use crate::content::{ContentFileStore, on_pool};
use crate::error::{DownloadFailure, FinalizeError, StorageIntegrityFault};
use crate::service::{CompletionStep, DownloadEvent, DownloadId, send_download_event};
use crate::storage::DownloadRepository;
use crate::{DownloadLifecycle, DownloadPaths};

mod across;
mod copy;
mod fs;
mod gate;
mod in_place;

use across::copy_into_place;
use copy::copy_path;
use fs::Refusal;
pub(crate) use fs::{CompletionFs, OsCompletionFs};
pub(crate) use gate::{CompletionGate, StopAnswer};
use in_place::finish;

/// The run's report that its finished file is in place (ADR-0115, step 6):
/// the actor writes the file's registry row from the download record at
/// `path` and ends its Served Download, then answers whether the row is
/// written.
#[derive(Debug)]
pub(crate) struct FinalFileInPlace {
    /// The download whose file is in place.
    pub(crate) download_id: DownloadId,
    /// Which run of it reports.
    pub(crate) run: crate::download::RunNumber,
    /// Where the file landed, a numbered name included.
    pub(crate) path: PathBuf,
    /// `true` once the row is written and the Served Download ended.
    pub(crate) written: oneshot::Sender<bool>,
}

/// What attach found of a row it found `Completing`, for its run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Recovered {
    /// The registry holds the file at the row's destination.
    pub(crate) row_written: bool,
}

/// The waits of the move: 1 s, doubling to 30 s.
struct Backoff(Duration);

impl Backoff {
    const FIRST: Duration = Duration::from_secs(1);
    const LONGEST: Duration = Duration::from_secs(30);

    const fn new() -> Self {
        Self(Self::FIRST)
    }

    fn next(&mut self) -> Duration {
        let wait = self.0;
        self.0 = (wait * 2).min(Self::LONGEST);
        wait
    }
}

/// Move a download whose every part is verified into place, steps 1 to 7.
/// `file_hash_only_parts` are the parts written while no part hash set was
/// held: verified the moment the whole file hashes.
///
/// A file that stands at the row's final path and hashes to the file hash
/// is the download's own, which a past move put there and a Pause or a stop
/// left before its row was written: the move finishes there, reading the
/// part file not at all, and numbers nothing past it.
pub(super) async fn complete<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    file: &Ed2kFileLink,
    file_hash_only_parts: Vec<u32>,
) -> Result<(), DownloadFailure> {
    let paths = row_paths(runner, download_id)?;
    complete_at(runner, download_id, file, &paths, file_hash_only_parts).await
}

/// [`complete`] the download whose row holds `paths`.
async fn complete_at<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    file: &Ed2kFileLink,
    paths: &DownloadPaths,
    file_hash_only_parts: Vec<u32>,
) -> Result<(), DownloadFailure> {
    let_go_of_part_file(runner, download_id, paths.part_path()).await?;
    let landed = own_file_at(runner, paths.final_path(), file).await?;
    if !landed {
        check(runner, download_id, file, paths.part_path()).await?;
    }
    for part_index in file_hash_only_parts {
        send_download_event(
            &runner.rt.evt_tx,
            DownloadEvent::PartVerified {
                download_id,
                part_index,
            },
        )
        .await;
    }
    if landed {
        store_destination(runner, download_id, paths.final_path())?;
        if !runner.completion.found_in_place() {
            return Err(stopped(runner).await);
        }
        return finish(runner, download_id, paths).await;
    }
    let destination = free_destination(paths).await;
    store_destination(runner, download_id, &destination)?;
    let placed = move_into_place(runner, download_id, file, paths, destination).await?;
    finish(runner, download_id, &placed).await
}

/// The paths the download's row holds.
fn row_paths<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
) -> Result<DownloadPaths, DownloadFailure> {
    runner
        .rt
        .store
        .load_download(download_id)
        .map(|record| record.paths().clone())
        .map_err(|_| DownloadFailure::StoreFailed)
}

/// The run of a row attach found `Completing` resolves it by what is on disk
/// (ADR-0115's recovery table) and completes it.
pub(super) async fn recover<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    file: &Ed2kFileLink,
    recovered: Recovered,
) -> Result<(), DownloadFailure> {
    let paths = row_paths(runner, download_id)?;
    let (part, destination) = {
        let (part, destination) = (paths.part_path().to_owned(), paths.final_path().to_owned());
        on_pool(move || (part.exists(), destination.exists())).await
    };
    let gate = &runner.completion;
    match (part, destination) {
        (false, false) => {
            gate.release();
            return Err(DownloadFailure::StorageIntegrityFailed(
                StorageIntegrityFault::PartFileMissing,
            ));
        }
        // A past process put the file in place: the part file left with the
        // rename, or the row of the copy that landed beside it was written.
        (false, true) => {}
        (true, true) if recovered.row_written => {}
        // The move again: a destination a past copy landed is found its
        // own there, so a stop while it is read leaves nothing to undo.
        (true, _) => {
            gate.release();
            remove_quietly(copy_path(paths.final_path())).await;
            return complete_at(runner, download_id, file, &paths, Vec::new()).await;
        }
    }
    if !gate.found_in_place() {
        return Err(stopped(runner).await);
    }
    finish(runner, download_id, &paths).await
}

/// The run hands its held part file at `part_path` over: still the file it
/// held, and released before anything reads or moves it, its Served
/// Download checked against it at rest from here.
async fn let_go_of_part_file<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    part_path: &Path,
) -> Result<(), DownloadFailure> {
    if let Some(part_file) = runner.part_file.lock().await.as_mut()
        && let Err(change) = part_file.check().await
    {
        return Err(crate::download::persist::part_file_changed(
            runner,
            download_id,
            part_file,
            change,
        )
        .await);
    }
    served::let_go_to_move(runner, part_path).await;
    Ok(())
}

/// Step 1: the part file at `part_path` hashes to the file hash, or the
/// download repairs. The run's stop is answered while the hash reads.
async fn check<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    file: &Ed2kFileLink,
    part_path: &Path,
) -> Result<(), DownloadFailure> {
    let hashed = runner
        .until_stop(ContentFileStore::hash_file(part_path, file.size))
        .await?;
    match hashed {
        Ok(hash) if hash == file.file_hash => Ok(()),
        Ok(_) => Err(refused(runner, download_id, FinalizeError::Mismatch).await),
        Err(error) => Err(refused(runner, download_id, error).await),
    }
}

/// Whether the file at `path` is the download's own finished file: of its
/// size and hashing to its hash. A file of any other size, or none, is
/// answered without a read.
async fn own_file_at<S, P>(
    runner: &RunnerContext<S, P>,
    path: &Path,
    file: &Ed2kFileLink,
) -> Result<bool, DownloadFailure> {
    let size = {
        let path = path.to_owned();
        on_pool(move || {
            std::fs::symlink_metadata(&path)
                .ok()
                .filter(std::fs::Metadata::is_file)
                .map(|metadata| metadata.len())
        })
        .await
    };
    if size != Some(file.size) {
        return Ok(false);
    }
    hashes_to(runner, path, file).await
}

/// Whether the file at `path` hashes to `file`'s hash: one read, the stop
/// answered meanwhile.
async fn hashes_to<S, P>(
    runner: &RunnerContext<S, P>,
    path: &Path,
    file: &Ed2kFileLink,
) -> Result<bool, DownloadFailure> {
    let hashed = runner
        .until_stop(ContentFileStore::hash_file(path, file.size))
        .await?;
    Ok(hashed.is_ok_and(|hash| hash == file.file_hash))
}

/// Step 2: the name the download was placed under, or the first free
/// numbered name of it beside it: counted from that name each time, as
/// aMule's is, so a move a past one numbered never numbers past the number.
async fn free_destination(row: &DownloadPaths) -> PathBuf {
    let placed = crate::free_name::placed(row);
    on_pool(move || crate::free_name::first_free(&placed, Path::exists)).await
}

/// Store `Completing` with `destination`, in one write, before it is used.
fn store_destination<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    destination: &Path,
) -> Result<(), DownloadFailure> {
    runner
        .rt
        .store
        .set_completing(download_id, destination)
        .map_err(|error| {
            tracing::warn!(%error, "the completion's destination could not be stored");
            DownloadFailure::StoreFailed
        })
}

/// Steps 3 to 5: rename the part file onto `destination`, wait while a
/// program holds it, copy across volumes; a name taken meanwhile takes the
/// next free one of the placed name, stored first. Answers the
/// paths the finished file and the part file hold once the file is in place.
async fn move_into_place<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    file: &Ed2kFileLink,
    row: &DownloadPaths,
    mut destination: PathBuf,
) -> Result<DownloadPaths, DownloadFailure> {
    let part_path = row.part_path();
    runner
        .rt
        .diagnostics
        .completion_step(download_id, CompletionStep::Moving);
    let mut backoff = Backoff::new();
    let mut waiting = false;
    loop {
        match land_free(runner, download_id, row, part_path, &mut destination).await? {
            Ok(()) => return Ok(DownloadPaths::new(destination, part_path.to_owned())),
            Err(Refusal::InUse { os_code }) => {
                if !waiting {
                    waiting = true;
                    tracing::info!(os_code, "another program holds the finished file; waiting");
                    tell(
                        runner,
                        download_id,
                        &destination,
                        CompletionStep::WaitingForRelease,
                    )
                    .await;
                }
                wait_or_stop(runner, backoff.next()).await?;
            }
            Err(Refusal::CrossesDevices) => {
                let destination =
                    copy_into_place(runner, download_id, file, row, destination).await?;
                return Ok(DownloadPaths::new(destination, part_path.to_owned()));
            }
            Err(Refusal::Other { os_code }) => {
                tracing::warn!(?os_code, "the finished file could not be moved into place");
                return Err(DownloadFailure::CompletedFileNotMoved { os_code });
            }
        }
    }
}

/// Land `from` under `destination` through the Completion Gate: a name a
/// file took since it was named gives way to the next free one of the
/// placed name, stored first, and the landing is tried again. `Ok(Err(_))`
/// when the system refused it; `Err` ends the run, a stop that closed the
/// gate among them.
async fn land_free<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    row: &DownloadPaths,
    from: &Path,
    destination: &mut PathBuf,
) -> Result<Result<(), Refusal>, DownloadFailure> {
    loop {
        if !runner.completion.begin() {
            return Err(stopped(runner).await);
        }
        let landed = land(runner, from, destination).await;
        runner.completion.settle(matches!(landed, Landed::InPlace));
        match landed {
            Landed::InPlace => return Ok(Ok(())),
            Landed::Taken => {
                *destination = free_destination(row).await;
                store_destination(runner, download_id, destination)?;
            }
            Landed::Refused(refusal) => return Ok(Err(refusal)),
        }
    }
}

/// What one landing attempt met.
enum Landed {
    InPlace,
    /// A file came to stand at the destination since it was named.
    Taken,
    Refused(Refusal),
}

/// Rename `from` onto `to` unless a file stands there now.
async fn land<S, P>(runner: &RunnerContext<S, P>, from: &Path, to: &Path) -> Landed {
    let fs = Arc::clone(&runner.rt.completion_fs);
    let (from, to) = (from.to_owned(), to.to_owned());
    on_pool(move || {
        if to.exists() {
            return Landed::Taken;
        }
        match fs.rename(&from, &to) {
            Ok(()) => Landed::InPlace,
            Err(refusal) => Landed::Refused(refusal),
        }
    })
    .await
}

/// Tell a step that waits or copies, and publish it as the row's level.
async fn tell<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    to: &Path,
    step: CompletionStep,
) {
    runner.rt.diagnostics.completion_step(download_id, step);
    send_download_event(
        &runner.rt.evt_tx,
        DownloadEvent::Completing {
            download_id,
            to: to.to_path_buf(),
            step,
        },
    )
    .await;
}

/// Sleep `wait`, or end with the run's stop.
async fn wait_or_stop<S, P>(
    runner: &RunnerContext<S, P>,
    wait: Duration,
) -> Result<(), DownloadFailure> {
    runner.until_stop(tokio::time::sleep(wait)).await
}

/// The stop that closed the gate, once it has reached the run: the actor
/// closes the gate, then sends it.
async fn stopped<S, P>(runner: &RunnerContext<S, P>) -> DownloadFailure {
    let mut stop_rx = runner.stop_rx.clone();
    wait_until_stop(&mut stop_rx).await;
    stop_reason(&stop_rx).unwrap_or(DownloadFailure::Cancelled)
}

/// Why the check or the copy did not complete the file, as the run's end.
/// Only a file that does not hash touches the parts; an unreadable part file
/// keeps every verified part, and the run ends by that cause.
async fn refused<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    error: FinalizeError,
) -> DownloadFailure {
    tracing::warn!(
        download_id = download_id.as_u64(),
        %error,
        "the finished file could not be completed",
    );
    match error {
        FinalizeError::Mismatch => repair(runner, download_id).await,
        FinalizeError::Unreadable { os_code } => {
            DownloadFailure::StorageIntegrityFailed(StorageIntegrityFault::PartFileUnreadable {
                os_code,
            })
        }
        FinalizeError::Store(_) => DownloadFailure::StoreFailed,
    }
}

/// The whole file did not hash (ADR-0094, "Finalize with lost parts"):
/// re-check every recorded part, drop those that fail and fetch them again;
/// when no part can be named, every part goes. A completing row goes back to
/// `Active`, and the Served Download's range shrinks to what still holds.
async fn repair<S, P>(runner: &RunnerContext<S, P>, download_id: DownloadId) -> DownloadFailure {
    let failure = crate::download::persist::repair_at_finalize(runner, download_id).await;
    if let Ok(record) = runner.rt.store.load_download(download_id)
        && record.lifecycle() == DownloadLifecycle::Completing
        && runner
            .rt
            .store
            .set_lifecycle(download_id, DownloadLifecycle::Active)
            .is_err()
    {
        return DownloadFailure::StoreFailed;
    }
    served::rule_recorded_range(runner, download_id);
    failure
}

/// Delete `path` if it is there; a delete that fails leaves a dot-prefixed
/// file the scan never reads and the next move deletes.
async fn remove_quietly(path: PathBuf) {
    if let Err(error) = on_pool(move || match std::fs::remove_file(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        removed => removed,
    })
    .await
    {
        tracing::warn!(%error, "a partial completion copy could not be deleted");
    }
}

#[cfg(test)]
mod tests;
