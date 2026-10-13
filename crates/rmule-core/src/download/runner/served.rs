//! The run's side of its **Served Download** (ADR-0113): what it writes
//! through the lease the actor handed it. The **Verified Range** is ruled
//! from the parts the store records against the part hash set in force — at
//! the lease's start, after every persist result before the queue enacts
//! anything else, after a set arrives and at the completion move's swap — so
//! no name ask,
//! reask or status the run sends names a part the serve side lacks. The
//! **Part File Identity** is read from the held handle: its key at the
//! lease's start, its key, length and time as a pause or the completion
//! move lets the handle go. A run with no lease — a download of one part —
//! writes nothing.

use std::path::Path;

use rmule_primitives::PartHash;

use crate::content::HeldPartFile;
use crate::download::state::DownloadState;
use crate::file_key::FileKey;
use crate::served_downloads::PartFileIdentity;
use crate::service::DownloadId;
use crate::storage::DownloadRepository;

use super::RunnerContext;

/// The run took the lease: the identity of the file it holds, and the range
/// the store's records hold against the set it records.
pub(super) async fn lease_started<S, P>(runner: &RunnerContext<S, P>, download_id: DownloadId) {
    let Some(lease) = &runner.served else {
        return;
    };
    if let Some(identity) = held_identity(runner, false).await {
        lease.record_identity(identity);
    }
    rule_recorded_range(runner, download_id);
}

/// Rule the Verified Range from the parts the store records against `set`.
/// A store that cannot list them leaves the range as it was: the run fails
/// on the same store at its next write.
pub(super) fn rule_range<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    set: &[PartHash],
) {
    let Some(lease) = &runner.served else {
        return;
    };
    match runner.rt.store.verified_parts(download_id) {
        Ok(records) => {
            lease.record_range(set, &records);
        }
        Err(error) => tracing::warn!(
            download_id = download_id.as_u64(),
            %error,
            "the verified range could not be read from the store"
        ),
    }
}

/// [`rule_range`] against the set the store records in force. A store that
/// cannot read the set leaves the range as it was, as one that cannot list
/// the parts does.
pub(super) fn rule_recorded_range<S, P>(runner: &RunnerContext<S, P>, download_id: DownloadId) {
    match runner.rt.store.hash_authority(download_id) {
        Ok(authority) => rule_range(runner, download_id, &authority.into_part_hashes()),
        Err(error) => tracing::warn!(
            download_id = download_id.as_u64(),
            %error,
            "the part hash set could not be read from the store"
        ),
    }
}

/// [`rule_range`] against the set the brain holds in force.
pub(super) fn rule_range_of<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    state: &DownloadState,
) {
    rule_range(runner, download_id, &state.resolved().hashes);
}

/// The finished file is in place at `path`, the destination the completion
/// move chose: the bytes are read from it now, with its identity — a rename
/// keeps the part file's key, a copy has its own — and the range is every
/// part the store records.
pub(super) async fn in_place<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    path: &std::path::Path,
) {
    let Some(lease) = &runner.served else {
        return;
    };
    rule_recorded_range(runner, download_id);
    lease.bytes_in_place(path, identity_at(path).await);
}

/// A pause lets the held part file go: the entry keeps the key, length and
/// time read through the handle, which every read of a paused download is
/// checked against. A pause that stops the completion move finds the handle
/// let go already and keeps what the move recorded.
pub(super) async fn let_go<S, P>(runner: &RunnerContext<S, P>) {
    let held = runner.part_file.lock().await.take();
    record_at_rest(runner, held, None).await;
}

/// The completion move lets the held part file go before it reads or moves
/// it (ADR-0115), recording it as a pause does: nothing writes the file from
/// here, so a Pause that stops the move leaves every read checked against
/// its length and time too. A run that holds no handle — one attach found
/// completing — reads them at `part_path`.
pub(super) async fn let_go_to_move<S, P>(runner: &RunnerContext<S, P>, part_path: &Path) {
    let held = runner.part_file.lock().await.take();
    record_at_rest(runner, held, Some(part_path)).await;
}

/// Record the identity, at rest, of the file `held` holds — of the file at
/// `unheld` when nothing is held — unless it cannot be read.
async fn record_at_rest<S, P>(
    runner: &RunnerContext<S, P>,
    held: Option<HeldPartFile>,
    unheld: Option<&Path>,
) {
    let Some(lease) = &runner.served else {
        return;
    };
    let identity = match (held, unheld) {
        (Some(file), _) => file
            .held_metadata()
            .await
            .ok()
            .and_then(|(key, meta)| PartFileIdentity::read(key, &meta, true)),
        (None, Some(path)) => identity_at(path).await,
        (None, None) => None,
    };
    if let Some(identity) = identity {
        lease.record_identity(identity);
    }
}

/// The identity, at rest, of the file at `path`; `None` when it cannot be
/// read.
async fn identity_at(path: &Path) -> Option<PartFileIdentity> {
    let owned = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        Some((FileKey::at(&owned).ok()?, std::fs::metadata(&owned).ok()?))
    })
    .await
    .ok()
    .flatten()
    .and_then(|(key, meta)| PartFileIdentity::read(key, &meta, true))
}

/// The identity of the file the run holds, read through its handle; `None`
/// when it holds none or the read fails.
async fn held_identity<S, P>(
    runner: &RunnerContext<S, P>,
    at_rest: bool,
) -> Option<PartFileIdentity> {
    let held = runner.part_file.lock().await;
    let (key, meta) = held.as_ref()?.held_metadata().await.ok()?;
    PartFileIdentity::read(key, &meta, at_rest)
}

#[cfg(test)]
mod tests;
