//! The run's side of its **Served Download** (ADR-0113): what it writes
//! through the lease the actor handed it. The **Verified Range** is ruled
//! from the parts the store records against the part hash set in force — at
//! the lease's start, after every persist result before the queue enacts
//! anything else, after a set arrives and after a finalize — so no name ask,
//! reask or status the run sends names a part the serve side lacks. The
//! **Part File Identity** is read from the held handle: its key at the
//! lease's start, its key, length and time as a pause lets the handle go.
//! A run with no lease — a download of one part — writes nothing.

use rmule_primitives::PartHash;

use crate::download::state::DownloadState;
use crate::file_key::FileKey;
use crate::served_downloads::PartFileIdentity;
use crate::service::DownloadId;
use crate::storage::{DownloadRepository, ResolvedAuthority};

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
    let set = match runner.rt.store.hash_authority(download_id) {
        Ok(ResolvedAuthority::Link(hashes) | ResolvedAuthority::Provisional(hashes)) => hashes,
        Ok(ResolvedAuthority::FileHashOnly) | Err(_) => Vec::new(),
    };
    rule_range(runner, download_id, &set);
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

/// [`rule_range`] against the set the brain holds in force.
pub(super) fn rule_range_of<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    state: &DownloadState,
) {
    rule_range(runner, download_id, &state.resolved().hashes);
}

/// The finished file is in place at the final path: the bytes are read from
/// it now, with its identity — a rename keeps the part file's key.
pub(super) async fn in_place<S, P>(runner: &RunnerContext<S, P>, download_id: DownloadId) {
    let Some(lease) = &runner.served else {
        return;
    };
    let Ok(record) = runner.rt.store.load_download(download_id) else {
        return;
    };
    let path = record.paths().final_path();
    let owned = path.to_path_buf();
    let identity = tokio::task::spawn_blocking(move || {
        Some((FileKey::at(&owned).ok()?, std::fs::metadata(&owned).ok()?))
    })
    .await
    .ok()
    .flatten()
    .and_then(|(key, meta)| PartFileIdentity::read(key, &meta, true));
    lease.bytes_in_place(identity);
}

/// A pause lets the held part file go: the entry keeps the key, length and
/// time read through the handle, which every read of a paused download is
/// checked against.
pub(super) async fn let_go<S, P>(runner: &RunnerContext<S, P>) {
    let Some(lease) = &runner.served else {
        return;
    };
    let identity = held_identity(runner, true).await;
    *runner.part_file.lock().await = None;
    if let Some(identity) = identity {
        lease.record_identity(identity);
    }
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
