//! The download rows the Transfers view reads, and the fold arm that maintains
//! them.
//!
//! A row carries only what an *edge* established — hash, status, part count,
//! restored progress, source tallies, metadata. Live per-part and per-worker
//! levels stay on [`UiState::diagnostics`](super::UiState::diagnostics), joined
//! by [`DownloadId`] at render time, so the edge path and the level path can
//! never drift apart.

use std::path::PathBuf;

use rmule_core::{
    CompletionStep, DownloadEvent, DownloadFailure, DownloadId, DownloadLifecycle,
    DownloadMetadata, SourceWait,
};
use rmule_primitives::{ED2K_PART_SIZE, FileHash};

use super::{UiState, note};

pub use crate::words::download::{
    FAILURE_NOT_RECORDED, NO_NETWORK_WAIT, download_failure_words, integrity_fault_words,
    lifecycle_words, part_fault_words, release_words, retirement_words,
};
use crate::words::{Sentence, download as words};

/// Spec §3.2 status column vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DownloadStatus {
    /// Queued, resumed, or out of sources: nothing is being fetched.
    Waiting,
    /// Its run found no connection to ask for sources on — no server session
    /// and no Kad — and waits for one (ADR-0097). Not a failure.
    NoConnection,
    /// A peer granted a slot, or a part is assigned.
    Downloading,
    /// Stopped on request; the row keeps everything it knows.
    Paused,
    /// Every part verified and the file checked: core moves the finished
    /// file into place (ADR-0115). Its step and the bytes copied are levels
    /// on the download's diagnostics row.
    Completing,
    /// Core called the file finished.
    Completed,
    /// Core called it terminally failed; the row keeps the reason.
    Failed,
}

/// One download's event-folded lifecycle facts. Live per-part/per-worker
/// *levels* deliberately do not live here — views join
/// [`UiState::diagnostics`] and [`UiState::rates`] by [`DownloadId`], so the
/// edge path and the level path can never drift apart.
#[derive(Clone, Debug)]
pub struct DownloadRow {
    /// Known from `DownloadQueued` and `DownloadRecovered` alike (ADR-0078):
    /// both edges carry the hash directly, so no row ever waits on a levels
    /// join to learn it.
    pub file_hash: Option<FileHash>,
    /// The status column, last edge wins.
    pub status: DownloadStatus,
    /// From `HashSetReceived`; `None` until the hash set lands.
    pub part_count: Option<usize>,
    /// Verified bytes as the edges state them: what the last
    /// `DownloadProgressRestored` restored (at recovery, and again at every
    /// resume), plus each part a `PartVerified` confirmed since. The Done
    /// figure of a download with no live part map.
    pub verified_bytes: u64,
    /// Name + exact size (ADR-0078), carried by the same `DownloadQueued`/
    /// `DownloadRecovered` edges as `file_hash`. `None` only for the brief
    /// window where some other edge created the row (edge-order tolerance)
    /// before either of those landed.
    pub metadata: Option<DownloadMetadata>,
    /// Where the download's bytes lie now, as core published it (ADR-0114):
    /// the `.part` from `DownloadQueued` or `DownloadRecovered`, the finished
    /// file once a `Completing` edge waiting for the store or
    /// `DownloadCompleted` names it. Never composed from the download
    /// directory and the name. `None` until one of those edges.
    pub file_path: Option<PathBuf>,
    /// Why the last run failed, as the `DownloadFailed` edge said, or as the
    /// store kept it across a restart (`DownloadRecovered`). `None` for a row
    /// not failed, and for one failed before the store kept reasons.
    pub failure: Option<DownloadFailure>,
    /// Who can still find a source for a run that has none to try, as its
    /// last `WaitingForSources` said; `None` once the status moves on.
    pub source_wait: Option<SourceWait>,
}

impl DownloadRow {
    fn new(status: DownloadStatus) -> Self {
        Self {
            file_hash: None,
            status,
            part_count: None,
            verified_bytes: 0,
            metadata: None,
            file_path: None,
            failure: None,
            source_wait: None,
        }
    }
}

impl UiState {
    /// Whether `download_id`'s row says bytes are moving: only a Downloading
    /// row has a speed or an estimate (ADR-0071, "Download ETA").
    fn download_running(&self, download_id: DownloadId) -> bool {
        self.downloads
            .get(&download_id)
            .is_some_and(|row| row.status == DownloadStatus::Downloading)
    }

    /// The download's Speed, bytes/sec: its meter while the row is
    /// Downloading, 0 in any other status however many bytes the meter's
    /// window still holds — the status is the fact, not the meter.
    #[must_use]
    pub fn download_speed(&self, download_id: DownloadId) -> f64 {
        if !self.download_running(download_id) {
            return 0.0;
        }
        self.rates
            .download_bps
            .get(&download_id)
            .copied()
            .unwrap_or(0.0)
    }

    /// The speed the download's ETA divides by: the minute's average while
    /// the row is Downloading, `None` (no estimate) in any other status.
    #[must_use]
    pub fn download_eta_speed(&self, download_id: DownloadId) -> Option<f64> {
        if !self.download_running(download_id) {
            return None;
        }
        self.rates.download_avg_bps.get(&download_id).copied()
    }
}

pub(super) fn fold(state: &mut UiState, event: DownloadEvent) -> bool {
    use DownloadEvent as E;
    match event {
        E::DownloadQueued {
            download_id,
            file_hash,
            metadata,
            file_path,
        } => {
            let row = row_mut(state, download_id);
            row.file_hash = Some(file_hash);
            row.metadata = Some(metadata);
            row.file_path = Some(file_path);
            row.status = DownloadStatus::Waiting;
            note(state, words::QUEUED)
        }
        E::DownloadRecovered {
            download_id,
            state: lifecycle,
            failure,
            file_hash,
            metadata,
            file_path,
        } => {
            let status = match lifecycle {
                // No run exists yet: core starts one at its pace (ADR-0093),
                // and `DownloadResumed` then a granted slot move the row on.
                DownloadLifecycle::Queued | DownloadLifecycle::Active => DownloadStatus::Waiting,
                DownloadLifecycle::Paused => DownloadStatus::Paused,
                DownloadLifecycle::Failed => DownloadStatus::Failed,
                DownloadLifecycle::Completed => DownloadStatus::Completed,
                // Its run starts at once and goes straight to the move.
                DownloadLifecycle::Completing => DownloadStatus::Completing,
                // A cancelled download has no row to recover.
                DownloadLifecycle::Cancelled => return false,
            };
            let row = row_mut(state, download_id);
            row.status = status;
            row.failure = failure;
            row.file_hash = Some(file_hash);
            row.metadata = Some(metadata);
            row.file_path = Some(file_path);
            note(state, words::RECOVERED)
        }
        E::DownloadProgressRestored {
            download_id,
            verified_bytes,
            ..
        } => {
            row_mut(state, download_id).verified_bytes = verified_bytes;
            true
        }
        E::PartVerified {
            download_id,
            part_index,
        } => {
            let row = row_mut(state, download_id);
            // A part is its full size but for the last, which is what the
            // file leaves; without the size yet, the full size is the fact.
            let start = u64::from(part_index).saturating_mul(ED2K_PART_SIZE);
            let len = row.metadata.as_ref().map_or(ED2K_PART_SIZE, |metadata| {
                metadata.size.saturating_sub(start).min(ED2K_PART_SIZE)
            });
            row.verified_bytes = row.verified_bytes.saturating_add(len);
            true
        }
        // The download's own view of a login that `ServerConnectionEvent`
        // already reported for the session as a whole. Folding the
        // connection here too would give `ed2k` two writers, one of which
        // (this one) can never say "disconnected" — so this arm keeps only
        // the log line `apply` pushed.
        E::ServerLoginAccepted { .. } => false,
        // What a lookup or an exchange answered is a log line: the sources a
        // download knows are the level its diagnostics row republishes, which
        // counts every surface's sources, not the last answer's.
        E::SourcesExchanged { .. } => false,
        // Seeds show on the sources they became; attach's one line is the
        // Networks log's.
        E::SeedsLoaded { .. } | E::SeedsDialled { .. } => false,
        // A lookup answered, so a download that waited for a connection has
        // one now.
        E::SourcesFound { download_id, .. } => {
            let waited = state
                .downloads
                .get(&download_id)
                .is_some_and(|row| row.status == DownloadStatus::NoConnection);
            waited && set_status(state, download_id, DownloadStatus::Waiting)
        }
        E::PeerSlotGranted { download_id, .. } | E::PartAssigned { download_id, .. } => {
            set_status(state, download_id, DownloadStatus::Downloading)
        }
        E::HashSetReceived {
            download_id,
            part_count,
            ..
        } => {
            row_mut(state, download_id).part_count = Some(part_count);
            true
        }
        E::DownloadCompleted {
            download_id,
            final_path,
        } => {
            row_mut(state, download_id).file_path = Some(final_path);
            let changed = set_status(state, download_id, DownloadStatus::Completed);
            note(state, words::COMPLETED) || changed
        }
        E::DownloadCancelled { download_id } => {
            state.downloads.remove(&download_id);
            note(state, words::CANCELLED)
        }
        // The download is forgotten; its file stays shared, so its mark is
        // the registry's Have, which this edge does not touch.
        E::DownloadCleared { download_id } => {
            state.downloads.remove(&download_id);
            note(state, words::CLEARED)
        }
        E::DownloadPaused { download_id } => set_status(state, download_id, DownloadStatus::Paused),
        E::DownloadResumed { download_id } => {
            row_mut(state, download_id).failure = None;
            set_status(state, download_id, DownloadStatus::Waiting)
        }
        E::DownloadFailed {
            download_id,
            reason,
        } => {
            let text = failure_line(state, download_id, &reason);
            row_mut(state, download_id).failure = Some(reason);
            set_status(state, download_id, DownloadStatus::Failed);
            note(state, text)
        }
        // A second link's sources joined the running download: the operator
        // pasted it, so the status feed answers them.
        E::LinkSourcesAdded {
            download_id, new, ..
        } => {
            let text = words::link_sources_added(&download_name(state, download_id), new);
            note(state, text)
        }
        E::FailureNotRecorded { download_id } => {
            let text = words::failure_not_recorded(&download_name(state, download_id));
            note(state, text)
        }
        E::DamagedPartsDropped {
            download_id,
            damaged,
        } => {
            let text = words::damaged_parts(&download_name(state, download_id), &damaged);
            note(state, text)
        }
        // The part file is the operator's to delete (ADR-0094): said at once,
        // with what it cost.
        E::PartFileLost {
            download_id,
            found,
            lost,
        } => {
            let text = words::part_file_lost(&download_name(state, download_id), found, lost);
            note(state, text)
        }
        // Once per run (ADR-0111): the note says it now; the Transfers
        // details modal keeps the verdict as the row's level.
        E::HoleLessDestination {
            download_id,
            directory,
        } => {
            let text = words::hole_less_destination(&download_name(state, download_id), &directory);
            note(state, text)
        }
        E::PartsDisproved {
            download_id,
            parts,
            bytes,
        } => {
            let text = words::parts_disproved(&download_name(state, download_id), parts, bytes);
            note(state, text)
        }
        E::FinishedFileRejected {
            download_id,
            parts_dropped,
            bytes_dropped,
        } => {
            let text = words::finished_file_rejected(
                &download_name(state, download_id),
                parts_dropped,
                bytes_dropped,
            );
            note(state, text)
        }
        // The operator's one Restart: core picked whether it continued
        // or started over, and the status bar says which and what it cost.
        E::DownloadRestarted {
            download_id,
            outcome,
        } => {
            row_mut(state, download_id).failure = None;
            let changed = set_status(state, download_id, DownloadStatus::Waiting);
            let text = words::restarted(&download_name(state, download_id), &outcome);
            note(state, text) || changed
        }
        // A step of the completion move that waits or copies began: the
        // row reads Completing, and the note says what it does (ADR-0115).
        // Waiting for the store is the one step core tells only once the
        // finished file is in place, so from it on the bytes lie at `to`:
        // a same-volume rename has taken the `.part` away.
        E::Completing {
            download_id,
            step,
            to,
        } => {
            if step == CompletionStep::WaitingForStore {
                row_mut(state, download_id).file_path = Some(to);
            }
            let changed = set_status(state, download_id, DownloadStatus::Completing);
            let text = words::completing(&download_name(state, download_id), step);
            note(state, text) || changed
        }
        E::WaitingForConnection { download_id } => {
            let changed = set_status(state, download_id, DownloadStatus::NoConnection);
            note(state, words::NO_NETWORK_WAIT_NOTE) || changed
        }
        // With no server session and Kad off nothing asks for it: the same
        // "No network" a lookup that found no connection leaves, worded for
        // a run whose sources are spent.
        E::WaitingForSources {
            download_id,
            reason,
        } => {
            let status = match reason {
                SourceWait::NoSession => DownloadStatus::NoConnection,
                SourceWait::Asking | SourceWait::KadAlone => DownloadStatus::Waiting,
            };
            let changed = set_status(state, download_id, status);
            let row = row_mut(state, download_id);
            let moved = row.source_wait != Some(reason);
            row.source_wait = Some(reason);
            note(state, words::waiting_for_sources(reason)) || changed || moved
        }
        // Per-peer texture for the sources pane and reask/queue detail —
        // no spine fact changes, so no redraw from here yet.
        E::PeerSelected { .. }
        | E::PeerQueued { .. }
        | E::PeerSlotTimeout { .. }
        | E::SourceRemoteQueued { .. }
        | E::SourceReaskAcked { .. }
        | E::SourceReaskQueueFull { .. }
        | E::SourceReaskedOverTcp { .. }
        | E::SourcePurged { .. }
        | E::SourceReaskDropped { .. }
        | E::ReaskReplyIgnored { .. }
        | E::DialEnded { .. }
        | E::PartReleased { .. }
        | E::PeerRetired { .. } => false,
    }
}

/// The download as the operator knows it: its name, or its number before any
/// edge named it.
fn download_name(state: &UiState, download_id: DownloadId) -> String {
    words::download_name(
        state
            .downloads
            .get(&download_id)
            .and_then(|row| row.metadata.as_ref()),
        download_id,
    )
}

/// The status-bar line for a `DownloadFailed`, read before the edge folds: a
/// row already Failed was being restarted, and that restart failed again —
/// said so, since the row itself does not change.
fn failure_line(state: &UiState, download_id: DownloadId, reason: &DownloadFailure) -> Sentence {
    let again = state
        .downloads
        .get(&download_id)
        .is_some_and(|row| row.status == DownloadStatus::Failed);
    words::failed(&download_name(state, download_id), reason, again)
}

/// The flash a `DownloadFailed` owes when it ends a restart of a download
/// already Failed: the row does not change, so without it the operator's
/// Restart looks like nothing happened. `None` for any other event.
#[must_use]
pub fn restart_failed_again(state: &UiState, event: &DownloadEvent) -> Option<Sentence> {
    match event {
        DownloadEvent::DownloadFailed {
            download_id,
            reason,
        } if state
            .downloads
            .get(download_id)
            .is_some_and(|row| row.status == DownloadStatus::Failed) =>
        {
            Some(failure_line(state, *download_id, reason))
        }
        _ => None,
    }
}

/// Row accessor tolerating edge order: an edge for an unknown download (e.g.
/// recovery flows) creates its row instead of being lost.
pub(super) fn row_mut(state: &mut UiState, download_id: DownloadId) -> &mut DownloadRow {
    state
        .downloads
        .entry(download_id)
        .or_insert_with(|| DownloadRow::new(DownloadStatus::Waiting))
}

fn set_status(state: &mut UiState, download_id: DownloadId, status: DownloadStatus) -> bool {
    let row = row_mut(state, download_id);
    let changed = row.status != status;
    row.status = status;
    row.source_wait = None;
    changed
}

#[cfg(test)]
mod tests;
