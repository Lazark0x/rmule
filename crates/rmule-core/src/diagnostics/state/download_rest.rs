//! A download's diagnostics row with no run behind it (ADR-0093, "The part
//! picture is the download's, not its run's"): which parts are held is a fact
//! of the download, so a paused, failed, waiting or restored download keeps a
//! row whose part map shows held and missing parts and nothing in flight.

use std::collections::BTreeMap;
use std::time::Instant;

use rmule_primitives::{FileHash, part_count};

use super::DiagnosticsState;
use crate::diagnostics::{DownloadDiagnostics, PartState};
use crate::{DownloadId, DownloadMetadata};

impl DiagnosticsState {
    /// Open (or reset) `download_id`'s row at rest from its durable facts: the
    /// part map is `Verified` at each index of `verified_parts` and `Missing`
    /// everywhere else over the file's `part_count(size)`, with no workers and
    /// no sources — what attach knows of a download before any run starts.
    pub fn rest_download(
        &self,
        download_id: DownloadId,
        file_hash: FileHash,
        metadata: DownloadMetadata,
        verified_parts: &[u32],
    ) {
        let parts = (0..part_count(metadata.size))
            .map(|index| {
                if verified_parts.contains(&index) {
                    PartState::Verified
                } else {
                    PartState::Missing
                }
            })
            .collect();
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let row = inner
            .downloads
            .entry(download_id)
            .or_insert_with(|| DownloadDiagnostics {
                download_id,
                file_hash,
                metadata,
                started_at: Instant::now(),
                parts: Vec::new(),
                retired_peers: 0,
                workers: BTreeMap::new(),
                received_bytes: 0,
                known_sources: 0,
                dials_ended: 0,
                reask_replies_ignored: 0,
                dial_ends: BTreeMap::new(),
            });
        row.parts = parts;
        row.workers.clear();
        row.known_sources = 0;
        row.dial_ends.clear();
    }

    /// `parts` were lost from the part file (ADR-0094, "The run holds its
    /// part file"): the picture shows them missing at once, so what
    /// the operator reads is what the file holds.
    pub fn parts_lost(&self, download_id: DownloadId, parts: &[u32]) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let Some(row) = inner.downloads.get_mut(&download_id) else {
            return;
        };
        for index in parts {
            if let Some(part) = usize::try_from(*index)
                .ok()
                .and_then(|index| row.parts.get_mut(index))
            {
                *part = PartState::Missing;
            }
        }
    }

    /// Put `download_id`'s row to rest as its run ends: a part in flight is not
    /// held, so it reads `Missing`; the workers and the sources were the run's
    /// and leave with it. A `completed` run holds every part. The row itself
    /// stays — only a cancel removes it.
    pub fn end_run(&self, download_id: DownloadId, completed: bool) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let Some(row) = inner.downloads.get_mut(&download_id) else {
            return;
        };
        for part in &mut row.parts {
            *part = match (*part, completed) {
                (_, true) => PartState::Verified,
                (PartState::InFlight, false) => PartState::Missing,
                (held, false) => held,
            };
        }
        row.workers.clear();
        row.known_sources = 0;
    }
}
