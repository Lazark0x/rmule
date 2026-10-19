//! A download's part file on its diagnostics row (ADR-0111): the **Allocated
//! Bytes** reading the run takes when it holds the file and after each part
//! it writes, and the **Hole Verdict** of the run's probe. Both are levels the
//! run publishes as read; neither is computed here.

use super::DiagnosticsState;
use crate::DownloadId;
use crate::content::HoleVerdict;

impl DiagnosticsState {
    /// The run read its part file's Allocated Bytes: `allocated`, or `None`
    /// when the reading failed. A no-op when the row is gone.
    pub fn part_file_read(&self, download_id: DownloadId, allocated: Option<u64>) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        if let Some(row) = inner.downloads.get_mut(&download_id) {
            row.allocated_bytes = allocated;
        }
    }

    /// The run's Hole Probe answered `verdict`. A no-op when the row is gone.
    pub fn hole_probed(&self, download_id: DownloadId, verdict: HoleVerdict) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        if let Some(row) = inner.downloads.get_mut(&download_id) {
            row.hole_verdict = Some(verdict);
        }
    }
}
