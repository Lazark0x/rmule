//! A completing download's move on its diagnostics row (ADR-0115): the step
//! the run publishes as each begins, and the bytes its Completion Copy has
//! written. Levels the run sets as it goes; nothing is computed here.

use super::DiagnosticsState;
use crate::DownloadId;
use crate::diagnostics::CompletionProgress;
use crate::service::CompletionStep;

impl DiagnosticsState {
    /// The move began `step`; the bytes copied so far stay. A no-op when the
    /// row is gone.
    pub fn completion_step(&self, download_id: DownloadId, step: CompletionStep) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        if let Some(row) = inner.downloads.get_mut(&download_id) {
            let copied = row.completion.map_or(0, |progress| progress.copied);
            row.completion = Some(CompletionProgress { step, copied });
        }
    }

    /// The Completion Copy has written `copied` bytes. A no-op when the row
    /// is gone or its move has not begun.
    pub fn completion_copied(&self, download_id: DownloadId, copied: u64) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        if let Some(progress) = inner
            .downloads
            .get_mut(&download_id)
            .and_then(|row| row.completion.as_mut())
        {
            progress.copied = copied;
        }
    }
}
