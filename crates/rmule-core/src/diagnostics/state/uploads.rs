//! Upload rows and the per-file share totals on the level: opening and closing
//! a peer's row, byte and request counts, and the stored-totals seed and flush.

use super::*;

impl DiagnosticsState {
    /// Open `peer`'s upload row on a slot grant for `file_hash`. Re-opening a
    /// live row only re-points its file (a peer re-granted for a second file
    /// keeps its running `bytes_sent`, aMule's per-client total).
    pub fn open_upload(&self, peer: PeerEndpoint, file_hash: FileHash) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner
            .uploads
            .entry(peer)
            .and_modify(|row| row.file_hash = file_hash)
            .or_insert_with(|| UploadDiagnostics {
                peer,
                file_hash,
                started_at: Instant::now(),
                bytes_sent: 0,
            });
    }

    /// Count `bytes` of payload just handed to `peer`'s connection writer
    /// (ADR-0077). Opens the row when the grant was never observed, so no
    /// served byte is dropped for want of a row.
    pub fn add_sent_bytes(&self, peer: PeerEndpoint, file_hash: FileHash, bytes: u64) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.up_bytes_total = inner.session.up_bytes_total.saturating_add(bytes);
        let row = inner
            .uploads
            .entry(peer)
            .or_insert_with(|| UploadDiagnostics {
                peer,
                file_hash,
                started_at: Instant::now(),
                bytes_sent: 0,
            });
        row.file_hash = file_hash;
        row.bytes_sent = row.bytes_sent.saturating_add(bytes);
        inner.shared_files.add(
            file_hash,
            ShareTotals {
                transferred: bytes,
                ..ShareTotals::default()
            },
        );
    }

    /// Count one upload request `file_hash` drew (aMule's `AddRequest`): a
    /// peer not already waiting asked for a slot and passed the per-address
    /// cap.
    pub fn count_upload_request(&self, file_hash: FileHash) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let request = ShareTotals {
            requests: 1,
            ..ShareTotals::default()
        };
        inner.shared_files.add(file_hash, request);
    }

    /// Count one upload slot granted for `file_hash` (aMule's `AddAccepted`).
    pub fn count_upload_accept(&self, file_hash: FileHash) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let accept = ShareTotals {
            accepted: 1,
            ..ShareTotals::default()
        };
        inner.shared_files.add(file_hash, accept);
    }

    /// Seed the all-time figures with what the Durable Store held at start.
    /// Once per core, before any serving: the all-time figure is always the
    /// stored one plus this run's.
    pub(crate) fn seed_share_totals(&self, stored: BTreeMap<FileHash, ShareTotals>) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.shared_files.seed(stored);
    }

    /// The all-time figures of every file whose counters moved since the
    /// last take — what a flush writes to the store.
    pub(crate) fn take_share_flush(&self) -> Vec<(FileHash, ShareTotals)> {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.shared_files.take_moved()
    }

    /// Hand back a flush the store refused, so the next one writes it.
    pub(crate) fn restore_share_flush(&self, files: impl IntoIterator<Item = FileHash>) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.shared_files.restore_moved(files);
    }

    /// Retire `peer`'s upload row when its slot is released. The bytes it
    /// carried stay counted in [`SessionCounters::up_bytes_total`].
    pub fn close_upload(&self, peer: PeerEndpoint) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.uploads.remove(&peer);
    }

    /// Retire every open upload row when the serve activity feeding them ends
    /// `close_upload` fires only on `UploadSlotReleased`, which
    /// an ending serve task never emits — the connection writers it was
    /// feeding simply stop existing with it — so a row still open at
    /// `StopServing`, a listener death, or a task failure would otherwise
    /// read "uploading" forever. `finish_serve` is the one place every serve
    /// end converges (`StopServing`, listener death, task
    /// failure), and so the one caller.
    ///
    /// `reason` is the same [`ServeStopReason`] `ServingStopped` carries —
    /// the exact "why the activity ended" fact already exists, so this takes
    /// it rather than inventing a second reason type to say the same thing.
    /// It is not persisted on a struct nothing reads (a closed row leaves the
    /// map, like any other close): it names the sweep in the one trace a
    /// consumer who was watching bytes climb on these peers gets.
    pub fn close_all_uploads(&self, reason: ServeStopReason) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        if inner.uploads.is_empty() {
            return;
        }
        let closed = inner.uploads.len();
        inner.uploads.clear();
        tracing::debug!(closed, ?reason, "upload rows closed: serve activity ended");
    }
}
