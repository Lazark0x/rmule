//! A download's short-ended roads on its diagnostics row: a dial that ended
//! before the peer's hello, kept per source and counted, and a reask reply
//! that changed nothing, counted.

use std::time::Instant;

use rmule_primitives::PeerEndpoint;

use super::DiagnosticsState;
use crate::DownloadId;
use crate::diagnostics::{DIAL_ENDS_KEPT, SourceDialEnd, WorkerEntry, WorkerPhase, WorkerSlot};
use crate::service::DialEnd;

impl DiagnosticsState {
    /// The dial to `peer` ended before its hello for `cause`: counted on the
    /// download's row and kept as `peer`'s **Dial End** (ADR-0110) until a
    /// slot dials it again. A no-op when the row is gone.
    pub fn dial_ended(&self, download_id: DownloadId, peer: PeerEndpoint, cause: DialEnd) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let Some(row) = inner.downloads.get_mut(&download_id) else {
            return;
        };
        row.dials_ended = row.dials_ended.saturating_add(1);
        let remembered = row
            .workers
            .values()
            .any(|entry| entry.peer_endpoint() == Some(peer) && entry.remembered());
        row.dial_ends.insert(
            peer,
            SourceDialEnd {
                cause,
                at: Instant::now(),
                remembered,
            },
        );
        while row.dial_ends.len() > DIAL_ENDS_KEPT {
            let oldest = row
                .dial_ends
                .iter()
                .min_by_key(|(_, end)| end.at)
                .map(|(peer, _)| *peer);
            let Some(oldest) = oldest else { break };
            row.dial_ends.remove(&oldest);
        }
    }

    /// `slot` of `download_id` dials `peer`: the slot names it, connecting,
    /// and `peer`'s earlier **Dial End** leaves — the new dial speaks for it.
    pub fn attach_worker(&self, download_id: DownloadId, slot: WorkerSlot, peer: PeerEndpoint) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let Some(row) = inner.downloads.get_mut(&download_id) else {
            return;
        };
        row.dial_ends.remove(&peer);
        let entry = row
            .workers
            .entry(slot)
            .or_insert_with(|| WorkerEntry::new(slot));
        entry.attach_peer(peer);
        entry.transition(WorkerPhase::Connecting);
    }

    /// A reask reply routed to `download_id` changed nothing. A no-op when
    /// the row is gone.
    pub fn count_reask_reply_ignored(&self, download_id: DownloadId) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        if let Some(row) = inner.downloads.get_mut(&download_id) {
            row.reask_replies_ignored = row.reask_replies_ignored.saturating_add(1);
        }
    }
}
