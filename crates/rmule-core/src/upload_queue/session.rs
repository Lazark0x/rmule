//! The **Upload Session** bound (ADR-0031): a slot ends at stock's bytes or
//! time while a waiter the queue can reach stands behind every slot, one a
//! second, so a holder cannot keep a slot for a whole file. The count lives on
//! the slot, and so rides a relink and ends with it.

use std::time::{Duration, Instant};

use rmule_primitives::PeerEndpoint;

use super::UploadSlotQueue;

/// Bytes an Upload Session may send while someone waits
/// (`UploadQueue.cpp:617`; 2.3.3 `UploadQueue.cpp:581`).
pub const SESSION_CAP_BYTES: u64 = 10_485_760;

/// How long an Upload Session may run while someone waits
/// (`UploadQueue.cpp:616`).
pub const SESSION_CAP_TIME: Duration = Duration::from_secs(60 * 60);

/// The pace sessions end at: `Process` starts one client a second
/// (`UploadQueue.cpp:244`).
const SESSION_END_PACE: Duration = Duration::from_secs(1);

impl UploadSlotQueue {
    /// `bytes` of `peer`'s session left for the socket. A block outliving its
    /// slot counts for nobody.
    pub fn count_session_sent(&mut self, peer: PeerEndpoint, bytes: u64) {
        if let Some(slot) = self.granted.iter_mut().find(|g| g.peer == peer) {
            slot.session_sent = slot.session_sent.saturating_add(bytes);
        }
    }

    /// The live slot whose Upload Session is over at `now`, its end taken
    /// from the pace: `None` unless every slot is taken, a waiter the queue
    /// can reach stands behind them, and a second has passed since the last.
    /// A session goes on past its bound for as long as nobody can use the
    /// slot (`UploadQueue.cpp:586-591`, `:244-258`).
    pub fn session_to_end(&mut self, now: Instant) -> Option<PeerEndpoint> {
        let paced = self
            .last_session_end
            .is_none_or(|last| now.saturating_duration_since(last) >= SESSION_END_PACE);
        let waiter = self.waiting.iter().any(|q| q.connected || q.dialable);
        if !paced || !waiter || self.granted.len() < self.budget {
            return None;
        }
        let over = self.granted.iter().find(|slot| {
            slot.dial_back_since.is_none()
                && (slot.session_sent > SESSION_CAP_BYTES
                    || now.saturating_duration_since(slot.session_start) > SESSION_CAP_TIME)
        })?;
        self.last_session_end = Some(now);
        Some(over.peer)
    }
}
