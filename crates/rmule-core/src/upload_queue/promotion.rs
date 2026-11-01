//! What a freed slot did: the grant it went to, and the waiters whose rank
//! moved for it.

use rmule_primitives::{FileHash, PeerEndpoint};

/// A waiter taking a freed slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotGrant {
    /// The waiter that took the slot.
    pub peer: PeerEndpoint,
    /// The file it waited for.
    pub file_hash: FileHash,
    /// The waiter had no live TCP serve connection (disconnected standing,
    /// ADR-0057), so its grant is a **dial-back**: rmule dials its TCP endpoint
    /// and sends `OP_ACCEPTUPLOADREQ` on connect, rather than granting over a
    /// dead socket.
    pub dial_back: bool,
}

/// What changed when a peer left the queue or released a slot: an optional
/// newly-granted head plus the queued peers whose rank moved. The queue reports
/// **only changed** ranks (it remembers each entry's last-reported rank), so the
/// serve task never re-sends an unchanged `OP_QUEUERANKING`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Promotion {
    /// The grant the freed slot went to, or `None` when nobody was waiting.
    pub granted: Option<SlotGrant>,
    /// Waiters whose 1-based rank changed, and their new rank. Only changed
    /// ranks appear, so this is exactly the set of `OP_QUEUERANKING` messages
    /// the serve task must send.
    pub reranked: Vec<(PeerEndpoint, u16)>,
}
