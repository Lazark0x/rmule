//! **Kad Presence**: whether a Kad node runs on this core, and
//! as which Kad ID — one live answer every per-connection task can read the
//! moment a frame's handling depends on it. A served link's `OP_CALLBACK`
//! (`0x99`, ADR-0061) is the reader that needed it: aMule's arm gates on
//! `Kademlia::IsRunning()` and on the check field inverting to *this* node's
//! Kad ID, and the serve bridge runs on neither the pump's task nor the
//! firewalled front's.
//!
//! One writer (ADR-0093): the **Kad Activity** in the actor's
//! ledger holds the only [`KadPresenceLease`], taken when the activity starts
//! and dropped by its one retire — whatever ended it — so "Kad runs" is the
//! ledger's own fact and no second liveness flag can disagree with it. The
//! Kad runtime owns the cell (it wires the view into the surfaces it builds)
//! and every reader holds a [`KadPresenceView`]; the lease is taken through
//! **Self Reach** alone. A lease clears the cell when dropped only while the
//! cell is still *its*, so a late drop never declares a successor gone.
//!
//! The cell is a `watch` channel so a reader that must *act* on a change —
//! the firewalled front lets its buddy go the moment Kad stops
//! — can await it instead of polling; every other reader just reads.

use std::sync::Arc;

use rmule_kad::KadId;
use tokio::sync::watch;

/// The cell both halves share. `generation` names the lease that last wrote
/// it, so a stale lease can tell it no longer owns the value.
#[derive(Debug, Default)]
struct Presence {
    generation: u64,
    running_as: Option<KadId>,
}

/// The cell: cheap to clone into every per-connection task; every clone reads
/// the same cell. A default view is a fresh cell no activity has leased —
/// "no node", what a core that never enables Kad answers. `pub` (not `pub(crate)`):
/// it rides the public
/// [`ServeRuntimeService::set_kad_presence`](crate::adapters::ServeRuntimeService::set_kad_presence)
/// and
/// [`PeerTransferService::set_kad_presence`](crate::adapters::PeerTransferService::set_kad_presence)
/// trait methods, so a private type there would be unreachable through them.
#[derive(Clone, Debug, Default)]
pub struct KadPresenceView(Arc<watch::Sender<Presence>>);

/// A subscription to the cell's changes, for a reader whose loop must act the
/// moment Kad starts or stops rather than on its next poll.
#[derive(Debug)]
pub(crate) struct KadPresenceChanges(watch::Receiver<Presence>);

/// Held by the running **Kad Activity**; the node is present exactly as long
/// as this is.
#[derive(Debug)]
pub(crate) struct KadPresenceLease {
    cell: Arc<watch::Sender<Presence>>,
    generation: u64,
}

impl KadPresenceView {
    /// A node started as `kad_id`: publish it, and hand back the lease whose
    /// drop is that node's end. Taken only by
    /// [`SharedSelfReach::lease_kad`](crate::reachability::SharedSelfReach::lease_kad).
    pub(crate) fn lease(&self, kad_id: KadId) -> KadPresenceLease {
        let mut generation = 0;
        self.0.send_modify(|cell| {
            cell.generation = cell.generation.wrapping_add(1);
            cell.running_as = Some(kad_id);
            generation = cell.generation;
        });
        KadPresenceLease {
            cell: Arc::clone(&self.0),
            generation,
        }
    }

    /// The running node's Kad ID, or `None` when no node runs.
    pub(crate) fn running_as(&self) -> Option<KadId> {
        self.0.borrow().running_as
    }

    /// Subscribe to the cell's changes from now on.
    pub(crate) fn changes(&self) -> KadPresenceChanges {
        KadPresenceChanges(self.0.subscribe())
    }
}

impl KadPresenceChanges {
    /// Resolve once the cell changed since the last call (or since
    /// subscribing). Cancel-safe, so it can be raced in a `select!`. A view
    /// holds the writer half alive, so the channel never closes under a
    /// reader that keeps its view; one that outlives every view parks.
    pub(crate) async fn changed(&mut self) {
        if self.0.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

impl Drop for KadPresenceLease {
    fn drop(&mut self) {
        self.cell.send_if_modified(|cell| {
            let ours = cell.generation == self.generation && cell.running_as.is_some();
            if ours {
                cell.running_as = None;
            }
            ours
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A restart takes its lease before the old pump has finished tearing
    /// down; the old lease's late drop must leave the new node present.
    #[test]
    fn a_stale_lease_never_clears_its_successor() {
        let presence = KadPresenceView::default();
        let view = presence.clone();
        let first = KadId::from_bytes([0x01; KadId::BYTE_LEN]);
        let second = KadId::from_bytes([0x02; KadId::BYTE_LEN]);

        let old = presence.lease(first);
        assert_eq!(view.running_as(), Some(first));
        let new = presence.lease(second);
        drop(old);
        assert_eq!(view.running_as(), Some(second));
        drop(new);
        assert_eq!(view.running_as(), None);
    }
}
