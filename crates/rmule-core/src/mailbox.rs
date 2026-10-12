//! The mailbox of a restartable node: a cell that holds the one live sender of
//! a node which starts, stops and starts again over a socket or a front that
//! outlives it.
//!
//! The Kad node's datagram inlet, its pump and its bootstrap handoff, and the
//! serve activity's dialed-connection sink are each held for the core's whole
//! life by the surfaces that feed them, and each `start` fills them afresh. A
//! node whose stop timed out can still be tearing down after its successor has
//! filled them, so a teardown that cleared "the cell" would empty the
//! successor's. [`Mailbox::install`] therefore returns a [`Lease`], and a
//! lease's drop clears the cell only while it still holds that lease's own
//! sender.
//!
//! The cell is empty while no node runs: that emptiness is the gate a sender
//! reads, so [`Mailbox::send`] says whether the message was dropped for want of
//! a node or for want of room, and each caller counts or logs the reason it
//! cares about.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Sender, WeakSender};

/// Why [`Mailbox::send`] did not hand a message over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DropReason {
    /// No node is installed, or the one that was has stopped.
    NoNode,
    /// A node is installed and its inbox is full.
    Full,
}

/// The shared cell: empty while no node runs, the live node's sender otherwise.
/// Cloning shares the one cell. The lock is a `std` mutex because no use holds
/// it across an `.await`, and no surface holding a socket open may block on it.
pub(crate) struct Mailbox<T> {
    slot: Arc<Mutex<Option<Sender<T>>>>,
}

impl<T> Clone for Mailbox<T> {
    fn clone(&self) -> Self {
        Self {
            slot: Arc::clone(&self.slot),
        }
    }
}

impl<T> Default for Mailbox<T> {
    fn default() -> Self {
        Self {
            slot: Arc::default(),
        }
    }
}

impl<T> std::fmt::Debug for Mailbox<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mailbox")
            .field("live", &self.is_live())
            .finish()
    }
}

impl<T> Mailbox<T> {
    fn slot(&self) -> MutexGuard<'_, Option<Sender<T>>> {
        self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Put `tx` in the cell, replacing whatever it held, and return the lease
    /// whose drop takes it out again. The lease holds the sender weakly, so
    /// holding it never keeps a channel open.
    #[must_use = "dropping the lease at once empties the cell it just filled"]
    pub(crate) fn install(&self, tx: Sender<T>) -> Lease<T> {
        let ours = tx.downgrade();
        *self.slot() = Some(tx);
        Lease {
            slot: Arc::clone(&self.slot),
            ours,
        }
    }

    /// Fill the cell for good: a fixture whose sender nothing ever retires.
    #[cfg(test)]
    pub(crate) fn install_for_good(&self, tx: Sender<T>) {
        std::mem::forget(self.install(tx));
    }

    /// Hand `message` to the installed node without waiting for room.
    pub(crate) fn send(&self, message: T) -> Result<(), DropReason> {
        let slot = self.slot();
        let tx = slot.as_ref().ok_or(DropReason::NoNode)?;
        tx.try_send(message).map_err(|error| match error {
            TrySendError::Full(_) => DropReason::Full,
            TrySendError::Closed(_) => DropReason::NoNode,
        })
    }

    /// Whether a node is installed and still listening.
    pub(crate) fn is_live(&self) -> bool {
        self.slot().as_ref().is_some_and(|tx| !tx.is_closed())
    }

    /// A handle on the installed node's sender, for a caller that waits for
    /// room instead of dropping (a connection that must not lose its serve
    /// half to a momentarily full queue).
    pub(crate) fn sender(&self) -> Option<Sender<T>> {
        self.slot().clone()
    }
}

/// One node's claim on a [`Mailbox`]: dropping it empties the cell, but only
/// while the cell still holds the sender this lease installed.
pub(crate) struct Lease<T> {
    slot: Arc<Mutex<Option<Sender<T>>>>,
    ours: WeakSender<T>,
}

impl<T> Lease<T> {
    /// A weak handle on the sender this lease installed, for a task that
    /// pushes to its own node without keeping the channel open.
    pub(crate) fn weak(&self) -> WeakSender<T> {
        self.ours.clone()
    }
}

impl<T> Drop for Lease<T> {
    fn drop(&mut self) {
        let mut slot = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
        // A weak handle that no longer upgrades means every sender of that
        // channel is gone, so the slot cannot hold it.
        if let (Some(held), Some(ours)) = (slot.as_ref(), self.ours.upgrade())
            && held.same_channel(&ours)
        {
            *slot = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;

    use super::{DropReason, Mailbox};

    /// A node's teardown closes the cell it filled, and only that. The actor's
    /// stop waits for the lever's confirmation and, on a timeout, lets the old
    /// node live on until its stalled step returns; a restart in that window
    /// installs a successor's sender, and the predecessor's late teardown must
    /// leave it — or the running node is deaf to everything the surfaces send
    /// it until the next restart.
    #[tokio::test]
    async fn a_stale_lease_leaves_the_successor_live_and_its_own_drop_empties_the_cell() {
        let mailbox = Mailbox::<u8>::default();
        let (old_tx, _old_rx) = mpsc::channel(1);
        let (new_tx, mut new_rx) = mpsc::channel(1);
        let predecessor = mailbox.install(old_tx);
        let successor = mailbox.install(new_tx);

        drop(predecessor);
        assert!(mailbox.is_live(), "the successor is still installed");
        assert_eq!(mailbox.send(7), Ok(()));
        assert_eq!(new_rx.recv().await, Some(7));

        drop(successor);
        assert!(!mailbox.is_live());
        assert_eq!(mailbox.send(8), Err(DropReason::NoNode));
    }

    /// The two ways a message is not handed over are told apart: nobody is
    /// there, and nobody has room.
    #[tokio::test]
    async fn send_reports_no_node_and_full() {
        let mailbox = Mailbox::<u8>::default();
        assert_eq!(mailbox.send(1), Err(DropReason::NoNode));

        let (tx, rx) = mpsc::channel(1);
        let lease = mailbox.install(tx);
        assert_eq!(mailbox.send(1), Ok(()));
        assert_eq!(mailbox.send(2), Err(DropReason::Full));

        drop(rx);
        assert_eq!(mailbox.send(3), Err(DropReason::NoNode));
        assert!(!mailbox.is_live());
        drop(lease);
    }
}
