//! The **Firewalled Front**'s shared face: the command half the running node
//! asks it through, and the buddy level read beside it — the slot's
//! [`BuddySnapshot`] and the Kad pump's [`RecruitStatus`], each with one
//! writer (ADR-0061).
//!
//! Late-bound like the NAT-T front's, because the client-UDP socket binds
//! after the cells that reach the front were woven: the command half is empty
//! until the front starts, and empty means no firewalled front at all — no
//! client-UDP socket bound, so this node has no UDP surface to be called back
//! on and no socket its buddy's hint could name.

use std::sync::{Arc, OnceLock};

use tokio::sync::{mpsc, watch};

use rmule_kad::KadId;

use super::{FirewalledCommand, KadStart};
use crate::firewalled::link::{BuddySnapshot, BuddyState, FirewalledSlot};
use crate::firewalled::recruit::RecruitStatus;

/// The front's command half and the buddy level's two cells, as every surface
/// that reaches the front holds them.
#[derive(Clone, Debug)]
pub(crate) struct SharedFirewalledFront {
    commands: Arc<OnceLock<mpsc::Sender<FirewalledCommand>>>,
    /// The **Buddy Snapshot**. Its one writer is the slot the front owns,
    /// which only [`slot`](Self::slot) hands it to.
    snapshot: Arc<watch::Sender<BuddySnapshot>>,
    /// The Kad pump's **Recruit Status**. Its one writer is the running Kad
    /// node's pump; it outlives every node, as the published Kad verdicts do.
    recruit: Arc<watch::Sender<RecruitStatus>>,
    /// The last Kad node's start, latest wins. Its one writer is the Kad
    /// runtime as each node starts; its one reader is the front.
    kad_start: Arc<watch::Sender<Option<KadStart>>>,
}

impl Default for SharedFirewalledFront {
    fn default() -> Self {
        Self {
            commands: Arc::default(),
            snapshot: Arc::new(watch::Sender::new(BuddySnapshot::default())),
            recruit: Arc::new(watch::Sender::new(RecruitStatus::default())),
            kad_start: Arc::new(watch::Sender::new(None)),
        }
    }
}

impl SharedFirewalledFront {
    /// Install the running front's command half. Idempotent: one front per
    /// core.
    pub(crate) fn install(&self, commands: mpsc::Sender<FirewalledCommand>) {
        let _ = self.commands.set(commands);
    }

    /// Ask the front for something, reporting whether there was a front to
    /// ask. `try_send`, never `send`: every caller runs inside another loop —
    /// the client-UDP demux, the Kad pump — and a full inbox must cost one
    /// callback rather than stall the socket behind it.
    pub(crate) fn send(&self, command: FirewalledCommand) -> bool {
        self.commands
            .get()
            .is_some_and(|commands| commands.try_send(command).is_ok())
    }

    /// Tell the front a Kad node started. A cell, not a command: it is never
    /// refused for a full inbox, and it waits for a front that has not
    /// started yet. Every start notifies, an identical one included — a
    /// restart under a pinned Kad ID is still a new node whose predecessor's
    /// buddy must be let go.
    pub(crate) fn kad_started(&self, start: KadStart) {
        self.kad_start.send_replace(Some(start));
    }

    /// The front's reader of the Kad Start cell. A start published before
    /// the front subscribed reads changed, so it is applied all the same.
    pub(super) fn kad_starts(&self) -> watch::Receiver<Option<KadStart>> {
        let mut starts = self.kad_start.subscribe();
        if starts.borrow().is_some() {
            starts.mark_changed();
        }
        starts
    }

    /// Publish the Kad pump's Recruit Status — the pump is its one writer.
    /// A status equal to the one published wakes nobody.
    pub(crate) fn publish_recruit(&self, status: RecruitStatus) {
        self.recruit.send_if_modified(|published| {
            let moved = *published != status;
            *published = status;
            moved
        });
    }

    /// The Recruit Status as the pump last published it.
    pub(crate) fn recruit_status(&self) -> RecruitStatus {
        *self.recruit.borrow()
    }

    /// The buddy level as its readers hold it.
    pub(crate) fn view(&self) -> BuddyView {
        BuddyView {
            slot: self.snapshot.subscribe(),
            recruit: self.recruit.subscribe(),
        }
    }

    /// The slot that publishes into this front's snapshot, for a node of
    /// `our_kad_id`. The front's own, and a test's that stands in for it.
    pub(super) fn slot(&self, our_kad_id: KadId) -> FirewalledSlot {
        FirewalledSlot::new(our_kad_id, Arc::clone(&self.snapshot))
    }

    /// A slot over a fresh front's snapshot, and the view of it — for a test
    /// that drives the slot as the front would and reads it as a reader does.
    #[cfg(test)]
    pub(crate) fn detached_slot(our_kad_id: KadId) -> (FirewalledSlot, BuddyView) {
        let front = Self::default();
        (front.slot(our_kad_id), front.view())
    }
}

/// The buddy level as a reader holds it: the slot's Buddy Snapshot and the
/// Kad pump's Recruit Status, each read from its own owner, composed here
/// into the operator's [`BuddyState`].
#[derive(Clone, Debug)]
pub(crate) struct BuddyView {
    slot: watch::Receiver<BuddySnapshot>,
    recruit: watch::Receiver<RecruitStatus>,
}

/// A view over cells nothing writes: no buddy, no walk — the reading of a
/// node with no firewalled front.
impl Default for BuddyView {
    fn default() -> Self {
        SharedFirewalledFront::default().view()
    }
}

impl BuddyView {
    /// The Buddy Snapshot as its owner last published it.
    pub(crate) fn snapshot(&self) -> BuddySnapshot {
        *self.slot.borrow()
    }

    /// The operator's buddy state, marking both halves seen: the read a
    /// reader that waits on [`changed`](Self::changed) takes.
    pub(crate) fn seen_state(&mut self) -> BuddyState {
        let walking = self.recruit.borrow_and_update().walking;
        self.slot.borrow_and_update().state_while(walking)
    }

    /// Wait until either half moves; `None` once both owners are gone.
    pub(crate) async fn changed(&mut self) -> Option<()> {
        tokio::select! {
            Ok(()) = self.slot.changed() => Some(()),
            Ok(()) = self.recruit.changed() => Some(()),
            else => None,
        }
    }
}
