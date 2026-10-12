//! The cells core owns around a Kad node, built once before any `start` and
//! lent to each.
//!
//! A node starts, stops and starts again over the same sockets, readers and
//! counters, so what it publishes into and what its neighbours read cannot be
//! the runtime's to create: a runtime that made its own would leave every
//! reader holding a cell that no pump of the core's ever writes. Core builds
//! the one set — [`KadCells`] — and hands it to
//! [`KadRuntimeFactory::start`](super::KadRuntimeFactory::start), so the runtime is a function of its inputs and
//! a fake of it states what it publishes through the same cells.

use std::sync::{Arc, Mutex, PoisonError};

use tokio::task::JoinHandle;

use super::{KadFactsView, KadPresenceView};
use crate::adapters::AdapterCells;
use crate::diagnostics::DiagnosticsState;
use crate::reachability::SharedKadVerdicts;

/// Where `start` leaves the ed2k→Kad handoff forwarder's task handle, and
/// `DisableKad` takes it back to join it beside the publisher. Empty before
/// the first start and again once taken.
#[derive(Clone, Debug, Default)]
pub(crate) struct HandoffSlot(Arc<Mutex<Option<JoinHandle<()>>>>);

impl HandoffSlot {
    /// Keep the forwarder `start` spawned.
    pub(crate) fn put(&self, forwarder: JoinHandle<()>) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(forwarder);
    }

    /// Take the forwarder back, if one was kept.
    pub(crate) fn take(&self) -> Option<JoinHandle<()>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).take()
    }
}

/// What core lends a Kad node for its life: the cells it publishes into, the
/// facts and traffic it counts, the slot it leaves its handoff task in, the
/// diagnostics it counts refusals into, and the adapter cells it shares with
/// the peer surfaces. Cheap to clone; every clone is the same set.
#[derive(Clone)]
pub struct KadCells {
    /// The Kad half of **Self Reach**: the two self-check verdicts and the
    /// join latch a node's pump writes, through the writer the actor's lease
    /// for that node mints.
    pub(crate) verdicts: SharedKadVerdicts,
    /// The table size, keyword index size and wire traffic a node's pump
    /// keeps moving, read by the diagnostics state.
    pub(crate) facts: KadFactsView,
    /// **Kad Presence**: whether a node runs, and as which Kad ID. Its one
    /// writer is the Kad Activity's lease in the actor's ledger.
    pub(crate) presence: KadPresenceView,
    /// Where `start` leaves its handoff forwarder.
    pub(crate) handoff: HandoffSlot,
    /// The live diagnostics state, installed by the actor before any start;
    /// the dial-back broker's pump is the single writer of its refusal counter.
    pub(crate) diagnostics: DiagnosticsState,
    /// The builder's one set of adapter cells: the bans, hints, helper gates,
    /// roster, filter and advertisements a node meets the peer surfaces on.
    pub(crate) adapters: AdapterCells,
}

impl KadCells {
    /// The set over `adapters`, every Kad cell fresh.
    pub(crate) fn new(adapters: AdapterCells) -> Self {
        Self {
            verdicts: SharedKadVerdicts::default(),
            facts: KadFactsView::default(),
            presence: KadPresenceView::default(),
            handoff: HandoffSlot::default(),
            diagnostics: DiagnosticsState::default(),
            adapters,
        }
    }

    /// A set shared with nothing, for a unit test that starts a node on its own.
    #[cfg(test)]
    pub(crate) fn detached() -> Self {
        Self::new(AdapterCells::detached())
    }
}
