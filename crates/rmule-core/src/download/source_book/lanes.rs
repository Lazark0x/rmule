//! The **Source Book**'s three pooled lanes, in dial order: each pooled record
//! waits in exactly the lane its stage names, and a fill drains High ID first,
//! then Low ID on the connected server, then Low ID global.

use std::collections::VecDeque;

use super::record::{Lane, RecordId};

/// The pooled records, one queue per [`Lane`].
#[derive(Debug, Default)]
pub(super) struct Lanes {
    high_id: VecDeque<RecordId>,
    low_id_connected: VecDeque<RecordId>,
    low_id_global: VecDeque<RecordId>,
}

impl Lanes {
    fn lane(&self, lane: Lane) -> &VecDeque<RecordId> {
        match lane {
            Lane::HighId => &self.high_id,
            Lane::LowIdConnected => &self.low_id_connected,
            Lane::LowIdGlobal => &self.low_id_global,
        }
    }

    fn lane_mut(&mut self, lane: Lane) -> &mut VecDeque<RecordId> {
        match lane {
            Lane::HighId => &mut self.high_id,
            Lane::LowIdConnected => &mut self.low_id_connected,
            Lane::LowIdGlobal => &mut self.low_id_global,
        }
    }

    /// Queue `id` last in `lane` — a sighting's turn.
    pub(super) fn push_back(&mut self, lane: Lane, id: RecordId) {
        self.lane_mut(lane).push_back(id);
    }

    /// Queue `id` first in `lane`, for the refill that follows a fall.
    pub(super) fn push_front(&mut self, lane: Lane, id: RecordId) {
        self.lane_mut(lane).push_front(id);
    }

    /// Take the first record of `lane`.
    pub(super) fn pop_front(&mut self, lane: Lane) -> Option<RecordId> {
        self.lane_mut(lane).pop_front()
    }

    /// Take `id` out of `lane`, wherever it waits.
    pub(super) fn remove(&mut self, lane: Lane, id: RecordId) {
        let queue = self.lane_mut(lane);
        if let Some(at) = queue.iter().position(|&held| held == id) {
            queue.remove(at);
        }
    }

    /// `lane`'s records, first to last.
    pub(super) fn iter(&self, lane: Lane) -> impl Iterator<Item = RecordId> + '_ {
        self.lane(lane).iter().copied()
    }

    /// Whether `lane` holds nothing.
    pub(super) fn is_empty(&self, lane: Lane) -> bool {
        self.lane(lane).is_empty()
    }
}
