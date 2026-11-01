//! The gate on what a run republishes from its brain. Most arrivals move no
//! record and no part's state, and a republish walks the whole Source Book, so
//! the drain and the wake read [`DownloadState::generation`] first.
//! ADR-0116's seats and ADR-0107's standings still hear every move: a record
//! that changed moves the number.

use std::time::{Duration, Instant};

use crate::download::state::DownloadState;

/// The longest a drain leaves a standing republish unread: a held fact also
/// reads the node's other runs (Queue Standings), which move no number here.
const REPUBLISH_AT_LEAST: Duration = Duration::from_secs(1);

/// The generation a run last republished at, and when.
#[derive(Clone, Copy, Debug)]
pub(super) struct Republished {
    generation: u64,
    at: Instant,
}

impl Republished {
    /// Whether the drain ending at `now` republishes: the brain moved since
    /// `last`, or `last` is [`REPUBLISH_AT_LEAST`] old.
    pub(super) fn due(last: Option<Self>, state: &DownloadState, now: Instant) -> bool {
        last.is_none_or(|last| {
            last.generation != state.generation()
                || now.saturating_duration_since(last.at) >= REPUBLISH_AT_LEAST
        })
    }

    /// The republish `state` was just read for at `now`.
    pub(super) fn of(state: &DownloadState, now: Instant) -> Self {
        Self {
            generation: state.generation(),
            at: now,
        }
    }
}

/// The fleet loop's reading of the brain's next wake. A turn that delivered a
/// block and moved nothing keeps the last reading; every other turn reads
/// again, whatever the generation, since a wake also reads the slot asks, the
/// budget's turn and the capability, none of which a block touches.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct WakeReading {
    last: Option<(u64, Option<Instant>)>,
    block_turn: bool,
}

impl WakeReading {
    /// The turn that just ended delivered a block.
    pub(super) fn block_turn(&mut self) {
        self.block_turn = true;
    }

    /// When the brain next has something due.
    pub(super) fn read(&mut self, state: &DownloadState) -> Option<Instant> {
        let block_turn = std::mem::take(&mut self.block_turn);
        let generation = state.generation();
        match self.last {
            Some((seen, wake)) if block_turn && seen == generation => wake,
            _ => {
                let wake = state.next_wake();
                self.last = Some((generation, wake));
                wake
            }
        }
    }
}
