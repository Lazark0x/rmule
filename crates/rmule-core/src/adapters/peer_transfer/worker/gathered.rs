//! The bytes of the block arriving now, gathered on their way to core. A stock
//! uploader frames a block in 10,240-byte packets (`UploadClient.cpp:290`), and
//! one event per packet costs the download's one brain a turn per packet; a
//! gathered run reaches core when its block is whole, when a packet does not
//! extend it, before anything else the worker says, and within
//! [`GATHER_WAIT`], so a slow link's progress still shows.

use std::time::Duration;

use rmule_peer::EMBLOCKSIZE;
use rmule_peer::PartIndex;
use rmule_primitives::ED2K_PART_SIZE;
use tokio::time::Instant;

use crate::adapters::PeerWorkerEvent;

/// The longest arrived bytes wait for the rest of their block.
pub(super) const GATHER_WAIT: Duration = Duration::from_millis(100);

/// One contiguous run of arrived bytes, within one part.
#[derive(Debug, Default)]
pub(super) struct Gathered {
    offset: u64,
    bytes: Vec<u8>,
    due: Option<Instant>,
}

impl Gathered {
    /// When the run in hand must reach core, while one is.
    pub(super) fn due(&self) -> Option<Instant> {
        self.due
    }

    /// Whether bytes at `offset` continue the run in hand: a part's first
    /// byte opens a run of its own.
    fn extends(&self, offset: u64) -> bool {
        !self.bytes.is_empty()
            && self.offset + self.bytes.len() as u64 == offset
            && !offset.is_multiple_of(ED2K_PART_SIZE)
    }

    /// Take `bytes` at `offset` that arrived at `now`. Answers the run they
    /// did not extend, for core ahead of them.
    pub(super) fn add(
        &mut self,
        now: Instant,
        offset: u64,
        bytes: &[u8],
    ) -> Option<PeerWorkerEvent> {
        let earlier = if self.extends(offset) {
            None
        } else {
            self.take()
        };
        if self.bytes.is_empty() {
            self.offset = offset;
            self.bytes = Vec::with_capacity(EMBLOCKSIZE as usize);
            self.due = Some(now + GATHER_WAIT);
        }
        self.bytes.extend_from_slice(bytes);
        earlier
    }

    /// The run in hand as the event core hears, leaving none.
    pub(super) fn take(&mut self) -> Option<PeerWorkerEvent> {
        self.due = None;
        if self.bytes.is_empty() {
            return None;
        }
        let part_index =
            PartIndex::new(u32::try_from(self.offset / ED2K_PART_SIZE).unwrap_or(u32::MAX));
        Some(PeerWorkerEvent::BlockReceived {
            part_index,
            offset: self.offset,
            bytes: std::mem::take(&mut self.bytes),
        })
    }
}
