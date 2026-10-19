//! A worker's request pipeline (ADR-0029 "Request pipeline"): the blocks asked
//! of the uploader and not yet arrived, the **Request Depth** they are held
//! to, and the range of the part being streamed. Pure bookkeeping over the
//! instants it is handed; the worker turns what it answers into
//! `OP_REQUESTPARTS` and `BlockReceived`.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use rmule_peer::{AskedRanges, EMBLOCKSIZE};

use crate::delivery_rate::DeliveryRate;

/// aMule's `STANDARD_BLOCKS_REQUEST` (stock 2.3.3 `updownclient.h:102`): the
/// depth floor, and the ranges one `OP_REQUESTPARTS` carries.
pub(super) const RANGES_PER_REQUEST: usize = 3;
/// The depth ceiling, amule-kno's (`DownloadClient.cpp:626-630`).
const MAX_DEPTH: usize = 24;

/// One block asked of the uploader and not yet wholly arrived.
#[derive(Clone, Copy, Debug)]
struct Asked {
    start: u64,
    end: u64,
    received: u64,
    asked_at: Instant,
    /// Whether it belongs to the part being streamed; a reassignment leaves
    /// the old part's blocks draining (ADR-0029).
    current: bool,
}

/// The link's pipeline, kept for the worker's life.
#[derive(Debug)]
pub(super) struct Pipeline {
    asked: VecDeque<Asked>,
    rate: DeliveryRate,
    min_rtt: Option<Duration>,
    /// The first offset of the streamed range not yet asked.
    next: u64,
    /// The streamed range's end, exclusive.
    end: u64,
    /// Whether this stream sent its first request.
    requested: bool,
    /// Whether a byte of this stream arrived: the slot is proven granted.
    flowing: bool,
    /// The link's **Asked Ranges** as of the last grant, and every block
    /// asked since: the uploader serves none of them again (ADR-0107).
    spent: AskedRanges,
    /// Whether the uploader holds a slot for this worker: from its grant to
    /// an `OP_OUTOFPARTREQS`.
    slot_held: bool,
}

impl Pipeline {
    pub(super) fn new() -> Self {
        Self {
            asked: VecDeque::new(),
            rate: DeliveryRate::default(),
            min_rtt: None,
            next: 0,
            end: 0,
            requested: false,
            flowing: false,
            spent: AskedRanges::default(),
            slot_held: false,
        }
    }

    /// The uploader granted the slot, still holding `asked` as asked of this
    /// link — what an earlier file asked before a silent release among them.
    pub(super) fn granted(&mut self, asked: &AskedRanges) {
        self.spent.extend(asked);
        self.slot_held = true;
    }

    /// Whether the uploader holds a slot for this worker, one a timeout must
    /// give back (ADR-0056).
    pub(super) fn holds_slot(&self) -> bool {
        self.slot_held
    }

    /// Stream `from..to` next. Blocks still asked of an earlier stream keep
    /// draining and are no longer this stream's; the rate leaves the wait
    /// between the two out.
    pub(super) fn begin(&mut self, from: u64, to: u64) {
        for asked in &mut self.asked {
            asked.current = false;
        }
        self.next = from;
        self.end = to.max(from);
        self.requested = false;
        self.flowing = false;
        self.rate.pause();
    }

    /// `OP_OUTOFPARTREQS`: the uploader dropped every block it held, and took
    /// the client out of its upload slots, forgetting what it was asked.
    pub(super) fn requeued(&mut self) {
        self.asked.clear();
        self.spent.clear();
        self.slot_held = false;
        self.rate.pause();
    }

    /// The Request Depth: `3 + ⌊2 × rate × rtt / EMBLOCKSIZE⌋`, held between
    /// 3 and 24; 3 until both are measured.
    pub(super) fn depth(&self) -> usize {
        let (Some(rate), Some(rtt)) = (self.rate.bytes_per_sec(), self.min_rtt) else {
            return RANGES_PER_REQUEST;
        };
        let headroom =
            2 * u128::from(rate) * rtt.as_micros() / (1_000_000 * u128::from(EMBLOCKSIZE));
        RANGES_PER_REQUEST
            .saturating_add(usize::try_from(headroom).unwrap_or(usize::MAX))
            .min(MAX_DEPTH)
    }

    /// The next request to send at `now`, up to three new blocks, or `None`
    /// when the depth is full, the range is all asked, or the stream's first
    /// request still waits on its first byte (the grant). Call until `None`.
    pub(super) fn next_request(&mut self, now: Instant) -> Option<Vec<(u64, u64)>> {
        if self.requested && !self.flowing {
            return None;
        }
        let room = self.depth().saturating_sub(self.asked.len());
        let mut blocks = Vec::new();
        while blocks.len() < room.min(RANGES_PER_REQUEST) && self.next < self.end {
            let end = self.unspent_end(self.next, (self.next + EMBLOCKSIZE).min(self.end));
            self.spent.insert(self.next, end);
            blocks.push((self.next, end));
            self.asked.push_back(Asked {
                start: self.next,
                end,
                received: 0,
                asked_at: now,
                current: true,
            });
            self.next = end;
        }
        if blocks.is_empty() {
            return None;
        }
        self.requested = true;
        Some(blocks)
    }

    /// The end of the block from `start`, at most `end`: one byte shorter for
    /// each range the uploader already holds as asked, so the block — and
    /// every later one of the stream — leaves the old grid (ADR-0107).
    fn unspent_end(&self, start: u64, end: u64) -> u64 {
        let mut fitted = end;
        while self.spent.contains(start, fitted) && fitted - start > 1 {
            fitted -= 1;
        }
        fitted
    }

    /// Credit `len` bytes at `offset` that arrived at `now` to the blocks they
    /// fall in. Answers whether they belong to the streamed range: only those
    /// go on to the download.
    pub(super) fn arrived(&mut self, now: Instant, offset: u64, len: u64) -> bool {
        let chunk_end = offset.saturating_add(len);
        let mut current = false;
        for asked in &mut self.asked {
            let overlap = chunk_end
                .min(asked.end)
                .saturating_sub(offset.max(asked.start));
            if overlap == 0 {
                continue;
            }
            if asked.received == 0 && offset <= asked.start {
                let rtt = now.saturating_duration_since(asked.asked_at);
                self.min_rtt = Some(self.min_rtt.map_or(rtt, |least| least.min(rtt)));
            }
            asked.received += overlap;
            current |= asked.current;
        }
        self.asked
            .retain(|asked| asked.received < asked.end - asked.start);
        if current {
            self.flowing = true;
        }
        self.rate.record(now, len);
        current
    }

    /// The block asked at `offset` will never arrive whole: the session could
    /// not inflate it, or refused it. It stops counting against the depth.
    /// Answers whether it was the streamed range's, a hole this slot cannot
    /// fill (ADR-0029 "A lost block ends the stream").
    pub(super) fn lost(&mut self, offset: u64) -> bool {
        let Some(at) = self.asked.iter().position(|asked| asked.start == offset) else {
            return false;
        };
        self.asked.remove(at).is_some_and(|asked| asked.current)
    }

    /// Whether every block of the streamed range has arrived.
    pub(super) fn streamed(&self) -> bool {
        self.next >= self.end && !self.asked.iter().any(|asked| asked.current)
    }
}

#[cfg(test)]
mod tests;
