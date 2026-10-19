//! A worker's request pipeline (ADR-0029 "Request pipeline", ADR-0117): the
//! blocks it was handed and has not asked yet, the blocks asked of the
//! uploader and not yet arrived, and the **Request Depth** they are held to.
//! Pure bookkeeping over the instants it is handed; the worker turns what it
//! answers into `OP_REQUESTPARTS`, `BlockReceived` and `BlocksWanted`.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use rmule_peer::{AskedRanges, EMBLOCKSIZE};
use rmule_primitives::ED2K_PART_SIZE;

use crate::BlockPlan;
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
}

/// The link's pipeline, kept for the worker's life.
#[derive(Debug)]
pub(super) struct Pipeline {
    asked: VecDeque<Asked>,
    /// The handed blocks not yet asked, as runs: consecutive blocks of one
    /// part, `next..end`, asked from `next` in order.
    runs: VecDeque<(u64, u64)>,
    rate: DeliveryRate,
    min_rtt: Option<Duration>,
    /// Whether this grant's first request went out.
    requested: bool,
    /// Whether a byte arrived since the grant: the slot is proven granted.
    flowing: bool,
    /// The link's **Asked Ranges** as of the last grant, and every block
    /// asked since: the uploader serves none of them again (ADR-0107).
    spent: AskedRanges,
    /// Whether the uploader holds a slot for this worker: from its grant to
    /// an `OP_OUTOFPARTREQS`.
    slot_held: bool,
    /// The last room `BlocksWanted` reported, and whether it was drained, so
    /// each is said once.
    wanted: Option<(usize, bool)>,
    /// The number of the last handout taken, which `BlocksWanted` names.
    handout: u32,
}

impl Pipeline {
    pub(super) fn new() -> Self {
        Self {
            asked: VecDeque::new(),
            runs: VecDeque::new(),
            rate: DeliveryRate::default(),
            min_rtt: None,
            requested: false,
            flowing: false,
            spent: AskedRanges::default(),
            slot_held: false,
            wanted: None,
            handout: 0,
        }
    }

    /// The uploader granted the slot, still holding `asked` as asked of this
    /// link — what an earlier file asked before a silent release among them.
    /// The grant's first request waits on its first byte again.
    pub(super) fn granted(&mut self, asked: &AskedRanges) {
        self.spent.extend(asked);
        self.slot_held = true;
        self.requested = false;
        self.flowing = false;
    }

    /// Whether the uploader holds a slot for this worker, one a timeout must
    /// give back (ADR-0056).
    pub(super) fn holds_slot(&self) -> bool {
        self.slot_held
    }

    /// Queue `blocks`, handout number `handout`, behind what the worker
    /// holds; consecutive blocks of one part join one run. A pipeline that had
    /// drained leaves the wait out of its rate.
    pub(super) fn hand(&mut self, blocks: &[BlockPlan], handout: u32) {
        self.handout = handout;
        if self.drained() {
            self.rate.pause();
        }
        for block in blocks {
            match self.runs.back_mut() {
                Some(run) if run.1 == block.start && block.start % ED2K_PART_SIZE != 0 => {
                    run.1 = block.end;
                }
                _ => self.runs.push_back((block.start, block.end)),
            }
        }
        self.wanted = None;
    }

    /// `OP_OUTOFPARTREQS`: the uploader dropped every block it held, and took
    /// the client out of its upload slots, forgetting what it was asked; core
    /// frees what the worker held, the blocks not yet asked among them.
    pub(super) fn requeued(&mut self) {
        self.asked.clear();
        self.runs.clear();
        self.spent.clear();
        self.slot_held = false;
        self.requested = false;
        self.flowing = false;
        self.wanted = None;
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

    /// The next request to send at `now`, up to three blocks from the runs, or
    /// `None` when the depth is full, nothing handed is left to ask, or the
    /// grant's first request still waits on its first byte. Call until `None`.
    pub(super) fn next_request(&mut self, now: Instant) -> Option<Vec<(u64, u64)>> {
        if self.requested && !self.flowing {
            return None;
        }
        let room = self.depth().saturating_sub(self.asked.len());
        let mut blocks = Vec::new();
        while blocks.len() < room.min(RANGES_PER_REQUEST) {
            let Some(&(start, run_end)) = self.runs.front() else {
                break;
            };
            let end = self.unspent_end(start, (start + EMBLOCKSIZE).min(run_end));
            self.spent.insert(start, end);
            blocks.push((start, end));
            self.asked.push_back(Asked {
                start,
                end,
                received: 0,
                asked_at: now,
            });
            match self.runs.front_mut() {
                Some(run) if end < run_end => run.0 = end,
                _ => {
                    self.runs.pop_front();
                }
            }
        }
        if blocks.is_empty() {
            return None;
        }
        self.requested = true;
        Some(blocks)
    }

    /// The end of the block from `start`, at most `end`: one byte shorter for
    /// each range the uploader already holds as asked, so the block — and
    /// every later one of its run — leaves the old grid (ADR-0107).
    fn unspent_end(&self, start: u64, end: u64) -> u64 {
        let mut fitted = end;
        while self.spent.contains(start, fitted) && fitted - start > 1 {
            fitted -= 1;
        }
        fitted
    }

    /// Credit `len` bytes at `offset` that arrived at `now` to the blocks they
    /// fall in. Answers whether they fall in an asked block: only those go on
    /// to the download.
    pub(super) fn arrived(&mut self, now: Instant, offset: u64, len: u64) -> bool {
        let chunk_end = offset.saturating_add(len);
        let mut asked_for = false;
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
            asked_for = true;
        }
        self.asked
            .retain(|asked| asked.received < asked.end - asked.start);
        if asked_for {
            self.flowing = true;
        }
        self.rate.record(now, len);
        asked_for
    }

    /// The block asked at `offset` will never arrive whole: the session could
    /// not inflate it, or refused it. It stops counting against the depth;
    /// answers its range, for core to free (ADR-0029 "A lost block is freed").
    /// The uploader sent it, so the slot is proven granted.
    pub(super) fn lost(&mut self, offset: u64) -> Option<(u64, u64)> {
        let at = self.asked.iter().position(|asked| asked.start == offset)?;
        self.flowing = true;
        self.asked.remove(at).map(|asked| (asked.start, asked.end))
    }

    /// What to tell core once everything handed is asked: the room the depth
    /// leaves and whether the pipeline drained — each said once. `None` while
    /// a handed block waits to be asked, the grant's first request waits on
    /// its first byte, or the depth is full.
    pub(super) fn want(&mut self) -> Option<(usize, bool)> {
        if !self.runs.is_empty() || (self.requested && !self.flowing) {
            return None;
        }
        let room = self.depth().saturating_sub(self.asked.len());
        let want = (room, self.asked.is_empty());
        if room == 0 || self.wanted == Some(want) {
            return None;
        }
        self.wanted = Some(want);
        Some(want)
    }

    /// The number of the last handout taken.
    pub(super) fn handout(&self) -> u32 {
        self.handout
    }

    /// Whether nothing handed is left to ask and nothing asked to arrive.
    pub(super) fn drained(&self) -> bool {
        self.runs.is_empty() && self.asked.is_empty()
    }
}

#[cfg(test)]
mod tests;
