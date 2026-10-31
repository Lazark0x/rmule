//! A slot holder's **Serve Flow** (ADR-0031): its asked ranges waiting, the one
//! read out, and what it has read ahead of the socket. One read at a time keeps
//! a flow's blocks in the order asked; the **Send-Ahead** carries the socket's
//! brake back to the disk; the flow's number tells a late read from one of a
//! slot the same peer was granted since. Every way a slot ends ends its flow.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use rmule_primitives::{FileHash, PeerEndpoint};

use super::served::Aim;
use super::{BlockRead, ServeDecision, ServeState};
use crate::service::ServeEvent;

/// Blocks a flow may hold read and not yet left for the socket. aMule 3.1.0
/// holds this many on a fast slot (`UploadDiskIOThread.cpp:192`), 2.3.3 only
/// 100 KiB (`UploadClient.cpp:195`).
const SEND_AHEAD_BLOCKS: usize = 10;

/// Asked ranges a flow keeps waiting: above the Request Depth's 24, so only a
/// peer asking past what it reads meets it.
const MAX_WAITING_RANGES: usize = 32;

/// How long a slot with nothing left to send may move nothing: aMule's
/// `CONNECTION_TIMEOUT` (`Constants.h:34`, `ClientTCPSocket.cpp:226`), the
/// bound of the peer that stopped reading with its bytes all in the kernel.
const SLOT_SILENCE_BOUND: Duration = Duration::from_secs(40);

/// The pace a block's bytes are lent at once they have left for the kernel,
/// where rmule cannot see them read: about half the 16 kbit/s the partial-share
/// bench holds a slot over.
const KERNEL_PACE_BYTES_PER_SEC: u64 = 1024;

/// The most a holder is lent: aMule's three asked blocks (540 KiB) at 16 kbit/s,
/// and what a dead holder costs its slot.
const KERNEL_LOAN_BOUND: Duration = Duration::from_secs(300);

/// One slot holder's flow.
#[derive(Debug)]
pub(super) struct ServeFlow {
    number: u64,
    /// The ranges asked, each aimed only when it comes up: a file may move
    /// or change hands while they wait.
    waiting: VecDeque<BlockRead>,
    read_out: bool,
    /// Blocks read and not yet left for the socket.
    ahead: usize,
    /// The link moved until here: the last word from the holder, or the end of
    /// the time the bytes that left for the kernel are lent, whichever is later.
    moved_until: Instant,
}

impl ServeFlow {
    /// Nothing of the flow is on rmule's side, so a silence is the peer's.
    fn is_drained(&self) -> bool {
        self.waiting.is_empty() && !self.read_out && self.ahead == 0
    }

    /// `bytes` left for the kernel at `now`, on top of those it may still hold.
    fn lend(&mut self, now: Instant, bytes: u64) {
        let lent = Duration::from_millis(bytes.saturating_mul(1000) / KERNEL_PACE_BYTES_PER_SEC);
        self.moved_until = (self.moved_until.max(now) + lent).min(now + KERNEL_LOAN_BOUND);
    }
}

impl ServeState {
    /// The flow of `peer`'s slot, begun at its first need.
    fn flow_of(&mut self, peer: PeerEndpoint, now: Instant) -> &mut ServeFlow {
        let flows_begun = &mut self.flows_begun;
        self.flows.entry(peer).or_insert_with(|| {
            *flows_begun += 1;
            ServeFlow {
                number: *flows_begun,
                waiting: VecDeque::new(),
                read_out: false,
                ahead: 0,
                moved_until: now,
            }
        })
    }

    /// Whether `peer`'s flow can take `more` asked ranges.
    pub(super) fn flow_has_room(&self, peer: PeerEndpoint, more: usize) -> bool {
        let waiting = self.flows.get(&peer).map_or(0, |flow| flow.waiting.len());
        waiting + more <= MAX_WAITING_RANGES
    }

    /// Queue `reads` on `peer`'s flow, and start the next if it may.
    pub(super) fn ask_flow(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        reads: impl IntoIterator<Item = BlockRead>,
    ) -> Option<ServeDecision> {
        self.flow_of(peer, now).waiting.extend(reads);
        self.next_read(peer)
    }

    /// The flow's next read, unless one is out or the Send-Ahead is full: its
    /// first range still in the share set, aimed at the file as the set holds
    /// it now. A range whose file's entry has ended waits at the head of the
    /// flow for the trigger owed ([`Aim::Trigger`]).
    fn next_read(&mut self, peer: PeerEndpoint) -> Option<ServeDecision> {
        loop {
            let flow = self.flows.get(&peer)?;
            if flow.read_out || flow.ahead >= SEND_AHEAD_BLOCKS {
                return None;
            }
            let block = *flow.waiting.front()?;
            let aim = self.aim(block.file_hash);
            let flow = self.flows.get_mut(&peer)?;
            match aim {
                Aim::Trigger => return None,
                Aim::Nowhere => {
                    flow.waiting.pop_front();
                }
                Aim::At(from) => {
                    flow.waiting.pop_front();
                    flow.read_out = true;
                    return Some(ServeDecision::ReadRange {
                        peer,
                        flow: flow.number,
                        from,
                        block,
                    });
                }
            }
        }
    }

    /// The range of a read that came to nothing because its file moved first
    /// goes back to the head of `peer`'s flow, to be aimed again.
    pub(super) fn read_again(
        &mut self,
        peer: PeerEndpoint,
        block: BlockRead,
    ) -> Option<ServeDecision> {
        self.flows.get_mut(&peer)?.waiting.push_front(block);
        self.next_read(peer)
    }

    /// The reads a share trigger lets go: those that waited for it at the
    /// head of a slot holder's flow.
    pub(super) fn reads_after_trigger(&mut self) -> Vec<ServeDecision> {
        let queue = &self.queue;
        let holders: Vec<PeerEndpoint> = self
            .flows
            .keys()
            .copied()
            .filter(|peer| queue.is_granted(*peer))
            .collect();
        holders
            .into_iter()
            .filter_map(|peer| self.next_read(peer))
            .collect()
    }

    /// A read of `flow` ended, whichever way. `false` when that flow is over:
    /// what the read found is for nobody.
    pub(super) fn read_ended(&mut self, peer: PeerEndpoint, number: u64) -> bool {
        match self.flows.get_mut(&peer) {
            Some(flow) if flow.number == number => {
                flow.read_out = false;
                true
            }
            _ => false,
        }
    }

    /// A read landed and its block went down the link: one more is ahead of
    /// the socket, and the next read starts if it may.
    pub(super) fn block_ahead(&mut self, peer: PeerEndpoint) -> Option<ServeDecision> {
        self.flows.get_mut(&peer)?.ahead += 1;
        self.next_read(peer)
    }

    /// The next read of `peer`'s flow, a block having come to nothing.
    pub(super) fn read_on(&mut self, peer: PeerEndpoint) -> Option<ServeDecision> {
        self.next_read(peer)
    }

    /// A block's last byte is in the kernel: it is counted, its place in the
    /// Send-Ahead frees, and the flow reads on. A block outliving its flow left
    /// all the same, so it is counted all the same.
    pub(super) fn on_block_left(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        file_hash: FileHash,
        bytes: u64,
    ) -> Vec<ServeDecision> {
        if let Some(flow) = self.flows.get_mut(&peer) {
            flow.ahead = flow.ahead.saturating_sub(1);
            flow.lend(now, bytes);
        }
        self.queue.count_session_sent(peer, bytes);
        let mut decisions = Vec::new();
        if let Some(identity) = self.identities.get(&peer) {
            decisions.push(ServeDecision::RecordCredit {
                user_hash: identity.user_hash(),
                at: peer.ip(),
                bytes,
            });
        }
        decisions.push(ServeDecision::CountSent {
            peer,
            file_hash,
            bytes,
        });
        decisions.extend(self.next_read(peer));
        decisions
    }

    /// `peer` said something, or a block of its left: its link moved, and what
    /// the block lends runs on from here.
    pub(super) fn link_moved(&mut self, now: Instant, peer: PeerEndpoint) {
        if let Some(flow) = self.flows.get_mut(&peer) {
            flow.moved_until = flow.moved_until.max(now);
        }
    }

    /// End every flow whose slot has gone, however it went: what waits goes,
    /// and what is under way is told it is over. Read after every batch of
    /// decisions, so no path out of a slot can leave one running.
    pub(in crate::serve) fn end_slotless_flows(&mut self) -> Vec<ServeDecision> {
        let queue = &self.queue;
        let mut ended = Vec::new();
        self.flows.retain(|peer, flow| {
            let holds = queue.is_granted(*peer);
            if !holds {
                ended.push(ServeDecision::EndFlow {
                    peer: *peer,
                    flow: flow.number,
                });
            }
            holds
        });
        ended
    }

    /// A slot holder silent past [`SLOT_SILENCE_BOUND`] with nothing left to
    /// send, the time its bytes in the kernel are lent spent, loses its slot
    /// and its link (ADR-0031). The slot goes here and not
    /// with the link, because a download riding the link holds it up. A slot
    /// nothing has moved on yet starts its clock here.
    pub(in crate::serve) fn on_slot_sweep(
        &mut self,
        now: Instant,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        let holders: Vec<PeerEndpoint> = self.queue.linked_holders().collect();
        let mut decisions = Vec::new();
        for peer in holders {
            let flow = self.flow_of(peer, now);
            let silent = now.saturating_duration_since(flow.moved_until) > SLOT_SILENCE_BOUND;
            if silent && flow.is_drained() {
                self.served_ranges
                    .retain(|(range_peer, _), _| *range_peer != peer);
                let promotion = self.leave_queue(peer, now, modifiers);
                decisions.push(ServeDecision::Emit(ServeEvent::UploadSlotReleased { peer }));
                decisions.extend(self.promotion_decisions(promotion));
                decisions.push(ServeDecision::Disconnect { peer });
            }
        }
        decisions.extend(self.end_over_session(now, modifiers));
        decisions
    }
}
