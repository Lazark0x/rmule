//! A slot holder's **Serve Flow** (ADR-0031): its asked ranges waiting, the one
//! read out, and what it has read ahead of the socket. One read at a time keeps
//! a flow's blocks in the order asked; the **Send-Ahead** carries the socket's
//! brake back to the disk; the flow's number tells a late read from one of a
//! slot the same peer was granted since. Every way a slot ends ends its flow.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use rmule_primitives::{FileHash, PeerEndpoint};

use super::{BlockRead, ServeDecision, ServeState};
use crate::served_downloads::ReadCheck;
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

/// A read waiting its turn in a flow.
#[derive(Debug)]
pub(super) struct AskedRead {
    pub(super) path: PathBuf,
    pub(super) block: BlockRead,
    pub(super) check: Option<ReadCheck>,
}

/// One slot holder's flow.
#[derive(Debug)]
pub(super) struct ServeFlow {
    number: u64,
    waiting: VecDeque<AskedRead>,
    read_out: bool,
    /// Blocks read and not yet left for the socket.
    ahead: usize,
    moved_at: Instant,
}

impl ServeFlow {
    /// Nothing of the flow is on rmule's side, so a silence is the peer's.
    fn is_drained(&self) -> bool {
        self.waiting.is_empty() && !self.read_out && self.ahead == 0
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
                moved_at: now,
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
        reads: impl IntoIterator<Item = AskedRead>,
    ) -> Option<ServeDecision> {
        self.flow_of(peer, now).waiting.extend(reads);
        self.next_read(peer)
    }

    /// The flow's next read, unless one is out or the Send-Ahead is full.
    fn next_read(&mut self, peer: PeerEndpoint) -> Option<ServeDecision> {
        let flow = self.flows.get_mut(&peer)?;
        if flow.read_out || flow.ahead >= SEND_AHEAD_BLOCKS {
            return None;
        }
        let AskedRead { path, block, check } = flow.waiting.pop_front()?;
        flow.read_out = true;
        Some(ServeDecision::ReadRange {
            peer,
            flow: flow.number,
            path,
            block,
            check,
        })
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
        peer: PeerEndpoint,
        file_hash: FileHash,
        bytes: u64,
    ) -> Vec<ServeDecision> {
        if let Some(flow) = self.flows.get_mut(&peer) {
            flow.ahead = flow.ahead.saturating_sub(1);
        }
        let mut decisions = Vec::new();
        if let Some(identity) = self.identities.get(&peer) {
            decisions.push(ServeDecision::RecordCredit {
                user_hash: identity.user_hash(),
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

    /// `peer` said something, or a block of its left: its link moved.
    pub(super) fn link_moved(&mut self, now: Instant, peer: PeerEndpoint) {
        if let Some(flow) = self.flows.get_mut(&peer) {
            flow.moved_at = now;
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
    /// send loses its slot and its link (ADR-0031). The slot goes here and not
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
            let silent = now.saturating_duration_since(flow.moved_at) > SLOT_SILENCE_BOUND;
            if silent && flow.is_drained() {
                self.served_ranges
                    .retain(|(range_peer, _), _| *range_peer != peer);
                let promotion = self.queue.release(peer, now, modifiers);
                decisions.push(ServeDecision::Emit(ServeEvent::UploadSlotReleased { peer }));
                decisions.extend(self.promotion_decisions(promotion));
                decisions.push(ServeDecision::Disconnect { peer });
            }
        }
        decisions
    }
}
