//! Handing a granted worker its blocks (ADR-0117): the room its Request Depth
//! reports, the handout that fills it from the first-ranked parts it
//! advertised, and what a worker that can be handed nothing comes to.

use std::collections::HashMap;
use std::time::Instant;

use rmule_primitives::PeerEndpoint;

use crate::adapters::PeerWorkerCommand;
use crate::assembly::PartAssembly;
use crate::byte_ranges::ByteRanges;
use crate::diagnostics::WorkerPhase;
use crate::scheduler::{Handout, Progress};
use crate::service::{DownloadEvent, PeerRetirementReason};

use super::{Decision, DownloadState};

/// The blocks a grant hands before the worker reports its room: the most the
/// grant's first request may carry (ADR-0029 "One request before the grant").
const GRANT_BLOCKS: usize = 3;

/// A worker's word that it has room (`BlocksWanted`), not yet answered.
#[derive(Clone, Copy, Debug)]
pub(super) struct Want {
    /// How many blocks fit its Request Depth.
    room: usize,
    /// Whether everything it asked has arrived.
    drained: bool,
}

impl DownloadState {
    /// `peer`'s uploader granted it a slot: a worker holding no block has an
    /// empty pipeline, with room for the grant's first request. One that holds
    /// blocks was granted already, and its own word says when it has room.
    pub(super) fn want_at_grant(&mut self, peer: PeerEndpoint) {
        if self.scheduler.parts_of(peer).is_empty() {
            self.wants.insert(
                peer,
                Want {
                    room: GRANT_BLOCKS,
                    drained: true,
                },
            );
        }
    }

    /// `peer` has room for `room` more blocks, its pipeline `drained` or
    /// not: hand them, or — drained with nothing for it — take the slot back.
    pub(super) fn on_blocks_wanted(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        room: u32,
        drained: bool,
        out: &mut Vec<Decision>,
    ) {
        if !self.slot_asks.granted(peer) {
            return;
        }
        let room = usize::try_from(room).unwrap_or(usize::MAX);
        self.wants.insert(peer, Want { room, drained });
        self.hand(now, peer, out);
    }

    /// Hand granted `peer` the blocks its room asks for (ADR-0117). A worker
    /// whose own probe has not answered is handed nothing, whatever its record
    /// kept from an earlier connection, and a queued one waits for its grant.
    /// One whose parts hold nothing we lack is retired `NoNeededParts`; a
    /// granted one, drained with nothing left for it, gives the slot back,
    /// `NoFreePart`.
    pub(super) fn hand(&mut self, now: Instant, peer: PeerEndpoint, out: &mut Vec<Decision>) {
        if let Some(reason) = self.hand_or_lacking(peer, out).unworkable() {
            self.retire(now, peer, reason, out);
        }
    }

    /// [`Self::hand`] short of the retirement: the handout's decisions or
    /// nothing, and what they came to — the caller retires a worker that
    /// cannot work its slot.
    pub(super) fn hand_or_lacking(
        &mut self,
        peer: PeerEndpoint,
        out: &mut Vec<Decision>,
    ) -> Handed {
        let Some(slot) = self.worker_slots.get(&peer).copied() else {
            return Handed::Unanswered;
        };
        let Some(parts) = self.sources.worker_parts(peer) else {
            return Handed::Unanswered;
        };
        if self.scheduler.is_complete() {
            return Handed::Complete;
        }
        if !self.scheduler.lacks_any_of(parts) {
            return Handed::NothingNeeded;
        }
        if !self.slot_asks.granted(peer) {
            return Handed::Queued;
        }
        let Some(want) = self.wants.get(&peer).copied() else {
            return Handed::Working;
        };
        let held_before = self.scheduler.parts_of(peer);
        let progress = Measured {
            assembly: &self.assembly,
        };
        let handout = self.scheduler.hand(
            peer,
            want.room,
            parts,
            self.sources.part_frequency(),
            self.sources.parts_known(),
            &progress,
        );
        let Handout::Blocks { blocks, .. } = handout else {
            return if want.drained {
                Handed::NothingFree
            } else {
                Handed::Working
            };
        };
        self.wants.remove(&peer);
        let mut opened: Vec<u32> = Vec::new();
        for block in &blocks {
            if !held_before.contains(&block.part_index) && !opened.contains(&block.part_index) {
                opened.push(block.part_index);
            }
        }
        for &part_index in &opened {
            out.push(Decision::Emit(DownloadEvent::PartAssigned {
                download_id: self.download_id,
                peer,
                part_index,
            }));
        }
        if held_before.is_empty() {
            out.push(Decision::Phase {
                slot,
                phase: WorkerPhase::RequestingPart {
                    part_index: blocks[0].part_index,
                },
            });
        }
        out.push(Decision::Send {
            peer,
            command: PeerWorkerCommand::RequestBlocks { blocks },
        });
        Handed::Working
    }
}

/// What the scheduler reads of this download (ADR-0117): each in-flight
/// part's Arrived Ranges.
struct Measured<'a> {
    assembly: &'a HashMap<u32, PartAssembly>,
}

impl Progress for Measured<'_> {
    fn arrived(&self, part_index: u32) -> Option<&ByteRanges> {
        self.assembly.get(&part_index).map(PartAssembly::arrived)
    }
}

/// What handing one worker its blocks came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Handed {
    /// It works: blocks handed now, or blocks still to arrive.
    Working,
    /// The file is complete: nothing is handed to anyone.
    Complete,
    /// It is queued: its grant hands it its blocks (ADR-0026).
    Queued,
    /// It is no worker whose own probe answered: that answer asks its slot
    /// (ADR-0112 §3).
    Unanswered,
    /// Its Advertised Parts hold no part the file lacks.
    NothingNeeded,
    /// It is granted and drained, and every block it could fetch is claimed
    /// by another worker (ADR-0117).
    NothingFree,
}

impl Handed {
    /// Why a worker this came to cannot work a slot, if it cannot.
    pub(super) const fn unworkable(self) -> Option<PeerRetirementReason> {
        match self {
            Self::NothingNeeded => Some(PeerRetirementReason::NoNeededParts),
            Self::NothingFree => Some(PeerRetirementReason::NoFreePart),
            Self::Working | Self::Complete | Self::Queued | Self::Unanswered => None,
        }
    }
}
