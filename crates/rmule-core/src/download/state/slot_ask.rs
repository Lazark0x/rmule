//! The slot ask and the download's one hash-set ask (ADR-0026, "The slot ask"
//! and "One hash-set ask at a time, with a deadline"): what a worker's probe
//! answer asks of its uploader, what its grant hands it — the hash-set ask
//! among it — and how that ask passes from granted link to granted link: at
//! its worker's end, at a refused answer and at the **Hash-Set Deadline**.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use rmule_primitives::{PartHashSet, PeerEndpoint};

use crate::adapters::PeerWorkerCommand;
use crate::diagnostics::WorkerPhase;
use crate::service::PeerRetirementReason;

use super::{Decision, DownloadState};

/// How long the download's one hash-set ask waits for its answer before the
/// ask passes on: half aMule's 40 s idle close (`CONNECTION_TIMEOUT`, stock
/// 2.3.3 `Constants.h:34`), so an uploader that never answers the set holds
/// the one ask no longer (ADR-0026).
pub(crate) const HASH_SET_DEADLINE: Duration = Duration::from_secs(20);

/// Where one worker's slot stands at its uploader, from its probe answer on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotAsk {
    /// Its slot ask is out: the uploader queues it.
    Queued,
    /// The uploader granted it a slot.
    Granted,
}

/// The slot asks of a download's workers and its one hash-set ask in flight.
#[derive(Debug, Default)]
pub(super) struct SlotAsks {
    by_worker: HashMap<PeerEndpoint, SlotAsk>,
    /// The worker asked for the part hash set, and when the ask passes on.
    hash_set: Option<(PeerEndpoint, Instant)>,
    /// Workers the deadline passed: not asked the set again while they live.
    passed: HashSet<PeerEndpoint>,
}

impl SlotAsks {
    /// Whether `peer`'s uploader granted it a slot.
    pub(super) fn granted(&self, peer: PeerEndpoint) -> bool {
        self.by_worker.get(&peer) == Some(&SlotAsk::Granted)
    }

    /// The instant the hash-set ask in flight passes on, if one is.
    pub(super) fn next_deadline(&self) -> Option<Instant> {
        self.hash_set.map(|(_, deadline)| deadline)
    }

    /// `peer`'s worker ended: forget its ask, and say whether it held the
    /// hash-set ask, which then passes on.
    fn forget(&mut self, peer: PeerEndpoint) -> bool {
        self.by_worker.remove(&peer);
        self.passed.remove(&peer);
        let asking = self.hash_set.is_some_and(|(asker, _)| asker == peer);
        if asking {
            self.hash_set = None;
        }
        asking
    }
}

impl DownloadState {
    /// Whether the download still wants the part hash set: a file of more than
    /// one hash, with no whole set from the link or a proven peer.
    fn hash_set_wanted(&self) -> bool {
        PartHashSet::expected_hash_count(self.file_size)
            .is_ok_and(|expected| expected > 0 && self.resolved.hashes.len() != expected)
    }

    /// `peer`'s probe answered with Advertised Parts holding a part we lack:
    /// ask its slot at once, whether or not a part is free. Nothing waits on
    /// the hash set: only a granted worker is asked it (ADR-0026, ADR-0116
    /// invariant 3), since a `0x51` unanswered on a link the uploader ranks
    /// costs that link at aMule's 40 s silent-link close.
    pub(super) fn ask_on_probe(&mut self, peer: PeerEndpoint, out: &mut Vec<Decision>) {
        if !self.slot_asks.by_worker.contains_key(&peer) {
            self.ask_slot(peer, out);
        }
    }

    /// Send `peer`'s slot ask: it waits queued, its part chosen at the grant.
    fn ask_slot(&mut self, peer: PeerEndpoint, out: &mut Vec<Decision>) {
        self.slot_asks.by_worker.insert(peer, SlotAsk::Queued);
        out.push(Decision::Send {
            peer,
            command: PeerWorkerCommand::AskSlot,
        });
        self.phase(peer, WorkerPhase::WaitingForSlot { rank: None }, out);
    }

    /// Make `peer` the download's one hash-set asker until the deadline.
    fn ask_hash_set(&mut self, now: Instant, peer: PeerEndpoint, out: &mut Vec<Decision>) {
        self.slot_asks.hash_set = Some((peer, now + HASH_SET_DEADLINE));
        out.push(Decision::Send {
            peer,
            command: PeerWorkerCommand::RequestHashSet,
        });
    }

    /// Whether `peer` may take the hash-set ask: the download wants the set
    /// and no link asks it, `peer` holds a granted slot, the deadline never
    /// passed it, and its parts name a part we lack. A worker only queued
    /// hangs up at its rank, so it never holds the ask (ADR-0116).
    fn may_ask_hash_set(&self, peer: PeerEndpoint) -> bool {
        self.hash_set_wanted()
            && self.slot_asks.hash_set.is_none()
            && self.slot_asks.granted(peer)
            && !self.slot_asks.passed.contains(&peer)
            && self
                .sources
                .worker_parts(peer)
                .is_some_and(|parts| self.scheduler.lacks_any_of(parts))
    }

    /// Pass the hash-set ask to the next transferring worker, in slot order,
    /// that may take it; with none, the next grant takes it (aMule
    /// `SetHashSetNeeded(true)`, ADR-0026).
    fn pass_hash_set_ask(&mut self, now: Instant, out: &mut Vec<Decision>) {
        self.slot_asks.hash_set = None;
        let next = self
            .connected_workers()
            .into_iter()
            .find(|&peer| self.may_ask_hash_set(peer));
        if let Some(peer) = next {
            self.ask_hash_set(now, peer, out);
        }
    }

    /// The download holds its part hash set now: the hash-set ask in flight
    /// ends.
    pub(super) fn hash_set_held(&mut self) {
        self.slot_asks.hash_set = None;
    }

    /// The **Hash-Set Deadline**: an asker that has not answered by `now` is
    /// not asked again, and the ask passes on.
    pub(super) fn hash_set_deadline(&mut self, now: Instant, out: &mut Vec<Decision>) {
        let Some((asker, deadline)) = self.slot_asks.hash_set else {
            return;
        };
        if now < deadline {
            return;
        }
        self.slot_asks.passed.insert(asker);
        self.pass_hash_set_ask(now, out);
    }

    /// `peer`'s worker ended: its ask goes with it, and a hash-set ask it held
    /// passes on.
    pub(super) fn forget_slot_ask(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        out: &mut Vec<Decision>,
    ) {
        if self.slot_asks.forget(peer) {
            self.pass_hash_set_ask(now, out);
        }
    }

    /// `OP_OUTOFPARTREQS` queued `peer`'s flow again: it waits for its next
    /// grant, unranked until a rank says.
    pub(super) fn queued_again(&mut self, peer: PeerEndpoint, out: &mut Vec<Decision>) {
        self.slot_asks.by_worker.insert(peer, SlotAsk::Queued);
        self.phase(peer, WorkerPhase::WaitingForSlot { rank: None }, out);
    }

    /// An `OP_QUEUERANKING` placed `peer` at `rank`: a worker without a grant
    /// has its answer, and hangs up — the **Queued Hang-Up** (ADR-0116). Its
    /// record keeps the standing the rank earned and waits in the RemoteQueued
    /// stage; the reask keeps its place (ADR-0057). A granted worker's rank
    /// changes nothing.
    pub(super) fn ranked(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        rank: u16,
        out: &mut Vec<Decision>,
    ) {
        if self.slot_asks.granted(peer) {
            return;
        }
        self.phase(peer, WorkerPhase::WaitingForSlot { rank: Some(rank) }, out);
        self.retire(now, peer, PeerRetirementReason::Queued, out);
    }

    /// `peer`'s uploader granted it a slot: hand it its part, or give the slot
    /// back (ADR-0026, ADR-0056). A slot the worker keeps takes the
    /// download's one hash-set ask when nobody asks it (ADR-0116 invariant 3),
    /// and is a grant on the peer's **Queue Standing**: the downloads waiting
    /// on it are called to this link, to take it by the swap rule (ADR-0107).
    pub(super) fn granted(&mut self, now: Instant, peer: PeerEndpoint, out: &mut Vec<Decision>) {
        if !self.worker_slots.contains_key(&peer) {
            return;
        }
        self.slot_asks.by_worker.insert(peer, SlotAsk::Granted);
        self.assign(now, peer, out);
        if self.may_ask_hash_set(peer) {
            self.ask_hash_set(now, peer, out);
        }
        if self.slot_asks.granted(peer) {
            out.push(Decision::CallStandingWaiters { peer });
        }
    }

    /// Retire `peer` for `reason`, a live source's: it was ranked without a
    /// grant (`Queued`, ADR-0116), its parts hold nothing we lack
    /// (`NoNeededParts`), or a granted slot found every part it holds that we
    /// lack in flight (`NoFreePart`). Its record waits in the RemoteQueued
    /// stage, unspent, and a granted slot goes back (ADR-0112 §6, ADR-0056).
    /// A worker an earlier retirement in the same batch already ended is
    /// left alone: one retirement's backfill can retire the next in turn.
    pub(super) fn retire(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        reason: PeerRetirementReason,
        out: &mut Vec<Decision>,
    ) {
        if !self.worker_slots.contains_key(&peer) {
            return;
        }
        out.push(Decision::Emit(crate::service::DownloadEvent::PeerRetired {
            download_id: self.download_id,
            peer,
            reason,
        }));
        self.release(now, peer, reason, out);
    }

    /// `peer`'s slot's phase, when it holds one.
    fn phase(&self, peer: PeerEndpoint, phase: WorkerPhase, out: &mut Vec<Decision>) {
        if let Some(&slot) = self.worker_slots.get(&peer) {
            out.push(Decision::Phase { slot, phase });
        }
    }
}
