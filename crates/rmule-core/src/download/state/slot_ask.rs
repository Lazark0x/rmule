//! The slot ask and the download's one hash-set ask (ADR-0026, "The slot ask"
//! and "One hash-set ask at a time, with a deadline"): what a worker's probe
//! answer asks of its uploader, what its grant hands it — the hash-set ask
//! among it — and how that ask passes from granted link to granted link: at
//! its worker's end, at a refused answer and at the **Hash-Set Deadline**.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use rmule_peer::{ClientFamily, ClientSoftware};
use rmule_primitives::{PartHashSet, PeerEndpoint};

use crate::adapters::{PeerWorkerCommand, WorkerOpening};
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
    /// It takes the grant its link carries, asking nothing (ADR-0107).
    Taking,
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
    /// Workers opened on a grant their uploader gave unasked (ADR-0057), until
    /// their own ask leaves: the slot is theirs to give back (ADR-0056).
    offered: HashSet<PeerEndpoint>,
    /// Offered workers that probe nothing: they take the grant at their
    /// connection, off the parts their record heard (ADR-0107).
    take_at_connect: HashSet<PeerEndpoint>,
}

impl SlotAsks {
    /// Whether `peer`'s uploader granted it a slot.
    pub(super) fn granted(&self, peer: PeerEndpoint) -> bool {
        self.by_worker.get(&peer) == Some(&SlotAsk::Granted)
    }

    /// Whether `peer` holds a slot at its uploader: granted on its own ask,
    /// or given unasked with no ask of its own out yet.
    pub(super) fn holds_slot(&self, peer: PeerEndpoint) -> bool {
        self.granted(peer) || self.offered.contains(&peer)
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
        self.offered.remove(&peer);
        self.take_at_connect.remove(&peer);
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
    /// A worker opened on a grant its link carries takes it instead, asking
    /// nothing the uploader would score (ADR-0107).
    pub(super) fn ask_on_probe(&mut self, peer: PeerEndpoint, out: &mut Vec<Decision>) {
        if self.slot_asks.by_worker.contains_key(&peer) {
            return;
        }
        if self.slot_asks.offered.contains(&peer) {
            self.slot_asks.by_worker.insert(peer, SlotAsk::Taking);
            out.push(Decision::Send {
                peer,
                command: PeerWorkerCommand::TakeGrant,
            });
        } else {
            self.ask_slot(peer, out);
        }
    }

    /// `peer`'s worker opened on a grant its uploader gave unasked: until it
    /// takes it or its own ask leaves, the slot is its to give back (ADR-0056
    /// item 3). Opened `Granted`, it probes nothing and takes the grant at its
    /// connection.
    pub(super) fn holds_offered_slot(&mut self, peer: PeerEndpoint, opening: WorkerOpening) {
        self.slot_asks.offered.insert(peer);
        if opening == WorkerOpening::Granted {
            self.slot_asks.take_at_connect.insert(peer);
        }
    }

    /// `peer`'s worker connected: one opened on a grant its link carries,
    /// probing nothing, takes it off the parts its record heard, as a probe's
    /// answer would have them (ADR-0107, ADR-0112).
    pub(super) fn take_grant_at_connect(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        out: &mut Vec<Decision>,
    ) {
        if self.slot_asks.take_at_connect.remove(&peer) && self.sources.take_heard_parts(peer) {
            self.on_probe_answer(now, peer, out);
        }
    }

    /// Send `peer`'s slot ask: it waits queued, its part chosen at the grant.
    fn ask_slot(&mut self, peer: PeerEndpoint, out: &mut Vec<Decision>) {
        self.slot_asks.offered.remove(&peer);
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
    /// has its answer, and its record holds the standing the rank earned. At
    /// an uploader that notices our close it hangs up — the **Queued
    /// Hang-Up** (ADR-0116) — and its record waits in the RemoteQueued stage,
    /// the reask keeping its place (ADR-0057). Elsewhere it holds the link,
    /// queued, until the uploader grants on it or closes it: a promotion
    /// written on a link we closed is lost there. A granted worker's rank
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
        let notices_close = self
            .sources
            .identity(peer)
            .is_some_and(|identity| notices_close(identity.software()));
        if notices_close {
            self.retire(now, peer, PeerRetirementReason::Queued, out);
        }
    }

    /// `peer`'s uploader granted it a slot: hand it its first blocks, or give
    /// the slot back (ADR-0026, ADR-0056, ADR-0117). A slot the worker keeps takes the
    /// download's one hash-set ask when nobody asks it (ADR-0116 invariant 3),
    /// and is a grant on the peer's **Queue Standing**: the downloads waiting
    /// on it are called to this link, to take it by the swap rule (ADR-0107).
    pub(super) fn granted(&mut self, now: Instant, peer: PeerEndpoint, out: &mut Vec<Decision>) {
        if !self.worker_slots.contains_key(&peer) {
            return;
        }
        self.slot_asks.by_worker.insert(peer, SlotAsk::Granted);
        self.want_at_grant(peer);
        self.hand(now, peer, out);
        if self.may_ask_hash_set(peer) {
            self.ask_hash_set(now, peer, out);
        }
        if self.slot_asks.granted(peer) {
            out.push(Decision::CallStandingWaiters { peer });
        }
    }

    /// Retire `peer` for `reason`, a live source's: it was ranked without a
    /// grant (`Queued`, ADR-0116), its parts hold nothing we lack
    /// (`NoNeededParts`), or a granted slot drained with every block it could
    /// fetch claimed elsewhere (`NoFreePart`). Its record waits in the RemoteQueued
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

/// Whether an uploader running `software` notices our close at once, so a
/// promotion it makes after our hang-up comes by dial-back (ADR-0116
/// invariant 3): eMule closes its side on the socket's close event (eMuleAI
/// `ListenSocket.cpp:711-720`), aMule 3 turns its socket layer's lost event
/// into a close (3.1.0 `EMSocket.h:124`), and rmule reads the end of the
/// stream. aMule 2's Boost.Asio build ignores that event (`LibSocket.h:124`)
/// and keeps the client connected to its 40 s idle close, writing a promotion
/// on the closed link; a client whose close handling is unread is held to
/// the same.
fn notices_close(software: &ClientSoftware) -> bool {
    match software.family() {
        ClientFamily::Emule | ClientFamily::Rmule => true,
        ClientFamily::Amule => software.version().is_some_and(|version| version.major >= 3),
        _ => false,
    }
}
