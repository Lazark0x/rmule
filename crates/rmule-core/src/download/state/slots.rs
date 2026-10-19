//! Worker-slot occupancy: which candidate fills a free slot, what a slot
//! release costs the parts it was working, and the assignment that hands a
//! peer its next part. The scheduling *policy* these three share is the
//! candidate order — a slot is never held open for a peer that cannot work.

use std::collections::HashMap;
use std::time::Instant;

use rmule_peer::natt::CALLBACK_SILENCE_FALLBACK;
use rmule_primitives::PeerEndpoint;

use crate::adapters::PeerWorkerCommand;
use crate::assembly::PartAssembly;
use crate::callback::CallbackSilence;
use crate::delivery_rate::DeliveryRate;
use crate::diagnostics::{WorkerPhase, WorkerSlot};
use crate::download::queue_standings::Role;
use crate::download::source_book::{Deadline, DialEnd, NextDial, Release, WorkerEnd};
use crate::scheduler::Assignment;
use crate::service::{DownloadEvent, PartReleaseReason, PeerRetirementReason};
use crate::{DownloadFailure, PartPlan};

use super::{Decision, DownloadState, LowIdCandidate, LowIdRoad};

impl DownloadState {
    /// Spawn workers from the candidate pool while the node's **Connection
    /// Budget** admits them and something reachable is left (ADR-0116). The
    /// **Source Book** picks each next dial in lane order and moves it to its
    /// stage; the brain claims a diagnostics slot for it and has the runner
    /// enact it. A refused fill takes nothing from its lane and wakes at the
    /// Dial Window's turn. The same path serves the initial fill, the
    /// on-retirement backfill (ADR-0030) and a TCP full ask. A record whose
    /// peer stands in another download's **Queue Standing** is not dialed: it
    /// waits on that standing (ADR-0107).
    pub(super) fn fill(&mut self, now: Instant, out: &mut Vec<Decision>) {
        while self
            .sources
            .has_next_dial(&self.callback_capability, self.dial)
        {
            if let Err(look_again) = self.budget.admit(now, self.sources.slots_in_use()) {
                self.budget_wake = look_again;
                return;
            }
            let Some(dial) = self.sources.next_dial(&self.callback_capability, self.dial) else {
                self.budget.give_back(now);
                break;
            };
            if let NextDial::Worker(peer) = dial
                && self.waits_on_standing(now, peer, out)
            {
                self.budget.give_back(now);
                continue;
            }
            let slot = self.claim_slot();
            match dial {
                // A High-ID candidate, or a Low-ID candidate's IPv6 half
                // (rung 0): dial it now.
                NextDial::Worker(peer) => self.spawn_worker(now, peer, slot, out),
                // A Low-ID candidate's callback road or punch (ADR-0091): hold
                // its slot until adoption or the slot-release deadline.
                NextDial::Callback { candidate, road } => {
                    self.open_low_id_road(now, candidate, road, slot, out);
                }
            }
        }
        self.budget_wake = None;
    }

    /// A diagnostics slot number for a new worker or road: the lowest one a
    /// retirement freed, else the first past every number in use.
    pub(super) fn claim_slot(&mut self) -> WorkerSlot {
        if let Some(free) = self.free_slots.pop_first() {
            return WorkerSlot::from_usize(free);
        }
        let highest = self
            .worker_slots
            .values()
            .chain(self.callback_slots.values())
            .map(|slot| slot.as_usize())
            .max();
        WorkerSlot::from_usize(highest.map_or(0, |highest| highest + 1))
    }

    /// Republish the connections this run holds to the node's **Connection
    /// Budget**: every dial, worker and callback road its book holds
    /// (ADR-0116 invariant 5). The runner calls it after every drain.
    pub(crate) fn hold_connections(&self) {
        self.budget.hold(self.sources.slots_in_use());
    }

    /// Republish the places this run's records hold in the node's **Queue
    /// Standings** (ADR-0107): every record holding a standing. The runner
    /// calls it after every drain.
    pub(crate) fn hold_standings(&self) {
        self.standings.publish(self.sources.places());
    }

    /// The fill took the record at `peer` to dial it, but another download
    /// holds that peer's **Queue Standing**: the record waits on it, asking
    /// nothing and opening nothing, as aMule's A4AF file waits on its client
    /// (`AddRequestForAnotherFile`, stock 2.3.3 `DownloadClient.cpp:496-507`;
    /// ADR-0107 invariant 13). Whether it waits.
    fn waits_on_standing(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        out: &mut Vec<Decision>,
    ) -> bool {
        let Some(place) = self.sources.dial_place(peer) else {
            return false;
        };
        let Role::Waits { asked_at } = self.standings.role(&place) else {
            return false;
        };
        if !self.sources.wait_on_standing(peer, asked_at, now) {
            return false;
        }
        out.push(Decision::Emit(DownloadEvent::SourceWaitsOnStanding {
            download_id: self.download_id,
            peer,
        }));
        true
    }

    /// Put a worker on `peer` in `slot`: register it as connecting and have
    /// the runner dial it, with the source ask its record's facts call for at
    /// `now`. A High-ID candidate and a Low-ID candidate's IPv6 half (rung 0)
    /// are dialed by this one path.
    pub(super) fn spawn_worker(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        slot: WorkerSlot,
        out: &mut Vec<Decision>,
    ) {
        self.seeds.dialable(peer);
        self.worker_slots.insert(peer, slot);
        out.push(Decision::Emit(DownloadEvent::PeerSelected {
            download_id: self.download_id,
            peer,
        }));
        out.push(Decision::Spawn {
            peer,
            slot,
            want_sources: self.sources.wants_sources_at(peer, now),
        });
    }
    /// Open `candidate`'s road at `now` on the `slot` it now holds, and arm
    /// what governs it on its record.
    ///
    /// **The slot-release deadline rides every road** (ADR-0039's injected
    /// 30 s): a target that never dials in and a punch that never raises a
    /// Tunnel each cost one slot for that long and no longer.
    ///
    /// On any callback road — the candidate's own direct-UDP invitation, a
    /// server's relay, or the candidate's buddy's — the 12 s **callback-silence
    /// fallback** (ADR-0091) rides too, but only when the candidate's own facts admit a Rendezvous
    /// coordinator — a candidate no coordinator could introduce us to arms
    /// nothing extra and waits out its 30 s exactly as before.
    ///
    /// On the punch road there is no callback and therefore no silence to
    /// measure, so the fall is emitted *here*, at once. Twelve seconds of
    /// waiting would be twelve seconds spent on an invitation that was never
    /// sent. Every deadline ends with the road, however it ends.
    fn open_low_id_road(
        &mut self,
        now: Instant,
        candidate: LowIdCandidate,
        road: LowIdRoad,
        slot: WorkerSlot,
        out: &mut Vec<Decision>,
    ) {
        let key = candidate.key();
        self.callback_slots.insert(key, slot);
        let callback_timeout = self.callback_timeout;
        if let Some(pending) = self.sources.road_mut(key) {
            pending.arm(Deadline::SlotRelease, now + callback_timeout);
        }
        let want_sources = self.sources.wants_sources_for(key, now);
        if road == LowIdRoad::DirectUdp {
            out.push(Decision::RequestDirectUdpCallback {
                candidate,
                want_sources,
            });
        }
        if road == LowIdRoad::BuddyCallback {
            out.push(Decision::RequestBuddyCallback {
                candidate,
                want_sources,
            });
        }
        let ours = self.callback_capability.server();
        if road == LowIdRoad::Callback {
            let elsewhere = candidate
                .source_server
                .filter(|_| !candidate.on_server(ours));
            match elsewhere {
                // The id is ours, or was minted with no server known: our
                // session relays it, aMule's `IsLocalServer` branch.
                None => out.push(Decision::RequestCallback {
                    low_id: candidate.low_id,
                    server: candidate.source_server,
                    want_sources,
                }),
                // Another server assigned it — a global answer, or our former
                // server: that server relays it (ADR-0051).
                Some(source_server) => out.push(Decision::RequestGlobalCallback {
                    low_id: candidate.low_id,
                    source_server,
                    want_sources,
                }),
            }
        }
        match road {
            LowIdRoad::DirectUdp | LowIdRoad::Callback | LowIdRoad::BuddyCallback => {
                if candidate.natt_facts(ours).admits_coordinator()
                    && let Some(pending) = self.sources.road_mut(key)
                {
                    pending.arm(Deadline::SilenceFallback, now + CALLBACK_SILENCE_FALLBACK);
                }
            }
            LowIdRoad::Punch => out.push(self.fall_to_nat_traversal(
                now,
                candidate,
                CallbackSilence::NoCallbackPossible,
            )),
        }
    }
    /// Retire `peer` after a failure (disconnect, slot rejection/timeout, or a
    /// verification failure it contributed to), or a slot it cannot work.
    /// Returns its in-flight part to the pool when it was the sole holder
    /// (ADR-0026), frees its diagnostics slot, hands the released part to a
    /// granted worker with none, passes a hash-set ask it held, and backfills
    /// a replacement from the candidate pool (ADR-0030). When the pool is
    /// exhausted and no worker remains, the download fails.
    pub(super) fn release(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        reason: PeerRetirementReason,
        out: &mut Vec<Decision>,
    ) {
        if let Some(plan) = self.scheduler.release_for_retry(peer) {
            out.push(Decision::Emit(DownloadEvent::PartReleased {
                download_id: self.download_id,
                peer,
                part_index: plan.part_index,
                reason: PartReleaseReason::PeerRetired(reason),
            }));
        }
        let holds_slot = self.slot_asks.holds_slot(peer);
        let granted = self.slot_asks.granted(peer);
        self.delivery.remove(&peer);
        if let Some(slot) = self.worker_slots.remove(&peer) {
            // A worker that hangs up, times out its slot wait or was ranked
            // without a grant keeps its standing (ADR-0057, ADR-0116). A source whose Advertised Parts hold
            // nothing we lack keeps that mark on its standing, or earns one
            // at rank 0, and reasks at twice the period, over TCP (aMule
            // `DS_NONEEDEDPARTS`, ADR-0112). One that gave back a granted
            // slot with no part free earns a standing on the ordinary cadence,
            // and so does one whose link failed or whose slot stalled while it
            // transferred, dated at its last ask (aMule `DS_DOWNLOADING` →
            // `DS_ONQUEUE`). Any other end is the standing's (ADR-0090, "How a
            // worker ends, and what its record keeps").
            match reason {
                PeerRetirementReason::PeerDisconnected | PeerRetirementReason::SlotTimeout
                    if granted =>
                {
                    self.sources.transfer_cut(peer, now);
                }
                PeerRetirementReason::PeerDisconnected
                | PeerRetirementReason::SlotTimeout
                | PeerRetirementReason::Queued => {}
                PeerRetirementReason::NoNeededParts => self.sources.no_needed_parts(peer, now),
                PeerRetirementReason::NoFreePart => self.sources.on_queue(peer, now),
                _ => self.sources.end_standing(peer),
            }
            // A worker that gave way in a merge left the book already: its
            // record joined the one that kept the peer.
            if reason != PeerRetirementReason::SameSource {
                // A dial that never completed its handshake — a crypt refusal
                // dialed nothing, and a distrusted peer's hello was read — is
                // settled before the backfill below reads the lanes. The
                // record's hello attachments end with the worker (ADR-0049).
                let failed = !self.sources.is_connected(peer)
                    && !matches!(
                        reason,
                        PeerRetirementReason::CryptIncompatible | PeerRetirementReason::Distrusted
                    );
                // A source that said it lacks the file is spent under every
                // name its record holds, whichever road reached it (ADR-0090).
                let end = if reason == PeerRetirementReason::FileNotFound {
                    self.sources.lacked_file(peer)
                } else {
                    self.sources.end_worker(peer, failed, self.dial)
                };
                // A source with nothing we need waits unranked: its
                // retirement says why, and no queue rank is reported.
                if end == Some(WorkerEnd::Release(Release::RemoteQueued))
                    && reason != PeerRetirementReason::NoNeededParts
                {
                    out.push(Decision::Emit(DownloadEvent::SourceRemoteQueued {
                        download_id: self.download_id,
                        peer,
                        rank: self.sources.rank(peer),
                    }));
                }
                self.note_worker_end(end);
            }
            // Every retirement ends its worker — a bad-data one included,
            // whose socket would otherwise idle until the peer dropped it. A
            // worker that cannot work a granted slot gives it back (ADR-0056).
            let unworkable = matches!(
                reason,
                PeerRetirementReason::NoNeededParts | PeerRetirementReason::NoFreePart
            );
            out.push(Decision::EndWorker {
                peer,
                cancel: holds_slot && unworkable,
            });
            // The row keeps the reason until the slot dials again (ADR-0028):
            // `ShutDown` is the whole download's stop, never one worker's.
            out.push(Decision::Phase {
                slot,
                phase: WorkerPhase::Retired { reason },
            });
            self.free_slots.insert(slot.as_usize());
        }
        self.retired_peers = self.retired_peers.saturating_add(1);
        self.forget_slot_ask(now, peer, out);
        // The released part goes to a granted worker with none; a queued one
        // is handed its part at its grant (ADR-0026).
        self.reassign_workers(now, out);
    }

    /// `peer`'s uploader ended its granted slot and put it back on the queue
    /// (`OP_OUTOFPARTREQS`, ADR-0057): the worker stays, waiting for a slot;
    /// the part it held goes back for retry (ADR-0026) and its record earns
    /// a standing without a rank, which the `OP_QUEUERANKING` that follows
    /// ranks. Its next grant hands it its next part; a granted worker with
    /// none takes the released one now.
    pub(super) fn requeued(&mut self, now: Instant, peer: PeerEndpoint, out: &mut Vec<Decision>) {
        if !self.worker_slots.contains_key(&peer) {
            return;
        }
        if let Some(plan) = self.scheduler.release_for_retry(peer) {
            out.push(Decision::Emit(DownloadEvent::PartReleased {
                download_id: self.download_id,
                peer,
                part_index: plan.part_index,
                reason: PartReleaseReason::BackOnQueue,
            }));
        }
        self.sources.on_queue(peer, now);
        self.queued_again(peer, out);
        self.reassign_workers(now, out);
    }

    /// Hand every granted worker with no part its next one and backfill the
    /// free slots; with the pool empty and nothing active or connecting the
    /// download fails (ADR-0026's terminal condition, ADR-0030). A worker
    /// left unable to work its slot is retired last, once all that has
    /// settled (ADR-0112 §6, ADR-0056).
    pub(super) fn reassign_workers(&mut self, now: Instant, out: &mut Vec<Decision>) {
        let unworkable = self.assign_connected(out);
        self.fill(now, out);
        if self.out_of_sources() {
            out.push(Decision::Fail(DownloadFailure::NoUsableSources));
        }
        for (peer, reason) in unworkable {
            self.retire(now, peer, reason, out);
        }
    }

    /// [`Self::assign_or_lacking`] for every connected worker, in slot
    /// order. The ones that cannot work a slot are returned with why, for
    /// the caller to retire once its own decisions have settled.
    pub(super) fn assign_connected(
        &mut self,
        out: &mut Vec<Decision>,
    ) -> Vec<(PeerEndpoint, PeerRetirementReason)> {
        self.connected_workers()
            .into_iter()
            .filter_map(|peer| {
                self.assign_or_lacking(peer, out)
                    .unworkable()
                    .map(|r| (peer, r))
            })
            .collect()
    }

    /// The workers that completed their handshake, in slot order so the
    /// decisions are deterministic.
    pub(super) fn connected_workers(&self) -> Vec<PeerEndpoint> {
        let mut connected: Vec<(usize, PeerEndpoint)> = self
            .worker_slots
            .iter()
            .filter(|(peer, _)| self.sources.is_connected(**peer))
            .map(|(peer, slot)| (slot.as_usize(), *peer))
            .collect();
        connected.sort_unstable_by_key(|&(slot, _)| slot);
        connected.into_iter().map(|(_, peer)| peer).collect()
    }

    /// Fold what a worker's end did to its record into the seeds: a dual-stack
    /// fall makes the other half dialable.
    pub(super) fn note_worker_end(&mut self, end: Option<WorkerEnd>) {
        if let Some(WorkerEnd::Dial(DialEnd::FellToOtherHalf(other))) = end {
            self.seeds.dialable(other);
        }
    }
    /// Assign granted `peer` its next part — a fresh pending part its
    /// Advertised Parts hold, else a raced in-flight one, by rank (ADR-0026,
    /// ADR-0112) — resuming from the part's shared prefix (ADR-0029). A worker
    /// whose own probe has not answered is handed nothing, whatever its record
    /// kept from an earlier connection, and a queued one waits for its grant.
    /// One whose parts hold nothing we lack is retired `NoNeededParts`; a
    /// granted one with nothing free gives the slot back, `NoFreePart`.
    pub(super) fn assign(&mut self, now: Instant, peer: PeerEndpoint, out: &mut Vec<Decision>) {
        if let Some(reason) = self.assign_or_lacking(peer, out).unworkable() {
            self.retire(now, peer, reason, out);
        }
    }

    /// [`Self::assign`] short of the retirement: the assignment decisions or
    /// nothing, and what they came to — the caller retires a worker that
    /// cannot work its slot.
    fn assign_or_lacking(&mut self, peer: PeerEndpoint, out: &mut Vec<Decision>) -> Handed {
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
        let pace = Pace {
            delivery: &self.delivery,
            assembly: &self.assembly,
        };
        let plan = match self.scheduler.assign_next(
            peer,
            parts,
            self.sources.part_frequency(),
            self.sources.parts_known(),
            &pace,
        ) {
            Assignment::Fresh(plan) | Assignment::Raced(plan) => plan,
            Assignment::Busy => return Handed::Assigned,
            Assignment::Nothing { .. } => return Handed::NothingFree,
        };
        let resume_offset = plan.offset
            + self
                .assembly
                .get(&plan.part_index)
                .map_or(0, PartAssembly::prefix_len);
        out.push(Decision::Emit(DownloadEvent::PartAssigned {
            download_id: self.download_id,
            peer,
            part_index: plan.part_index,
        }));
        out.push(Decision::Phase {
            slot,
            phase: WorkerPhase::RequestingPart {
                part_index: plan.part_index,
            },
        });
        out.push(Decision::Send {
            peer,
            command: PeerWorkerCommand::RequestPart {
                plan,
                resume_offset,
            },
        });
        Handed::Assigned
    }
}

/// What a Tail Race reads of this download (ADR-0026): each worker's
/// Delivery Rate and each in-flight part's assembled prefix.
struct Pace<'a> {
    delivery: &'a HashMap<PeerEndpoint, DeliveryRate>,
    assembly: &'a HashMap<u32, PartAssembly>,
}

impl crate::scheduler::Pace for Pace<'_> {
    fn rate(&self, peer: PeerEndpoint) -> Option<u64> {
        self.delivery.get(&peer)?.bytes_per_sec()
    }

    fn remaining(&self, plan: &PartPlan) -> u64 {
        let assembled = self
            .assembly
            .get(&plan.part_index)
            .map_or(0, PartAssembly::prefix_len);
        plan.len.saturating_sub(assembled)
    }
}

/// What handing one worker its next part came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Handed {
    /// It holds a part: one handed now, or the one it already works.
    Assigned,
    /// The file is complete: nothing is handed to anyone.
    Complete,
    /// It is queued: its grant hands it its part (ADR-0026).
    Queued,
    /// It is no worker whose own probe answered: that answer asks its slot
    /// (ADR-0112 §3).
    Unanswered,
    /// Its Advertised Parts hold no part the file lacks.
    NothingNeeded,
    /// It is granted, and every part it holds that we lack is in flight
    /// elsewhere, or it may not race one (ADR-0026).
    NothingFree,
}

impl Handed {
    /// Why a worker this came to cannot work a slot, if it cannot.
    const fn unworkable(self) -> Option<PeerRetirementReason> {
        match self {
            Self::NothingNeeded => Some(PeerRetirementReason::NoNeededParts),
            Self::NothingFree => Some(PeerRetirementReason::NoFreePart),
            Self::Assigned | Self::Complete | Self::Queued | Self::Unanswered => None,
        }
    }
}
