//! Worker-slot occupancy: which candidate fills a free slot, what a slot
//! release costs the parts it was working, and the assignment that hands a
//! peer its next part. The scheduling *policy* these three share is the
//! candidate order — a slot is never held open for a peer that cannot work.

use std::time::Instant;

use rmule_peer::natt::CALLBACK_SILENCE_FALLBACK;
use rmule_primitives::PeerEndpoint;

use crate::DownloadFailure;
use crate::adapters::PeerWorkerCommand;
use crate::assembly::PartAssembly;
use crate::callback::CallbackSilence;
use crate::diagnostics::{WorkerPhase, WorkerSlot};
use crate::download::source_book::{Deadline, DialEnd, NextDial, Release, WorkerEnd};
use crate::scheduler::Assignment;
use crate::service::{DownloadEvent, PartReleaseReason, PeerRetirementReason};

use super::{Decision, DownloadState, LowIdCandidate, LowIdRoad};

impl DownloadState {
    /// Spawn workers from the candidate pool until the fleet (active +
    /// connecting, and every callback in flight) reaches `peer_concurrency` or
    /// nothing reachable is left. The **Source Book** picks each next dial in
    /// lane order and moves it to its stage; the brain claims a free
    /// diagnostics slot for it and has the runner enact it. The same path
    /// serves the initial fill and the on-retirement backfill (ADR-0030).
    pub(super) fn fill(&mut self, now: Instant, out: &mut Vec<Decision>) {
        while let Some(&slot_idx) = self.free_slots.first() {
            let Some(dial) =
                self.sources
                    .next_dial(self.peer_concurrency, &self.callback_capability, self.dial)
            else {
                break;
            };
            self.free_slots.remove(&slot_idx);
            let slot = WorkerSlot::from_usize(slot_idx);
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
    /// verification failure it contributed to). Returns its in-flight part to
    /// the pool when it was the sole holder (ADR-0026), frees its diagnostics
    /// slot, hands the released part to a still-connected idle worker, and
    /// backfills a replacement from the candidate pool (ADR-0030). When the
    /// pool is exhausted and no worker remains, the download fails.
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
        if let Some(slot) = self.worker_slots.remove(&peer) {
            // A worker that hangs up, times out its slot wait or is refused
            // for parts while queued keeps its standing (ADR-0057); refused,
            // it holds no part we need and reasks at twice the period, over
            // TCP (aMule `DS_NONEEDEDPARTS`). A source whose Advertised Parts
            // hold nothing we lack keeps that mark on its standing, or earns
            // one at rank 0 (ADR-0112). Any other end is the standing's.
            match reason {
                PeerRetirementReason::PeerDisconnected | PeerRetirementReason::SlotTimeout => {}
                PeerRetirementReason::SlotRejected => {
                    if self.sources.rank(peer).is_some() {
                        self.sources.no_needed_parts(peer, now);
                    }
                }
                PeerRetirementReason::NoNeededParts => self.sources.no_needed_parts(peer, now),
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
                let end = self.sources.end_worker(peer, failed, self.dial);
                // A source with nothing we need waits unranked: its
                // retirement says why, and no queue rank is reported.
                if end == Some(WorkerEnd::Release(Release::RemoteQueued))
                    && reason != PeerRetirementReason::NoNeededParts
                {
                    out.push(Decision::Emit(DownloadEvent::SourceRemoteQueued {
                        download_id: self.download_id,
                        peer,
                        rank: self.sources.rank(peer).unwrap_or_default(),
                    }));
                }
                self.note_worker_end(end);
            }
            // Every retirement ends its worker — a bad-data one included,
            // whose socket would otherwise idle until the peer dropped it. A
            // source with nothing we need gives back a slot it granted.
            out.push(Decision::EndWorker {
                peer,
                cancel: reason == PeerRetirementReason::NoNeededParts,
            });
            out.push(Decision::Phase {
                slot,
                phase: WorkerPhase::Retired { reason },
            });
            out.push(Decision::Phase {
                slot,
                phase: WorkerPhase::ShutDown,
            });
            self.free_slots.insert(slot.as_usize());
        }
        self.retired_peers = self.retired_peers.saturating_add(1);
        // Hand the released part to a still-connected idle worker whose parts
        // are known; any other is assigned on its own probe answer (ADR-0112).
        let unneeded = self.offer_connected(out);
        self.fill(now, out);
        // ADR-0026's terminal condition (ADR-0030): only fail once the pool is
        // empty and nothing is active or connecting.
        if self.out_of_sources() {
            out.push(Decision::Fail(DownloadFailure::NoUsableSources));
        }
        for peer in unneeded {
            self.retire_no_needed_parts(now, peer, out);
        }
    }

    /// Offer every connected worker its next part, in slot order. The ones
    /// whose Advertised Parts hold no part we lack are returned, for the
    /// caller to retire once its own release has settled.
    pub(super) fn offer_connected(&mut self, out: &mut Vec<Decision>) -> Vec<PeerEndpoint> {
        self.connected_workers()
            .into_iter()
            .filter(|&peer| !self.offer(peer, out))
            .collect()
    }

    /// Retire `peer`, whose Advertised Parts hold no part we lack, as
    /// `NoNeededParts` (ADR-0112 §6): its record waits in the RemoteQueued
    /// stage with the mark, unspent, and its slot is backfilled.
    pub(super) fn retire_no_needed_parts(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        out: &mut Vec<Decision>,
    ) {
        out.push(Decision::Emit(DownloadEvent::PeerRetired {
            download_id: self.download_id,
            peer,
            reason: PeerRetirementReason::NoNeededParts,
        }));
        self.release(now, peer, PeerRetirementReason::NoNeededParts, out);
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
    /// Assign `peer` its next part — a fresh pending part its Advertised
    /// Parts hold, else a raced in-flight one, by rank (ADR-0026, ADR-0112) —
    /// resuming from the part's shared prefix (ADR-0029), or an `Idle` phase
    /// when every part it holds that we lack is in flight. A worker whose
    /// Advertised Parts are not known yet is handed nothing: its probe answer
    /// assigns it. One whose parts hold nothing we lack is retired
    /// `NoNeededParts`.
    pub(super) fn assign(&mut self, now: Instant, peer: PeerEndpoint, out: &mut Vec<Decision>) {
        if !self.offer(peer, out) {
            self.retire_no_needed_parts(now, peer, out);
        }
    }

    /// [`Self::assign`]'s offer: the assignment decisions, an `Idle` phase,
    /// or nothing, and `false` only when `peer`'s Advertised Parts hold no
    /// part the unfinished file lacks.
    fn offer(&mut self, peer: PeerEndpoint, out: &mut Vec<Decision>) -> bool {
        let Some(slot) = self.worker_slots.get(&peer).copied() else {
            return true;
        };
        let Some(parts) = self.sources.parts(peer) else {
            return true;
        };
        let plan = match self.scheduler.assign_next(
            peer,
            parts,
            self.sources.part_frequency(),
            self.sources.parts_known(),
        ) {
            Assignment::Fresh(plan) | Assignment::Raced(plan) => plan,
            Assignment::Nothing { lacked: false } if !self.scheduler.is_complete() => {
                return false;
            }
            Assignment::Nothing { .. } => {
                out.push(Decision::Phase {
                    slot,
                    phase: WorkerPhase::Idle,
                });
                return true;
            }
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
        true
    }
}
