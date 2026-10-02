//! Worker-slot occupancy: which candidate fills a free slot, what a slot
//! release costs the parts it was working, and the assignment that hands a
//! peer its next part. The scheduling *policy* these three share is the
//! candidate order — a slot is never held open for a peer that cannot work.

use std::collections::VecDeque;

use rmule_peer::natt::CALLBACK_SILENCE_FALLBACK;
use rmule_primitives::PeerEndpoint;

use crate::DownloadFailure;
use crate::adapters::PeerWorkerCommand;
use crate::assembly::PartAssembly;
use crate::callback::CallbackSilence;
use crate::diagnostics::{WorkerPhase, WorkerSlot};
use crate::service::{DownloadEvent, PartReleaseReason, PeerRetirementReason};

use super::candidates::fall_to_nat_traversal;
use super::{
    Decision, DownloadState, LowIdCandidate, LowIdRoad, LowIdRoute, PendingCallback, Worker,
};

impl DownloadState {
    /// Spawn workers from the candidate pool until the fleet (active +
    /// connecting) reaches `peer_concurrency` or the pool is exhausted. Each
    /// spawn claims a free diagnostics slot and registers the peer as
    /// connecting; the runner enacts the [`Decision::Spawn`] by putting it on
    /// the wire. The same path serves the initial fill and the on-retirement
    /// backfill (ADR-0030).
    pub(super) fn fill(&mut self, out: &mut Vec<Decision>) {
        // Fleet = active/connecting workers + outstanding callbacks (the one
        // pending set spans connected-server and per-server global); each holds a
        // diagnostics slot and counts toward the concurrency cap (ADR-0039 / ADR-0051).
        while self.workers.len() + self.pending_callbacks.len() < self.peer_concurrency {
            if let Some(peer) = self.pool.pop_front() {
                // High-ID candidate: dial immediately (ADR-0030).
                let Some(slot_idx) = self.free_slots.pop_first() else {
                    self.pool.push_front(peer);
                    break;
                };
                self.spawn_worker(peer, WorkerSlot::from_usize(slot_idx), out);
            } else {
                // No reachable High-ID candidate left: take a Low-ID one by
                // whichever route the admission rule leaves open — its IPv6
                // half first (rung 0), else a callback road or the
                // punch (ADR-0091) — and hold its slot until adoption, a
                // failed dial, or the slot-release deadline.
                let Some(slot_idx) = self.free_slots.pop_first() else {
                    break;
                };
                let Some((candidate, route)) = self.take_low_id() else {
                    // No admissible Low-ID candidate of either kind: release the
                    // claimed slot.
                    self.free_slots.insert(slot_idx);
                    break;
                };
                let slot = WorkerSlot::from_usize(slot_idx);
                match route {
                    LowIdRoute::DirectIpv6(half) => {
                        self.open_direct_ipv6(candidate, half, slot, out);
                    }
                    LowIdRoute::Road(road) => self.open_low_id_road(candidate, road, slot, out),
                }
            }
        }
    }
    /// Put a worker on `peer` in `slot`: register it as connecting and have
    /// the runner dial it. A High-ID candidate and a Low-ID candidate's IPv6
    /// half (rung 0) are dialed by this one path.
    pub(super) fn spawn_worker(
        &mut self,
        peer: PeerEndpoint,
        slot: WorkerSlot,
        out: &mut Vec<Decision>,
    ) {
        self.seeds.dialable(peer);
        self.workers.insert(
            peer,
            Worker {
                slot,
                connected: false,
            },
        );
        out.push(Decision::Emit(DownloadEvent::PeerSelected {
            download_id: self.download_id,
            peer,
        }));
        out.push(Decision::Spawn { peer, slot });
    }
    /// Remove the first admissible Low-ID candidate and name its route. Prefers
    /// the connected-server queue (ADR-0039) over the per-server global one
    /// (ADR-0051) — the connected server is already logged in — and skips, but
    /// keeps, a record no route can reach.
    fn take_low_id(&mut self) -> Option<(LowIdCandidate, LowIdRoute)> {
        let position = |state: &Self, pool: &VecDeque<LowIdCandidate>| {
            pool.iter()
                .position(|candidate| state.low_id_route(candidate).is_some())
        };
        let taken = match position(self, &self.low_id_pool) {
            Some(index) => self.low_id_pool.remove(index),
            None => position(self, &self.low_id_global_pool)
                .and_then(|index| self.low_id_global_pool.remove(index)),
        }?;
        self.low_id_route(&taken).map(|route| (taken, route))
    }
    /// Open `candidate`'s road on the `slot` it now holds, and arm what governs
    /// it.
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
    /// sent. Both roads' deadlines are cancelled together, by the
    /// one `CancelCallbackTimeout` adoption or lapse emits.
    fn open_low_id_road(
        &mut self,
        candidate: LowIdCandidate,
        road: LowIdRoad,
        slot: WorkerSlot,
        out: &mut Vec<Decision>,
    ) {
        let key = candidate.key();
        self.pending_callbacks.insert(
            key,
            PendingCallback {
                slot,
                candidate,
                road,
                traversal_retired: None,
                traversal_begun: road == LowIdRoad::Punch,
                slot_lapsed: false,
                fallback_spelling_sent: false,
            },
        );
        if road == LowIdRoad::DirectUdp {
            out.push(Decision::RequestDirectUdpCallback { candidate });
        }
        if road == LowIdRoad::BuddyCallback {
            out.push(Decision::RequestBuddyCallback { candidate });
        }
        if road == LowIdRoad::Callback {
            match candidate.source_server {
                // Connected-server form: `server = None`, the runner resolves it.
                None => out.push(Decision::RequestCallback {
                    low_id: candidate.low_id,
                }),
                // Per-server global form: keyed by the source-server that relays it.
                Some(source_server) => out.push(Decision::RequestGlobalCallback {
                    low_id: candidate.low_id,
                    source_server,
                }),
            }
        }
        out.push(Decision::ArmCallbackTimeout {
            key,
            after: self.callback_timeout,
        });
        match road {
            LowIdRoad::DirectUdp | LowIdRoad::Callback | LowIdRoad::BuddyCallback => {
                if candidate.natt_facts().admits_coordinator() {
                    out.push(Decision::ArmCallbackSilenceFallback {
                        key,
                        after: CALLBACK_SILENCE_FALLBACK,
                    });
                }
            }
            LowIdRoad::Punch => out.extend(fall_to_nat_traversal(
                candidate,
                CallbackSilence::NoCallbackPossible,
            )),
        }
    }
    /// A worker's dial at `peer` ended — `failed` when a dial was made and
    /// never completed its handshake. Its end belongs to the one road that
    /// dialed it: a rung-0 dial hands its Low-ID candidate to the callback
    /// roads ([`Self::on_direct_ipv6_ended`]); a High-ID dial spends the
    /// endpoint and, for a dual-stack half, falls to the other family
    /// ([`Self::on_high_id_dial_ended`]).
    pub(super) fn on_dial_ended(&mut self, peer: PeerEndpoint, failed: bool) {
        if self.direct_ipv6_dials.contains_key(&peer) {
            self.on_direct_ipv6_ended(peer, !failed);
        } else {
            self.on_high_id_dial_ended(peer, failed);
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
        if let Some(worker) = self.workers.remove(&peer) {
            // The endpoint's hello-crypt and hello-hash attachments never
            // outlive the record they ride (ADR-0049, ADR-0090 "Attachments"):
            // `peer`'s worker just ended, so
            // nothing here still wants them, and a re-dial that finds the
            // endpoint bare simply re-learns them off the next hello.
            self.hello_crypts.remove(&peer);
            self.peer_user_hashes.remove(&peer);
            // A dial that never completed its handshake — a crypt refusal
            // dialed nothing, and a distrusted peer's hello was read — is
            // settled before the backfill below reads the queues.
            let failed = !worker.connected
                && !matches!(
                    reason,
                    PeerRetirementReason::CryptIncompatible | PeerRetirementReason::Distrusted
                );
            self.on_dial_ended(peer, failed);
            // Every retirement ends its worker — a bad-data one included,
            // whose socket would otherwise idle until the peer dropped it.
            out.push(Decision::EndWorker { peer });
            out.push(Decision::Phase {
                slot: worker.slot,
                phase: WorkerPhase::Retired { reason },
            });
            out.push(Decision::Phase {
                slot: worker.slot,
                phase: WorkerPhase::ShutDown,
            });
            self.free_slots.insert(worker.slot.as_usize());
        }
        self.retired_peers = self.retired_peers.saturating_add(1);
        // Hand the released part to a still-connected idle worker; a connecting
        // backfill is assigned on its own `Connected` event (ADR-0030). Visit
        // in slot order so the decisions are deterministic.
        let mut connected: Vec<(usize, PeerEndpoint)> = self
            .workers
            .iter()
            .filter(|(_, w)| w.connected)
            .map(|(p, w)| (w.slot.as_usize(), *p))
            .collect();
        connected.sort_unstable_by_key(|&(slot, _)| slot);
        for (_, p) in connected {
            self.assign(p, out);
        }
        self.fill(out);
        // ADR-0026's terminal condition (ADR-0030): only fail once the pool is
        // empty and nothing is active or connecting.
        if self.workers.is_empty()
            && self.pending_callbacks.is_empty()
            && self.no_usable_candidate()
            && !self.scheduler.is_complete()
        {
            out.push(Decision::Fail(DownloadFailure::NoUsableSources));
        }
    }
    /// Assign `peer` its next part (a fresh pending part, else a raced
    /// in-flight one, ADR-0026), resuming from the part's shared prefix
    /// (ADR-0029). Emits the assignment decisions, or an `Idle` phase when
    /// there is nothing for the peer to do.
    pub(super) fn assign(&mut self, peer: PeerEndpoint, out: &mut Vec<Decision>) {
        let Some(slot) = self.workers.get(&peer).map(|w| w.slot) else {
            return;
        };
        if let Some(plan) = self.scheduler.assign_next(peer) {
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
        } else {
            out.push(Decision::Phase {
                slot,
                phase: WorkerPhase::Idle,
            });
        }
    }
}
