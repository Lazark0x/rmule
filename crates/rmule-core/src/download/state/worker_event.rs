//! Worker facts folded into the download's state: what a spawn failure, a
//! delivered block, a hash set, a persist result and a retirement each do to
//! the scheduler, the assembly, and the fleet. Every entry point returns the
//! ordered decisions the runner enacts — nothing here awaits.

use std::time::Instant;

use rmule_peer::{PartIndex, PeerIdentity};
use rmule_primitives::{PartHash, PeerEndpoint, UserHash};

use crate::DownloadFailure;
use crate::adapters::{PeerWorkerCommand, PeerWorkerEvent};
use crate::assembly::{ArrivedPart, CellHash, PartAssembly};
use crate::diagnostics::WorkerPhase;
use crate::hashing::{hash_set_proves_file, resolve_hash_set_authority};
use crate::service::{DownloadEvent, PeerRetirementReason, VerificationAuthority};

use super::{Decision, DownloadState};

/// Send the ranges of `bytes`, delivered at `offset`, that `fresh` names to
/// the file. A block wholly new, the common arrival, moves as it came.
fn write_fresh(offset: u64, mut bytes: Vec<u8>, fresh: &[(u64, u64)], out: &mut Vec<Decision>) {
    if let [(start, end)] = *fresh
        && start == offset
    {
        bytes.truncate((end - start) as usize);
        out.push(Decision::WriteBytes { offset, bytes });
        return;
    }
    for &(start, end) in fresh {
        let within = (start - offset) as usize..(end - offset) as usize;
        out.push(Decision::WriteBytes {
            offset: start,
            bytes: bytes[within].to_vec(),
        });
    }
}

impl DownloadState {
    /// Resume after the runner could not put a spawned candidate on the wire
    /// (its `start_peer_worker` failed). Free the claimed slot, drop the
    /// candidate, and try the next; a never-connected worker is not a
    /// retirement, so the retired count is unchanged (ADR-0030).
    pub(crate) fn on_spawn_failed(&mut self, now: Instant, peer: PeerEndpoint) -> Vec<Decision> {
        let mut out = Vec::new();
        if let Some(slot) = self.worker_slots.remove(&peer) {
            self.free_slots.insert(slot.as_usize());
            // A dial that could not even start is a failed dial: a rung-0
            // Low-ID candidate falls to its callback roads, and a
            // High-ID endpoint is spent and a dual-stack half falls to its
            // other family.
            let end = self.sources.end_worker(peer, true, self.dial);
            self.note_worker_end(end);
        }
        self.fill(now, &mut out);
        if self.out_of_sources() {
            out.push(Decision::Fail(DownloadFailure::NoUsableSources));
        }
        self.settle_seed_dials(&mut out);
        out
    }
    /// Drive one worker event at `now` to its scheduling decisions.
    /// The hello of the worker at `peer` named our own User Hash, which the
    /// runner read (ADR-0090 invariant 6): its dial reached this node, and the
    /// source leaves the book, spent.
    pub(crate) fn on_own_hello(&mut self, now: Instant, peer: PeerEndpoint) -> Vec<Decision> {
        let mut out = vec![Decision::Emit(DownloadEvent::PeerRetired {
            download_id: self.download_id,
            peer,
            reason: PeerRetirementReason::OurOwnNode,
        })];
        self.release(now, peer, PeerRetirementReason::OurOwnNode, &mut out);
        out
    }

    pub(crate) fn on_worker_event(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        event: PeerWorkerEvent,
    ) -> Vec<Decision> {
        let mut out = Vec::new();
        self.sources.turn_spent(now);
        self.note_seed_fact(peer, &event);
        match event {
            // The worker's slot ask waits for its Advertised Parts and its
            // part for the grant (ADR-0112, ADR-0026): the handshake alone
            // asks nothing.
            PeerWorkerEvent::Connected => {
                self.sources.connected(peer);
                if let Some(slot) = self.worker_slots.get(&peer).copied() {
                    out.push(Decision::Phase {
                        slot,
                        phase: WorkerPhase::AskingFile,
                    });
                }
                // Ask this peer for the file's master hash, as stock's file
                // request does (`DownloadClient.cpp:SendFileRequest`): it feeds
                // the vote, and a recovery ask goes only to a peer stating the
                // trusted root (ADR-0038). A contested file has neither.
                if self.aich_root.wants_roots() {
                    out.push(Decision::Send {
                        peer,
                        command: PeerWorkerCommand::RequestAichFileHash,
                    });
                }
                self.take_grant_at_connect(now, peer, &mut out);
            }
            // The peer's identity, at its hello and at every revision: it
            // rides the worker's record and dies with that worker (ADR-0049);
            // what the run keeps past the worker is derived on arrival. A
            // distrusted peer reached through a record that named no hash — a
            // server answer, an address it moved to — is retired here, before
            // any part is assigned to it.
            PeerWorkerEvent::Identity(identity) => {
                if let Some(slot) = self.worker_slots.get(&peer).copied() {
                    out.push(Decision::Identify {
                        slot,
                        software: identity.software().clone(),
                    });
                }
                if self.sources.identify(peer, identity) {
                    out.push(Decision::Emit(DownloadEvent::PeerRetired {
                        download_id: self.download_id,
                        peer,
                        reason: PeerRetirementReason::Distrusted,
                    }));
                    self.release(now, peer, PeerRetirementReason::Distrusted, &mut out);
                } else {
                    let ended = self.sources.fold_named_half(peer);
                    self.end_merged(now, ended, &mut out);
                }
            }
            // The source-ask gate's stamps (ADR-0108), on the peer's record:
            // the ask going out — not when the download decided it wanted
            // sources, aMule stamps inside `SendFileRequest` (stock 2.3.3
            // `DownloadClient.cpp:260-261`) — and its complete-or-not
            // advertisement.
            PeerWorkerEvent::SourcesAsked => self.sources.asked(peer, now),
            // The probe's answer: the record keeps the parts, and the worker
            // asks its slot on them, its part chosen at the grant (ADR-0112,
            // ADR-0026). No parts at all is the peer saying it lacks the file
            // (`0x48`, at the probe or mid-slot): the source is spent for this
            // download (ADR-0090).
            PeerWorkerEvent::PartsAdvertised { parts, complete } => {
                self.sources.advertised(peer, complete, now);
                let lacks_file = parts.is_none();
                self.sources.probe_answered(peer, parts);
                if lacks_file {
                    out.push(Decision::Emit(DownloadEvent::PeerRetired {
                        download_id: self.download_id,
                        peer,
                        reason: PeerRetirementReason::FileNotFound,
                    }));
                    self.release(now, peer, PeerRetirementReason::FileNotFound, &mut out);
                } else {
                    self.on_probe_answer(now, peer, &mut out);
                }
            }
            PeerWorkerEvent::BlockReceived {
                part_index,
                offset,
                bytes,
            } => self.on_block(now, peer, part_index, offset, bytes, &mut out),
            // Why the dial ended before the hello; the terminal fact that
            // follows releases the worker.
            PeerWorkerEvent::DialEnded { cause } => {
                out.push(Decision::Emit(DownloadEvent::DialEnded {
                    download_id: self.download_id,
                    peer,
                    cause,
                }));
            }
            // The worker reaches its peer over a link another holds: told,
            // the source's standing unchanged until its `Connected`.
            PeerWorkerEvent::LinkShared { turn } => {
                if turn == crate::service::LinkTurn::Riding {
                    self.rides_a_link(peer);
                }
                out.push(Decision::Emit(DownloadEvent::LinkShared {
                    download_id: self.download_id,
                    peer,
                    turn,
                }));
            }
            PeerWorkerEvent::Disconnected => {
                self.release(now, peer, PeerRetirementReason::PeerDisconnected, &mut out);
            }
            PeerWorkerEvent::HandedBack => self.handed_back(now, peer, &mut out),
            PeerWorkerEvent::NoLinkToRide => self.on_peers_clock(now, peer, &mut out),
            PeerWorkerEvent::CryptIncompatible => {
                // The dial was refused before any socket. aMule
                // deletes the client outright (`CheckContactPreconditions`,
                // `BaseClient.cpp` 1913-1917 at the Fork Pin): every road to
                // this source — a rung-0 candidate's callback roads included —
                // meets the same two stances, so its candidate is dropped here
                // rather than handed back to those roads — and a dual-stack
                // source's other family, which meets the same two stances, is
                // no family failure to retry. The worker never completed a
                // handshake but dialed nothing, so its end is not a failed
                // dial: the record leaves the book unspent.
                self.release(now, peer, PeerRetirementReason::CryptIncompatible, &mut out);
            }
            PeerWorkerEvent::SlotTimeout => {
                out.push(Decision::Emit(DownloadEvent::PeerSlotTimeout {
                    download_id: self.download_id,
                    peer,
                }));
                self.release(now, peer, PeerRetirementReason::SlotTimeout, &mut out);
            }
            // The upload request left: the source is on the uploader's queue,
            // ranked or not, as aMule's `DS_ONQUEUE` (ADR-0090).
            PeerWorkerEvent::SlotAsked => self.sources.on_queue(peer, now),
            PeerWorkerEvent::Requeued => self.requeued(now, peer, &mut out),
            PeerWorkerEvent::Queued { rank } => {
                // The rank earns or refreshes the record's standing, its clock
                // started at ask time as aMule dates it, so a source that
                // hangs up later reasks on schedule (ADR-0057).
                self.sources.queued(peer, rank, now);
                out.push(Decision::Emit(DownloadEvent::PeerQueued {
                    download_id: self.download_id,
                    peer,
                    rank,
                }));
                self.ranked(now, peer, rank, &mut out);
            }
            PeerWorkerEvent::SlotGranted => {
                // A grant ends the standing: the source is live, not queued.
                // It hands the worker its part, or the slot goes back.
                self.sources.end_standing(peer);
                out.push(Decision::Emit(DownloadEvent::PeerSlotGranted {
                    download_id: self.download_id,
                    peer,
                }));
                self.granted(now, peer, &mut out);
            }
            // The worker has room for more blocks: hand them, or give a
            // drained slot with nothing left for it back (ADR-0117).
            PeerWorkerEvent::BlocksWanted {
                room,
                drained,
                handout,
            } => self.on_blocks_wanted(now, peer, room, drained, handout, &mut out),
            // A block that will not come on this slot is freed for the next
            // worker with room; the slot is kept (ADR-0029 "A lost block is
            // freed").
            PeerWorkerEvent::BlockLost { start, end } => {
                self.scheduler.lose(peer, start, end);
                self.reassign_workers(now, &mut out);
            }
            PeerWorkerEvent::HashSetReceived { part_hashes } => {
                self.on_hash_set(now, peer, &part_hashes, &mut out);
            }
            // The runner takes a source-exchange answer at the wire boundary,
            // through the gate, as a sighting batch (`on_sightings`).
            PeerWorkerEvent::SourcesReceived { .. } => {}
            PeerWorkerEvent::AichAnswerReceived {
                part,
                recovery_data,
            } => self.on_aich_answer(
                now,
                PartIndex::new(u32::from(part)),
                recovery_data,
                &mut out,
            ),
            PeerWorkerEvent::AichFileHashReceived { root } => {
                self.on_aich_file_hash_proposal(peer, root, &mut out);
            }
        }
        self.settle_seed_dials(&mut out);
        out
    }
    /// `peer`'s probe answered with parts: one holding nothing we lack is
    /// retired `NoNeededParts` (ADR-0112 §6); any other asks its slot
    /// (ADR-0026).
    pub(super) fn on_probe_answer(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        out: &mut Vec<Decision>,
    ) {
        let Some(parts) = self.sources.worker_parts(peer) else {
            return;
        };
        if self.scheduler.is_complete() {
            return;
        }
        if self.scheduler.lacks_any_of(parts) {
            self.ask_on_probe(now, peer, out);
        } else {
            self.retire(now, peer, PeerRetirementReason::NoNeededParts, out);
        }
    }
    /// Resume after the runner has verified-and-persisted (or failed to) the
    /// bytes of `part_index` that `peer` completed; `cells` is what the file
    /// held for each cell, read when the verdict needs it.
    pub(crate) fn on_persist_result(
        &mut self,
        now: Instant,
        part_index: PartIndex,
        peer: Option<PeerEndpoint>,
        result: Result<(), DownloadFailure>,
        cells: Option<Vec<CellHash>>,
    ) -> Vec<Decision> {
        let mut out = Vec::new();
        let mut assembled = self.pending_persist.remove(&part_index);
        if let (Some(assembled), Some(cells)) = (assembled.as_mut(), cells) {
            assembled.read_back(cells);
        }
        self.moved.insert(part_index);
        match result {
            Ok(()) => {
                self.scheduler.complete_verified(part_index);
                if let Some(assembled) = &assembled {
                    self.judge_failed_cells(now, part_index, assembled, &mut out);
                }
                // The verifier and the racers it beat hold no part now: each
                // granted one is handed its next or gives its slot back, and
                // a worker left holding nothing we need goes (ADR-0112 §6).
                let unworkable = self.assign_connected(&mut out);
                if self.scheduler.is_complete() {
                    out.push(Decision::Finalize);
                    self.settle_seed_dials(&mut out);
                }
                for (peer, reason) in unworkable {
                    self.retire(now, peer, reason, &mut out);
                }
            }
            Err(_) => {
                let Some(assembled) = assembled else {
                    return out;
                };
                // With a trusted AICH root and a peer stating it past its
                // clock, recover at block granularity (ADR-0038): ask it for
                // the part's recovery data and hold the corrupt buffer (with
                // its provenance) until `on_aich_answer`, the part still
                // verifying so none of its blocks is handed meanwhile. With
                // none, its refetch attributes it (ADR-0117 §1).
                let wire = u16::try_from(part_index.value());
                let asker = self
                    .aich_root
                    .trusted()
                    .filter(|_| wire.is_ok())
                    .and_then(|root| Some((root, self.recovery_asker(now, root, peer)?)));
                match (asker, wire) {
                    (Some((root, asker)), Ok(part)) => {
                        if let Some(place) = self.sources.dial_place(asker) {
                            self.standings.asked_recovery(&place.names, now);
                        }
                        self.awaiting_recovery
                            .insert(part_index, (asker, assembled));
                        out.push(Decision::Send {
                            peer: asker,
                            command: PeerWorkerCommand::RequestAich { part, root },
                        });
                    }
                    _ => self.refetch_rootless(now, part_index, &assembled, &mut out),
                }
            }
        }
        out
    }
    /// Merge a delivered block into its part's Arrived Ranges, send what is
    /// new to the file and settle the claims they now cover; when they cover
    /// the part, ask the runner to verify it (a `PersistPart` round-trip).
    /// The worker's row counts the bytes of the part it delivered (ADR-0117).
    fn on_block(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        part_index: PartIndex,
        offset: u64,
        bytes: Vec<u8>,
        out: &mut Vec<Decision>,
    ) {
        // Bytes flowing end the standing: the source is live, not queued.
        self.sources.end_standing(peer);
        let user_hash = self.sources.identity(peer).map(PeerIdentity::user_hash);
        if let Some(user_hash) = user_hash {
            out.push(Decision::RecordCredit {
                user_hash,
                at: peer.ip(),
                bytes: bytes.len() as u64,
            });
        }
        let delivered = if self.worker_slots.contains_key(&peer) {
            self.delivery
                .entry(peer)
                .or_default()
                .record(now, bytes.len() as u64);
            let row = self.delivered.entry(peer).or_insert((part_index, 0));
            if row.0 != part_index {
                *row = (part_index, 0);
            }
            row.1 += bytes.len() as u64;
            row.1
        } else {
            0
        };
        // A copy of a part already assembled or verified — a duplicate's, or a
        // block still draining — opens no buffer (ADR-0117).
        if self.pending_persist.contains_key(&part_index)
            || self.awaiting_recovery.contains_key(&part_index)
            || self.scheduler.is_part_verified(part_index)
        {
            return;
        }
        let part = crate::planning::part_plan(self.file_size, part_index);
        let assembled = self
            .assembly
            .entry(part_index)
            .or_insert_with(|| PartAssembly::new(part));
        let fresh = assembled.merge(peer, user_hash, offset, bytes.len() as u64);
        let complete = assembled.is_complete();
        if !fresh.is_empty() {
            self.moved.insert(part_index);
        }
        write_fresh(offset, bytes, &fresh, out);
        self.scheduler.settle(part_index, assembled.arrived());
        if let Some(slot) = self.worker_slots.get(&peer).copied() {
            out.push(Decision::Phase {
                slot,
                phase: WorkerPhase::ReceivingPart {
                    part_index: part_index.value(),
                    bytes_received: delivered,
                },
            });
        }
        if !complete {
            return;
        }
        if let Some(slot) = self.worker_slots.get(&peer).copied() {
            out.push(Decision::Phase {
                slot,
                phase: WorkerPhase::VerifyingPart {
                    part_index: part_index.value(),
                },
            });
        }
        self.check_part(part_index, Some(peer), out);
    }

    /// `part_index` is whole: the runner reads it back and verifies it. Its
    /// assembly stands aside with its writers until the result comes back, so
    /// a failure can repair or attribute it (ADR-0117 §1).
    fn check_part(
        &mut self,
        part_index: PartIndex,
        peer: Option<PeerEndpoint>,
        out: &mut Vec<Decision>,
    ) {
        let Some(assembled) = self.assembly.remove(&part_index) else {
            return;
        };
        let plan = crate::planning::part_plan(self.file_size, part_index);
        self.pending_persist.insert(part_index, assembled);
        self.scheduler.verifying(part_index);
        out.push(Decision::PersistPart {
            part_index,
            peer,
            offset: plan.offset,
            len: plan.len,
            read_cells: self.failed_cells.contains_key(&part_index),
        });
    }

    /// The parts a run starts with whole go to their check first: they stood
    /// on the lane or awaited a recovery answer as the last run ended
    /// (ADR-0117 §4).
    pub(super) fn check_whole_parts(&mut self, out: &mut Vec<Decision>) {
        let mut whole: Vec<PartIndex> = self
            .assembly
            .iter()
            .filter(|(_, assembled)| assembled.is_complete())
            .map(|(&part_index, _)| part_index)
            .collect();
        whole.sort_unstable();
        for part_index in whole {
            self.check_part(part_index, None, out);
        }
    }

    /// What of every in-flight part moved since the last call, for a
    /// checkpoint: a part with no bytes left says so.
    pub(crate) fn take_checkpoint(&mut self) -> Vec<ArrivedPart> {
        std::mem::take(&mut self.moved)
            .into_iter()
            .map(|part_index| {
                self.assembly
                    .get(&part_index)
                    .or_else(|| self.pending_persist.get(&part_index))
                    .or_else(|| {
                        self.awaiting_recovery
                            .get(&part_index)
                            .map(|(_, assembled)| assembled)
                    })
                    .map_or_else(|| ArrivedPart::none(part_index), PartAssembly::arrived_part)
            })
            .collect()
    }
    /// Adopt or reconcile a peer-supplied part hash set (ADR-0027). A set that
    /// is not the file's own — its MD4 is not the file hash, aMule's
    /// `LoadHashsetFromFile` rule — is refused and its sender retired and
    /// distrusted: the file hash proves it wrong, whatever authority is in
    /// force. A proven set is re-resolved against the link's own
    /// hashes, persisted when it becomes the provisional authority, and
    /// announced; one proven set can never contradict another.
    fn on_hash_set(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        part_hashes: &[PartHash],
        out: &mut Vec<Decision>,
    ) {
        if !hash_set_proves_file(self.file_hash, self.file_size, part_hashes) {
            self.distrust(peer, out);
            out.push(Decision::Emit(DownloadEvent::PeerRetired {
                download_id: self.download_id,
                peer,
                reason: PeerRetirementReason::VerificationAuthorityMismatch,
            }));
            self.release(
                now,
                peer,
                PeerRetirementReason::VerificationAuthorityMismatch,
                out,
            );
            return;
        }
        match resolve_hash_set_authority(self.link_part_hash_set.as_ref(), Some(part_hashes)) {
            Ok(resolved) => {
                self.resolved = resolved;
                if self.resolved.authority == VerificationAuthority::PeerHashSet {
                    out.push(Decision::PersistProvisionalHashes(
                        self.resolved.hashes.clone(),
                    ));
                }
                out.push(Decision::Emit(DownloadEvent::HashSetReceived {
                    download_id: self.download_id,
                    part_count: self.resolved.hashes.len(),
                    authority: self.resolved.authority,
                }));
                // The set is held: the one hash-set ask ends (ADR-0026).
                self.hash_set_held();
            }
            // A link hash set that disagrees with the peer's is unrecoverable.
            Err(failure) => out.push(Decision::Fail(failure)),
        }
    }
    /// The store dropped `parts`, verified before the part hash set arrived
    /// and disproved by it (ADR-0113): they are fetched again, handed to the
    /// next grants.
    pub(crate) fn refetch(&mut self, now: Instant, parts: &[PartIndex]) -> Vec<Decision> {
        let mut out = Vec::new();
        let plans = parts
            .iter()
            .map(|&part| crate::planning::part_plan(self.file_size, part));
        let repended = plans
            .filter(|&plan| self.scheduler.repend_verified(plan))
            .count();
        if repended > 0 {
            self.reassign_workers(now, &mut out);
        }
        out
    }
    /// `peer` is proven to have served this file bad data (ADR-0090
    /// invariant 4): the **Source Book** distrusts the User Hash its hello
    /// named, and a new distrust is persisted by the runner. *Proven* is the
    /// rule's whole weight — the AICH recovery pins corrupt blocks on their
    /// senders, a part's refetch proves a cell's sender (ADR-0117 §1), a hash
    /// set that is not the file's own convicts its sender — and a peer whose
    /// hello named no hash leaves nothing to key the distrust by.
    pub(super) fn distrust(&mut self, peer: PeerEndpoint, out: &mut Vec<Decision>) {
        if let Some(user_hash) = self.sources.distrust(peer) {
            Self::distrusted(peer, user_hash, out);
        }
    }

    /// [`Self::distrust`] by the User Hash `peer`'s hello named when it wrote,
    /// whether or not its worker is still live.
    pub(super) fn distrust_hash(
        &mut self,
        peer: PeerEndpoint,
        user_hash: UserHash,
        out: &mut Vec<Decision>,
    ) {
        if self.sources.distrust_hash(user_hash) {
            Self::distrusted(peer, user_hash, out);
        }
    }

    /// Say a new distrust of `peer` and hand it to the runner to persist.
    fn distrusted(peer: PeerEndpoint, user_hash: UserHash, out: &mut Vec<Decision>) {
        tracing::info!(%peer, "a peer that served bad data is distrusted for this download");
        out.push(Decision::DistrustPeer { user_hash });
    }
}
