//! Worker facts folded into the download's state: what a spawn failure, a
//! delivered block, a hash set, a persist result and a retirement each do to
//! the scheduler, the assembly, and the fleet. Every entry point returns the
//! ordered decisions the runner enacts — nothing here awaits.

use std::time::Instant;

use rmule_peer::PeerIdentity;
use rmule_primitives::{PartHash, PeerEndpoint};

use crate::DownloadFailure;
use crate::adapters::{PeerWorkerCommand, PeerWorkerEvent};
use crate::assembly::PartAssembly;
use crate::diagnostics::WorkerPhase;
use crate::hashing::{hash_set_proves_file, resolve_hash_set_authority};
use crate::service::{DownloadEvent, PeerRetirementReason, VerificationAuthority};

use super::{Decision, DownloadState};

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
    pub(crate) fn on_worker_event(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        event: PeerWorkerEvent,
    ) -> Vec<Decision> {
        let mut out = Vec::new();
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
                // No trusted AICH root yet (link carried no `h=`): ask this peer
                // for the file's master hash to feed the trusted-set vote
                // (ADR-0038). Once a root is committed we stop asking.
                if self.trusted_aich_root.is_none() {
                    out.push(Decision::Send {
                        peer,
                        command: PeerWorkerCommand::RequestAichFileHash,
                    });
                }
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
            PeerWorkerEvent::IdentityVerified {
                user_hash,
                public_key,
            } => {
                out.push(Decision::BindIdentity {
                    user_hash,
                    public_key,
                });
            }
            PeerWorkerEvent::BlockReceived {
                part_index,
                offset,
                bytes,
            } => self.on_block(now, peer, part_index, offset, &bytes, &mut out),
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
                out.push(Decision::Emit(DownloadEvent::LinkShared {
                    download_id: self.download_id,
                    peer,
                    turn,
                }));
            }
            PeerWorkerEvent::Disconnected => {
                self.release(now, peer, PeerRetirementReason::PeerDisconnected, &mut out);
            }
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
            PeerWorkerEvent::PartStreamed { .. } => {
                self.sources.end_standing(peer);
                // The worker delivered its whole assigned range. If a co-racer
                // already finished the part (it no longer holds one) give it the
                // next, or give its slot back; otherwise its completing block
                // reassigned it, so leave that assignment alone.
                if !self.scheduler.is_working(peer) {
                    self.assign(now, peer, &mut out);
                }
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
            } => self.on_aich_answer(now, u32::from(part), &recovery_data, &mut out),
            PeerWorkerEvent::AichFileHashReceived { root } => {
                self.on_aich_file_hash_proposal(peer, root);
            }
        }
        self.settle_seed_dials(&mut out);
        out
    }
    /// `peer`'s probe answered with parts: one holding nothing we lack is
    /// retired `NoNeededParts` (ADR-0112 §6); any other asks its slot, or
    /// the hash set first (ADR-0026).
    fn on_probe_answer(&mut self, now: Instant, peer: PeerEndpoint, out: &mut Vec<Decision>) {
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
    /// assembled bytes of `part_index` that `peer` completed.
    pub(crate) fn on_persist_result(
        &mut self,
        now: Instant,
        part_index: u32,
        peer: PeerEndpoint,
        result: Result<(), DownloadFailure>,
    ) -> Vec<Decision> {
        let mut out = Vec::new();
        let assembled = self.pending_persist.remove(&part_index);
        match result {
            Ok(()) => {
                self.scheduler.complete_verified(peer);
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
                // With a trusted AICH root and the completing peer still
                // connected, recover at block granularity (ADR-0038): ask that
                // peer for the part's recovery data and hold the corrupt buffer
                // (with its provenance) until `on_aich_answer`. Without a root,
                // fall back to ADR-0029's retire-all.
                match self.trusted_aich_root {
                    Some(root) if self.worker_slots.contains_key(&peer) => {
                        self.awaiting_recovery.insert(part_index, assembled);
                        out.push(Decision::Send {
                            peer,
                            command: PeerWorkerCommand::RequestAich {
                                part: part_index as u16,
                                root,
                            },
                        });
                    }
                    _ => self.retire_all_contributors(now, &assembled, &mut out),
                }
            }
        }
        out
    }
    /// ADR-0029 retire-all: retire every peer that contributed to the failed
    /// part attempt and let `release` return the part for a fresh refetch. Used
    /// when no trusted AICH root is available and as the AICH fallback. Sorted
    /// by slot so the decisions are deterministic.
    pub(super) fn retire_all_contributors(
        &mut self,
        now: Instant,
        assembled: &PartAssembly,
        out: &mut Vec<Decision>,
    ) {
        let mut contributors: Vec<(usize, PeerEndpoint)> = assembled
            .contributors()
            .iter()
            .filter_map(|c| self.worker_slots.get(c).map(|slot| (slot.as_usize(), *c)))
            .collect();
        contributors.sort_unstable_by_key(|&(slot, _)| slot);
        // A sole contributor is the proven sender of the bad bytes.
        if let [(_, sole)] = contributors[..] {
            self.distrust(sole, out);
        }
        for (_, contributor) in contributors {
            out.push(Decision::Emit(DownloadEvent::PeerRetired {
                download_id: self.download_id,
                peer: contributor,
                reason: PeerRetirementReason::PartVerificationFailed,
            }));
            self.release(
                now,
                contributor,
                PeerRetirementReason::PartVerificationFailed,
                out,
            );
        }
    }
    /// Merge a delivered block into its part's shared prefix; when the prefix
    /// reaches the part length, hand the assembled bytes to the runner to
    /// verify and persist (a `PersistPart` round-trip).
    fn on_block(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        part_index: u32,
        offset: u64,
        bytes: &[u8],
        out: &mut Vec<Decision>,
    ) {
        // Bytes flowing end the standing: the source is live, not queued.
        self.sources.end_standing(peer);
        if let Some(user_hash) = self.sources.identity(peer).map(PeerIdentity::user_hash) {
            out.push(Decision::RecordCredit {
                user_hash,
                bytes: bytes.len() as u64,
            });
        }
        if self.worker_slots.contains_key(&peer) {
            self.delivery
                .entry(peer)
                .or_default()
                .record(now, bytes.len() as u64);
        }
        // A race's loser still streaming a part another copy already
        // assembled: its bytes open no buffer (ADR-0026 "Bounded racing").
        if self.pending_persist.contains_key(&part_index)
            || self.awaiting_recovery.contains_key(&part_index)
            || self.scheduler.is_part_verified(part_index)
        {
            return;
        }
        let part = crate::planning::part_plan(self.file_size, part_index);
        let assembled = self.assembly.entry(part_index).or_default();
        assembled.merge_block(peer, offset.saturating_sub(part.offset), bytes);
        let prefix_len = assembled.prefix_len();
        let complete = assembled.is_complete(part.len);
        if let Some(slot) = self.worker_slots.get(&peer).copied() {
            out.push(Decision::Phase {
                slot,
                phase: WorkerPhase::ReceivingPart {
                    part_index,
                    bytes_received: prefix_len,
                },
            });
        }
        if !complete {
            return;
        }
        // The prefix is complete: hand the assembled bytes to the runner to
        // verify and persist. Hold the buffer (with its contributor set) until
        // the result comes back, so a failure can retire-all (ADR-0029).
        let assembled = self
            .assembly
            .remove(&part_index)
            .expect("a just-completed part has an assembly entry");
        if let Some(slot) = self.worker_slots.get(&peer).copied() {
            out.push(Decision::Phase {
                slot,
                phase: WorkerPhase::VerifyingPart { part_index },
            });
        }
        let bytes = assembled.bytes().to_vec();
        self.pending_persist.insert(part_index, assembled);
        out.push(Decision::PersistPart {
            part_index,
            peer,
            offset: part.offset,
            bytes,
        });
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
                // The set is held: the one hash-set ask ends, and a slot ask
                // waiting on it goes out (ADR-0026).
                self.hash_set_held(out);
            }
            // A link hash set that disagrees with the peer's is unrecoverable.
            Err(failure) => out.push(Decision::Fail(failure)),
        }
    }
    /// The store dropped `parts`, verified before the part hash set arrived
    /// and disproved by it (ADR-0113): they are fetched again, handed to the
    /// next grants.
    pub(crate) fn refetch(&mut self, now: Instant, parts: &[u32]) -> Vec<Decision> {
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
    /// senders, a part's sole contributor has nobody else to blame, a hash set
    /// that is not the file's own convicts its sender — and a peer whose hello
    /// named no hash leaves nothing to key the distrust by.
    pub(super) fn distrust(&mut self, peer: PeerEndpoint, out: &mut Vec<Decision>) {
        if let Some(user_hash) = self.sources.distrust(peer) {
            tracing::info!(%peer, "a peer that served bad data is distrusted for this download");
            out.push(Decision::DistrustPeer { user_hash });
        }
    }
}
