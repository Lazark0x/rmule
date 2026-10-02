//! Worker facts folded into the download's state: what a spawn failure, a
//! delivered block, a hash set, a persist result and a retirement each do to
//! the scheduler, the assembly, and the fleet. Every entry point returns the
//! ordered decisions the runner enacts — nothing here awaits.

use rmule_primitives::{PartHash, PeerCrypt, PeerEndpoint};

use crate::DownloadFailure;
use crate::adapters::{PeerWorkerCommand, PeerWorkerEvent};
use crate::assembly::PartAssembly;
use crate::diagnostics::WorkerPhase;
use crate::dialable::resolve_family;
use crate::hashing::{hash_set_proves_file, resolve_hash_set_authority};
use crate::service::{DownloadEvent, PeerRetirementReason, VerificationAuthority};

use super::{Decision, DownloadState, LowIdCandidate};

impl DownloadState {
    /// Resume after the runner could not put a spawned candidate on the wire
    /// (its `start_peer_worker` failed). Free the claimed slot, drop the
    /// candidate, and try the next; a never-connected worker is not a
    /// retirement, so the retired count is unchanged (ADR-0030).
    pub(crate) fn on_spawn_failed(&mut self, peer: PeerEndpoint) -> Vec<Decision> {
        let mut out = Vec::new();
        if let Some(worker) = self.workers.remove(&peer) {
            self.free_slots.insert(worker.slot.as_usize());
            // A dial that could not even start is a failed dial: a rung-0
            // Low-ID candidate falls to its callback roads, and a
            // High-ID endpoint is spent and a dual-stack half falls to its
            // other family.
            self.on_dial_ended(peer, true);
        }
        self.fill(&mut out);
        if self.workers.is_empty()
            && self.pending_callbacks.is_empty()
            && self.no_usable_candidate()
            && !self.scheduler.is_complete()
        {
            out.push(Decision::Fail(DownloadFailure::NoUsableSources));
        }
        self.settle_seed_dials(&mut out);
        out
    }
    /// Drive one worker event to its scheduling decisions.
    pub(crate) fn on_worker_event(
        &mut self,
        peer: PeerEndpoint,
        event: PeerWorkerEvent,
    ) -> Vec<Decision> {
        let mut out = Vec::new();
        self.note_seed_fact(peer, &event);
        match event {
            PeerWorkerEvent::Connected => {
                if let Some(worker) = self.workers.get_mut(&peer) {
                    worker.connected = true;
                }
                self.assign(peer, &mut out);
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
            PeerWorkerEvent::Identified {
                user_hash,
                crypt,
                software,
            } => {
                if let Some(slot) = self.workers.get(&peer).map(|w| w.slot) {
                    out.push(Decision::Identify { slot, software });
                }
                self.on_hello_hash(peer, user_hash, &mut out);
                // The peer's own hello outranks its record at every later dial
                // (ADR-0049) — an adopted inbound worker's own
                // identity carries its hello stance through adoption too
                // So it seeds `hello_crypts` exactly as a
                // dialed worker's hello does.
                if let Some(stance) = crypt {
                    self.hello_crypts
                        .insert(peer, PeerCrypt::new(stance, Some(user_hash)));
                }
            }
            PeerWorkerEvent::ServingBuddy { buddy_udp } => self.on_hello_buddy(peer, buddy_udp),
            PeerWorkerEvent::UdpContact { .. }
            | PeerWorkerEvent::SourceExchange { .. }
            | PeerWorkerEvent::SourcesAsked
            | PeerWorkerEvent::PartsAdvertised { .. } => {
                // The peer's client-UDP reask contact (ADR-0057), its
                // source-exchange facts and the source ask going out
                // (ADR-0108) are runner-owned plumbing, not scheduling inputs —
                // the runner observes them off the same event stream to pool a
                // queued-then-hung-up source and to keep its Source Ask Clock.
                // The brain ignores them.
            }
            PeerWorkerEvent::SoftwareRevised { software } => {
                if let Some(slot) = self.workers.get(&peer).map(|w| w.slot) {
                    out.push(Decision::Identify { slot, software });
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
            } => self.on_block(peer, part_index, offset, &bytes, &mut out),
            // Why the dial ended before the hello; the terminal fact that
            // follows releases the worker.
            PeerWorkerEvent::DialEnded { cause } => {
                out.push(Decision::Emit(DownloadEvent::DialEnded {
                    download_id: self.download_id,
                    peer,
                    cause,
                }));
            }
            PeerWorkerEvent::Disconnected => {
                self.release(peer, PeerRetirementReason::PeerDisconnected, &mut out);
            }
            PeerWorkerEvent::CryptIncompatible => {
                // The dial was refused before any socket. aMule
                // deletes the client outright (`CheckContactPreconditions`,
                // `BaseClient.cpp` 1913-1917 at the Fork Pin): every road to
                // this source — a rung-0 candidate's callback roads included —
                // meets the same two stances, so its candidate is dropped here
                // rather than handed back to those roads — and a dual-stack
                // source's other family, which meets the same two stances, is
                // no family failure to retry.
                self.direct_ipv6_dials.remove(&peer);
                self.dual_stack_fallbacks.remove(&peer);
                self.release(peer, PeerRetirementReason::CryptIncompatible, &mut out);
            }
            PeerWorkerEvent::SlotRejected => {
                self.release(peer, PeerRetirementReason::SlotRejected, &mut out);
            }
            PeerWorkerEvent::SlotTimeout => {
                out.push(Decision::Emit(DownloadEvent::PeerSlotTimeout {
                    download_id: self.download_id,
                    peer,
                }));
                self.release(peer, PeerRetirementReason::SlotTimeout, &mut out);
            }
            PeerWorkerEvent::Queued { rank } => {
                out.push(Decision::Emit(DownloadEvent::PeerQueued {
                    download_id: self.download_id,
                    peer,
                    rank,
                }));
            }
            PeerWorkerEvent::SlotGranted => {
                out.push(Decision::Emit(DownloadEvent::PeerSlotGranted {
                    download_id: self.download_id,
                    peer,
                }));
            }
            PeerWorkerEvent::PartStreamed { .. } => {
                // The worker delivered its whole assigned range. If a co-racer
                // already finished the part (it no longer holds one) give it the
                // next; otherwise its completing block reassigned it, so leave
                // that assignment alone.
                if !self.scheduler.is_working(peer) {
                    self.assign(peer, &mut out);
                }
            }
            PeerWorkerEvent::HashSetReceived { part_hashes } => {
                self.on_hash_set(peer, &part_hashes, &mut out);
            }
            PeerWorkerEvent::SourcesReceived { sources } => {
                // ADR-0055: peer-exchanged sources refill the candidate pool,
                // superseding ADR-0026's single snapshot. Add the High-ID
                // sources not already known (a live worker or already pooled),
                // and queue the Low-ID ones for whichever road the admission
                // rule leaves open (ADR-0039 / ADR-0091); then fill any free
                // slots.
                for source in sources {
                    // A dual-stack record is dialed first in the family the
                    // Dial Chooser picks, its other half kept (ADR-0087).
                    if let Some(order) = resolve_family(source, self.dial) {
                        // Remember the crypt side the record stated (ADR-0042,
                        // ADR-0049) at both halves; the runner reads it at spawn.
                        for half in order.halves() {
                            self.note_peer_crypt(half, source.peer_crypt());
                        }
                        self.pool_high_id(order, source.peer_crypt().user_hash());
                    } else if let Some(candidate) = LowIdCandidate::from_source(source, None) {
                        // A peer-exchanged Low-ID source is on the connected
                        // server, so its record is minted in that namespace
                        // (`source_server: None`) — which is also what lets the
                        // server introduce us to it when we cannot be called
                        // back (ADR-0091 rung 1). A v≥2 answer carried the
                        // target's User Hash (ADR-0042), the one rung-1 fact
                        // this channel names.
                        self.admit_low_id(candidate);
                    }
                }
                self.fill(&mut out);
            }
            PeerWorkerEvent::AichAnswerReceived {
                part,
                recovery_data,
            } => self.on_aich_answer(u32::from(part), &recovery_data, &mut out),
            PeerWorkerEvent::AichFileHashReceived { root } => {
                self.on_aich_file_hash_proposal(peer, root);
            }
        }
        self.settle_seed_dials(&mut out);
        out
    }
    /// Resume after the runner has verified-and-persisted (or failed to) the
    /// assembled bytes of `part_index` that `peer` completed.
    pub(crate) fn on_persist_result(
        &mut self,
        part_index: u32,
        peer: PeerEndpoint,
        result: Result<(), DownloadFailure>,
    ) -> Vec<Decision> {
        let mut out = Vec::new();
        let assembled = self.pending_persist.remove(&part_index);
        match result {
            Ok(()) => {
                self.scheduler.complete_verified(peer);
                self.assign(peer, &mut out);
                if self.scheduler.is_complete() {
                    out.push(Decision::Finalize);
                    self.settle_seed_dials(&mut out);
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
                    Some(root) if self.workers.contains_key(&peer) => {
                        self.awaiting_recovery.insert(part_index, assembled);
                        out.push(Decision::Send {
                            peer,
                            command: PeerWorkerCommand::RequestAich {
                                part: part_index as u16,
                                root,
                            },
                        });
                    }
                    _ => self.retire_all_contributors(&assembled, &mut out),
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
        assembled: &PartAssembly,
        out: &mut Vec<Decision>,
    ) {
        let mut contributors: Vec<(usize, PeerEndpoint)> = assembled
            .contributors()
            .iter()
            .filter_map(|c| self.workers.get(c).map(|w| (w.slot.as_usize(), *c)))
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
        peer: PeerEndpoint,
        part_index: u32,
        offset: u64,
        bytes: &[u8],
        out: &mut Vec<Decision>,
    ) {
        if let Some(&user_hash) = self.peer_user_hashes.get(&peer) {
            out.push(Decision::RecordCredit {
                user_hash,
                bytes: bytes.len() as u64,
            });
        }
        let part = crate::planning::part_plan(self.file_size, part_index);
        let assembled = self.assembly.entry(part_index).or_default();
        assembled.merge_block(peer, offset.saturating_sub(part.offset), bytes);
        let prefix_len = assembled.prefix_len();
        let complete = assembled.is_complete(part.len);
        if let Some(slot) = self.workers.get(&peer).map(|w| w.slot) {
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
        if let Some(slot) = self.workers.get(&peer).map(|w| w.slot) {
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
            }
            // A link hash set that disagrees with the peer's is unrecoverable.
            Err(failure) => out.push(Decision::Fail(failure)),
        }
    }
}
