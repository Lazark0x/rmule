//! Serving file data out: which reads a granted flow's block request
//! decides — inside a Partial Share's **Verified Range** only (ADR-0113
//! §"Reading a part file") — what a completed block read becomes for the flow
//! that asked, the AICH recovery answer built from the cached hash tree
//! (ADR-0038) — the one read purpose whose result is a hash set, not a block —
//! and what a failed or refused read does: the file stops being offered at
//! once.

use rmule_peer::{PartRanges, ServerCommand};
use rmule_primitives::{AichHashSet, ED2K_PART_SIZE, FileHash, PeerEndpoint};

use std::collections::HashMap;
use std::time::Instant;

use super::connection::{record_served_range, subtract_served_ranges};
use super::served::Found;
use super::{ReadPurpose, ServeDecision, ServeState, rank_updates};
use crate::served_downloads::PartialEnd;
use crate::service::ServeEvent;
use crate::upload_queue::WaiterLeaveCause;

impl ServeState {
    /// A granted flow's block request: every sub-range left after the ranges
    /// already served is read — a row's from its path, a Partial Share's
    /// from the path holding its bytes, checked against its Part File
    /// Identity. One sub-range of a Partial Share outside its Verified Range
    /// ends the peer's slot with nothing read and nothing sent, the link
    /// kept: aMule throws on an incomplete block and its handler only takes
    /// the client out of the upload queue (`UploadClient.cpp:227-231`,
    /// `:270-282`, `UploadQueue.cpp:522-546`). A peer holding no slot is read
    /// nothing, as aMule drops its block request (`UploadClient.cpp:497-500`).
    pub(super) fn on_parts_requested(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        file_hash: FileHash,
        ranges: &PartRanges,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        if !self.queue.is_granted(peer) {
            return Vec::new();
        }
        let (path, check, range) = match self.lookup(file_hash).filter(Found::offered) {
            None => return Vec::new(),
            Some(Found::Row(entry)) => (entry.path.clone(), None, None),
            Some(Found::Download { look, .. }) => {
                let (path, check) = look.served.read_target();
                (path, Some(check), Some(look.served.range.clone()))
            }
        };
        let mut served = self
            .served_ranges
            .get(&(peer, file_hash))
            .cloned()
            .unwrap_or_default();
        let mut reads = Vec::new();
        // `PartRanges::as_array()` yields the fixed `[(u64,u64); 3]`; the
        // `(0,0)` padding slots are skipped by the `e > s` filter.
        for &(start, end) in ranges.as_array().iter().filter(|(s, e)| e > s) {
            for (send_start, send_end) in subtract_served_ranges(start, end, &served) {
                record_served_range(&mut served, send_start, send_end);
                reads.push((send_start, send_end));
            }
        }
        if range.is_some_and(|range| !reads.iter().all(|&(s, e)| range.covers(s, e))) {
            return self.end_slot(now, peer, modifiers);
        }
        // Recorded at decision time, not on the read result: a repeat
        // request must not double-send a range whose read is still in
        // flight, and a failed read ends the file's offer (its holders'
        // ranges go with their slots), so nothing is stranded.
        self.served_ranges.insert((peer, file_hash), served);
        reads
            .into_iter()
            .map(|(start, end)| ServeDecision::ReadRange {
                peer,
                path: path.clone(),
                offset: start,
                len: end - start,
                purpose: ReadPurpose::Block {
                    file_hash,
                    start,
                    end,
                },
                check: check.clone(),
            })
            .collect()
    }

    /// End `peer`'s slot and nothing else: its flow's ranges go, the slot
    /// is released and the next waiter promoted; nothing is sent to it, and
    /// its link stays.
    fn end_slot(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        self.served_ranges
            .retain(|(range_peer, _), _| *range_peer != peer);
        let promotion = self.queue.release(peer, now, modifiers);
        let mut decisions = vec![ServeDecision::Emit(ServeEvent::UploadSlotReleased { peer })];
        decisions.extend(self.promotion_decisions(promotion));
        decisions
    }

    /// Resume a [`ServeDecision::ReadRange`] round trip that read its bytes —
    /// the read-side twin of `DownloadState::on_persist_result`.
    ///
    /// A read lands after the state it was asked under may have moved on: a
    /// file no longer offered answers nothing and caches nothing, and a block
    /// goes only to a peer still holding a slot, as aMule drops a block ask
    /// from a client it is not uploading to (`UploadClient.cpp:497-500`).
    pub(crate) fn on_read_result(
        &mut self,
        peer: PeerEndpoint,
        purpose: ReadPurpose,
        bytes: Vec<u8>,
    ) -> Vec<ServeDecision> {
        let file_hash = purpose.file_hash();
        if !self.in_share_set(file_hash) {
            return Vec::new();
        }
        match purpose {
            ReadPurpose::Block {
                file_hash,
                start,
                end,
            } => {
                if !self.queue.is_granted(peer) {
                    return Vec::new();
                }
                let mut decisions = Vec::new();
                if let Some(identity) = self.identities.get(&peer) {
                    decisions.push(ServeDecision::RecordCredit {
                        user_hash: identity.user_hash(),
                        bytes: bytes.len() as u64,
                    });
                }
                decisions.push(ServeDecision::Send {
                    peer,
                    command: ServerCommand::SendBlock {
                        file_hash,
                        start,
                        end,
                        bytes,
                    },
                });
                decisions
            }
            ReadPurpose::AichRecovery { file_hash, part } => {
                let tree = self
                    .aich_cache
                    .entry(file_hash)
                    .or_insert_with(|| AichHashSet::from_bytes(&bytes));
                answer_aich_recovery(peer, file_hash, part, tree)
            }
            ReadPurpose::AichMasterRoot { file_hash } => {
                let root = self
                    .aich_cache
                    .entry(file_hash)
                    .or_insert_with(|| AichHashSet::from_bytes(&bytes))
                    .master_root();
                vec![ServeDecision::Send {
                    peer,
                    command: ServerCommand::AnswerAichFileHash { root },
                }]
            }
        }
    }

    /// A read of a shared file failed, a block's or an AICH build's: what is
    /// offered must be readable now, so the file stops being served at once
    /// ([`stop_serving`](Self::stop_serving)), the peer that asked is told
    /// `OP_FILEREQANSNOFIL`, and the **Registry Check** looks at the row
    /// (ADR-0106, "The registry against the disk"). The connection stays.
    pub(crate) fn on_read_failed(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        purpose: ReadPurpose,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        let file_hash = purpose.file_hash();
        let mut decisions = self.stop_and_tell(now, peer, file_hash, modifiers);
        decisions.push(ServeDecision::ReadFailed(file_hash));
        decisions
    }

    /// A checked read of a Partial Share found neither of its paths
    /// readable: it stops being served at once and its range empties
    /// (ADR-0113). It has no row, so the Registry Check is not told.
    pub(crate) fn on_part_file_unreadable(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        purpose: ReadPurpose,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        self.withdraw_partial(
            now,
            peer,
            purpose.file_hash(),
            PartialEnd::Unreadable,
            modifiers,
        )
    }

    /// A checked read of a Partial Share found the file not the one its
    /// Verified Range was read from, or could not tell: nothing of it is
    /// sent, it stops being served at once, and its range empties until the
    /// download's holder reads the file again (ADR-0113).
    pub(crate) fn on_part_file_changed(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        purpose: ReadPurpose,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        self.withdraw_partial(
            now,
            peer,
            purpose.file_hash(),
            PartialEnd::Changed,
            modifiers,
        )
    }

    /// Stop serving the Partial Share of `file_hash`, telling the peer whose
    /// read found it so, and empty its range in the cell for `cause` — the
    /// range as the read was checked against it, which is this brain's copy:
    /// a read lands within the batch that decided it.
    fn withdraw_partial(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        file_hash: FileHash,
        cause: PartialEnd,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        let checked = self.served.get(&file_hash).map(|look| look.served.identity);
        let mut decisions = self.stop_and_tell(now, peer, file_hash, modifiers);
        if let Some(checked) = checked {
            decisions.push(ServeDecision::EmptyRange {
                file_hash,
                checked,
                cause,
            });
        }
        decisions
    }

    /// [`stop_serving`](Self::stop_serving), and `OP_FILEREQANSNOFIL` to
    /// `peer` too when it was not among the file's waiters and holders.
    fn stop_and_tell(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        file_hash: FileHash,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        let told = self.queue.engaged_peers(file_hash).contains(&peer);
        let mut decisions = self.stop_serving(file_hash, now, modifiers);
        if !told {
            decisions.push(not_found(peer, file_hash));
        }
        decisions
    }

    /// Stop serving `file_hash` now: it leaves the share set, and every peer
    /// queued or holding a slot for it is told `OP_FILEREQANSNOFIL` and
    /// released, waiters first so a freed slot never goes to another asker
    /// of the same file. A downloader that hears it records us as a dead
    /// source for the file (aMule `ClientTCPSocket.cpp:503-507`).
    pub(super) fn stop_serving(
        &mut self,
        file_hash: FileHash,
        now: Instant,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        self.shared.remove(&file_hash);
        self.partials.remove(&file_hash);
        self.aich_cache.remove(&file_hash);
        let (holders, waiters): (Vec<PeerEndpoint>, Vec<PeerEndpoint>) = self
            .queue
            .engaged_peers(file_hash)
            .into_iter()
            .partition(|peer| self.queue.is_granted(*peer));
        let mut decisions = Vec::new();
        // Every release reports the ranks it moved. They are told once, after
        // the last release: a later report supersedes an earlier one for the
        // same waiter, and a waiter that left or took a slot meanwhile is told
        // no rank.
        let mut moved: Vec<(PeerEndpoint, u16)> = Vec::new();
        let mut note_moves = |reranked: Vec<(PeerEndpoint, u16)>| {
            for (waiter, rank) in reranked {
                moved.retain(|(earlier, _)| *earlier != waiter);
                moved.push((waiter, rank));
            }
        };
        for peer in waiters {
            note_moves(self.queue.release(peer, now, modifiers).reranked);
            decisions.push(not_found(peer, file_hash));
            decisions.push(ServeDecision::Emit(ServeEvent::WaiterLeft {
                peer,
                cause: WaiterLeaveCause::Purged,
            }));
        }
        for peer in holders {
            self.served_ranges
                .retain(|(range_peer, _), _| *range_peer != peer);
            decisions.push(not_found(peer, file_hash));
            decisions.push(ServeDecision::Emit(ServeEvent::UploadSlotReleased { peer }));
            let mut promotion = self.queue.release(peer, now, modifiers);
            note_moves(std::mem::take(&mut promotion.reranked));
            decisions.extend(self.promotion_decisions(promotion));
        }
        moved.retain(|(waiter, _)| self.queue.waiting_file(*waiter).is_some());
        decisions.extend(rank_updates(&self.queue, &self.identities, moved));
        decisions
    }
}

fn not_found(peer: PeerEndpoint, file_hash: FileHash) -> ServeDecision {
    ServeDecision::Send {
        peer,
        command: ServerCommand::AnswerFileNotFound { file_hash },
    }
}

/// The requested part's recovery data from a built tree, or nothing when the
/// part offset falls outside the file (the request is dropped; the requester's
/// own timeout handles it).
pub(super) fn answer_aich_recovery(
    peer: PeerEndpoint,
    file_hash: FileHash,
    part: u16,
    tree: &AichHashSet,
) -> Vec<ServeDecision> {
    let part_start = u64::from(part) * ED2K_PART_SIZE;
    tree.create_part_recovery_data(part_start)
        .map(|recovery_data| {
            vec![ServeDecision::Send {
                peer,
                command: ServerCommand::AnswerAich {
                    file_hash,
                    part,
                    root: tree.master_root(),
                    recovery_data,
                },
            }]
        })
        .unwrap_or_default()
}
