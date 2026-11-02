//! Serving file data out: which reads a granted flow's block request
//! decides — none for a request with a range past the file's end, longer than
//! three blocks, or outside a Partial Share's **Verified Range**, which ends
//! the slot (ADR-0031, ADR-0113 §"Reading a part file") — what a completed
//! block read becomes for the flow
//! that asked, and what a failed or refused read does: the file stops being
//! offered at once.

use rmule_peer::{MAX_REQUESTED_RANGE, PartRanges, PeerIdentity, ServerCommand};
use rmule_primitives::{FileHash, PeerEndpoint};

use std::time::Instant;

use super::connection::{record_served_range, subtract_served_ranges};
use super::served::Found;
use super::{BlockRead, ServeDecision, ServeState, rank_updates};
use crate::served_downloads::{PartFileIdentity, PartialEnd, ReadTarget};
use crate::service::{BlockAskFault, ServeEvent};
use crate::upload_queue::ScoreModifiers;
use crate::upload_queue::WaiterLeaveCause;

impl ServeState {
    /// A granted flow's block request, judged whole before anything is read
    /// (ADR-0031): a range whose end is not past its start is skipped alone;
    /// one live range past the file's end or longer than three
    /// blocks, as asked, or — a Partial Share's — one sub-range left after the
    /// ranges already served outside its **Verified Range** (ADR-0113
    /// §"Reading a part file") ends the peer's slot with nothing of the request
    /// read or sent ([`Self::refuse_block_ask`]). Otherwise every such
    /// sub-range joins the peer's **Serve Flow**, to be read in turn — a row's
    /// from its path, a Partial Share's from the path holding its bytes then,
    /// checked against its Part File Identity then. A peer holding no slot is read
    /// nothing, as aMule drops its block request
    /// (`UploadClient.cpp:497-500`). An ask the flow has no room for is
    /// dropped whole and not recorded as served, as if it had not come.
    pub(super) fn on_parts_requested(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        file_hash: FileHash,
        ranges: &PartRanges,
        modifiers: &dyn ScoreModifiers,
    ) -> Vec<ServeDecision> {
        if !self.queue.is_granted(peer) {
            return Vec::new();
        }
        self.last_ask.insert(peer, (file_hash, *ranges));
        let Some(found) = self.lookup_for(peer, file_hash).filter(Found::offered) else {
            return Vec::new();
        };
        // Only the live ranges are judged: padding and a backward pair are
        // skipped alone, wherever they point (`UploadClient.cpp:871-882`).
        let asked: Vec<(u64, u64)> = ranges.live().collect();
        let file_size = found.file_size();
        if let Some(fault) = asked
            .iter()
            .find_map(|&(start, end)| range_fault(file_size, start, end))
        {
            return self.refuse_block_ask(now, peer, file_hash, fault, modifiers);
        }
        let range = match found {
            Found::Row(_) => None,
            Found::Download { look, .. } => Some(&look.served.range),
        };
        let mut served = self
            .served_ranges
            .get(&(peer, file_hash))
            .cloned()
            .unwrap_or_default();
        let mut reads = Vec::new();
        for (start, end) in asked {
            for (send_start, send_end) in subtract_served_ranges(start, end, &served) {
                record_served_range(&mut served, send_start, send_end);
                reads.push((send_start, send_end));
            }
        }
        // A Partial Share's guard reads the unserved rest only (ADR-0113).
        if range.is_some_and(|range| !reads.iter().all(|&(s, e)| range.covers(s, e))) {
            let fault = BlockAskFault::Unverified;
            return self.refuse_block_ask(now, peer, file_hash, fault, modifiers);
        }
        if !self.flow_has_room(peer, reads.len()) {
            return Vec::new();
        }
        // Recorded at decision time, not on the read result: a repeat
        // request must not double-send a range whose read is still in
        // flight, and a failed read ends the file's offer (its holders'
        // ranges go with their slots), so nothing is stranded.
        self.served_ranges.insert((peer, file_hash), served);
        let asked = reads.into_iter().map(|(start, end)| BlockRead {
            file_hash,
            start,
            end,
        });
        self.ask_flow(now, peer, asked).into_iter().collect()
    }

    /// End `peer`'s slot for its block request's `fault`, before anything of
    /// it is read: the refusal is told, its flow's ranges go, the slot is
    /// released and the next waiter promoted. Nothing is sent to it, its link
    /// stays and its address is not banned, as aMule's handler only takes the
    /// client out of the upload queue (`UploadClient.cpp:270-281`).
    fn refuse_block_ask(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        file_hash: FileHash,
        fault: BlockAskFault,
        modifiers: &dyn ScoreModifiers,
    ) -> Vec<ServeDecision> {
        self.served_ranges
            .retain(|(range_peer, _), _| *range_peer != peer);
        let promotion = self.leave_queue(peer, now, modifiers);
        let mut decisions = vec![
            ServeDecision::Emit(ServeEvent::BlockAskRefused {
                peer,
                file_hash,
                fault,
            }),
            ServeDecision::Emit(ServeEvent::UploadSlotReleased { peer }),
        ];
        decisions.extend(self.promotion_decisions(promotion));
        decisions
    }

    /// A [`ServeDecision::ReadRange`] came back with its bytes — the read-side
    /// twin of `DownloadState::on_persist_result`.
    ///
    /// A read lands after the state it was asked under may have moved on: a
    /// read of an ended flow is for nobody, a file no longer offered sends
    /// nothing, and a block goes only to a peer still holding a slot, as aMule
    /// drops a block ask from a client it is not uploading to
    /// (`UploadClient.cpp:497-500`). A block goes to be deflated unless it is
    /// an archive's (`Found::compressible`) or its peer does not inflate
    /// (ADR-0031). It is credited and counted once it has left.
    pub(crate) fn on_read_result(
        &mut self,
        peer: PeerEndpoint,
        flow: u64,
        block: BlockRead,
        bytes: Vec<u8>,
    ) -> Vec<ServeDecision> {
        if !self.read_ended(peer, flow) {
            return Vec::new();
        }
        let file_hash = block.file_hash;
        if !self.in_share_set(file_hash) || !self.queue.is_granted(peer) {
            return self.read_on(peer).into_iter().collect();
        }
        let compressible = self
            .lookup(file_hash)
            .is_some_and(|found| found.compressible());
        let inflates = self
            .identities
            .get(&peer)
            .is_some_and(PeerIdentity::inflates_parts);
        let send = ServeDecision::SendBlock {
            peer,
            flow,
            block,
            bytes,
            deflate: compressible && inflates,
        };
        std::iter::once(send)
            .chain(self.block_ahead(peer))
            .collect()
    }

    /// A read of a shared file's block failed: what is
    /// offered must be readable now, so the file stops being served at once
    /// ([`stop_serving`](Self::stop_serving)), the peer that asked is told
    /// `OP_FILEREQANSNOFIL`, and the **Registry Check** looks at the row
    /// (ADR-0106, "The registry against the disk"). The connection stays.
    pub(crate) fn on_read_failed(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        flow: u64,
        file_hash: FileHash,
        modifiers: &dyn ScoreModifiers,
    ) -> Vec<ServeDecision> {
        self.read_ended(peer, flow);
        let mut decisions = self.stop_and_tell(now, peer, file_hash, modifiers);
        decisions.push(ServeDecision::ReadFailed(file_hash));
        decisions
    }

    /// A checked read of a Partial Share found neither of its paths
    /// readable: it stops being served at once and its range empties
    /// (ADR-0113), unless its bytes moved first. It has no row, so the
    /// Registry Check is not told.
    pub(crate) fn on_part_file_unreadable(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        flow: u64,
        read: (BlockRead, Option<ReadTarget>),
        modifiers: &dyn ScoreModifiers,
    ) -> Vec<ServeDecision> {
        self.on_read_refused(now, peer, flow, read, PartialEnd::Unreadable, modifiers)
    }

    /// A checked read of a Partial Share found the file not the one its
    /// Verified Range was read from, or could not tell: nothing of it is
    /// sent, it stops being served at once, and its range empties until the
    /// download's holder reads the file again (ADR-0113), unless its bytes
    /// moved first.
    pub(crate) fn on_part_file_changed(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        flow: u64,
        read: (BlockRead, Option<ReadTarget>),
        modifiers: &dyn ScoreModifiers,
    ) -> Vec<ServeDecision> {
        self.on_read_refused(now, peer, flow, read, PartialEnd::Changed, modifiers)
    }

    /// A checked read, aimed at `target`, came to nothing. Against an entry
    /// that moved since, it found the move and not a fault of the file: its
    /// block is aimed again and nobody hears that the file left (ADR-0113).
    /// Against the entry as it stands, it found a fault: `cause`.
    fn on_read_refused(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        flow: u64,
        (block, target): (BlockRead, Option<ReadTarget>),
        cause: PartialEnd,
        modifiers: &dyn ScoreModifiers,
    ) -> Vec<ServeDecision> {
        let flow_lives = self.read_ended(peer, flow);
        if self.moved_since(block.file_hash, target.as_ref()) {
            if !flow_lives {
                return Vec::new();
            }
            return self.read_again(peer, block).into_iter().collect();
        }
        let checked = target.and_then(|target| target.identity);
        self.withdraw_partial(now, peer, (block.file_hash, checked), cause, modifiers)
    }

    /// Stop serving the Partial Share of `file_hash`, telling the peer whose
    /// read found it so, and empty its range in the cell for `cause`: the
    /// range as the read was `checked` against it, which the entry may have
    /// moved on from while the read was out.
    fn withdraw_partial(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        (file_hash, checked): (FileHash, Option<PartFileIdentity>),
        cause: PartialEnd,
        modifiers: &dyn ScoreModifiers,
    ) -> Vec<ServeDecision> {
        let mut decisions = self.stop_and_tell(now, peer, file_hash, modifiers);
        decisions.push(ServeDecision::EmptyRange {
            file_hash,
            checked,
            cause,
        });
        decisions
    }

    /// [`stop_serving`](Self::stop_serving), and `OP_FILEREQANSNOFIL` to
    /// `peer` too when it was not among the file's waiters and holders.
    fn stop_and_tell(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        file_hash: FileHash,
        modifiers: &dyn ScoreModifiers,
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
        modifiers: &dyn ScoreModifiers,
    ) -> Vec<ServeDecision> {
        self.shared.remove(&file_hash);
        self.partials.remove(&file_hash);
        let (holders, waiters): (Vec<PeerEndpoint>, Vec<PeerEndpoint>) = self
            .queue
            .engaged_peers(file_hash)
            .into_iter()
            .partition(|peer| self.queue.is_granted(*peer));
        let mut decisions = Vec::new();
        if self.aich.leave(file_hash) {
            decisions.push(ServeDecision::StopAichBuild);
        }
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
            note_moves(self.leave_queue(peer, now, modifiers).reranked);
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
            let mut promotion = self.leave_queue(peer, now, modifiers);
            note_moves(std::mem::take(&mut promotion.reranked));
            decisions.extend(self.promotion_decisions(promotion));
        }
        moved.retain(|(waiter, _)| self.queue.waiting_file(*waiter).is_some());
        decisions.extend(rank_updates(&self.queue, &self.identities, moved));
        decisions
    }
}

/// What ends the slot of a peer asking `start..end` of a `file_size`-byte
/// file, judged as asked in aMule's order (ADR-0031): past the file's end
/// (`UploadClient.cpp:211-213`), then longer than three blocks (`:221-224`).
const fn range_fault(file_size: u64, start: u64, end: u64) -> Option<BlockAskFault> {
    if end > file_size {
        Some(BlockAskFault::PastEnd)
    } else if end - start > MAX_REQUESTED_RANGE {
        Some(BlockAskFault::TooLong)
    } else {
        None
    }
}

pub(super) fn not_found(peer: PeerEndpoint, file_hash: FileHash) -> ServeDecision {
    ServeDecision::Send {
        peer,
        command: ServerCommand::AnswerFileNotFound { file_hash },
    }
}
