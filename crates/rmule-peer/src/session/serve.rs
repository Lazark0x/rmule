//! The **Server Capability**: the half of the connection that answers for
//! files this node shares (ADR-0031).
//!
//! Answers name, status and part requests, grants and releases the one
//! served slot, and sends blocks out of it. Who gets a slot, at what rank,
//! within what budget is core's decision across all connections; this leg
//! carries out the per-connection mechanics and reports inbound asks as
//! events.

use rmule_primitives::{Ed2kText, FileHash};

use super::{PeerError, PeerEvent, PeerSession};
use crate::ServerEvent;
use crate::file::PartBitmap;
use crate::file_request::{FileReqAnsNoFil, FileStatus, PartStatusTail, ReqFileNameAnswer};
use crate::parts::RequestParts as RequestPartsPacket;
use crate::parts::{CompressedPart, SendingPart};
use crate::slot::{AcceptUploadReq, QueueRanking};

impl PeerSession {
    pub(super) fn on_file_requested(&mut self, file_hash: FileHash, status: PartStatusTail) {
        self.core
            .push_event(PeerEvent::Server(ServerEvent::FileRequested {
                file_hash,
                status,
            }));
    }

    pub(super) fn on_file_id_set(&mut self, file_hash: FileHash) {
        self.core
            .push_event(PeerEvent::Server(ServerEvent::FileIdSet { file_hash }));
    }

    pub(super) fn on_hash_set_requested(&mut self, file_hash: FileHash) {
        self.core
            .push_event(PeerEvent::Server(ServerEvent::HashSetRequested {
                file_hash,
            }));
    }

    pub(super) fn on_slot_requested(&mut self, file_hash: FileHash) {
        self.core
            .push_event(PeerEvent::Server(ServerEvent::SlotRequested { file_hash }));
    }

    /// Server Capability — the remote peer canceled its held upload slot
    /// (`OP_CANCELTRANSFER`, ADR-0056). aMule's `RemoveFromUploadQueue`
    /// silently returns `false` for a peer holding no slot: a slotless
    /// cancel clears nothing and emits no event. A held slot clears
    /// `served_slot` here (so a late `SendBlock` for it is harmless) and
    /// surfaces `TransferCancelled` so core runs the release/promote batch;
    /// the connection itself is untouched.
    pub(super) fn on_cancel_transfer(&mut self) {
        let Some(file_hash) = self.served_slot else {
            return;
        };
        self.served_slot = None;
        self.core
            .push_event(PeerEvent::Server(ServerEvent::TransferCancelled {
                file_hash,
            }));
    }

    /// Server Capability — answer an inbound `RequestFileName` with the file's
    /// name, composing into a pending `OP_MULTIPACKETANSWER` (ADR-0054) instead
    /// of framing `OP_REQFILENAMEANSWER` standalone when this file's request
    /// arrived bundled.
    pub(super) fn answer_file_name(&mut self, file_hash: FileHash, file_name: Ed2kText) {
        if let Some(pending) = self.served_multipacket.get_mut(&file_hash) {
            pending.name = Some(file_name);
            self.try_flush_multipacket_answer(file_hash);
        } else {
            self.write_packet(
                ReqFileNameAnswer {
                    file_hash,
                    file_name,
                }
                .encode_packet(),
            );
        }
    }

    /// Server Capability — the file is not shared: aMule's semantics are
    /// mirrored exactly for a bundled request too (ADR-0054) — plain
    /// `OP_FILEREQANSNOFIL` and no `OP_MULTIPACKETANSWER` at all. Core answers
    /// a bundle once, for the bundle as a whole, so one not-found goes out
    /// however many asks it held (ADR-0055 §Name-ask surface).
    pub(super) fn answer_file_not_found(&mut self, file_hash: FileHash) {
        self.served_multipacket.remove(&file_hash);
        self.write_packet(FileReqAnsNoFil { file_hash }.encode_packet());
    }

    /// Server Capability — answer an inbound `SetReqFileId` with the file's
    /// part bitmap, composing into a pending `OP_MULTIPACKETANSWER` (ADR-0054)
    /// instead of framing `OP_FILESTATUS` standalone when bundled. A bitmap
    /// holding every part collapses to aMule's own writer shape first
    /// (`ClientTCPSocket.cpp` `OP_SETREQFILEID`, kno `ab483654`:
    /// `IsPartFile() ? WritePartStatus() : data.WriteUInt16(0)` — a
    /// fully-owned shared file is never a `CPartFile`, so it has no bitmap
    /// to spell out): the literal part-count-0 sentinel, not a real bitmap
    /// with every bit set. Both the standalone and the bundled writer share
    /// this one call site, so the collapse covers both.
    pub(super) fn answer_file_status(&mut self, file_hash: FileHash, bitmap: PartBitmap) {
        let bitmap = if bitmap.is_complete() {
            PartBitmap::complete_source_sentinel()
        } else {
            bitmap
        };
        if let Some(pending) = self.served_multipacket.get_mut(&file_hash) {
            pending.status = Some(bitmap);
            self.try_flush_multipacket_answer(file_hash);
        } else {
            self.write_packet(FileStatus { file_hash, bitmap }.encode_packet());
        }
    }

    /// Server Capability — core admitted this peer: the one served slot
    /// becomes `file_hash` and `OP_ACCEPTUPLOADREQ` invites its part requests.
    pub(super) fn grant_slot(&mut self, file_hash: FileHash) {
        if !self.require_identified() {
            return;
        }
        self.served_slot = Some(file_hash);
        self.write_packet(AcceptUploadReq.encode_packet());
    }

    /// Server Capability — the waiting peer's place in core's cross-connection
    /// queue (`OP_QUEUERANKING`). The ranking is core's; this only frames it,
    /// and only toward a peer that speaks the extended protocol, as aMule's
    /// `SendRankingInfo` (`UploadClient.cpp:724`).
    pub(super) fn set_queue_rank(&mut self, rank: u16) {
        if !self.require_identified() || !self.peer_software.ext_protocol() {
            return;
        }
        self.write_packet(QueueRanking { rank }.encode_packet());
    }

    pub(super) fn on_parts_requested(&mut self, req: RequestPartsPacket) {
        if self.served_slot == Some(req.file_hash) {
            self.core
                .push_event(PeerEvent::Server(ServerEvent::PartsRequested {
                    file_hash: req.file_hash,
                    ranges: req.ranges,
                }));
        } else {
            self.core
                .push_event(PeerEvent::Server(ServerEvent::PartsWithoutSlot {
                    file_hash: req.file_hash,
                }));
        }
    }

    /// Serve one block as aMule's uploader cuts it (ADR-0031): a run of
    /// `OP_SENDINGPART` of about 10 KiB, or — when the peer advertised
    /// compression and the zlib stream is smaller, as eMule does — a run of
    /// `OP_COMPRESSEDPART` sharing the block's start and the stream's length.
    /// A stock downloader restarts its download timeout only on a whole
    /// packet (`DownloadClient.cpp:848`), so one block-sized packet would
    /// starve a slow link. `bytes` is the block; its range is
    /// `start..start + bytes.len()`.
    pub(super) fn send_block(&mut self, file_hash: FileHash, start: u64, bytes: Vec<u8>) {
        if !self.require_identified() {
            return;
        }
        if self.served_slot != Some(file_hash) {
            self.reject(PeerError::ServeSlotNotGranted);
            return;
        }
        let peer_compresses = self
            .peer_misc_options
            .is_some_and(|m| m.data_compression_version() > 0);
        // `nBlockSize` is a u32: a stream it cannot name goes plain.
        let compressed = peer_compresses
            .then(|| crate::compress::deflate(&bytes))
            .filter(|c| c.len() < bytes.len() && u32::try_from(c.len()).is_ok());
        let end = start + bytes.len() as u64;
        match compressed {
            Some(stream) => {
                for frame in CompressedPart::block_frames(file_hash, start, end, &stream) {
                    self.core.push_write(frame.into());
                }
            }
            None => {
                for frame in SendingPart::block_frames(file_hash, start, &bytes) {
                    self.core.push_write(frame.into());
                }
            }
        }
    }
}
