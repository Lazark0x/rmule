//! The **Requester Capability**: the half of the connection that chases
//! parts (ADR-0031).
//!
//! Probes a file, asks for its name, status and hash set, claims the one
//! in-flight slot per connection (ADR-0025), and reassembles the blocks —
//! plain and compressed — the peer sends back.

use std::collections::HashMap;

use rmule_primitives::{ED2K_PART_SIZE, Ed2kText, FileHash, part_count};

use super::{FileProbeStatus, PeerError, PeerEvent, PeerSession, SlotReleaseReason, State};
use crate::RequesterEvent;
use crate::capability::{MiscOptions1, MiscOptions2};
use crate::compress::InflateFailed;
use crate::file::PartBitmap;
use crate::file_request::{FileStatus, ReqFileNameAnswer, RequestFileName, SetReqFileId};
use crate::hash_set::HashSetRequest;
use crate::multipacket::{MultiPacketRequest, RequestItem};
use crate::parts::RequestParts as RequestPartsPacket;
use crate::parts::{CompressedPart, PartOffsetWidth, PartRanges};
use crate::slot::StartUploadReq;

/// The per-file flow each hash accumulates while probe, hash-set and slot
/// legs interleave (ADR-0025).
#[derive(Debug, Default)]
pub(super) struct FileFlow {
    pub(super) file_size: Option<u64>,
    pub(super) probe: ProbeState,
    pub(super) hash_set: HashSetState,
    pub(super) slot: SlotState,
    pub(super) last_rank: Option<u16>,
    /// `Some` once a `RequestParts` command is in flight for this file
    /// and the per-file state still owes us a slot grant.
    pub(super) pending_request: Option<PendingRequest>,
    /// In-flight `OP_COMPRESSEDPART` blocks, keyed by uncompressed `start`
    /// offset → accumulated compressed bytes. A block's chunks accumulate
    /// until `nBlockSize` bytes arrive, then it is inflated and removed.
    pub(super) compressed_blocks: HashMap<u64, Vec<u8>>,
    /// How many source-exchange candidates this file has already been handed
    /// across earlier `OP_ANSWERSOURCES` answers — the running count the
    /// per-file source cap is honored against cumulatively, not reset per
    /// answer (ADR-0055).
    pub(super) sources_forwarded: usize,
    /// What rmule holds of this file, as the last `ProbeFile` / `RequestFile`
    /// declared it — the part status a later standalone name ask repeats.
    pub(super) own_status: Option<PartBitmap>,
}

/// The running count of `FileFlow::compressed_blocks` entries across every
/// per-file flow — what a hostile peer can hold buffered session-wide.
/// The field is private to this module, so only
/// [`PeerSession::on_compressed_part`] can move it: up when a block opens,
/// down when one is inflated or dropped.
#[derive(Debug, Default)]
pub(super) struct CompressedBlocksInFlight(usize);

#[derive(Debug, Clone)]
pub(super) struct PendingRequest {
    pub(super) ranges: PartRanges,
    pub(super) width: PartOffsetWidth,
    pub(super) requestparts_sent: bool,
}

#[derive(Debug, Default)]
pub(super) enum ProbeState {
    #[default]
    NotIssued,
    Pending {
        name: Option<Ed2kText>,
        bitmap: Option<PartBitmap>,
        /// aMule's `m_bCompleteSource` as the bitmap came: the part-count-0
        /// sentinel, or a one-part file's prefilled bitmap (ADR-0108).
        complete: bool,
    },
    Available {
        file_name: Ed2kText,
        bitmap: PartBitmap,
        complete: bool,
    },
    NotAvailable,
}

#[derive(Debug, Default)]
pub(super) enum HashSetState {
    #[default]
    NotIssued,
    Pending,
    // The hashes themselves are emitted on the wire-event channel
    // immediately; the session only needs to remember that they've
    // arrived to decide whether to re-request on a subsequent
    // RequestParts. Once a downstream consumer needs the cached
    // hashes (e.g. for in-session verification, which ADR-0026
    // forbids today), revive the Vec<PartHash> payload.
    Cached,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) enum SlotState {
    #[default]
    Idle,
    /// `OP_STARTUPLOADREQ` sent, awaiting `OP_ACCEPTUPLOADREQ` or
    /// queue terminal.
    Queued,
    /// Slot granted; `OP_REQUESTPARTS` sent, awaiting part bytes.
    Downloading,
    /// Slot held but no needed parts available; `OP_CANCELTRANSFER` sent
    /// (ADR-0056). The connection stays open for re-ask when parts
    /// become available.
    Standby,
    Released,
}

impl PeerSession {
    /// Accumulate a compressed part chunk; once the block's full `nBlockSize`
    /// compressed bytes have arrived, inflate and surface the plaintext as
    /// `PartReceived` — the same event a raw `OP_SENDINGPART` produces, so
    /// core's block assembly (ADR-0029) is unchanged. A block that fails to
    /// inflate emits a non-terminal `CompressedPartSkipped`; the session stays
    /// open and core re-requests the block.
    pub(super) fn on_compressed_part(&mut self, cp: &CompressedPart) {
        // A compressed block never spans more than one ED2K part; bound the
        // inflated output for safety.
        const COMPRESSED_BLOCK_CEILING: usize = 9_728_000;
        // A zlib stream that inflates within the ceiling only exceeds it by
        // the compressBound-style worst case (~0.1% plus a small header) —
        // and aMule/eMule never even compress a block that would not shrink.
        // A larger declared `nBlockSize` is malformed or hostile: refuse it
        // before buffering a single byte.
        const COMPRESSED_INPUT_CEILING: usize =
            COMPRESSED_BLOCK_CEILING + COMPRESSED_BLOCK_CEILING / 1000 + 64;
        // An `OP_REQUESTPARTS` asks for at most 3 ranges, so a well-behaved
        // sender keeps very few blocks mid-accumulation; 8 leaves slack for
        // pipelined re-requests while capping what a hostile peer can hold
        // buffered at `8 × COMPRESSED_INPUT_CEILING` per session.
        const MAX_INFLIGHT_COMPRESSED_BLOCKS: usize = 8;

        // Parts are only ever solicited: our own RequestParts created the
        // flow before a legal peer sends one. An unsolicited hash must not
        // create per-file state — drop the chunk silently, as
        // core drops parts for unknown hashes.
        let Some(flow) = self.per_file.get_mut(&cp.file_hash) else {
            return;
        };
        if cp.compressed_block_len as usize > COMPRESSED_INPUT_CEILING {
            // Drop any bytes an earlier, legal declaration buffered for this
            // offset — the peer has shown the block malformed either way.
            if flow.compressed_blocks.remove(&cp.start).is_some() {
                self.compressed_blocks_in_flight.0 -= 1;
            }
            self.core.push_event(PeerEvent::Requester(
                RequesterEvent::CompressedPartSkipped {
                    file_hash: cp.file_hash,
                    offset: cp.start,
                    reason: InflateFailed::DeclaredTooLarge {
                        declared: cp.compressed_block_len,
                        ceiling: COMPRESSED_INPUT_CEILING,
                    },
                },
            ));
            return;
        }
        let starts_new_block = !flow.compressed_blocks.contains_key(&cp.start);
        if starts_new_block && self.compressed_blocks_in_flight.0 >= MAX_INFLIGHT_COMPRESSED_BLOCKS
        {
            self.core.push_event(PeerEvent::Requester(
                RequesterEvent::CompressedPartSkipped {
                    file_hash: cp.file_hash,
                    offset: cp.start,
                    reason: InflateFailed::TooManyInFlight,
                },
            ));
            return;
        }
        if starts_new_block {
            self.compressed_blocks_in_flight.0 += 1;
        }
        let buf = flow.compressed_blocks.entry(cp.start).or_default();
        buf.extend_from_slice(&cp.compressed_chunk);
        if buf.len() < cp.compressed_block_len as usize {
            return;
        }
        let compressed = flow
            .compressed_blocks
            .remove(&cp.start)
            .expect("entry just inserted");
        self.compressed_blocks_in_flight.0 -= 1;
        let event = match crate::compress::inflate(&compressed, COMPRESSED_BLOCK_CEILING) {
            Ok(bytes) => PeerEvent::Requester(RequesterEvent::PartReceived {
                file_hash: cp.file_hash,
                offset: cp.start,
                bytes,
            }),
            Err(reason) => PeerEvent::Requester(RequesterEvent::CompressedPartSkipped {
                file_hash: cp.file_hash,
                offset: cp.start,
                reason,
            }),
        };
        self.core.push_event(event);
    }

    // --- Command handlers --------------------------------------

    pub(super) fn handle_probe_file(
        &mut self,
        file_hash: FileHash,
        file_size: u64,
        own_status: PartBitmap,
    ) {
        if !matches!(self.state, State::Identified) {
            self.reject(PeerError::PeerProtocolViolation {
                reason: "command before peer identified",
            });
            return;
        }
        let flow = self.per_file.entry(file_hash).or_default();
        // Recorded up front, same as `handle_request_file`: a status reply
        // to this probe may carry aMule's part-count-0 "complete source"
        // sentinel, and expanding it needs the file's real size.
        flow.file_size = Some(file_size);
        flow.own_status = Some(own_status);
        match &flow.probe {
            ProbeState::Available {
                file_name,
                bitmap,
                complete,
            } => {
                let event = PeerEvent::Requester(RequesterEvent::FileProbed {
                    file_hash,
                    status: FileProbeStatus::Available {
                        file_name: file_name.clone(),
                        bitmap: bitmap.clone(),
                        complete: *complete,
                    },
                });
                self.core.push_event(event);
            }
            ProbeState::NotAvailable => {
                let event = PeerEvent::Requester(RequesterEvent::FileProbed {
                    file_hash,
                    status: FileProbeStatus::NotAvailable,
                });
                self.core.push_event(event);
            }
            ProbeState::Pending { .. } => {
                // Probe already in flight; do nothing extra.
            }
            ProbeState::NotIssued => {
                flow.probe = ProbeState::Pending {
                    name: None,
                    bitmap: None,
                    complete: false,
                };
                let name_ask = self.name_ask(file_hash, file_size);
                self.write_packet(name_ask.encode_packet());
                self.write_packet(SetReqFileId { file_hash }.encode_packet());
            }
        }
    }

    /// The name ask for `file_hash` at this session's extended-requests
    /// level: the bare hash at level 0, else followed by what rmule holds —
    /// as the file's flow last declared it, or nothing held when no probe or
    /// request declared anything. At level 1 the status is not optional:
    /// aMule's standalone reader disconnects a claimant whose name ask is the
    /// bare hash (`UploadClient.cpp` `ProcessExtendedInfo`, "Wrong size on
    /// extended info packet").
    fn name_ask(&self, file_hash: FileHash, file_size: u64) -> RequestFileName {
        let status = self.name_ask_status(file_hash, file_size);
        RequestFileName::new(file_hash, status.as_ref())
    }

    /// The status [`Self::name_ask`] follows the hash with, bundled or not.
    fn name_ask_status(&self, file_hash: FileHash, file_size: u64) -> Option<PartBitmap> {
        self.extended_requests().carries_part_status().then(|| {
            self.per_file
                .get(&file_hash)
                .and_then(|flow| flow.own_status.clone())
                .unwrap_or_else(|| PartBitmap::downloader_empty(file_size))
        })
    }

    /// The bundled-file-request decision core (ADR-0054 emit): fold the
    /// per-packet send conditions into one ordered item set, then put it on the
    /// wire as either a single `OP_MULTIPACKET` / `OP_MULTIPACKET_EXT` bundle
    /// (when the peer advertised MultiPacket) or the equivalent separate
    /// standalone packets. Both shapes share this one item decision.
    pub(super) fn handle_request_file(
        &mut self,
        file_hash: FileHash,
        file_size: u64,
        want_sources: bool,
        want_aich_root: bool,
        own_status: PartBitmap,
    ) {
        if !self.require_identified() {
            return;
        }
        // Item composition, in aMule's request order: 0x58 always, 0x4F only
        // when multi-part, then the SX ask and the AICH-root ask per the
        // caller's policy. "Multi-part" here is aMule's own boundary —
        // `SendFileRequest` gates `OP_SETREQFILEID` on `GetPartCount() > 1`
        // (`DownloadClient.cpp:232`, stock 2.3.3), and `GetPartCount()` is
        // `CKnownFile::m_iPartCount` (`KnownFile.cpp` `SetFileSize`), the
        // *data*-part count with the phantom last part folded out for an
        // exact multiple of the part size — the same count
        // [`crate::file::PartBitmap::downloader`] calls `real` and
        // `rmule_primitives::part_count` computes. So a file of exactly one
        // part size (9,728,000 bytes) has `GetPartCount() == 1` and gets no
        // `0x4F`; one byte over does. The SX sub follows the existing
        // source-ask policy ([`Self::sx_request_item`], ADR-0055): the v4
        // `0x83` form iff the peer advertised SourceExchange2, else the v1
        // `0x81`.
        let multi_part = part_count(file_size) > 1;
        // Record the solicitation: the answer handlers only accept answers
        // for a file whose flow exists. The item set IS the probe
        // — mark it in flight so a later `RequestParts` does not re-issue the
        // standalone `0x58`+`0x4F` on top of this request. A multi-part
        // probe waits for the name + part-status pair; a one-part probe asks
        // the name alone, and its answer means a complete source (aMule
        // `ProcessFileInfo`: `GetPartCount() == 1` → every part held, no
        // `OP_FILESTATUS` asked or awaited), so the bitmap is known up front.
        let flow = self.per_file.entry(file_hash).or_default();
        // Recorded up front, same as `handle_request_parts`: a status reply
        // to this probe may carry aMule's part-count-0 "complete source"
        // sentinel, and expanding it needs the file's real size
        // — this is the only solicitation path that did not already
        // save it.
        flow.file_size = Some(file_size);
        flow.own_status = Some(own_status);
        if matches!(flow.probe, ProbeState::NotIssued) {
            flow.probe = ProbeState::Pending {
                name: None,
                bitmap: (!multi_part).then(PartBitmap::one_part_complete),
                complete: !multi_part,
            };
        }
        let mut items = vec![RequestItem::Name {
            part_status: self.name_ask_status(file_hash, file_size),
        }];
        if multi_part {
            items.push(RequestItem::SetReqId);
        }
        let support = self.source_exchange_support();
        let sources_asked = want_sources && support.askable();
        if sources_asked {
            items.push(self.sx_request_item());
        }
        if want_aich_root {
            items.push(RequestItem::AichRoot);
        }

        // Bundle iff the peer advertised MultiPacket (MiscOptions1 bit 1);
        // frame as 0xA4 iff it also advertised ExtMultiPacket (MiscOptions2
        // bit 5) — aMule selects on that bit alone and always writes size8 in
        // the EXT form.
        if self
            .peer_misc_options
            .is_some_and(MiscOptions1::supports_multipacket)
        {
            let ext = self
                .peer_misc_options2
                .is_some_and(MiscOptions2::supports_multipacket_ext);
            let request = MultiPacketRequest {
                file_hash,
                file_size: ext.then_some(file_size),
                items,
                unknown_sub: None,
                cut: None,
            };
            self.write_packet(request.encode_packet());
        } else {
            self.emit_standalone_file_request(file_hash, &items);
        }
        self.core
            .push_event(PeerEvent::Requester(RequesterEvent::FileRequestSent {
                file_hash,
                sources_asked,
            }));
    }

    /// The standalone wire shape of a [`RequestItem`] set — each item as the
    /// separate packet whose hash-stripped payload the bundle sub-item
    /// mirrors, in the same order, except the source ask, which is always SX1. Serves both [`Self::handle_request_file`]'s
    /// non-multipacket fallback and the granular
    /// [`crate::RequesterCommand::RequestSources`] command.
    pub(super) fn emit_standalone_file_request(
        &mut self,
        file_hash: FileHash,
        items: &[RequestItem],
    ) {
        for item in items {
            match item {
                RequestItem::Name { part_status } => {
                    let name_ask = RequestFileName::new(file_hash, part_status.as_ref());
                    self.write_packet(name_ask.encode_packet());
                }
                RequestItem::SetReqId => {
                    self.write_packet(SetReqFileId { file_hash }.encode_packet());
                }
                // A standalone source ask is always the 16-byte SX1 `0x81`: aMule
                // 2.3.3's standalone `0x83` arm disconnects on any payload but 16
                // bytes (`ClientTCPSocket.cpp` `size != 16`), so the 19-byte SX2
                // form fails against it, and a hello cannot tell aMule apart
                // (rmule advertises aMule's own version word). SX2 rides only
                // inside a bundle.
                RequestItem::Sources | RequestItem::Sources2 { .. } => {
                    self.write_packet(
                        crate::source_exchange::RequestSources { file_hash }.encode_packet(),
                    );
                }
                RequestItem::AichRoot => {
                    self.write_packet(crate::aich::AichFileHashReq { file_hash }.encode_packet());
                }
            }
        }
    }

    pub(super) fn handle_request_parts(
        &mut self,
        file_hash: FileHash,
        file_size: u64,
        ranges: PartRanges,
    ) {
        if !matches!(self.state, State::Identified) {
            self.reject(PeerError::PeerProtocolViolation {
                reason: "command before peer identified",
            });
            return;
        }
        match self.active_slot {
            Some(active) if active == file_hash => {
                // Slot already held for this file: send another block
                // request directly over it (ADR-0025, amended). Only once
                // the slot is granted (`Downloading`); before the grant the
                // first request is still pending and carries the ranges. A
                // flow queued again by `OP_OUTOFPARTREQS` holds none: this
                // request waits for the next grant, as a first one does.
                let width = PartOffsetWidth::for_file_size(file_size);
                let Some(flow) = self.per_file.get_mut(&file_hash) else {
                    return;
                };
                match flow.slot {
                    SlotState::Downloading => {}
                    SlotState::Queued if flow.pending_request.is_none() => {
                        flow.pending_request = Some(PendingRequest {
                            ranges,
                            width,
                            requestparts_sent: false,
                        });
                        return;
                    }
                    _ => return,
                }
                let req = RequestPartsPacket { file_hash, ranges };
                match req.encode_packet(width) {
                    Ok(p) => self.write_packet(p),
                    Err(_) => self.release_slot(file_hash, SlotReleaseReason::ProtocolViolation),
                }
                return;
            }
            // A different file holds the slot: one active slot per
            // connection (ADR-0025), so this is busy.
            Some(_) => {
                self.reject(PeerError::SlotBusy);
                return;
            }
            None => {}
        }
        // File-size consistency check.
        if let Some(flow) = self.per_file.get(&file_hash)
            && let Some(known) = flow.file_size
            && known != file_size
        {
            self.reject(PeerError::FileSizeMismatch {
                requested: file_size,
                known,
            });
            return;
        }

        let width = PartOffsetWidth::for_file_size(file_size);
        let pending = PendingRequest {
            ranges,
            width,
            requestparts_sent: false,
        };

        // Mutate per-file state in a scoped borrow, gather the
        // decisions, then drop the borrow before emitting writes.
        enum NextAction {
            Reject(&'static str),
            Send {
                send_probe: bool,
                send_hashset: bool,
                send_start_upload: bool,
            },
        }
        let action = {
            let flow = self.per_file.entry(file_hash).or_default();
            if matches!(flow.probe, ProbeState::NotAvailable) {
                NextAction::Reject("peer previously answered FILEREQANSNOFIL for this hash")
            } else {
                flow.file_size = Some(file_size);
                flow.slot = SlotState::Idle;
                flow.last_rank = None;
                flow.pending_request = Some(pending);
                let send_probe = matches!(flow.probe, ProbeState::NotIssued);
                if send_probe {
                    // A one-part probe no longer asks `OP_SETREQFILEID`
                    // So no `OP_FILESTATUS` answer is coming for it
                    // either — prefill the bitmap the same way
                    // `handle_request_file` does, or `maybe_emit_probed`
                    // would wait forever on a status a well-behaved peer
                    // never sends.
                    let multi_part = part_count(file_size) > 1;
                    flow.probe = ProbeState::Pending {
                        name: None,
                        bitmap: (!multi_part).then(PartBitmap::one_part_complete),
                        complete: !multi_part,
                    };
                }
                let needs_hashset = file_size >= ED2K_PART_SIZE;
                let send_hashset =
                    needs_hashset && matches!(flow.hash_set, HashSetState::NotIssued);
                if send_hashset {
                    flow.hash_set = HashSetState::Pending;
                } else if !needs_hashset && matches!(flow.hash_set, HashSetState::NotIssued) {
                    flow.hash_set = HashSetState::Cached;
                }
                let probe_done = matches!(flow.probe, ProbeState::Available { .. });
                let hashset_cached = matches!(flow.hash_set, HashSetState::Cached);
                let send_start_upload = probe_done && hashset_cached;
                NextAction::Send {
                    send_probe,
                    send_hashset,
                    send_start_upload,
                }
            }
        };
        match action {
            NextAction::Reject(reason) => {
                self.reject(PeerError::PeerProtocolViolation { reason });
            }
            NextAction::Send {
                send_probe,
                send_hashset,
                send_start_upload,
            } => {
                self.active_slot = Some(file_hash);
                if send_probe {
                    let name_ask = self.name_ask(file_hash, file_size);
                    self.write_packet(name_ask.encode_packet());
                    // `OP_SETREQFILEID` only for a multi-part file (aMule
                    // `SendFileRequest`, `DownloadClient.cpp:207-333`,
                    // `GetPartCount() > 1`): a one-part file's part status is
                    // trivial, so the name ask alone is the whole probe. A
                    // file of exactly one part size has `GetPartCount() == 1`
                    // (`KnownFile.cpp` `SetFileSize` folds the phantom last
                    // part out of an exact multiple), so it gets no `0x4F`
                    // either.
                    if part_count(file_size) > 1 {
                        self.write_packet(SetReqFileId { file_hash }.encode_packet());
                    }
                }
                if send_hashset {
                    self.write_packet(HashSetRequest { file_hash }.encode_packet());
                }
                if send_start_upload {
                    self.try_send_start_upload(file_hash);
                }
            }
        }
    }

    // --- Wire-event handlers -----------------------------------

    pub(super) fn on_req_filename_answer(&mut self, answer: ReqFileNameAnswer) {
        let file_hash = answer.file_hash;
        // Answers are only ever solicited — the flow exists from our own
        // probe or request. An unsolicited hash must not create per-file
        // state.
        let Some(flow) = self.per_file.get_mut(&file_hash) else {
            return;
        };
        match &mut flow.probe {
            ProbeState::Pending { name, .. } => {
                *name = Some(answer.file_name);
            }
            // Unsolicited or duplicate — preserve as Unknown event-ish behaviour:
            // upgrade the probe state so a re-probe sees Available eventually.
            _ => {
                flow.probe = ProbeState::Pending {
                    name: Some(answer.file_name),
                    bitmap: None,
                    complete: false,
                };
            }
        }
        self.maybe_emit_probed(file_hash);
    }

    pub(super) fn on_file_status(&mut self, status: FileStatus) {
        let file_hash = status.file_hash;
        // Same gate as `on_req_filename_answer`.
        let Some(flow) = self.per_file.get_mut(&file_hash) else {
            return;
        };
        // Only a flow that named the file's size can read a status for it: a
        // bare `RequestSources` opened none, and asked for no status.
        let Some(file_size) = flow.file_size else {
            return;
        };
        // aMule and eMule count a peer complete on the sentinel alone; a
        // spelled-out bitmap with every part is a part file, not complete
        // (stock 2.3.3 `DownloadClient.cpp:405-409`, `:428`; eMule
        // `DownloadClient.cpp:516`).
        let sentinel = status.bitmap.part_count() == 0;
        // A count that is not the file's is aMule's "wrong part number"
        // throw, and the connection drops (`DownloadClient.cpp:417-425`,
        // `ClientTCPSocket.cpp:2018-2047`).
        let Some(bitmap) = status.bitmap.advertised_parts(file_size) else {
            self.reject(PeerError::PeerProtocolViolation {
                reason: "file status counts other parts than the file has",
            });
            self.close_protocol_violation();
            return;
        };
        match &mut flow.probe {
            ProbeState::Pending {
                bitmap: pending_bitmap,
                complete,
                ..
            } => {
                *pending_bitmap = Some(bitmap);
                *complete = sentinel;
            }
            // A status on an already-settled probe never un-settles it
            // (aMule `ProcessFileStatus`: once `m_reqfile` is known, a
            // status only updates `m_downPartStatus`/availability — it
            // never resets the file to unknown). A late or unsolicited
            // `OP_FILESTATUS` for a probe we already resolved to
            // `Available` folds its bits in (a no-op when identical, as
            // aMule's own late answer to a one-part probe is) and is not
            // raised again: rmule asks once per connection.
            ProbeState::Available {
                bitmap: settled_bitmap,
                complete,
                ..
            } => {
                settled_bitmap.merge_from(&bitmap);
                *complete = sentinel;
                return;
            }
            ProbeState::NotIssued | ProbeState::NotAvailable => {
                flow.probe = ProbeState::Pending {
                    name: None,
                    bitmap: Some(bitmap),
                    complete: sentinel,
                };
            }
        }
        self.maybe_emit_probed(file_hash);
    }

    /// State follow-up after the projection emits `FileProbed{NotAvailable}`:
    /// record unavailability and end the active slot if this file held it —
    /// the peer lacks the file, a terminal path (ADR-0025).
    pub(super) fn after_file_unavailable(&mut self, file_hash: FileHash) {
        // Only record unavailability for a file we actually asked about — an
        // unsolicited FILEREQANSNOFIL must not create state or pre-poison a
        // later request.
        let Some(flow) = self.per_file.get_mut(&file_hash) else {
            return;
        };
        flow.probe = ProbeState::NotAvailable;
        if self.active_slot == Some(file_hash) {
            self.release_slot(file_hash, SlotReleaseReason::FileNotFound);
        }
    }

    fn maybe_emit_probed(&mut self, file_hash: FileHash) {
        let flow = self
            .per_file
            .get_mut(&file_hash)
            .expect("per_file entry must exist");
        let ready = matches!(
            &flow.probe,
            ProbeState::Pending {
                name: Some(_),
                bitmap: Some(_),
                ..
            }
        );
        if !ready {
            return;
        }
        // Replace Pending with Available (move the values out).
        let probe = std::mem::replace(&mut flow.probe, ProbeState::NotIssued);
        let (file_name, bitmap, complete) = match probe {
            ProbeState::Pending {
                name: Some(n),
                bitmap: Some(b),
                complete,
            } => (n, b, complete),
            _ => unreachable!("ready guarded above"),
        };
        flow.probe = ProbeState::Available {
            file_name: file_name.clone(),
            bitmap: bitmap.clone(),
            complete,
        };
        self.core
            .push_event(PeerEvent::Requester(RequesterEvent::FileProbed {
                file_hash,
                status: FileProbeStatus::Available {
                    file_name,
                    bitmap,
                    complete,
                },
            }));

        // Advance the active-slot flow if this file owns it.
        if self.active_slot == Some(file_hash) {
            self.advance_active_slot(file_hash);
        }
    }

    /// State follow-up after the projection emits `HashSetReceived`: mark
    /// the hash set cached and, if this file holds the active slot, advance
    /// it toward `STARTUPLOADREQ`.
    pub(super) fn after_hash_set(&mut self, file_hash: FileHash) {
        // Only cache a hash set we asked for — a planted answer must not
        // create state or satisfy a later request's hash-set gate.
        let Some(flow) = self.per_file.get_mut(&file_hash) else {
            return;
        };
        flow.hash_set = HashSetState::Cached;
        if self.active_slot == Some(file_hash) {
            self.advance_active_slot(file_hash);
        }
    }

    pub(super) fn on_accept_upload(&mut self) {
        let Some(active) = self.active_slot else {
            return;
        };
        let flow = self
            .per_file
            .get_mut(&active)
            .expect("active_slot entry must exist");
        flow.slot = SlotState::Downloading;
        self.core
            .push_event(PeerEvent::Requester(RequesterEvent::SlotGranted {
                file_hash: active,
            }));
        // Send REQUESTPARTS for the pending request.
        if let Some(pending) = &mut flow.pending_request
            && !pending.requestparts_sent
        {
            let ranges = pending.ranges;
            let width = pending.width;
            pending.requestparts_sent = true;
            let req = RequestPartsPacket {
                file_hash: active,
                ranges,
            };
            match req.encode_packet(width) {
                Ok(p) => self.write_packet(p),
                Err(_) => {
                    // Width mismatch — treat as protocol violation
                    // for the active slot.
                    self.release_slot(active, SlotReleaseReason::ProtocolViolation);
                }
            }
        }
    }

    /// `OP_OUTOFPARTREQS`: on a granted slot the uploader ended our transfer
    /// and queued us again, so the flow goes back to queued on this link, the
    /// blocks asked for dropped and its rank forgotten for the
    /// `OP_QUEUERANKING` that follows (ADR-0025). aMule acts on it only while
    /// downloading (`ClientTCPSocket.cpp:755-762`): while only queued it
    /// changes nothing.
    pub(super) fn on_out_of_part_reqs(&mut self) {
        let Some(active) = self.active_slot else {
            return;
        };
        let flow = self
            .per_file
            .get_mut(&active)
            .expect("active_slot entry must exist");
        if flow.slot != SlotState::Downloading {
            return;
        }
        flow.slot = SlotState::Queued;
        flow.pending_request = None;
        flow.last_rank = None;
        self.core
            .push_event(PeerEvent::Requester(RequesterEvent::Requeued {
                file_hash: active,
            }));
    }

    pub(super) fn on_queue_ranking(&mut self, rank: u16) {
        let Some(active) = self.active_slot else {
            return;
        };
        let flow = self
            .per_file
            .get_mut(&active)
            .expect("active_slot entry must exist");
        match flow.last_rank {
            None => {
                flow.last_rank = Some(rank);
                self.core
                    .push_event(PeerEvent::Requester(RequesterEvent::QueueRanked {
                        file_hash: active,
                        rank,
                    }));
            }
            Some(prev) if prev == rank => {
                // Dedup identical observation per ADR-0025.
            }
            Some(prev) => {
                flow.last_rank = Some(rank);
                self.core
                    .push_event(PeerEvent::Requester(RequesterEvent::QueueProgress {
                        file_hash: active,
                        previous_rank: prev,
                        new_rank: rank,
                    }));
            }
        }
    }

    // --- Internal helpers --------------------------------------

    /// Frame `OP_STARTUPLOADREQ` for the slot we are chasing, once — a flow
    /// already queued or further along is left alone.
    fn try_send_start_upload(&mut self, file_hash: FileHash) {
        let flow = self
            .per_file
            .get_mut(&file_hash)
            .expect("per_file entry must exist");
        if !matches!(flow.slot, SlotState::Idle) {
            return;
        }
        flow.slot = SlotState::Queued;
        self.write_packet(StartUploadReq { file_hash }.encode_packet());
        self.core
            .push_event(PeerEvent::Requester(RequesterEvent::SlotAsked {
                file_hash,
            }));
    }

    /// Terminate the active slot context for `file_hash` (ADR-0025): the
    /// flow's slot is `Released`, the pending request dropped, and the
    /// connection-level `active_slot` cleared so a new `RequestParts` may
    /// proceed.
    pub(super) fn release_slot(&mut self, file_hash: FileHash, reason: SlotReleaseReason) {
        let flow = self
            .per_file
            .get_mut(&file_hash)
            .expect("per_file entry must exist");
        flow.slot = SlotState::Released;
        flow.pending_request = None;
        self.active_slot = None;
        self.core
            .push_event(PeerEvent::Requester(RequesterEvent::SlotReleased {
                file_hash,
                reason,
            }));
    }

    fn advance_active_slot(&mut self, file_hash: FileHash) {
        // Called after probe completes or hash-set arrives for the
        // file holding the active slot. Issues STARTUPLOADREQ when
        // both probe + hash-set are ready and we haven't already.
        let flow = self
            .per_file
            .get(&file_hash)
            .expect("per_file entry must exist");
        let probe_done = matches!(flow.probe, ProbeState::Available { .. });
        let hashset_done = matches!(flow.hash_set, HashSetState::Cached);
        let slot_idle = matches!(flow.slot, SlotState::Idle);
        if probe_done && hashset_done && slot_idle {
            self.try_send_start_upload(file_hash);
        }
    }
}
