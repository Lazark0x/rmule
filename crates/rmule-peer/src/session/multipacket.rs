//! Bundled requests (ADR-0054): one `OP_MULTIPACKET` carrying several
//! sub-asks about a single file, fanned in to the legs that own them and
//! fanned back out as one composed answer.
//!
//! A bundle answers only once every sub-item it actually asked for has an
//! answer; sub-items the bundle omitted never appear in the composition.

use rmule_primitives::{AichRootHash, Ed2kText, FileHash};

use super::{PeerEvent, PeerSession};
use crate::file::PartBitmap;
use crate::file_request::{FileStatus, ReqFileNameAnswer};
use crate::multipacket::{
    AnswerItem, BundledAsk, MultiPacketAnswer, MultiPacketRequest, RequestItem,
};
use crate::{NoticeEvent, RequesterEvent, ServerEvent};

/// Accumulates the standalone-shaped serve answers a bundled
/// `OP_MULTIPACKET`/`OP_MULTIPACKET_EXT` request is owed, so they can compose
/// into one `OP_MULTIPACKETANSWER` instead of separate packets (ADR-0054).
/// `wants_*` records which sub-items the *request* carried; the
/// `Option` fields fill in as core's existing `Answer*` commands arrive, in
/// whatever order.
///
/// `wants_name`/`wants_status` are the hard completion gate — real requests
/// always carry `Name`, so this is the trigger that actually fires in
/// practice. `wants_aich` is deliberately never part of that gate: core may
/// legitimately never answer an AICH-root request (the hashset isn't
/// complete), and ADR-0054 calls for silent omission in that case rather than
/// an answer that never arrives. When `wants_name` and `wants_status` are both
/// false, AICH becomes the sole trigger (see
/// [`PeerSession::try_flush_multipacket_answer`]); a bundle that asked for
/// none of the three (Source subs only) never opens an entry at all.
#[derive(Debug, Default)]
pub(super) struct PendingMultipacketAnswer {
    pub(super) wants_name: bool,
    pub(super) wants_status: bool,
    pub(super) wants_aich: bool,
    pub(super) name: Option<Ed2kText>,
    pub(super) status: Option<PartBitmap>,
    pub(super) aich: Option<AichRootHash>,
}

impl PeerSession {
    /// Hand a bundled `OP_MULTIPACKET`/`OP_MULTIPACKET_EXT` request (ADR-0054)
    /// to core as one [`ServerEvent::FileBundleRequested`], so the file gates
    /// the whole bundle as aMule's does before its sub-opcode loop (stock
    /// 2.3.3 `4e8f2b3c` `ClientTCPSocket.cpp:1061-1085`): one
    /// `OP_FILEREQANSNOFIL` for a file we do not share, else each ask
    /// answered in turn. The answers core sends for the name, status and AICH
    /// asks compose here into one `OP_MULTIPACKETANSWER`; a source ask's
    /// answer is a *separate*, throttled `0x82` / `0x84` (aMule answers
    /// source subs out-of-band as well, ADR-0055).
    pub(super) fn on_multipacket_request(&mut self, req: MultiPacketRequest) {
        let wants_name = req
            .items
            .iter()
            .any(|i| matches!(i, RequestItem::Name { .. }));
        let wants_status = req.items.iter().any(|i| matches!(i, RequestItem::SetReqId));
        let wants_aich = req.items.iter().any(|i| matches!(i, RequestItem::AichRoot));
        if wants_name || wants_status || wants_aich {
            self.served_multipacket.insert(
                req.file_hash,
                PendingMultipacketAnswer {
                    wants_name,
                    wants_status,
                    wants_aich,
                    ..Default::default()
                },
            );
        }
        if wants_aich {
            // `OP_AICHFILEHASHANS` names no file: remember which one this
            // bundle asked about, for `answer_aich_file_hash` to route.
            self.served_aich_request = Some(req.file_hash);
        }
        let mut asks = Vec::with_capacity(req.items.len());
        for item in &req.items {
            asks.push(match item {
                RequestItem::Name { part_status } => BundledAsk::Name {
                    part_status: part_status.clone(),
                },
                RequestItem::SetReqId => BundledAsk::SetReqId,
                RequestItem::AichRoot => BundledAsk::AichRoot,
                // A plain `Sources` sub carries no version (`0`, SX1 path);
                // `Sources2` carries the SX2 `<ver>` the serve pick reads.
                RequestItem::Sources => {
                    self.note_source_ask(req.file_hash, 0);
                    BundledAsk::Sources
                }
                RequestItem::Sources2 { version, .. } => {
                    self.note_source_ask(req.file_hash, *version);
                    BundledAsk::Sources
                }
            });
        }
        self.core
            .push_event(PeerEvent::Server(ServerEvent::FileBundleRequested {
                file_hash: req.file_hash,
                file_size: req.file_size,
                asks,
                cut: req.cut,
            }));
        if let Some(unknown) = req.unknown_sub {
            self.core
                .push_event(PeerEvent::Notice(NoticeEvent::MultiPacketUnknownSub {
                    file_hash: req.file_hash,
                    opcode: unknown.opcode,
                    remaining: unknown.remaining,
                }));
        }
    }

    /// Fan a bundled `OP_MULTIPACKETANSWER` (ADR-0054) into the exact same
    /// handlers a standalone `ReqFileNameAnswer`/`FileStatus`/`AichFileHashAns`
    /// would reach, so a bundle upgrades per-file probe state identically to
    /// the separate-packet sequence — including when unsolicited.
    pub(super) fn on_multipacket_answer(&mut self, ans: MultiPacketAnswer) {
        let file_hash = ans.file_hash;
        for item in ans.items {
            // A refused status closed the session: nothing after it is read.
            if self.core.is_closed() {
                return;
            }
            match item {
                AnswerItem::Name(file_name) => self.on_req_filename_answer(ReqFileNameAnswer {
                    file_hash,
                    file_name,
                }),
                AnswerItem::Status(bitmap) => {
                    self.on_file_status(FileStatus { file_hash, bitmap });
                }
                AnswerItem::AichRoot(root) => {
                    self.core.push_event(PeerEvent::Requester(
                        RequesterEvent::AichFileHashReceived { root },
                    ));
                }
            }
        }
        if let Some(unknown) = ans.unknown_sub {
            self.core
                .push_event(PeerEvent::Notice(NoticeEvent::MultiPacketUnknownSub {
                    file_hash,
                    opcode: unknown.opcode,
                    remaining: unknown.remaining,
                }));
        }
    }

    /// Compose and send the pending `OP_MULTIPACKETANSWER` for `file_hash` once
    /// every sub-item its request hard-requires has answered (ADR-0054). See
    /// [`PendingMultipacketAnswer`] for the completion rule; a no-op while the
    /// gate isn't met yet, and idempotent once already flushed (the entry is
    /// gone).
    pub(super) fn try_flush_multipacket_answer(&mut self, file_hash: FileHash) {
        let Some(pending) = self.served_multipacket.get(&file_hash) else {
            return;
        };
        let hard_required = pending.wants_name || pending.wants_status;
        let ready = if hard_required {
            (!pending.wants_name || pending.name.is_some())
                && (!pending.wants_status || pending.status.is_some())
        } else {
            // Nothing hard-required: AICH is the sole trigger.
            // `on_multipacket_request` never opens an entry that wants none
            // of the three, so `wants_aich` is true whenever this arm runs.
            pending.wants_aich && pending.aich.is_some()
        };
        if !ready {
            return;
        }
        let pending = self
            .served_multipacket
            .remove(&file_hash)
            .expect("checked Some above");
        let mut items = Vec::new();
        if let Some(name) = pending.name {
            items.push(AnswerItem::Name(name));
        }
        if let Some(status) = pending.status {
            items.push(AnswerItem::Status(status));
        }
        if let Some(aich) = pending.aich {
            items.push(AnswerItem::AichRoot(aich));
        }
        let answer = MultiPacketAnswer {
            file_hash,
            items,
            unknown_sub: None,
        };
        self.write_packet(answer.encode_packet());
    }
}
