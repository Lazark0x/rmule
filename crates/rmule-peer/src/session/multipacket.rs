//! Bundled requests (ADR-0054): one `OP_MULTIPACKET` carrying several
//! sub-asks about a single file, fanned in to the legs that own them and
//! fanned back out as one composed answer.
//!
//! A bundle answers only once every sub-item it actually asked for has an
//! answer; sub-items the bundle omitted never appear in the composition, and
//! their standalone asks are answered standalone, open bundle or not. Core
//! answers a link's asks in order, so a bundle's own answers reach it first.

use rmule_primitives::{AichRootHash, Ed2kText, FileHash};

use super::{PeerEvent, PeerSession};
use crate::file_request::{FileStatus, ReqFileNameAnswer};
use crate::multipacket::{
    AnswerItem, BundledAsk, MultiPacketAnswer, MultiPacketRequest, RequestItem,
};
use crate::wire_status::WireStatus;
use crate::{NoticeEvent, RequesterEvent, ServerEvent};

/// Which answers a bundled request flushes on. `Name` and `Status` are the hard
/// gate: real requests always carry `Name`, so this is the trigger that actually
/// fires in practice. AICH is deliberately never part of that gate: core may
/// answer an AICH-root request long after, or never (the hashset is still being
/// built, ADR-0038), and ADR-0054 calls for silent omission in that case rather
/// than an answer the rest of the bundle waits for. Only a bundle that asked for
/// neither flushes on AICH alone; one that asked for none of the three (Source
/// subs only) opens no entry at all.
#[derive(Clone, Copy, Debug)]
enum FlushGate {
    Name,
    Status,
    NameAndStatus,
    AichAlone,
}

impl FlushGate {
    /// The gate a request's sub-items set, or `None` when no answer composes.
    fn for_items(items: &[RequestItem]) -> Option<Self> {
        let asked = |item: fn(&RequestItem) -> bool| items.iter().any(item);
        let name = asked(|i| matches!(i, RequestItem::Name { .. }));
        let status = asked(|i| matches!(i, RequestItem::SetReqId));
        match (name, status) {
            (true, true) => Some(Self::NameAndStatus),
            (true, false) => Some(Self::Name),
            (false, true) => Some(Self::Status),
            (false, false) => {
                asked(|i| matches!(i, RequestItem::AichRoot)).then_some(Self::AichAlone)
            }
        }
    }
}

/// Accumulates the standalone-shaped serve answers a bundled
/// `OP_MULTIPACKET`/`OP_MULTIPACKET_EXT` request is owed, so they can compose
/// into one `OP_MULTIPACKETANSWER` instead of separate packets (ADR-0054). The
/// `Option` fields fill in as core's existing `Answer*` commands arrive, in
/// whatever order; each holds at most the one answer its bundle asked for.
#[derive(Debug)]
pub(super) struct PendingMultipacketAnswer {
    gate: FlushGate,
    asks_aich: bool,
    name: Option<Ed2kText>,
    status: Option<WireStatus>,
    aich: Option<AichRootHash>,
}

impl PendingMultipacketAnswer {
    fn opened(gate: FlushGate, items: &[RequestItem]) -> Self {
        Self {
            gate,
            asks_aich: items.iter().any(|i| matches!(i, RequestItem::AichRoot)),
            name: None,
            status: None,
            aich: None,
        }
    }

    /// Take `name` when the bundle still owes one, else hand it back to go
    /// out standalone.
    pub(super) fn take_name(&mut self, name: Ed2kText) -> Option<Ed2kText> {
        let owed = matches!(self.gate, FlushGate::Name | FlushGate::NameAndStatus);
        if owed && self.name.is_none() {
            self.name = Some(name);
            return None;
        }
        Some(name)
    }

    /// As [`Self::take_name`], for a part status.
    pub(super) fn take_status(&mut self, status: WireStatus) -> Option<WireStatus> {
        let owed = matches!(self.gate, FlushGate::Status | FlushGate::NameAndStatus);
        if owed && self.status.is_none() {
            self.status = Some(status);
            return None;
        }
        Some(status)
    }

    /// As [`Self::take_name`], for an AICH root.
    pub(super) fn take_aich(&mut self, root: AichRootHash) -> Option<AichRootHash> {
        if self.asks_aich && self.aich.is_none() {
            self.aich = Some(root);
            return None;
        }
        Some(root)
    }

    /// Whether every answer the gate names has arrived.
    const fn ready(&self) -> bool {
        match self.gate {
            FlushGate::Name => self.name.is_some(),
            FlushGate::Status => self.status.is_some(),
            FlushGate::NameAndStatus => self.name.is_some() && self.status.is_some(),
            FlushGate::AichAlone => self.aich.is_some(),
        }
    }
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
        if let Some(gate) = FlushGate::for_items(&req.items) {
            self.served_multipacket.insert(
                req.file_hash,
                PendingMultipacketAnswer::opened(gate, &req.items),
            );
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
                RequestItem::Sources => BundledAsk::Sources {
                    form: self.served_sources_version(0),
                },
                RequestItem::Sources2 { version, .. } => BundledAsk::Sources {
                    form: self.served_sources_version(*version),
                },
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
    /// the separate-packet sequence. `frame_gate` has refused an answer about
    /// a file this link never asked, before any item reaches here.
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
                        RequesterEvent::AichFileHashReceived { file_hash, root },
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
    /// [`FlushGate`] for the completion rule; a no-op while the
    /// gate isn't met yet, and idempotent once already flushed (the entry is
    /// gone).
    pub(super) fn try_flush_multipacket_answer(&mut self, file_hash: FileHash) {
        if !self
            .served_multipacket
            .get(&file_hash)
            .is_some_and(PendingMultipacketAnswer::ready)
        {
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
