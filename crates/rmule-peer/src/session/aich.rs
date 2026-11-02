//! The AICH legs: requesting a part's recovery hash from a peer, and
//! answering a peer's request for a file's AICH root, which core may do long
//! after the ask (ADR-0038): the answer names its own file.

use rmule_primitives::{AichRootHash, FileHash};

use super::{PeerEvent, PeerSession};
use crate::ServerEvent;

impl PeerSession {
    /// Send `OP_AICHREQUEST` for `part` of `file_hash`, quoting the trusted
    /// master `root` (ADR-0038). No-op before the hello exchange.
    pub(super) fn handle_request_aich(
        &mut self,
        file_hash: FileHash,
        part: u16,
        root: AichRootHash,
    ) {
        if self.require_identified() {
            self.asked_aich.push((file_hash, part));
            self.write_packet(
                crate::aich::AichRequest {
                    file_hash,
                    part,
                    root,
                }
                .encode_packet(),
            );
        }
    }

    /// An answer about `file_hash` and `part` landed: its ask, or the oldest
    /// one out when it names neither, is settled. Whether it was the ask's own.
    pub(super) fn settle_aich_ask(&mut self, file_hash: FileHash, part: u16) -> bool {
        match self
            .asked_aich
            .iter()
            .position(|ask| *ask == (file_hash, part))
        {
            Some(at) => {
                self.asked_aich.remove(at);
                true
            }
            None => {
                self.settle_any_aich_ask(Some(file_hash));
                false
            }
        }
    }

    /// A refusal landed: the ask about `file_hash` is settled, or the oldest
    /// one out when no ask names it.
    pub(super) fn settle_any_aich_ask(&mut self, file_hash: Option<FileHash>) {
        let at = self
            .asked_aich
            .iter()
            .position(|(asked, _)| Some(*asked) == file_hash)
            .unwrap_or(0);
        if at < self.asked_aich.len() {
            self.asked_aich.remove(at);
        }
    }

    pub(super) fn on_aich_requested(&mut self, req: crate::aich::AichRequest) {
        self.core
            .push_event(PeerEvent::Server(ServerEvent::AichRequested {
                file_hash: req.file_hash,
                part: req.part,
                root: req.root,
            }));
    }

    pub(super) fn on_aich_file_hash_requested(&mut self, file_hash: FileHash) {
        self.core
            .push_event(PeerEvent::Server(ServerEvent::AichFileHashRequested {
                file_hash,
            }));
    }

    /// Server Capability — answer an AICH-root ask for `file_hash`. Routes into
    /// a pending `OP_MULTIPACKETANSWER` (ADR-0054) when that file has a bundle
    /// still open that asked for one; otherwise (the bundle already flushed on
    /// `Name`/`SetReqId` alone, never asked, or none was ever opened) it rides
    /// as a standalone `AichFileHashAns`. Either way the bundle is never
    /// blocked waiting on an AICH answer that may not come.
    pub(super) fn answer_aich_file_hash(&mut self, file_hash: FileHash, root: AichRootHash) {
        let root = match self.served_multipacket.get_mut(&file_hash) {
            Some(pending) => pending.take_aich(root),
            None => Some(root),
        };
        match root {
            Some(root) => {
                self.write_packet(crate::aich::AichFileHashAns { file_hash, root }.encode_packet());
            }
            None => self.try_flush_multipacket_answer(file_hash),
        }
    }
}
