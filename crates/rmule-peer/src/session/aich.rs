//! The AICH legs: requesting a part's recovery hash from a peer, and
//! answering a peer's request for a file's AICH root.
//!
//! `OP_AICHFILEHASHANS` carries no file hash of its own — the file is "the
//! connection's requested file" — so the pending request is routed by the
//! hash the session recorded when the ask arrived.

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

    pub(super) fn on_aich_requested(&mut self, req: crate::aich::AichRequest) {
        self.core
            .push_event(PeerEvent::Server(ServerEvent::AichRequested {
                file_hash: req.file_hash,
                part: req.part,
                root: req.root,
            }));
    }

    pub(super) fn on_aich_file_hash_requested(&mut self, file_hash: FileHash) {
        // `OP_AICHFILEHASHANS` carries no file hash of its own, so remember
        // which file this request named — `answer_aich_file_hash` reads it
        // back to route the eventual answer, standalone or bundled alike.
        self.served_aich_request = Some(file_hash);
        self.core
            .push_event(PeerEvent::Server(ServerEvent::AichFileHashRequested {
                file_hash,
            }));
    }

    /// Server Capability — answer the connection's outstanding AICH-root
    /// request. Routes into a pending `OP_MULTIPACKETANSWER` (ADR-0054) when
    /// `served_aich_request` names a file with a bundle still open; otherwise
    /// (the bundle already flushed on `Name`/`SetReqId` alone, or none was ever
    /// opened) the answer rides as a standalone `AichFileHashAns`. Either way the
    /// bundle is never blocked waiting on an AICH answer that may not come.
    pub(super) fn answer_aich_file_hash(&mut self, root: AichRootHash) {
        let Some(file_hash) = self.served_aich_request.take() else {
            // No request context to name the file, so a standalone answer would
            // be unroutable (its wire form leads with the file hash). Nothing
            // asked, nothing answered.
            return;
        };
        if let Some(pending) = self.served_multipacket.get_mut(&file_hash) {
            pending.aich = Some(root);
            self.try_flush_multipacket_answer(file_hash);
            return;
        }
        // Standalone (the bundle already flushed on name/status, or none was
        // opened): carries `[file_hash][root]`, the non-bundled wire form.
        self.write_packet(crate::aich::AichFileHashAns { file_hash, root }.encode_packet());
    }
}
