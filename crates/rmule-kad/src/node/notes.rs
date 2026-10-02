//! The notes leg: this node answers `KADEMLIA2_SEARCH_NOTES_REQ` with an empty
//! result and refuses `KADEMLIA2_PUBLISH_NOTES_REQ`, which is what a node that
//! keeps no notes index owes the protocol (the refusal is classified, never
//! silent).

use super::{KadEvent, KadNode, KadNodeDiagnostic};
use crate::notes::{classify_publish, decode_publish_notes_req, decode_search_notes_req};
use crate::{KadEnvelope, KadNodeEndpoint};

impl KadNode {
    /// The notes layer's search answer (ADR-0063 Empty-Storer Parity): aMule's
    /// own handler has no gates at all — it always attempts the lookup and
    /// only replies inside an index hit. rmule holds no notes index, so every
    /// search is unconditionally an empty answer: wire-silent, exactly like a
    /// genuine miss (`served-empty`).
    pub(super) fn on_search_notes_req(&mut self, from: KadNodeEndpoint, envelope: &KadEnvelope) {
        let target = match decode_search_notes_req(envelope) {
            Ok((target, _file_size)) => target,
            Err(error) => {
                self.emit_diagnostic(KadNodeDiagnostic::UndecodableNotesReq { from, error });
                return;
            }
        };
        self.emit_event(KadEvent::NotesSearchServedEmpty { from, target });
    }

    /// The notes layer's publish intake (ADR-0063 Empty-Storer Parity):
    /// classify through aMule's own gate order — firewalled, then tolerance,
    /// then the terminal capacity gate this permanently-empty,
    /// permanently-refusing index always hits. Every branch is wire-silent: no
    /// `0x4B` is ever sent for a notes publish.
    pub(super) fn on_publish_notes_req(&mut self, from: KadNodeEndpoint, envelope: &KadEnvelope) {
        let key = match decode_publish_notes_req(envelope) {
            Ok(key) => key,
            Err(error) => {
                self.emit_diagnostic(KadNodeDiagnostic::UndecodableNotesReq { from, error });
                return;
            }
        };
        let reason = classify_publish(
            self.config.id,
            self.reachability.udp_firewalled,
            from.ip(),
            key,
        );
        self.emit_diagnostic(KadNodeDiagnostic::NotesPublishRefused { from, reason });
    }
}
