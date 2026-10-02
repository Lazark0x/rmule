//! Buddy recruitment for firewalled nodes (ADR-0061): the `0x51` request this
//! node sends to a prospective buddy, the `0x5A` answer it gives one, and the
//! tracked-packet guard that separates a solicited reply from a stranger's.

use rmule_primitives::Ipv4Endpoint;

use super::{KadEvent, KadNode, KadNodeDiagnostic};
use crate::buddy::{BuddyMessage, confirms_recruitment, recruitment_target};
use crate::{KadEnvelope, KadId, KadInstant, KadNodeEndpoint};

impl KadNode {
    /// Emit a `0x51 KADEMLIA_FINDBUDDY_REQ` toward `target`, recruiting it as our
    /// buddy (ADR-0061 firewalled-node operation, rmule-as-firewalled-node). The
    /// request's `buddyID` is the recruitment target `~ourKadID` (aMule's
    /// `Search.cpp` FindBuddy `m_target`), so the answer XOR-verifies back; it also
    /// carries our client hash and advertised TCP port so the accepting open node
    /// can open our buddy TCP link. `target`'s IP is tracked for
    /// the firewall-check window so its `0x5A` answer passes the
    /// tracked-packet guard.
    ///
    /// This is the sans-I/O *emit* mechanism; the recruit *trigger* (Kad-joined ∧
    /// TCP+UDP firewalled ∧ no buddy ∧ FindBuddy pacing) is the core-side
    /// firewalled-node policy. A driver / the buddy-recruit orchestrator picks the
    /// convergence contact and calls this — one `0x51` per tracked target.
    pub fn recruit_buddy(&mut self, now: KadInstant, target: KadNodeEndpoint) {
        let request = BuddyMessage::FindBuddyReq {
            buddy_id: recruitment_target(self.config.id),
            requester_hash: self.config.user_hash,
            requester_tcp_port: self.config.tcp_port,
        };
        self.send_envelope(target, &request.encode());
        self.buddy_recruit
            .push((target.ip(), now + crate::reachability::CHECK_WINDOW));
    }

    /// Run the **FINDBUDDY walk** toward `target` (`~ourKadID`): the ordinary
    /// lookup machinery, whose terminal action is one `0x51` to the closest
    /// contact that answered (aMule's `CSearch::FINDBUDDY`,
    /// [`Search.cpp#L784`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Search.cpp#L784)).
    ///
    /// Two walks toward one target would ask two open nodes for a slot that
    /// holds one buddy, so a walk already in flight toward `target` is left to
    /// finish — the caller's pacing decides when to try again.
    pub(super) fn start_findbuddy_walk(&mut self, now: KadInstant, target: KadId) {
        if self.walks.iter().any(|walk| walk.target() == target) {
            self.emit_diagnostic(KadNodeDiagnostic::DuplicateFindBuddyWalk { target });
            return;
        }
        self.start_walk(
            now,
            crate::lookup_walk::KadWalkPurpose::FindBuddy { target },
        );
    }

    /// Emit a `0x5A KADEMLIA_FINDBUDDY_RES` to `requester`, accepting it as the
    /// client we buddy for (ADR-0061 open-node buddy service, rmule-as-open-node).
    /// Echoes `buddy_id` and carries our client hash + advertised TCP port (config)
    /// so the firewalled requester can address our buddy TCP link; `connect_options`,
    /// when `Some`, appends the v7+ connect-options byte (aMule appends it only for
    /// a request that carried a sender key). The sans-I/O *emit* mechanism behind
    /// the [`AnswerFindBuddy`](crate::KadCommand::AnswerFindBuddy) command; the accept
    /// decision (refusal matrix) is the core buddy service's.
    pub(super) fn answer_findbuddy(
        &mut self,
        requester: KadNodeEndpoint,
        buddy_id: KadId,
        connect_options: Option<u8>,
    ) {
        let answer = BuddyMessage::FindBuddyRes {
            buddy_id,
            responder_hash: self.config.user_hash,
            responder_tcp_port: self.config.tcp_port,
            connect_options,
        };
        self.send_envelope(requester, &answer.encode());
    }

    /// Emit a plaintext `0x52 KADEMLIA_CALLBACK_REQ` to `buddy` — the emit behind
    /// [`RequestBuddyCallback`](crate::KadCommand::RequestBuddyCallback).
    /// Bypasses the obfuscation matrix on purpose: aMule sends this one
    /// unencrypted because nothing tells it the buddy's Kad version, and a
    /// buddy that is also a stored crypt contact must still read it.
    pub(super) fn request_buddy_callback(
        &mut self,
        buddy: KadNodeEndpoint,
        buddy_id: KadId,
        file_hash: rmule_primitives::FileHash,
        tcp_port: u16,
    ) {
        let request = BuddyMessage::CallbackReq {
            buddy_id,
            file_hash,
            requester_tcp_port: tcp_port,
        };
        self.outputs.push_back(super::KadOutput::Datagram {
            to: buddy,
            bytes: request.encode().encode(),
        });
    }

    /// Consume a `0x51`/`0x5A`/`0x52` buddy/callback datagram (ADR-0061). The node
    /// owns the codec and the recruiter's tracked-packet guard; the buddy-slot and
    /// relay decisions the emitted events feed are core-side.
    pub(super) fn on_buddy_message(
        &mut self,
        now: KadInstant,
        from: KadNodeEndpoint,
        envelope: &KadEnvelope,
    ) {
        let message = match BuddyMessage::decode(envelope) {
            Ok(message) => message,
            Err(error) => {
                self.emit_diagnostic(KadNodeDiagnostic::MalformedBuddyMessage { from, error });
                return;
            }
        };
        match message {
            // `0x51`: a firewalled peer wants us to be its buddy. Core's single-slot
            // service applies the refusal matrix and, on accept, commands the `0x5A`.
            BuddyMessage::FindBuddyReq {
                buddy_id,
                requester_hash,
                requester_tcp_port,
            } => self.emit_event(KadEvent::FindBuddyRequested {
                requester: Ipv4Endpoint::new(from.ip(), from.udp_port()),
                buddy_id,
                requester_hash,
                requester_tcp_port,
            }),
            // `0x5A`: an answer to our own recruitment. Accept only from a tracked
            // `0x51` target whose echoed buddyID XOR-inverts to our Kad ID (aMule's
            // `CHECK_TRACKED_PACKET` + `GetKadID() == check`); else drop it.
            BuddyMessage::FindBuddyRes {
                buddy_id,
                responder_hash,
                responder_tcp_port,
                connect_options,
            } => {
                self.buddy_recruit.retain(|(_, deadline)| now < *deadline);
                let tracked = self.buddy_recruit.iter().any(|(ip, _)| *ip == from.ip());
                if tracked && confirms_recruitment(buddy_id, self.config.id) {
                    self.buddy_recruit.retain(|(ip, _)| *ip != from.ip());
                    self.emit_event(KadEvent::BuddyFound {
                        buddy: Ipv4Endpoint::new(from.ip(), from.udp_port()),
                        buddy_id,
                        buddy_hash: responder_hash,
                        buddy_tcp_port: responder_tcp_port,
                        connect_options,
                    });
                } else {
                    self.emit_diagnostic(KadNodeDiagnostic::UnrequestedBuddyResponse { from });
                }
            }
            // `0x52`: a peer wants our firewalled buddy to dial it back. Core
            // verifies the buddyID against our slot (the tightening) and relays.
            BuddyMessage::CallbackReq {
                buddy_id,
                file_hash,
                requester_tcp_port,
            } => self.emit_event(KadEvent::CallbackRelayRequested {
                requester: Ipv4Endpoint::new(from.ip(), from.udp_port()),
                buddy_id,
                file_hash,
                requester_tcp_port,
            }),
        }
    }
}
