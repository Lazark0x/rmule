//! The legs a human drives rather than a transfer: chat messages, file
//! descriptions, shared-file browsing, and the public-IP question.
//!
//! Browsing is refused by policy and the unsolicited answers are diagnosed
//! and discarded — an unasked-for answer is hearsay, never state.

use rmule_primitives::{ClientId, Packet, PacketProtocol};

use super::{PeerEvent, PeerSession};
use crate::{IdentityChange, NoticeEvent, RequesterEvent, SideEvent};

impl PeerSession {
    /// Respond-by-parity: `OP_ASKSHAREDFILES`/`OP_ASKSHAREDDIRS`/
    /// `OP_ASKSHAREDFILESDIR` all get the same unconditional
    /// `OP_ASKSHAREDDENIEDANS` reply — the `CanSeeShares == nobody` refusal
    /// path every one of aMule's three browse handlers takes. A new emit
    /// surface, forced by parity: the most private aMule refuses explicitly,
    /// it does not go silent.
    pub(super) fn deny_browse(&mut self) {
        self.write_packet(Packet::new(
            PacketProtocol::Edonkey,
            crate::human_layer::OP_ASKSHAREDDENIEDANS,
            Vec::new(),
        ));
        self.core
            .push_event(PeerEvent::Notice(NoticeEvent::BrowseDenied));
    }

    /// Drop-with-counter: an unsolicited browse answer (rmule never browses).
    pub(super) fn on_unsolicited_browse_answer(&mut self) {
        self.core.push_event(PeerEvent::Notice(
            NoticeEvent::UnsolicitedBrowseAnswerDropped,
        ));
    }

    /// Respond-by-parity: `OP_PUBLICIP_REQ` is ungated in aMule — no privacy
    /// preference silences it — so answering with the peer's own observed
    /// IPv4 is the only posture-consistent response.
    pub(super) fn on_public_ip_req(&mut self) {
        // `OP_PUBLICIP_ANSWER` is a 32-bit field: an IPv6 peer has no true
        // answer, so its request is counted and left unanswered (ADR-0085).
        let Some(peer) = self.peer.as_v4() else {
            self.core
                .push_event(PeerEvent::Side(SideEvent::PublicIpRequestUnanswerable));
            return;
        };
        self.write_packet(crate::human_layer::PublicIpAnswer { ip: peer.ip }.encode_packet());
        self.core
            .push_event(PeerEvent::Side(SideEvent::PublicIpAnswered));
    }

    /// Drop-with-counter: an unsolicited `OP_PUBLICIP_ANSWER` (rmule never
    /// asks — the server's IDCHANGE serves that need, ADR-0047).
    pub(super) fn on_unsolicited_public_ip_answer(&mut self) {
        self.core.push_event(PeerEvent::Notice(
            NoticeEvent::UnsolicitedPublicIpAnswerDropped,
        ));
    }

    /// Surface-as-event: inbound chat text, already capped to aMule's
    /// 450-char limit by the codec. No reply, no state, no spam gate — the
    /// captcha machinery exists to protect a chat feature rmule doesn't have.
    pub(super) fn on_message(&mut self, message: crate::human_layer::Message) {
        self.core
            .push_event(PeerEvent::Notice(NoticeEvent::ChatMessageReceived {
                text: message.text,
            }));
    }

    /// Surface-as-event: inbound file rating/comment, already capped to
    /// aMule's 50-char limit by the codec.
    pub(super) fn on_file_desc(&mut self, desc: crate::human_layer::FileDesc) {
        self.core
            .push_event(PeerEvent::Requester(RequesterEvent::FileCommentReceived {
                rating: desc.rating,
                comment: desc.comment,
            }));
    }

    /// `OP_CHANGE_CLIENT_ID` (`0x4D`): the peer's Client ID changed. Wire-silent;
    /// the identity takes the new ID, so what this session offers other peers
    /// as the peer's source coordinate is where it now is.
    ///
    /// aMule (`ClientTCPSocket.cpp:751-776`) takes a Low ID only for a server it
    /// knows, and a High ID only when it is the address the connection came
    /// from; anything else leaves the client as it was. The session has no
    /// server list, so it takes every Low ID (a Low-ID source is never offered
    /// on, so this moves nothing a stranger could use) and holds the High-ID
    /// rule exactly: a High ID that is not the peer's own IPv4 is ignored.
    /// The server named beside the ID is kept on the identity, so the "on our
    /// server" claim follows the peer to it. Whether that server is one the
    /// node knows is the consumer's judgement, as only it knows its server:
    /// the abuse guard matches the named address against the connected server
    /// and nothing else.
    pub(super) fn on_change_client_id(&mut self, change: crate::human_layer::ChangeClientId) {
        let new_id = change.new_id;
        if new_id.is_high_id() {
            let own = self
                .peer
                .as_v4()
                .map(|peer| ClientId::from_u32(u32::from_le_bytes(peer.ip.octets())));
            if own != Some(new_id) {
                return;
            }
        }
        self.revise_identity(IdentityChange::ClientId, |identity| {
            identity.revise_client_id(new_id, change.new_server_ip)
        });
    }

    /// Drop-with-counter: an inbound chat-captcha challenge or answer.
    /// `OP_CHATCAPTCHAREQ`/`RES` ride on outbound chat, which rmule never
    /// sends, so any inbound instance is unsolicited.
    pub(super) fn on_chat_captcha(&mut self) {
        self.core
            .push_event(PeerEvent::Notice(NoticeEvent::ChatCaptchaDropped));
    }
}
