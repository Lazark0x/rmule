//! The legs a human drives rather than a transfer: chat messages, file
//! descriptions, shared-file browsing, and the public-IP question.
//!
//! Browsing is refused by policy and the unsolicited answers are diagnosed
//! and discarded — an unasked-for answer is hearsay, never state.

use rmule_primitives::{ClientId, Packet, PacketProtocol};

use super::{PeerEvent, PeerSession};
use crate::{ConnectionEvent, IdentityChange, NoticeEvent, RequesterEvent, SideEvent};

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

    /// `OP_CHANGE_CLIENT_ID` (`0x4D`): the peer's Client ID changed.
    /// Wire-silent. aMule (`ClientTCPSocket.cpp:773-787`) takes a Low ID only
    /// for a server it knows, and a High ID only when it is the address the
    /// connection came from; anything else leaves the client as it was. The
    /// session holds no server list, so it offers the change to core, which
    /// answers with [`ConnectionCommand::TakeClientId`] when it knows the
    /// server; a High ID that is not the peer's own IPv4 is ignored here.
    /// A Low ID's server is now where a callback reaches the peer, and so a
    /// name a download finds its link under (ADR-0107): a stranger's word
    /// moves no name.
    ///
    /// [`ConnectionCommand::TakeClientId`]: crate::ConnectionCommand::TakeClientId
    pub(super) fn on_change_client_id(&mut self, change: crate::human_layer::ChangeClientId) {
        if self.is_foreign_high_id(change.new_id) {
            return;
        }
        self.core
            .push_event(PeerEvent::Connection(ConnectionEvent::ClientIdOffered {
                client_id: change.new_id,
                server: change.new_server_ip,
            }));
    }

    /// Take the Client ID core accepted, on the known `server` it named
    /// (ADR-0107); the rule the offer passed is held again here.
    pub(super) fn take_client_id(
        &mut self,
        client_id: ClientId,
        server: Option<rmule_primitives::Ipv4Endpoint>,
    ) {
        if self.is_foreign_high_id(client_id) || (client_id.is_low_id() && server.is_none()) {
            return;
        }
        self.revise_identity(IdentityChange::ClientId, |identity| {
            identity.revise_client_id(client_id, server)
        });
    }

    /// Whether `id` is a High ID other than the address the link came from.
    fn is_foreign_high_id(&self, id: ClientId) -> bool {
        id.is_high_id()
            && self
                .peer
                .as_v4()
                .map(|peer| ClientId::from_u32(u32::from_le_bytes(peer.ip.octets())))
                != Some(id)
    }

    /// Drop-with-counter: an inbound chat-captcha challenge or answer.
    /// `OP_CHATCAPTCHAREQ`/`RES` ride on outbound chat, which rmule never
    /// sends, so any inbound instance is unsolicited.
    pub(super) fn on_chat_captcha(&mut self) {
        self.core
            .push_event(PeerEvent::Notice(NoticeEvent::ChatCaptchaDropped));
    }
}
