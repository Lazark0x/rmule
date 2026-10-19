//! The datagram boundary: bytes in from the transport, decoded frames routed
//! to the leg that owns each opcode.
//!
//! Decode failures never panic and never touch state — they close the
//! connection with a typed [`super::PeerCloseReason`] or skip the frame, so a
//! hostile peer cannot drive the session off its state machine.
//!
//! Every stateful opcode dispatches to a leg method, even where that method
//! only pushes one event: the legs' `on_*` handlers are the single surface a
//! packet reaches whether it arrived standalone or fanned in from an
//! `OP_MULTIPACKET` bundle (`multipacket.rs`), so no arm here inlines what a
//! bundle would then have to duplicate.

use rmule_primitives::{Packet, SessionCore};

use super::{PeerEvent, PeerSession, State};
use crate::capability::MiscOptions1;
use crate::error::PeerPacketDecodeError;
use crate::file_request::ExtendedRequests;
use crate::hello::HelloAnswer;
use crate::hello::HelloRefusal;
use crate::opcode::PeerOpcode;
use crate::packet::{DecodedPeerFrame, PeerPacket};
use crate::software::SoftwareEvidence;
use crate::{ConnectionEvent, NoticeEvent, RequesterEvent};

impl PeerSession {
    /// Append bytes from the socket, extract complete frames, and dispatch
    /// them. Silently no-ops after the session has closed. The buffer loop
    /// lives in [`SessionCore::feed`]; a frame that fails to decode closes
    /// with the unit `ProtocolViolation` reason.
    pub fn handle_bytes(&mut self, bytes: &[u8]) {
        SessionCore::feed(
            self,
            |session| &mut session.core,
            bytes,
            Self::dispatch,
            |session, _error| session.close_protocol_violation(),
        );
    }

    /// The extended-requests level this session speaks: the
    /// lower of rmule's own claim and the peer's, `NONE` before it identified.
    /// Both the name asks rmule writes and the bundle subs it reads use it.
    pub(super) fn extended_requests(&self) -> ExtendedRequests {
        ExtendedRequests::negotiated(
            self.extended_requests_capture_override
                .unwrap_or(MiscOptions1::rmule_advertised().extended_requests_version()),
            self.peer_misc_options
                .map_or(0, MiscOptions1::extended_requests_version),
        )
    }

    fn dispatch(&mut self, packet: Packet) {
        // The answering peer's own claimed SX1 nibble, tracked from its hello
        // (ADR-0055) — `0` before the peer has identified, matching
        // aMule's own default for a client that never claimed the
        // capability. `AnswerSources::decode_packet`'s cross-check reads
        // this as `m_client->GetSourceExchange1Version()` would.
        let claim = crate::source_exchange::SourceExchangeClaim {
            sx1_nibble: self
                .peer_misc_options
                .map_or(0, MiscOptions1::source_exchange_version),
            // ADR-0087: an ExtSX claimant answers in the record form, which no
            // geometry check could recognise.
            ext_sx: self
                .peer_mod_misc()
                .is_some_and(crate::capability::ModMiscOptions::supports_ext_sx),
        };
        let peer_packet = match PeerPacket::decode_frame(&packet, claim, self.extended_requests()) {
            Ok(DecodedPeerFrame::Packet(p)) => p,
            Ok(DecodedPeerFrame::CompressedFrameSkipped {
                opcode,
                compressed_len,
                reason,
            }) => {
                self.core
                    .push_event(PeerEvent::Notice(NoticeEvent::CompressedFrameSkipped {
                        opcode,
                        compressed_len,
                        reason,
                    }));
                return;
            }
            Err(PeerPacketDecodeError::SourceExchange { source }) => {
                // aMule's `AddClientSources` silently ignores a malformed source
                // answer (`PartFile.cpp` @4e8f2b3c) — a non-terminal drop, not a
                // protocol violation. Closing here would tear down an
                // otherwise-healthy (possibly actively downloading) peer over a
                // bad source list, so emit a diagnostic and drop only the answer.
                self.core.push_event(PeerEvent::Requester(
                    RequesterEvent::SourceExchangeAnswerSkipped {
                        reason: source.into(),
                    },
                ));
                return;
            }
            Err(PeerPacketDecodeError::SourceExchange2 { source }) => {
                // A malformed `0x84` gets the same non-terminal treatment as
                // `0x82` above — aMule's `AddClientSources` returns silently for
                // the SX2 branch too (`PartFile.cpp` @4e8f2b3c).
                self.core.push_event(PeerEvent::Requester(
                    RequesterEvent::SourceExchangeAnswerSkipped {
                        reason: source.into(),
                    },
                ));
                return;
            }
            Err(PeerPacketDecodeError::Slot { .. })
                if packet.protocol() == PeerOpcode::StartUploadReq.protocol()
                    && packet.opcode() == PeerOpcode::StartUploadReq.as_u8() =>
            {
                // aMule acts on a slot ask only at the hash's exact length and
                // otherwise lets it pass, connection kept (stock 2.3.3
                // `4e8f2b3c` `ClientTCPSocket.cpp:606-618`, no `throw`):
                // preserved as unknown, stay open (ADR-0018).
                self.core
                    .push_event(PeerEvent::Notice(NoticeEvent::UnknownPacket {
                        protocol: packet.protocol(),
                        opcode: packet.opcode(),
                        payload_len: packet.payload().len(),
                    }));
                return;
            }
            Err(
                PeerPacketDecodeError::Hello { source }
                | PeerPacketDecodeError::HelloAnswer { source },
            ) => {
                if let Some(refusal) = HelloRefusal::from_decode_error(&source) {
                    self.core
                        .push_event(PeerEvent::Connection(ConnectionEvent::HelloRefused {
                            refusal,
                        }));
                }
                self.close_protocol_violation();
                return;
            }
            Err(_) => {
                self.close_protocol_violation();
                return;
            }
        };
        // State-independent events come from one tested source
        // (`tests/peer/peer_event_projection.rs`); state-dependent packets
        // (including `AnswerSources`, whose consume path needs session
        // context — ADR-0055) return `None` and are handled by the
        // match below.
        if let Some(event) = PeerEvent::from_peer_packet(&peer_packet) {
            self.core.push_event(event);
        }
        match peer_packet {
            PeerPacket::Hello(hello) => {
                if matches!(self.state, State::AwaitingHello) {
                    // Inbound handshake: reply OP_HELLOANSWER, then identify
                    // the dialing peer — the inverse of `start()`. The answer
                    // must be queued FIRST: identifying kicks off Secure User
                    // Identification, and the dialer (still awaiting our
                    // answer) drops any SUI packet that precedes it. An
                    // `OP_HELLO` starts the software evidence afresh (the
                    // references' `ClearHelloProperties`).
                    self.peer_software = SoftwareEvidence::default();
                    self.peer_software.hello(hello.body(), hello.trailer());
                    self.send_emule_info_if_legacy();
                    let answer_body = self.hello_body_to_write();
                    self.write_packet(HelloAnswer::new(answer_body).encode_packet());
                    self.identify_peer(hello.body());
                } else {
                    // Outbound dialer, or already past the handshake: an
                    // OP_HELLO is unexpected. Preserve as Unknown, stay open.
                    self.core
                        .push_event(PeerEvent::Notice(NoticeEvent::UnknownPacket {
                            protocol: PeerOpcode::Hello.protocol(),
                            opcode: PeerOpcode::Hello.as_u8(),
                            payload_len: packet.payload().len(),
                        }));
                }
            }
            PeerPacket::HelloAnswer(answer) => {
                if !matches!(self.state, State::AwaitingHelloAnswer) {
                    self.core
                        .push_event(PeerEvent::Notice(NoticeEvent::UnknownPacket {
                            protocol: PeerOpcode::HelloAnswer.protocol(),
                            opcode: PeerOpcode::HelloAnswer.as_u8(),
                            payload_len: packet.payload().len(),
                        }));
                    return;
                }
                self.peer_software.hello(answer.body(), answer.trailer());
                self.identify_peer(answer.body());
            }
            PeerPacket::EmuleInfo { answer, info, .. } => self.on_emule_info(answer, &info),
            PeerPacket::ReqFileNameAnswer(a) => self.on_req_filename_answer(a),
            PeerPacket::FileStatus(s) => self.on_file_status(s),
            PeerPacket::MultiPacketAnswer(ans) => self.on_multipacket_answer(ans),
            // The projection already emitted the verbatim event; these arms
            // carry only the state follow-up.
            PeerPacket::FileReqAnsNoFil(n) => self.after_file_unavailable(n.file_hash),
            PeerPacket::HashSetAnswer(a) => self.after_hash_set(a.file_hash),
            PeerPacket::AcceptUploadReq(_) => self.on_accept_upload(),
            PeerPacket::OutOfPartReqs(_) => self.on_out_of_part_reqs(),
            PeerPacket::QueueRanking(r) => self.on_queue_ranking(r.rank),
            // Server Capability — serve requests dispatch on every session
            // (ADR-0031: one bidirectional session). A serve request before
            // the hello exchange is out of order: preserve as Unknown, stay
            // open (ADR-0018). A bundled request (ADR-0054) gets the same
            // treatment as a whole frame — it never partially fans in.
            PeerPacket::RequestFileName(_)
            | PeerPacket::SetReqFileId(_)
            | PeerPacket::HashSetRequest(_)
            | PeerPacket::StartUploadReq(_)
            | PeerPacket::CancelTransfer(_)
            | PeerPacket::RequestParts(_)
            | PeerPacket::RequestSources(_)
            | PeerPacket::RequestSources2(_)
            | PeerPacket::AichRequest(_)
            | PeerPacket::AichFileHashReq(_)
            | PeerPacket::MultiPacketRequest(_)
                if !matches!(self.state, State::Identified) =>
            {
                self.core
                    .push_event(PeerEvent::Notice(NoticeEvent::UnknownPacket {
                        protocol: packet.protocol(),
                        opcode: packet.opcode(),
                        payload_len: packet.payload().len(),
                    }));
            }
            PeerPacket::RequestFileName(r) => {
                self.on_file_requested(r.file_hash, r.status);
            }
            PeerPacket::SetReqFileId(r) => self.on_file_id_set(r.file_hash),
            PeerPacket::HashSetRequest(r) => self.on_hash_set_requested(r.file_hash),
            PeerPacket::StartUploadReq(r) => self.on_slot_requested(r.file_hash),
            PeerPacket::CancelTransfer(_) => self.on_cancel_transfer(),
            PeerPacket::RequestParts(r) => self.on_parts_requested(r),
            // Standalone source-exchange serve requests (ADR-0055). A
            // plain `0x81` carries no requested version (`0`, forcing the SX1
            // path); a `0x83` carries the SX2 `<ver>` the serve pick reads.
            PeerPacket::RequestSources(r) => self.on_sources_requested(r.file_hash, 0),
            PeerPacket::RequestSources2(r) => self.on_sources_requested(r.file_hash, r.version),
            PeerPacket::AichRequest(r) => self.on_aich_requested(r),
            PeerPacket::AichFileHashReq(r) => self.on_aich_file_hash_requested(r.file_hash),
            PeerPacket::MultiPacketRequest(req) => self.on_multipacket_request(req),
            PeerPacket::CompressedPart(cp) => self.on_compressed_part(&cp),
            // ADR-0055: the sanity filter, Low-ID routing rule, and
            // per-file cap all read session context (our own endpoint, the
            // connected server, the file's running forwarded count), so this
            // packet is handled here rather than by the generic projection.
            PeerPacket::AnswerSources(a) => self.on_answer_sources(a),
            // ADR-0055 requester consume: a peer's `0x84` answer to our own
            // `0x83` ask routes through the same sanity/provenance/cap core as
            // `0x82` (its entries already carry the declaring server).
            PeerPacket::AnswerSources2(a) => self.on_answer_sources2(a),
            // Secure User Identification (ADR-0041). An SUI packet before the
            // hello exchange is out of order: preserve as Unknown, stay open
            // (ADR-0018). The guard also guarantees `peer_user_hash` is set by
            // the time the handlers run.
            PeerPacket::SecIdentState(_) | PeerPacket::PublicKey(_) | PeerPacket::Signature(_)
                if !matches!(self.state, State::Identified) =>
            {
                self.core
                    .push_event(PeerEvent::Notice(NoticeEvent::UnknownPacket {
                        protocol: packet.protocol(),
                        opcode: packet.opcode(),
                        payload_len: packet.payload().len(),
                    }));
            }
            PeerPacket::SecIdentState(p) => self.on_secident_state(p),
            PeerPacket::PublicKey(p) => self.on_public_key(p),
            PeerPacket::Signature(p) => self.on_signature(p),
            // ADR-0068 human-layer catalog, Private-Citizen Parity. A
            // human-layer packet before the hello exchange is out of order:
            // preserve as Unknown, stay open (ADR-0018) — the same posture
            // every other stateful packet above gets.
            PeerPacket::AskSharedFiles
            | PeerPacket::AskSharedDirs
            | PeerPacket::AskSharedFilesDir
            | PeerPacket::AskSharedDeniedAns
            | PeerPacket::AskSharedFilesAnswer
            | PeerPacket::AskSharedDirsAns
            | PeerPacket::AskSharedFilesDirAns
            | PeerPacket::PublicIpReq
            | PeerPacket::PublicIpAnswer(_)
            | PeerPacket::Message(_)
            | PeerPacket::FileDesc(_)
            | PeerPacket::ChangeClientId(_)
            | PeerPacket::ChatCaptchaReq
            | PeerPacket::ChatCaptchaRes
                if !matches!(self.state, State::Identified) =>
            {
                self.core
                    .push_event(PeerEvent::Notice(NoticeEvent::UnknownPacket {
                        protocol: packet.protocol(),
                        opcode: packet.opcode(),
                        payload_len: packet.payload().len(),
                    }));
            }
            // Respond-by-parity (ADR-0068): the most private aMule refuses
            // explicitly rather than going silent. Denied unconditionally —
            // rmule has no browse feature, so no payload ever changes the
            // answer.
            PeerPacket::AskSharedFiles
            | PeerPacket::AskSharedDirs
            | PeerPacket::AskSharedFilesDir => self.deny_browse(),
            PeerPacket::PublicIpReq => self.on_public_ip_req(),
            // Drop-with-counter (ADR-0068): rmule never browses and never
            // asks for its own public IP, so any of these is unsolicited.
            PeerPacket::AskSharedDeniedAns
            | PeerPacket::AskSharedFilesAnswer
            | PeerPacket::AskSharedDirsAns
            | PeerPacket::AskSharedFilesDirAns => self.on_unsolicited_browse_answer(),
            PeerPacket::PublicIpAnswer(_) => self.on_unsolicited_public_ip_answer(),
            // Surface-as-event (ADR-0068): wire-silent, payload up the spine.
            PeerPacket::Message(m) => self.on_message(m),
            PeerPacket::FileDesc(d) => self.on_file_desc(d),
            PeerPacket::ChangeClientId(c) => self.on_change_client_id(c),
            // The peer's IPv6 moved: a revision of its identity (ADR-0087).
            PeerPacket::ChangeClientIpV6(c) => self.on_change_client_ipv6(c.address()),
            // Drop-with-counter: rmule never emits `OP_MESSAGE`, so a captcha
            // challenge/answer riding on it is always unsolicited.
            PeerPacket::ChatCaptchaReq | PeerPacket::ChatCaptchaRes => self.on_chat_captcha(),
            // ADR-0061 buddy keepalive: an inbound `OP_BUDDYPING` is
            // surfaced as `BuddyPingReceived` by the projection above (like the
            // firewall ack), so its owner can route it to the core buddy service's
            // `on_buddy_ping` and answer with `SendBuddyPong` only for our
            // registered buddy. The pong decision stays core-side; the session just
            // frames what it is told. An inbound `OP_BUDDYPONG` (were we ever the
            // pinger) is a pure keepalive ack — its meaning is its arrival, so no
            // stateful action here.
            // The two relays our own buddy forwards (ADR-0061 firewalled-node
            // consume) are surfaced verbatim by the projection above and are
            // wire-silent here: the `0x99`'s answer is a fresh TCP dial and the
            // `0x9A`'s is a client-UDP datagram, neither of which belongs to
            // this link's session.
            PeerPacket::BuddyPing
            | PeerPacket::BuddyPong
            | PeerPacket::BuddyCallback(_)
            | PeerPacket::BuddyReaskCallback(_) => {}
            // Fully covered by the projection above. The firewall ack is a
            // state-independent signal — the projection emits the event; core's
            // session owner bridges it to the Kad window guard.
            PeerPacket::SendingPart(_)
            | PeerPacket::AichAnswer(_)
            | PeerPacket::AichFileHashAns(_)
            | PeerPacket::KadFirewallAck
            | PeerPacket::KadUdpFirewallRequest(_)
            | PeerPacket::Unknown { .. } => {}
        }
    }
}
