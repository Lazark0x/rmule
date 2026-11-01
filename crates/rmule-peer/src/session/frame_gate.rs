//! What a frame costs the link, ruled the way stock's handler rules it: by
//! when it came and who asked for it, before its body means anything.
//!
//! A read stock throws from reaches `PacketReceived`'s catch and disconnects
//! (2.3.3 `ClientTCPSocket.cpp:2018-2047`); a reader that logs and returns
//! keeps the link. So the question for each leg is never "is this frame well
//! formed" but "does stock's handler throw here". The phase gate runs on every
//! plain frame, packed ones once inflated; the solicitation gate runs on the
//! decoded packet, ahead of the event it would raise; the malformed path takes
//! the frames no decoder could read.

use rmule_primitives::{FileHash, Packet, PacketProtocol, part_count};

use super::download::{HashSetState, SlotState};
use super::{PeerEvent, PeerSession, PeerViolation, State};
use crate::aich::HEADER_LEN as AICH_HEADER_LEN;
use crate::error::{PeerPacketDecodeError, WireFault};
use crate::hello::HelloRefusal;
use crate::opcode::PeerOpcode;
use crate::packet::PeerPacket;
use crate::source_exchange::SourceExchangeVersion;
use crate::{ConnectionEvent, NoticeEvent, RequesterEvent, ServerEvent};

/// `<file_hash 16>`, the head of every leg below that names its file.
const HASH_LEN: usize = FileHash::BYTE_LEN;
/// The eMule opcodes stock refuses while `CheckHandshakeFinished` is false
/// (`ClientTCPSocket.cpp:1053`, `:1208`, `:1301`, `:1330`, `:1342`, `:1360`,
/// `:1421`, `:1442`, `:1504`, `:1528`, `:1554`).
const HANDSHAKE_GATED: [PeerOpcode; 14] = [
    PeerOpcode::MultiPacket,
    PeerOpcode::MultiPacketExt,
    PeerOpcode::MultiPacketAnswer,
    PeerOpcode::SecIdentState,
    PeerOpcode::PublicKey,
    PeerOpcode::Signature,
    PeerOpcode::CompressedPart,
    PeerOpcode::CompressedPartI64,
    PeerOpcode::SendingPartI64,
    PeerOpcode::QueueRanking,
    PeerOpcode::RequestSources,
    PeerOpcode::RequestSources2,
    PeerOpcode::AnswerSources,
    PeerOpcode::AnswerSources2,
];

/// Whether `packet` is `opcode` under its own protocol byte.
fn is(packet: &Packet, opcode: PeerOpcode) -> bool {
    packet.protocol() == opcode.protocol() && packet.opcode() == opcode.as_u8()
}

impl PeerSession {
    /// The close a frame costs for arriving when it did, whatever it holds.
    /// A link waiting for a hello has no client yet, and stock throws on every
    /// frame but `OP_HELLO` (`:307-308`, `:1027-1029`). A dial whose hello is
    /// unanswered throws on [`HANDSHAKE_GATED`] and `OP_FILEDESC`; the eDonkey
    /// legs only log it (`:309-311`).
    pub(super) fn refused_by_phase(&self, packet: &Packet) -> Option<PeerViolation> {
        match self.state {
            State::AwaitingHello if !is(packet, PeerOpcode::Hello) => {
                Some(PeerViolation::BeforeHello)
            }
            State::AwaitingHelloAnswer
                if HANDSHAKE_GATED.iter().any(|gated| is(packet, *gated))
                    || (packet.protocol() == PacketProtocol::Emule
                        && packet.opcode() == crate::human_layer::OP_FILEDESC) =>
            {
                Some(PeerViolation::HandshakeUnfinished)
            }
            _ => None,
        }
    }

    /// The close a decoded packet costs for answering what this link never
    /// asked. Stock's readers throw on a file that is not the client's own
    /// request file; a link here can ask after several files, so a file with a
    /// flow is one it asked about.
    pub(super) fn refused_as_unsolicited(
        &self,
        frame: &Packet,
        packet: &PeerPacket,
    ) -> Option<PeerViolation> {
        match packet {
            // `DownloadClient.cpp:339-348`, `:1213-1224` of the bundle.
            PeerPacket::ReqFileNameAnswer(answer) => self.asked_about(answer.file_hash),
            PeerPacket::MultiPacketAnswer(answer) => self.asked_about(answer.file_hash),
            PeerPacket::FileStatus(status) => self
                .asked_about(status.file_hash)
                .or_else(|| self.status_cut_short(frame, status)),
            // `DownloadClient.cpp:573-578`: `m_fHashsetRequesting` falls when
            // an answer lands, so a second one throws as a first unasked does.
            PeerPacket::HashSetAnswer(answer) => self.asked_about(answer.file_hash).or_else(|| {
                let pending = self
                    .per_file
                    .get(&answer.file_hash)
                    .is_some_and(|flow| matches!(flow.hash_set, HashSetState::Pending));
                (!pending).then_some(PeerViolation::Unsolicited)
            }),
            // `BaseClient.cpp:1178-1183`: a comment names no file, and throws
            // when the client has none.
            PeerPacket::FileDesc(_) => self.per_file.is_empty().then_some(PeerViolation::WrongFile),
            // `DownloadClient.cpp:1606-1608`.
            PeerPacket::AichAnswer(_) | PeerPacket::AichRefused(_) => self
                .asked_aich
                .is_empty()
                .then_some(PeerViolation::Unsolicited),
            PeerPacket::SendingPart(part) => {
                self.block_refused(part.file_hash, part.start == part.end)
            }
            PeerPacket::CompressedPart(part) => {
                self.block_refused(part.file_hash, part.compressed_chunk.is_empty())
            }
            _ => None,
        }
    }

    fn asked_about(&self, file_hash: FileHash) -> Option<PeerViolation> {
        (!self.per_file.contains_key(&file_hash)).then_some(PeerViolation::WrongFile)
    }

    /// `ProcessFileStatus` reads the bitmap one part at a time up to the
    /// file's real count (`DownloadClient.cpp:430-449`) and throws where the
    /// bytes end, so only the side that knows the file can tell a cut status.
    fn status_cut_short(
        &self,
        frame: &Packet,
        status: &crate::file_request::FileStatus,
    ) -> Option<PeerViolation> {
        let file_size = self.per_file.get(&status.file_hash)?.file_size?;
        let bits = status.bitmap.count() != 0
            && u32::from(status.bitmap.count())
                == rmule_primitives::ed2k_status_part_count(file_size);
        let held = frame.payload().len().saturating_sub(HASH_LEN + 2);
        (bits && held < (part_count(file_size) as usize).div_ceil(8))
            .then_some(PeerViolation::MalformedFrame)
    }

    /// The file whose blocks this link reads now: stock reads none outside
    /// `DS_DOWNLOADING` (`DownloadClient.cpp:836-838`).
    fn downloading_file(&self) -> Option<FileHash> {
        let active = self.active_slot?;
        let flow = self.per_file.get(&active)?;
        (flow.slot == SlotState::Downloading).then_some(active)
    }

    /// Inside a slot a block of another file throws (`:856-858`), and one with
    /// no bytes throws with the corrupted ones (`:885-887`).
    fn block_refused(&self, file_hash: FileHash, empty: bool) -> Option<PeerViolation> {
        let active = self.downloading_file()?;
        if file_hash != active {
            return Some(PeerViolation::WrongFile);
        }
        empty.then_some(PeerViolation::MalformedFrame)
    }

    /// A frame no decoder could read. Most legs close here; the ones listed
    /// are where stock's reader returns instead of throwing, or never reads.
    pub(super) fn on_malformed_frame(&mut self, frame: &Packet, error: PeerPacketDecodeError) {
        match error {
            PeerPacketDecodeError::SourceExchange { source } => {
                if self.source_answer_throws(frame, 0, true) {
                    return self.close_protocol_violation(PeerViolation::MalformedFrame);
                }
                self.skip_source_answer(source.into());
            }
            PeerPacketDecodeError::SourceExchange2 { source } => {
                let counted = frame
                    .payload()
                    .first()
                    .is_some_and(|version| SourceExchangeVersion::from_u8(*version).is_some());
                if self.source_answer_throws(frame, 1, counted) {
                    return self.close_protocol_violation(PeerViolation::MalformedFrame);
                }
                self.skip_source_answer(source.into());
            }
            PeerPacketDecodeError::Hello { source }
            | PeerPacketDecodeError::HelloAnswer { source } => {
                if let Some(refusal) = HelloRefusal::from_decode_error(&source) {
                    self.core
                        .push_event(PeerEvent::Connection(ConnectionEvent::HelloRefused {
                            refusal,
                        }));
                }
                self.close_protocol_violation(PeerViolation::BadHello);
            }
            PeerPacketDecodeError::Frame { source } => self.on_malformed_leg(frame, &source),
        }
    }

    fn on_malformed_leg(&mut self, frame: &Packet, fault: &WireFault) {
        if is(frame, PeerOpcode::StartUploadReq) {
            // Scored before its size is looked at, and then let pass
            // (`:601-618`); a dial with its hello unanswered breaks out first.
            if matches!(self.state, State::Identified(_)) {
                self.core
                    .push_event(PeerEvent::Server(ServerEvent::MalformedSlotAsk));
            }
            return self.notice_unread(frame);
        }
        if [
            PeerOpcode::SendingPart,
            PeerOpcode::SendingPartI64,
            PeerOpcode::CompressedPart,
            PeerOpcode::CompressedPartI64,
        ]
        .iter()
        .any(|opcode| is(frame, *opcode))
        {
            return self.on_malformed_block(frame, fault);
        }
        if is(frame, PeerOpcode::AichAnswer) {
            return self.on_malformed_aich_answer(frame);
        }
        self.close_protocol_violation(PeerViolation::MalformedFrame);
    }

    /// `ProcessBlockPacket`'s `catch (CEOFException)` logs a cut header and
    /// returns (`DownloadClient.cpp:1039-1046`). Only a wrong file, read
    /// before the cut, and a range the bytes deny throw past it.
    fn on_malformed_block(&mut self, frame: &Packet, fault: &WireFault) {
        let Some(active) = self.downloading_file() else {
            return self.notice_unread(frame);
        };
        let hash = frame.payload().first_chunk::<HASH_LEN>();
        if hash.is_some_and(|hash| *hash != *active.as_bytes()) {
            return self.close_protocol_violation(PeerViolation::WrongFile);
        }
        if matches!(fault, WireFault::Truncated { .. }) {
            return self.notice_unread(frame);
        }
        self.close_protocol_violation(PeerViolation::MalformedFrame);
    }

    /// `ProcessAICHAnswer` throws with no ask out, reads the part next, and
    /// reads the root only for the file and part asked; any other answer
    /// fails the ask and keeps the link (`DownloadClient.cpp:1606-1641`).
    fn on_malformed_aich_answer(&mut self, frame: &Packet) {
        if self.asked_aich.is_empty() {
            return self.close_protocol_violation(PeerViolation::Unsolicited);
        }
        let payload = frame.payload();
        debug_assert!(payload.len() < AICH_HEADER_LEN);
        let Some((hash, part)) = payload
            .first_chunk::<HASH_LEN>()
            .zip(payload.get(HASH_LEN..HASH_LEN + 2))
        else {
            return self.close_protocol_violation(PeerViolation::MalformedFrame);
        };
        let file_hash = FileHash::from_bytes(*hash);
        let part = u16::from_le_bytes([part[0], part[1]]);
        if self.settle_aich_ask(file_hash, part) {
            return self.close_protocol_violation(PeerViolation::MalformedFrame);
        }
        self.core
            .push_event(PeerEvent::Requester(RequesterEvent::AichRefused {
                file_hash: Some(file_hash),
            }));
    }

    /// `AddClientSources` returns on a list it cannot size, and only the
    /// reads ahead of that can throw (`:1508`, `:1532-1533`,
    /// `PartFile.cpp:2699`, `:2740`): the hash always, the count for a file
    /// being fetched. `counted` says the count would be read at all: an SX2
    /// version stock does not know returns ahead of it (`PartFile.cpp:2735`).
    fn source_answer_throws(&self, frame: &Packet, hash_at: usize, counted: bool) -> bool {
        let payload = frame.payload();
        let Some(hash) = payload
            .get(hash_at..)
            .and_then(<[u8]>::first_chunk::<HASH_LEN>)
        else {
            return true;
        };
        let count_cut = payload.len() < hash_at + HASH_LEN + 2;
        count_cut && counted && self.per_file.contains_key(&FileHash::from_bytes(*hash))
    }

    fn skip_source_answer(&mut self, reason: crate::source_exchange::AnswerSourcesSkip) {
        self.core.push_event(PeerEvent::Requester(
            RequesterEvent::SourceExchangeAnswerSkipped { reason },
        ));
    }

    /// One frame stock let pass, shape only, nothing of it kept.
    pub(super) fn notice_unread(&mut self, frame: &Packet) {
        self.core
            .push_event(PeerEvent::Notice(NoticeEvent::UnknownPacket {
                protocol: frame.protocol(),
                opcode: frame.opcode(),
                payload_len: frame.payload().len(),
            }));
    }
}
