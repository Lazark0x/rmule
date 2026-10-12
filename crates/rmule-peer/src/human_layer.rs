//! The peer-TCP **human-layer catalog** (ADR-0068): browse, public-IP
//! self-discovery, chat, file comments, and client-ID reassignment. rmule
//! behaves byte-exact as an aMule 2.3.3 client at its most private setting
//! (`CanSeeShares = nobody`, no comments/ratings feature, chat received but
//! never answered) — Private-Citizen Parity, the human-layer sibling of
//! `rmule-kad`'s `notes` module's Empty-Storer Parity (ADR-0063).
//!
//! Every payload-less opcode this catalog needs (the browse requests/answers,
//! `OP_PUBLICIP_REQ`, the chat-captcha pair) is a bare `PeerPacket` unit
//! variant handled directly in `packet.rs` (mirroring `BuddyPing`/
//! `BuddyPong`); this module holds only the four opcodes whose payload
//! carries real fields (`Message`, `FileDesc`, `ChangeClientId`,
//! `PublicIpAnswer`), plus the two raw wire bytes `packet.rs` special-cases
//! ahead of the shared [`PeerOpcode`] registry:
//! `0x60` and `0x61` each carry a second meaning under the opposite protocol
//! byte that the registry's byte-keyed `try_from_u8` cannot also claim
//! (ADR-0025) — `OP_ASKSHAREDFILESDIRANS` (Edonkey) collides with the
//! already-modeled `OP_QUEUERANKING` (Emule, `PeerOpcode::QueueRanking`);
//! `OP_FILEDESC` (Emule) collides with `OP_ASKSHAREDDENIEDANS` (Edonkey).
//!
//! ## Provenance
//!
//! Opcodes and payload shapes read from the pinned aMule source
//! (`4e8f2b3c3f90cda23765730546b04c684a92e4f5`), per ADR-0068:
//!
//! - `OP_MESSAGE` (`0x4E`, Edonkey): `<len 2><text>`. The declared length
//!   must exactly account for the whole frame — aMule's own strict check
//!   ([ClientTCPSocket.cpp#L800](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L800));
//!   only the *read* is capped at [`MAX_CLIENT_MSG_LEN`] bytes (aMule
//!   truncates an oversize message, never rejects it).
//! - `OP_FILEDESC` (`0x61`, Emule): `<rating 1><len 4><comment>`
//!   ([BaseClient.cpp#L1176](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/BaseClient.cpp#L1176)).
//!   The header's own comment reads `<len 2><NAME len>` — stale; the real
//!   handler (`ProcessMuleCommentPacket`) is what's modeled here, matching
//!   the ADR. The comment is a **safe read**: a declared `len4` past the
//!   actual remaining bytes clamps to what's there instead of failing
//!   ("won't break if string size is < than advertised len"), and trailing
//!   bytes after it are tolerated (aMule's handler never checks for them);
//!   the read is additionally capped at [`MAX_FILE_COMMENT_LEN`] bytes.
//! - `OP_CHANGE_CLIENT_ID` (`0x4D`, Edonkey): `<newID 4><newServerIP 4>`
//!   ([ClientTCPSocket.cpp#L765](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L765)).
//!   The header's own comment reads `<ID_old 4><ID_new 4>` — likewise stale.
//! - `OP_PUBLICIP_ANSWER` (`0x98`, Emule): `<ip 4>`
//!   ([ClientTCPSocket.cpp#L1578](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L1578)).

use std::net::Ipv4Addr;

use rmule_primitives::{ClientId, Ed2kText, Packet, PacketProtocol, WireReader, WireTruncated};
use thiserror::Error;

use crate::opcode::PeerOpcode;

/// `OP_ASKSHAREDFILESDIRANS` under Edonkey — collides with `OP_QUEUERANKING`
/// under Emule (`PeerOpcode::QueueRanking`), so it is deliberately not a
/// `PeerOpcode` variant (see the module doc). `packet.rs` special-cases the
/// raw `(protocol, opcode)` pair ahead of the shared registry. Payload-less
/// on rmule's side: it is never emitted (rmule never browses) and, received,
/// is an unsolicited answer to parse-count-drop, never inspected.
pub(crate) const OP_ASKSHAREDFILESDIRANS: u8 = 0x60;

/// `OP_ASKSHAREDDENIEDANS` under Edonkey — collides with `OP_FILEDESC` under
/// Emule, so it is deliberately not a `PeerOpcode` variant either (see
/// [`OP_ASKSHAREDFILESDIRANS`]). rmule both emits this (the browse-denied
/// reply) and may receive an unsolicited copy (dropped).
pub(crate) const OP_ASKSHAREDDENIEDANS: u8 = 0x61;

/// `OP_FILEDESC` under Emule — the other side of [`OP_ASKSHAREDDENIEDANS`]'s
/// collision.
pub(crate) const OP_FILEDESC: u8 = 0x61;

/// aMule's inbound chat cap (`ClientTCPSocket.cpp`'s `MAX_CLIENT_MSG_LEN`):
/// text past this many bytes is truncated, never rejected.
const MAX_CLIENT_MSG_LEN: usize = 450;

/// aMule's `MAXFILECOMMENTLEN`
/// ([Constants.h](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/include/protocol/ed2k/Constants.h)):
/// a received file comment is truncated to this many bytes, never rejected.
const MAX_FILE_COMMENT_LEN: usize = 50;

/// `OP_MESSAGE` (`0x4E`): inbound chat text (ADR-0068 surface-as-event; rmule
/// has no chat feature, so it never replies and applies no spam gate — the
/// captcha machinery exists to protect a chat feature rmule doesn't have).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// Already capped to `MAX_CLIENT_MSG_LEN` bytes, matching aMule's own
    /// truncation (not rejection) of an oversize message.
    pub text: Ed2kText,
}

impl Message {
    /// Decode `<len2><text>`. The declared length must exactly account for
    /// the whole frame (aMule's strict check); only the *read* is capped to
    /// `MAX_CLIENT_MSG_LEN` bytes.
    pub fn decode_packet(packet: &Packet) -> Result<Self, HumanLayerDecodeError> {
        let payload = packet.payload();
        let mut reader = WireReader::new(payload);
        let declared_len = usize::from(reader.read_u16_le("message length")?);
        if declared_len + 2 != payload.len() {
            return Err(HumanLayerDecodeError::SizeMismatch {
                declared: declared_len,
                actual: payload.len(),
            });
        }
        let read_len = declared_len.min(MAX_CLIENT_MSG_LEN);
        let text = Ed2kText::from_bytes(reader.take(read_len, "message text")?.to_vec());
        Ok(Self { text })
    }

    #[must_use]
    /// Frame the message, length-prefixed.
    pub fn encode_packet(&self) -> Packet {
        let text = self.text.as_bytes();
        let mut payload = Vec::with_capacity(2 + text.len());
        let len = u16::try_from(text.len()).expect("chat message length exceeds u16");
        payload.extend_from_slice(&len.to_le_bytes());
        payload.extend_from_slice(text);
        Packet::new(
            PeerOpcode::Message.protocol(),
            PeerOpcode::Message.as_u8(),
            payload,
        )
    }
}

/// `OP_FILEDESC` (`0x61` under Emule): inbound file rating/comment (ADR-0068
/// surface-as-event). Collides with `OP_ASKSHAREDDENIEDANS` (`0x61` under
/// Edonkey; see the module doc), so `packet.rs` special-cases the raw
/// `(protocol, opcode)` pair ahead of the shared registry — this decoder
/// self-validates both rather than trusting an upstream `PeerOpcode` match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileDesc {
    /// Raw wire byte, preserved as-is: aMule clamps an out-of-range (`> 5`)
    /// rating to 0 internally for its own rating store, but rmule has no
    /// rating store — no clamping to replicate — so this surfaces the byte
    /// the peer actually sent.
    pub rating: u8,
    /// Already capped to `MAX_FILE_COMMENT_LEN` bytes, matching aMule's own
    /// truncation.
    pub comment: Ed2kText,
}

impl FileDesc {
    /// `<rating 1><len 4><comment>`, self-validated (see the type doc): the
    /// rating and length prefix are a hard 5-byte header — aMule's own
    /// primitive reads are not safe-guarded — but the comment string itself
    /// is a **safe read**, clamped to whatever remains rather than rejected,
    /// and trailing bytes past it are tolerated.
    pub fn decode_packet(packet: &Packet) -> Result<Self, HumanLayerDecodeError> {
        if packet.protocol() != PacketProtocol::Emule || packet.opcode() != OP_FILEDESC {
            return Err(HumanLayerDecodeError::WrongFrame {
                opcode: packet.opcode(),
            });
        }
        let mut reader = WireReader::new(packet.payload());
        let rating = reader.read_u8("rating")?;
        let declared_len =
            usize::try_from(reader.read_u32_le("comment length")?).unwrap_or(usize::MAX);
        let read_len = declared_len
            .min(reader.remaining())
            .min(MAX_FILE_COMMENT_LEN);
        let comment = Ed2kText::from_bytes(reader.take(read_len, "comment")?.to_vec());
        Ok(Self { rating, comment })
    }

    #[must_use]
    /// Frame the rating and comment.
    pub fn encode_packet(&self) -> Packet {
        let comment = self.comment.as_bytes();
        let mut payload = Vec::with_capacity(1 + 4 + comment.len());
        payload.push(self.rating);
        let len = u32::try_from(comment.len()).expect("file comment length exceeds u32");
        payload.extend_from_slice(&len.to_le_bytes());
        payload.extend_from_slice(comment);
        Packet::new(PacketProtocol::Emule, OP_FILEDESC, payload)
    }
}

/// `OP_CHANGE_CLIENT_ID` (`0x4D`): a peer's ID (and, when Low-ID, its server)
/// changed. Wire-silent either way — aMule marks it "Unused for sending" and
/// rmule never emits it — but the session applies it to the identity it keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChangeClientId {
    /// The id the peer now answers to.
    pub new_id: ClientId,
    /// The server it named alongside that id.
    pub new_server_ip: Ipv4Addr,
}

impl ChangeClientId {
    const PAYLOAD_LEN: usize = 8;

    /// Read the change, which is a fixed eight bytes.
    pub fn decode_packet(packet: &Packet) -> Result<Self, HumanLayerDecodeError> {
        let payload = packet.payload();
        if payload.len() != Self::PAYLOAD_LEN {
            return Err(HumanLayerDecodeError::WrongPayloadLen {
                expected: Self::PAYLOAD_LEN,
                actual: payload.len(),
            });
        }
        let mut reader = WireReader::new(payload);
        let new_id = ClientId::from_u32(reader.read_u32_le("new client id")?);
        let new_server_ip = Ipv4Addr::from(reader.read_array::<4>("new server address")?);
        Ok(Self {
            new_id,
            new_server_ip,
        })
    }

    #[must_use]
    /// Frame the change. rmule never sends one; the encoder exists so a capture can be replayed.
    pub fn encode_packet(&self) -> Packet {
        let mut payload = Vec::with_capacity(Self::PAYLOAD_LEN);
        payload.extend_from_slice(&self.new_id.as_u32().to_le_bytes());
        payload.extend_from_slice(&self.new_server_ip.octets());
        Packet::new(
            PeerOpcode::ChangeClientId.protocol(),
            PeerOpcode::ChangeClientId.as_u8(),
            payload,
        )
    }
}

/// `OP_PUBLICIP_ANSWER` (`0x98`): rmule's answer to a peer's
/// `OP_PUBLICIP_REQ` (respond-by-parity), or an unsolicited copy rmule
/// receives and drops (rmule never asks — IDCHANGE serves that need,
/// ADR-0047).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicIpAnswer {
    /// The address the peer observed us at.
    pub ip: Ipv4Addr,
}

impl PublicIpAnswer {
    const PAYLOAD_LEN: usize = 4;

    /// Read the answer, which is one IPv4 address.
    pub fn decode_packet(packet: &Packet) -> Result<Self, HumanLayerDecodeError> {
        let payload = packet.payload();
        if payload.len() != Self::PAYLOAD_LEN {
            return Err(HumanLayerDecodeError::WrongPayloadLen {
                expected: Self::PAYLOAD_LEN,
                actual: payload.len(),
            });
        }
        let mut reader = WireReader::new(payload);
        Ok(Self {
            ip: Ipv4Addr::from(reader.read_array::<4>("public address")?),
        })
    }

    #[must_use]
    /// Frame the answer.
    pub fn encode_packet(&self) -> Packet {
        Packet::new(
            PeerOpcode::PublicIpAnswer.protocol(),
            PeerOpcode::PublicIpAnswer.as_u8(),
            self.ip.octets().to_vec(),
        )
    }
}

impl From<WireTruncated> for HumanLayerDecodeError {
    fn from(truncated: WireTruncated) -> Self {
        Self::Truncated {
            needed: truncated.needed,
            actual: truncated.available,
        }
    }
}

/// Why a human-layer packet with real fields could not be decoded.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum HumanLayerDecodeError {
    /// The decoder was handed some other opcode — these opcodes collide
    /// across protocols, so the frame check is part of decoding.
    #[error("not the expected human-layer frame: opcode 0x{opcode:02X}")]
    WrongFrame {
        /// The opcode that arrived.
        opcode: u8,
    },

    /// The payload ended inside the header.
    #[error("human-layer payload truncated: needed at least {needed} bytes, had {actual}")]
    Truncated {
        /// Bytes the header requires.
        needed: usize,
        /// Bytes present.
        actual: usize,
    },

    /// A fixed-size packet was not that size.
    #[error("human-layer payload wrong size: expected {expected} bytes, had {actual}")]
    WrongPayloadLen {
        /// The size the shape requires.
        expected: usize,
        /// The size that arrived.
        actual: usize,
    },

    /// A declared text length overruns the frame that carries it.
    #[error("declared length {declared} does not match frame size {actual}")]
    SizeMismatch {
        /// The length declared.
        declared: usize,
        /// The frame's own size.
        actual: usize,
    },
}
