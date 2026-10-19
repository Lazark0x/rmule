//! The eD2k frame envelope: the protocol byte (eDonkey, eMule, or packed), the
//! length-prefixed header every frame opens with, and the opcode plus payload
//! it carries. Decoding enforces the frame ceiling so a malformed length cannot
//! make a reader allocate on a counterparty's word.

use crate::{PrimitiveError, Result};

const EDONKEY_PROTOCOL_BYTE: u8 = 0xE3;
const EMULE_PROTOCOL_BYTE: u8 = 0xC5;
const PACKED_ED2K_PROTOCOL_BYTE: u8 = 0xD4;
const PACKET_HEADER_LEN: usize = 5;

/// Maximum decoded length (opcode + payload) the framer accepts.
///
/// A hostile peer can declare `length = u32::MAX` in the frame header
/// (~4 GiB), so without a cap the decoder would happily report a
/// `TruncatedPacket` with `needed = 4 GiB+5`, and a streaming caller
/// that pre-allocates `needed` bytes would OOM. 16 MiB sits well above
/// any wire-realistic packet — the welcome burst is < 1 KiB, the
/// (future) compression transport caps inflation at 250 KB — and well
/// below any plausible allocation budget.
const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

/// Which of the three eD2k framings a packet uses, named by its marker byte.
///
/// The marker is not a version: a session mixes all three freely, choosing per
/// packet according to which opcode it carries and whether the body was worth
/// compressing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PacketProtocol {
    /// Standard eDonkey protocol (`OP_EDONKEYPROT = 0xE3`).
    Edonkey,
    /// eMule extended protocol (`OP_EMULEPROT = 0xC5`). Carries
    /// extended-only opcodes like `OP_QUEUERANKING`,
    /// `OP_REQUESTPARTS_I64`, `OP_SENDINGPART_I64`.
    Emule,
    /// Zlib-compressed eD2k frame (`OP_PACKEDPROT = 0xD4`).
    PackedEd2k,
}

impl PacketProtocol {
    /// The marker byte this protocol is written as.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Edonkey => EDONKEY_PROTOCOL_BYTE,
            Self::Emule => EMULE_PROTOCOL_BYTE,
            Self::PackedEd2k => PACKED_ED2K_PROTOCOL_BYTE,
        }
    }

    /// Stable, human-readable protocol tag for diagnostics and packet
    /// inspection. The single home for this projection: `rmule-peer`'s
    /// `PeerEvent` Display and `rmule-tools`' packet inspectors both consume it
    /// instead of re-deriving the mapping.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Edonkey => "edonkey",
            Self::Emule => "emule",
            Self::PackedEd2k => "packed-ed2k",
        }
    }
}

/// One eD2k frame: its protocol marker, its opcode, and the payload bytes
/// left uninterpreted.
///
/// The payload stays raw here so framing and meaning never depend on each
/// other — a frame whose opcode this build has no model for still decodes,
/// still re-encodes byte-identically, and can be kept rather than dropped
/// (ADR-0018).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    protocol: PacketProtocol,
    opcode: u8,
    payload: Vec<u8>,
}

impl Packet {
    /// A packet from its three parts, ready to encode.
    pub fn new(protocol: PacketProtocol, opcode: u8, payload: Vec<u8>) -> Self {
        Self {
            protocol,
            opcode,
            payload,
        }
    }

    /// Decode a buffer that must hold exactly one frame.
    ///
    /// # Errors
    /// [`PrimitiveError::TrailingPacketBytes`] if anything follows the frame,
    /// plus everything [`Self::decode`] can raise.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self> {
        let (packet, consumed) = Self::decode(bytes)?;
        if consumed != bytes.len() {
            return Err(PrimitiveError::TrailingPacketBytes {
                trailing: bytes.len() - consumed,
            });
        }
        Ok(packet)
    }

    /// Decode the first frame in `bytes`, returning it and how many bytes it
    /// consumed — the streaming entry point, so a reader can loop over a
    /// buffer holding several frames.
    ///
    /// # Errors
    /// [`PrimitiveError::TruncatedPacket`] when the buffer stops short (wait
    /// for more bytes), [`PrimitiveError::UnsupportedProtocolByte`] on an
    /// unknown marker, [`PrimitiveError::InvalidPacketLength`] on a zero or
    /// over-ceiling declared length.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.len() < PACKET_HEADER_LEN {
            return Err(PrimitiveError::TruncatedPacket {
                needed: PACKET_HEADER_LEN,
                actual: bytes.len(),
            });
        }

        let protocol = match bytes[0] {
            EDONKEY_PROTOCOL_BYTE => PacketProtocol::Edonkey,
            EMULE_PROTOCOL_BYTE => PacketProtocol::Emule,
            PACKED_ED2K_PROTOCOL_BYTE => PacketProtocol::PackedEd2k,
            protocol => return Err(PrimitiveError::UnsupportedProtocolByte { protocol }),
        };
        let length = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        if length == 0 || length > MAX_FRAME_LEN {
            return Err(PrimitiveError::InvalidPacketLength { length });
        }

        let length_usize =
            usize::try_from(length).map_err(|_| PrimitiveError::InvalidPacketLength { length })?;
        let packet_len = PACKET_HEADER_LEN
            .checked_add(length_usize)
            .ok_or(PrimitiveError::InvalidPacketLength { length })?;
        if bytes.len() < packet_len {
            return Err(PrimitiveError::TruncatedPacket {
                needed: packet_len,
                actual: bytes.len(),
            });
        }

        let opcode = bytes[PACKET_HEADER_LEN];
        let payload = bytes[PACKET_HEADER_LEN + 1..packet_len].to_vec();
        Ok((
            Self {
                protocol,
                opcode,
                payload,
            },
            packet_len,
        ))
    }

    /// Serialize as a TCP frame: `[protocol][length LE u32][opcode][payload]`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        Self::encode_with(self.protocol, self.opcode, self.payload.len(), |frame| {
            frame.extend_from_slice(&self.payload);
        })
    }

    /// Serialize a TCP frame whose payload `write` appends in place, so a
    /// sender framing borrowed bytes copies them once, into the frame, rather
    /// than into a payload first. `payload_len` sizes the one allocation; the
    /// length field counts what `write` actually appended.
    ///
    /// # Panics
    /// If the payload is larger than a `u32` can express.
    #[must_use]
    pub fn encode_with(
        protocol: PacketProtocol,
        opcode: u8,
        payload_len: usize,
        write: impl FnOnce(&mut Vec<u8>),
    ) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(PACKET_HEADER_LEN + 1 + payload_len);
        encoded.push(protocol.as_byte());
        encoded.extend_from_slice(&[0; 4]);
        encoded.push(opcode);
        write(&mut encoded);
        let length = u32::try_from(encoded.len() - PACKET_HEADER_LEN)
            .expect("packet payload length exceeds u32");
        encoded[1..PACKET_HEADER_LEN].copy_from_slice(&length.to_le_bytes());
        encoded
    }

    /// Serialize for an eD2k **UDP** datagram: `[protocol][opcode][payload]` — no
    /// 4-byte length prefix, unlike [`Self::encode`] (the TCP frame). eD2k UDP packets
    /// carry a 2-byte header only (aMule `CMuleUDPSocket` writes `GetUDPHeader`, and
    /// the receive side reads `buffer[1]` directly as the opcode). The datagram
    /// boundary delimits a lone packet; a server may pack several, each delimited by
    /// its own body structure (the decoder advances per packet). Cite-and-rewrite
    /// only (ADR-0004).
    #[must_use]
    pub fn encode_udp(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(2 + self.payload.len());
        encoded.push(self.protocol.as_byte());
        encoded.push(self.opcode);
        encoded.extend_from_slice(&self.payload);
        encoded
    }

    /// Which framing this packet carries.
    #[must_use]
    pub const fn protocol(&self) -> PacketProtocol {
        self.protocol
    }

    /// The opcode byte, uninterpreted — its meaning depends on the protocol
    /// marker and on which side of a session is reading it.
    #[must_use]
    pub const fn opcode(&self) -> u8 {
        self.opcode
    }

    /// The payload bytes, exactly as they arrived.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The value the TCP frame's length field carries: the payload plus the
    /// opcode byte it counts.
    ///
    /// # Panics
    /// If the payload is larger than a `u32` can express, which decoding
    /// cannot produce — only a hand-built packet could.
    #[must_use]
    pub fn encoded_payload_len(&self) -> u32 {
        u32::try_from(self.payload.len() + 1).expect("packet payload length exceeds u32")
    }
}
