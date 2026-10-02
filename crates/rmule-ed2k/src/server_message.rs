//! `OP_SERVERMESSAGE` (0x38): free text a server pushes at its clients —
//! motd, warnings, rejections in prose.
//!
//! The wire length prefix is a `u16`, so the cap is validated at construction
//! and encoding stays infallible.

use rmule_primitives::{Ed2kText, Packet, PacketProtocol};

use crate::{Ed2kError, Opcode, Result};

const TEXT_LENGTH_PREFIX: usize = 2;

/// `OP_SERVERMESSAGE`: free text for the user — a banner, a rule, a notice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerMessage {
    text: Ed2kText,
}

impl ServerMessage {
    /// Construct an `OP_SERVERMESSAGE` from its decoded text. The wire
    /// `text_length` field is a `u16`, so text byte length is capped at
    /// `u16::MAX`. Validating at construction rather than at encode time
    /// keeps `encode_packet` infallible.
    pub fn new(text: Ed2kText) -> Result<Self> {
        if u16::try_from(text.as_bytes().len()).is_err() {
            return Err(Ed2kError::InvalidPayload {
                opcode: Opcode::ServerMessage.as_u8(),
                reason: "OP_SERVERMESSAGE text exceeds u16 wire ceiling (65535 bytes)",
            });
        }
        Ok(Self { text })
    }

    /// The message, byte-faithful: server banners are routinely not UTF-8.
    #[must_use]
    pub const fn text(&self) -> &Ed2kText {
        &self.text
    }

    /// Decode this packet's payload.
    ///
    /// # Errors
    /// [`Ed2kError::InvalidPayload`] if the protocol byte, the opcode, or the
    /// body layout is not this packet's.
    pub fn decode_packet(packet: &Packet) -> Result<Self> {
        let opcode = Opcode::ServerMessage.as_u8();
        if packet.protocol() != PacketProtocol::Edonkey {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "unsupported packet protocol",
            });
        }
        if packet.opcode() != opcode {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "wrong opcode for OP_SERVERMESSAGE",
            });
        }

        let payload = packet.payload();
        if payload.len() < TEXT_LENGTH_PREFIX + 1 {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_SERVERMESSAGE payload smaller than length prefix + 1 byte",
            });
        }
        let declared = usize::from(u16::from_le_bytes([payload[0], payload[1]]));
        if declared != payload.len() - TEXT_LENGTH_PREFIX {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_SERVERMESSAGE text_length does not match payload",
            });
        }
        Ok(Self {
            text: Ed2kText::from_bytes(payload[TEXT_LENGTH_PREFIX..].to_vec()),
        })
    }

    /// The packet form, ready to frame and send.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        let bytes = self.text.as_bytes();
        // Invariant maintained by `Self::new` and `Self::decode_packet`:
        // text byte length fits in a `u16`.
        let len = u16::try_from(bytes.len()).expect("ServerMessage invariant: text fits in u16");
        let mut payload = Vec::with_capacity(TEXT_LENGTH_PREFIX + bytes.len());
        payload.extend_from_slice(&len.to_le_bytes());
        payload.extend_from_slice(bytes);
        Packet::new(
            PacketProtocol::Edonkey,
            Opcode::ServerMessage.as_u8(),
            payload,
        )
    }
}
