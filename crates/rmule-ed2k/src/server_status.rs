//! `OP_SERVERSTATUS` (0x34): the user and file counts a server reports, the
//! fixed eight-byte answer that follows a login.

use rmule_primitives::{Packet, PacketProtocol, ServerStatusReport};

use crate::{Ed2kError, Opcode, Result};

const PAYLOAD_LEN: usize = 8;

/// `OP_SERVERSTATUS`: the server's user and file counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerStatus {
    report: ServerStatusReport,
}

impl ServerStatus {
    /// A status packet carrying this report.
    #[must_use]
    pub const fn new(report: ServerStatusReport) -> Self {
        Self { report }
    }

    /// The counts, as the server claims them.
    #[must_use]
    pub const fn report(&self) -> &ServerStatusReport {
        &self.report
    }

    /// Decode this packet's payload.
    ///
    /// # Errors
    /// [`Ed2kError::InvalidPayload`] if the protocol byte, the opcode, or the
    /// body layout is not this packet's.
    pub fn decode_packet(packet: &Packet) -> Result<Self> {
        let opcode = Opcode::ServerStatus.as_u8();
        if packet.protocol() != PacketProtocol::Edonkey {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "unsupported packet protocol",
            });
        }
        if packet.opcode() != opcode {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "wrong opcode for OP_SERVERSTATUS",
            });
        }
        let payload = packet.payload();
        if payload.len() != PAYLOAD_LEN {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_SERVERSTATUS payload must be exactly 8 bytes",
            });
        }
        let user_count = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let file_count = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        Ok(Self {
            report: ServerStatusReport {
                user_count,
                file_count,
            },
        })
    }

    /// The packet form, ready to frame and send.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        let mut payload = Vec::with_capacity(PAYLOAD_LEN);
        payload.extend_from_slice(&self.report.user_count.to_le_bytes());
        payload.extend_from_slice(&self.report.file_count.to_le_bytes());
        Packet::new(
            PacketProtocol::Edonkey,
            Opcode::ServerStatus.as_u8(),
            payload,
        )
    }
}
