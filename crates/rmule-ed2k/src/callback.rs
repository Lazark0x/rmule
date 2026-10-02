//! `OP_CALLBACKREQUEST` (0x1C): asking our connected server to tell a Low-ID
//! source to dial us (ADR-0039).
//!
//! The inverse direction — the server telling *us* to dial a High-ID
//! requester because *we* are the Low-ID one — is `peer_callback`. Distinct
//! opcodes, distinct roles.

use rmule_primitives::{ClientId, Packet, PacketProtocol, empty_body_codec};

use crate::{Ed2kError, Opcode, Result};

const LOW_ID_LEN: usize = 4;

/// `OP_CALLBACKREQUEST` (`0x1C`) — rmule (High ID) asks its connected server to
/// relay an invitation to a Low-ID **source** so that source dials rmule back
/// (ADR-0039). Payload is the source's server-assigned low id, `[low_id u32]`,
/// pinned from aMule `BaseClient.cpp` (`WriteUInt32(m_nUserIDHybrid)` under
/// `OP_EDONKEYPROT`).
///
/// The inverse direction — the server telling *us* to dial a High-ID requester
/// because *we* are Low ID — is [`crate::PeerCallback`] (`OP_CALLBACKREQUESTED`,
/// `0x35`); the two are distinct opcodes and distinct roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CallbackRequest {
    /// The Low-ID source we want the server to invite.
    pub low_id: ClientId,
}

impl CallbackRequest {
    /// A callback request naming the source to invite.
    #[must_use]
    pub const fn new(low_id: ClientId) -> Self {
        Self { low_id }
    }

    /// Decode this packet's payload.
    ///
    /// # Errors
    /// [`Ed2kError::InvalidPayload`] if the protocol byte, the opcode, or the
    /// body layout is not this packet's.
    pub fn decode_packet(packet: &Packet) -> Result<Self> {
        let opcode = Opcode::CallbackRequest.as_u8();
        if packet.protocol() != PacketProtocol::Edonkey {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "unsupported packet protocol",
            });
        }
        if packet.opcode() != opcode {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "wrong opcode for OP_CALLBACKREQUEST",
            });
        }
        let payload = packet.payload();
        if payload.len() != LOW_ID_LEN {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_CALLBACKREQUEST payload must be a 4-byte low id",
            });
        }
        let low_id = ClientId::from_u32(u32::from_le_bytes(
            payload.try_into().expect("validated 4-byte low id"),
        ));
        Ok(Self { low_id })
    }

    /// The packet form, ready to frame and send.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        Packet::new(
            PacketProtocol::Edonkey,
            Opcode::CallbackRequest.as_u8(),
            self.low_id.as_u32().to_le_bytes().to_vec(),
        )
    }
}

empty_body_codec! {
    /// `OP_CALLBACK_FAIL` (`0x36`) — the server could not route a callback (the
    /// Low-ID source is gone or its id is unknown). aMule documents the payload as
    /// "null notverified", so the body is ignored. rmule treats this as a
    /// non-terminal release of the pending callback (ADR-0039).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    CallbackFailed, Ed2kError, Opcode::CallbackFail.as_u8(), "OP_CALLBACK_FAIL", tolerate_body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_request_encodes_the_low_id_little_endian_under_0x1c() {
        let packet = CallbackRequest::new(ClientId::from_u32(0x1234_5678)).encode_packet();
        assert_eq!(packet.protocol(), PacketProtocol::Edonkey);
        assert_eq!(packet.opcode(), 0x1C);
        assert_eq!(packet.payload(), &[0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn callback_request_round_trips() {
        let request = CallbackRequest::new(ClientId::from_u32(42));
        let decoded = CallbackRequest::decode_packet(&request.encode_packet()).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn callback_request_rejects_a_non_four_byte_payload() {
        let bad = Packet::new(PacketProtocol::Edonkey, 0x1C, vec![1, 2, 3]);
        assert!(CallbackRequest::decode_packet(&bad).is_err());
    }

    #[test]
    fn callback_failed_is_an_empty_0x36_packet_and_ignores_a_body() {
        let packet = CallbackFailed.encode_packet();
        assert_eq!(packet.opcode(), 0x36);
        assert!(packet.payload().is_empty());
        // a server that sends a stray body still decodes (null notverified).
        let with_body = Packet::new(PacketProtocol::Edonkey, 0x36, vec![0xFF]);
        assert_eq!(
            CallbackFailed::decode_packet(&with_body).unwrap(),
            CallbackFailed
        );
    }
}
