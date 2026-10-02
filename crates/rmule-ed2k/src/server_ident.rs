//! `OP_SERVERIDENT` (0x41): the server naming itself — its hash, the endpoint
//! it advertises, and the identity tags that carry its name and description.

use rmule_primitives::{
    Ipv4Endpoint, Packet, PacketProtocol, ServerHash, ServerIdentSource, ServerIdentity, Tag,
};

use crate::{Ed2kError, Opcode, Result};

const FIXED_PREFIX_LEN: usize = 16 + Ipv4Endpoint::WIRE_LEN + 4; // hash + endpoint + tag_count

/// `OP_SERVERIDENT`: the server describing itself — its hash, the address it
/// advertises, and its identity tags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerIdent {
    server_hash: ServerHash,
    advertised: Ipv4Endpoint,
    identity_tags: Vec<Tag>,
}

impl ServerIdent {
    /// An identity packet from its three wire fields.
    #[must_use]
    pub const fn new(
        server_hash: ServerHash,
        advertised: Ipv4Endpoint,
        identity_tags: Vec<Tag>,
    ) -> Self {
        Self {
            server_hash,
            advertised,
            identity_tags,
        }
    }

    /// The address the server says it is reached at — its own claim, which
    /// need not match the address we dialed.
    #[must_use]
    pub const fn advertised(&self) -> &Ipv4Endpoint {
        &self.advertised
    }

    /// The typed projection of this packet: name and description promoted,
    /// every other tag kept verbatim.
    #[must_use]
    pub fn identity(&self) -> ServerIdentity {
        ServerIdentity::from_serverident_source(self)
    }

    /// Decode this packet's payload.
    ///
    /// # Errors
    /// [`Ed2kError::InvalidPayload`] if the protocol byte, the opcode, or the
    /// body layout is not this packet's.
    pub fn decode_packet(packet: &Packet) -> Result<Self> {
        let opcode = Opcode::ServerIdent.as_u8();
        if packet.protocol() != PacketProtocol::Edonkey {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "unsupported packet protocol",
            });
        }
        if packet.opcode() != opcode {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "wrong opcode for OP_SERVERIDENT",
            });
        }

        let payload = packet.payload();
        if payload.len() < FIXED_PREFIX_LEN {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_SERVERIDENT payload smaller than fixed prefix",
            });
        }

        let server_hash = ServerHash::from_bytes(
            payload[0..16]
                .try_into()
                .expect("validated server hash length"),
        );
        let endpoint_chunk: &[u8; Ipv4Endpoint::WIRE_LEN] = payload
            [16..16 + Ipv4Endpoint::WIRE_LEN]
            .try_into()
            .expect("validated advertised endpoint length");
        let advertised = Ipv4Endpoint::decode(endpoint_chunk);
        let tag_count_offset = 16 + Ipv4Endpoint::WIRE_LEN;
        let tag_count = u32::from_le_bytes(
            payload[tag_count_offset..tag_count_offset + 4]
                .try_into()
                .expect("validated tag count length"),
        );
        let tag_count = usize::try_from(tag_count).map_err(|_| Ed2kError::InvalidPayload {
            opcode,
            reason: "OP_SERVERIDENT tag count exceeds usize",
        })?;

        let (tags, consumed) = Tag::decode_block(&payload[FIXED_PREFIX_LEN..], tag_count)?;
        let position = FIXED_PREFIX_LEN + consumed;
        if position != payload.len() {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "trailing bytes after OP_SERVERIDENT tag block",
            });
        }

        Ok(Self {
            server_hash,
            advertised,
            identity_tags: tags,
        })
    }

    /// The packet form, ready to frame and send.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        let tag_bytes: Vec<u8> = self.identity_tags.iter().flat_map(|t| t.encode()).collect();
        let mut payload = Vec::with_capacity(FIXED_PREFIX_LEN + tag_bytes.len());
        payload.extend_from_slice(self.server_hash.as_bytes());
        payload.extend_from_slice(&self.advertised.encode());
        let count =
            u32::try_from(self.identity_tags.len()).expect("OP_SERVERIDENT tag count exceeds u32");
        payload.extend_from_slice(&count.to_le_bytes());
        payload.extend_from_slice(&tag_bytes);
        Packet::new(
            PacketProtocol::Edonkey,
            Opcode::ServerIdent.as_u8(),
            payload,
        )
    }
}

impl ServerIdentSource for ServerIdent {
    fn server_hash(&self) -> ServerHash {
        self.server_hash
    }

    fn identity_tags(&self) -> &[Tag] {
        &self.identity_tags
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Made bytes, not a capture: a well-formed hash and endpoint, then a
    /// tag count of `u32::MAX` with no tag behind it.
    #[test]
    fn a_made_frame_claiming_four_billion_tags_is_refused_without_reserving_them() {
        let mut payload: Vec<u8> = (0x10..0x20).collect();
        payload.extend_from_slice(&[198, 51, 100, 23, 0x36, 0x12]);
        payload.extend_from_slice(&u32::MAX.to_le_bytes());
        let packet = Packet::new(
            PacketProtocol::Edonkey,
            Opcode::ServerIdent.as_u8(),
            payload,
        );

        assert!(ServerIdent::decode_packet(&packet).is_err());
    }
}
