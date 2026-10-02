//! The umbrella for every packet rmule sends a server: one typed variant per
//! client opcode, mirroring `server_packet` on the inbound side.
//!
//! Unknown well-formed opcodes keep their bytes (ADR-0018), so the inspector
//! and any replay tool can still surface what rmule has no model for.

use rmule_primitives::{Packet, PacketProtocol};

use crate::{
    CallbackRequest, Ed2kError, GetServerList, GetSourcesRequest, LoginRequest, OfferFiles, Opcode,
    QueryMoreResults, Result, SearchRequest,
};

/// Umbrella for every client-emitted packet rmule decodes. Mirrors
/// `ServerPacket`: unknown well-formed opcodes are preserved per ADR-0018 so
/// the inspector and any future replay tool can still surface them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientPacket {
    /// The login handshake.
    LoginRequest(LoginRequest),
    /// A request for more servers.
    GetServerList(GetServerList),
    /// A search.
    SearchRequest(SearchRequest),
    /// The next page of the link's last search.
    QueryMoreResults(QueryMoreResults),
    /// A source lookup, in whichever of its three forms the client used.
    GetSources(GetSourcesRequest),
    /// A request that the server invite a Low-ID source to dial us.
    CallbackRequest(CallbackRequest),
    /// A publication of the client's shared files.
    OfferFiles(OfferFiles),
    /// A well-formed frame whose opcode this build has no model for, kept
    /// whole rather than dropped (ADR-0018).
    Unknown {
        /// The unmodelled opcode.
        opcode: u8,
        /// Its payload, byte-for-byte as it arrived.
        payload: Vec<u8>,
    },
}

impl ClientPacket {
    /// Decode a client-emitted packet.
    ///
    /// # Errors
    /// [`Ed2kError::InvalidPayload`] if the protocol byte is not eD2k or a
    /// modelled opcode's body does not match its layout.
    pub fn decode(packet: &Packet) -> Result<Self> {
        if packet.protocol() != PacketProtocol::Edonkey {
            return Err(Ed2kError::InvalidPayload {
                opcode: packet.opcode(),
                reason: "unsupported packet protocol",
            });
        }
        let opcode = packet.opcode();
        if opcode == Opcode::LoginRequest.as_u8() {
            Ok(Self::LoginRequest(LoginRequest::decode_packet(packet)?))
        } else if opcode == Opcode::GetServerList.as_u8() {
            Ok(Self::GetServerList(GetServerList::decode_packet(packet)?))
        } else if opcode == Opcode::SearchRequest.as_u8() {
            Ok(Self::SearchRequest(SearchRequest::decode_packet(packet)?))
        } else if opcode == Opcode::QueryMoreResult.as_u8() {
            Ok(Self::QueryMoreResults(QueryMoreResults::decode_packet(
                packet,
            )?))
        } else if opcode == Opcode::GetSources.as_u8() || opcode == Opcode::GetSourcesObfu.as_u8() {
            Ok(Self::GetSources(GetSourcesRequest::decode_packet(packet)?))
        } else if opcode == Opcode::CallbackRequest.as_u8() {
            Ok(Self::CallbackRequest(CallbackRequest::decode_packet(
                packet,
            )?))
        } else if opcode == Opcode::OfferFiles.as_u8() {
            Ok(Self::OfferFiles(OfferFiles::decode_packet(packet)?))
        } else {
            Ok(Self::Unknown {
                opcode,
                payload: packet.payload().to_vec(),
            })
        }
    }

    #[must_use]
    /// Re-encode the packet; an unknown frame re-emits its kept bytes.
    pub fn encode(&self) -> Packet {
        match self {
            Self::LoginRequest(p) => p.encode_packet(),
            Self::GetServerList(p) => p.encode_packet(),
            Self::SearchRequest(p) => p.encode_packet(),
            Self::QueryMoreResults(p) => p.encode_packet(),
            Self::GetSources(p) => p.encode_packet(),
            Self::CallbackRequest(p) => p.encode_packet(),
            Self::OfferFiles(p) => p.encode_packet(),
            Self::Unknown { opcode, payload } => {
                Packet::new(PacketProtocol::Edonkey, *opcode, payload.clone())
            }
        }
    }
}
