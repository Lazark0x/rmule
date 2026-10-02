//! `OP_GLOBCALLBACKREQ` (0x9C): asking a Low-ID source's own
//! server — over UDP, with no TCP session of ours — to relay a callback so
//! that peer dials rmule back. The request self-reports rmule's contact
//! because the source-server cannot infer it from a session.

use rmule_primitives::{ClientId, Ipv4Endpoint, Packet, PacketProtocol};

use crate::{Ed2kError, Opcode, Result};

/// `OP_GLOBCALLBACKREQ` (0x9C): rmule (High-ID, listener bound) asks a Low-ID
/// global source's **own** source-server — over UDP, with no TCP session — to
/// relay a callback so that Low-ID peer dials rmule back (ADR-0039
/// generalized per-server). Unlike the connected-server TCP `OP_CALLBACKREQUEST`
/// (`<low_id u32>` only), the request self-reports rmule's contact because the
/// source-server cannot infer it from a session.
///
/// Body `[ip 4][port 2 LE][client_id 4 LE]` (`Ipv4Endpoint::encode` ++ the target
/// low id), pinned in `docs/reference/notes/server-udp.md` from aMule `UDP.h`
/// (`OP_GLOBCALLBACKREQ // <IP 4><PORT 2><client_ID 4>`) and the Wireshark
/// `packet-edonkey` dissector (`Callback Request: <Address> <Client ID>`).
/// Cite-and-rewrite only (ADR-0004).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GlobCallbackRequest {
    /// rmule's own public IP and advertised TCP listen port (where the peer dials).
    pub requester: Ipv4Endpoint,
    /// The target source's server-assigned Low-ID (which client the server relays to).
    pub low_id: ClientId,
}

impl GlobCallbackRequest {
    /// A relayed callback request: dial `requester` back on behalf of the
    /// client at `low_id`.
    #[must_use]
    pub const fn new(requester: Ipv4Endpoint, low_id: ClientId) -> Self {
        Self { requester, low_id }
    }

    /// The packet form, ready to frame and send.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        let mut payload = Vec::with_capacity(Ipv4Endpoint::WIRE_LEN + 4);
        payload.extend_from_slice(&self.requester.encode());
        payload.extend_from_slice(&self.low_id.as_u32().to_le_bytes());
        Packet::new(
            PacketProtocol::Edonkey,
            Opcode::GlobCallbackRequest.as_u8(),
            payload,
        )
    }

    /// Decode an `OP_GLOBCALLBACKREQ` UDP datagram (the source-server's view of the
    /// request, exercised by the loopback fake server). The frame is
    /// `[protocol 0xE3][opcode 0x9C]` then the fixed-width body
    /// `[ip 4][port 2 LE][client_id 4 LE]` — no length prefix.
    pub fn decode_udp(bytes: &[u8]) -> Result<Self> {
        let opcode = Opcode::GlobCallbackRequest.as_u8();
        let [protocol, op, body @ ..] = bytes else {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_GLOBCALLBACKREQ datagram missing header",
            });
        };
        if *protocol != PacketProtocol::Edonkey.as_byte() {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "unsupported packet protocol",
            });
        }
        if *op != opcode {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "wrong opcode for OP_GLOBCALLBACKREQ",
            });
        }
        if body.len() != Ipv4Endpoint::WIRE_LEN + 4 {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_GLOBCALLBACKREQ payload must be [ip 4][port 2][client_id 4]",
            });
        }
        let address: [u8; Ipv4Endpoint::WIRE_LEN] = body[..Ipv4Endpoint::WIRE_LEN]
            .try_into()
            .expect("validated 6-byte address");
        let low_id = ClientId::from_u32(u32::from_le_bytes(
            body[Ipv4Endpoint::WIRE_LEN..]
                .try_into()
                .expect("validated 4-byte client id"),
        ));
        Ok(Self {
            requester: Ipv4Endpoint::decode(&address),
            low_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmule_primitives::Ipv4Endpoint;
    use std::net::Ipv4Addr;

    /// The canonical `OP_GLOBCALLBACKREQ` wire body (cycle-0 pin):
    /// `[ip 4][port 2 LE][client_id 4 LE]`. IP 1.2.3.4 (octets in order),
    /// port 4662 = 0x1236, target low id 0x1234.
    const GLOB_CALLBACK_WIRE: [u8; 10] = [1, 2, 3, 4, 0x36, 0x12, 0x34, 0x12, 0x00, 0x00];

    fn sample_request() -> GlobCallbackRequest {
        GlobCallbackRequest::new(
            Ipv4Endpoint::new(Ipv4Addr::new(1, 2, 3, 4), 4662),
            ClientId::from_u32(0x1234),
        )
    }

    #[test]
    fn glob_callback_request_encodes_a_no_length_udp_datagram() {
        let datagram = sample_request().encode_packet().encode_udp();
        // [protocol 0xE3][opcode 0x9C][body] — no 4-byte length prefix.
        let mut expected = vec![0xE3, 0x9C];
        expected.extend_from_slice(&GLOB_CALLBACK_WIRE);
        assert_eq!(datagram, expected);
    }

    #[test]
    fn glob_callback_request_decodes_requester_endpoint_and_target_low_id() {
        let mut datagram = vec![PacketProtocol::Edonkey.as_byte(), 0x9C];
        datagram.extend_from_slice(&GLOB_CALLBACK_WIRE);
        let decoded = GlobCallbackRequest::decode_udp(&datagram).expect("decodes");
        assert_eq!(decoded, sample_request());
        assert_eq!(decoded.requester.ip, Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(decoded.requester.port, 4662);
        assert_eq!(decoded.low_id, ClientId::from_u32(0x1234));
    }

    #[test]
    fn glob_callback_request_rejects_a_short_datagram() {
        let bad = vec![PacketProtocol::Edonkey.as_byte(), 0x9C, 1, 2, 3];
        assert!(GlobCallbackRequest::decode_udp(&bad).is_err());
    }
}
