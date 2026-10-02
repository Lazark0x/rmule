//! `OP_IDCHANGE` (0x40): the server's login answer and id (re-)assignment.
//! The payload is **progressive** (aMule `ServerSocket.cpp` reads by `size
//! >=` thresholds), all fields `u32 LE`:
//!
//! | offset | field | present when |
//! |---|---|---|
//! | 0 | `client_id` | always (size ≥ 4) |
//! | 4 | `tcp_flags` | size ≥ 8 (a bare 4-byte reply zeroes aMule's stored flags) |
//! | 8 | `standard_tcp_port` | size ≥ 12 ("aux port login": the server's standard port to advertise) |
//! | 12 | `public_ip` + `obfuscation_tcp_port` | size ≥ 20 (the pair lands together; 13–19 bytes yield neither) |
//!
//! Bytes past offset 20 — and the 12..20 residue of a between-thresholds
//! payload — are preserved verbatim as `trailing` (ADR-0018). Wire pinned in
//! `docs/reference/notes/ed2k-login.md`; cite-and-rewrite only (ADR-0004).

use rmule_primitives::{ClientId, Packet, PacketProtocol};

use crate::{Ed2kError, Opcode, Result, ServerTcpFlags};

/// `OP_IDCHANGE`: the server's answer to our login, and every later
/// re-assignment.
///
/// Every field past the id is optional because the payload is progressive —
/// an older server simply stops earlier, and each stopping point is a valid
/// reply, so absence means "this server did not say", never "zero".
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IdChange {
    /// The id the server assigned us — High means peers can dial us directly,
    /// Low means every contact must be brokered.
    pub client_id: ClientId,
    /// `SRV_TCPFLG_*` grants (size ≥ 8). Absent on the bare 4-byte reply,
    /// which aMule treats as "no grants" (`SetTCPFlags(0)`).
    pub tcp_flags: Option<ServerTcpFlags>,
    /// The server's standard/advertised TCP port (size ≥ 12), sent when the
    /// login came through an auxiliary port so clients advertise the
    /// standard one. Wire-faithful `u32` (aMule narrows at its consumer).
    pub standard_tcp_port: Option<u32>,
    /// The server's view of rmule's public IPv4 (size ≥ 20, first of the
    /// pair), as the eD2k ip-as-`u32 LE` (octets in wire order). The
    /// LowID-valued discard is the session projection's rule, not the
    /// codec's.
    pub public_ip: Option<u32>,
    /// The server's obfuscated TCP listener (size ≥ 20, second of the
    /// pair). `0` on the wire means not offered.
    pub obfuscation_tcp_port: Option<u32>,
    /// Unconsumed payload tail, preserved verbatim per ADR-0018: bytes past
    /// offset 20, or the 12..20 residue of a between-thresholds payload.
    pub trailing: Vec<u8>,
}

impl IdChange {
    /// Decode this packet's payload.
    ///
    /// # Errors
    /// [`Ed2kError::InvalidPayload`] if the protocol byte, the opcode, or the
    /// body layout is not this packet's.
    pub fn decode_packet(packet: &Packet) -> Result<Self> {
        let opcode = Opcode::IdChange.as_u8();
        if packet.protocol() != PacketProtocol::Edonkey {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "unsupported packet protocol",
            });
        }
        if packet.opcode() != opcode {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "wrong opcode for OP_IDCHANGE",
            });
        }
        let payload = packet.payload();
        if payload.len() < 4 {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_IDCHANGE payload must be at least 4 bytes",
            });
        }
        let read_u32 = |offset: usize| {
            u32::from_le_bytes(
                payload[offset..offset + 4]
                    .try_into()
                    .expect("validated 4-byte field"),
            )
        };
        let client_id = ClientId::from_u32(read_u32(0));
        let tcp_flags = (payload.len() >= 8).then(|| ServerTcpFlags::from_bits(read_u32(4)));
        let standard_tcp_port = (payload.len() >= 12).then(|| read_u32(8));
        let (public_ip, obfuscation_tcp_port) = if payload.len() >= 20 {
            (Some(read_u32(12)), Some(read_u32(16)))
        } else {
            (None, None)
        };
        let consumed = match payload.len() {
            0..=7 => 4,
            8..=11 => 8,
            12..=19 => 12,
            _ => 20,
        };
        Ok(Self {
            client_id,
            tcp_flags,
            standard_tcp_port,
            public_ip,
            obfuscation_tcp_port,
            trailing: payload[consumed..].to_vec(),
        })
    }

    /// The packet form, ready to frame and send.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        // The progressive layout makes a deeper field unrepresentable
        // without its shallower ones, and the size-20 pair indivisible.
        assert_eq!(
            self.public_ip.is_some(),
            self.obfuscation_tcp_port.is_some(),
            "IdChange::encode_packet: public_ip and obfuscation_tcp_port land together",
        );
        let depth = [
            self.tcp_flags.is_some(),
            self.standard_tcp_port.is_some(),
            self.public_ip.is_some(),
        ];
        assert!(
            depth.windows(2).all(|pair| pair[0] || !pair[1]),
            "IdChange::encode_packet: a deeper IDCHANGE field without its shallower ones is unrepresentable",
        );
        assert!(
            self.trailing.is_empty() || self.tcp_flags.is_some(),
            "IdChange::encode_packet: trailing bytes without tcp_flags are unrepresentable",
        );
        let mut payload = Vec::with_capacity(20 + self.trailing.len());
        payload.extend_from_slice(&self.client_id.as_u32().to_le_bytes());
        if let Some(flags) = self.tcp_flags {
            payload.extend_from_slice(&flags.bits().to_le_bytes());
        }
        if let Some(port) = self.standard_tcp_port {
            payload.extend_from_slice(&port.to_le_bytes());
        }
        if let (Some(ip), Some(obfuscation)) = (self.public_ip, self.obfuscation_tcp_port) {
            payload.extend_from_slice(&ip.to_le_bytes());
            payload.extend_from_slice(&obfuscation.to_le_bytes());
        }
        payload.extend_from_slice(&self.trailing);
        Packet::new(PacketProtocol::Edonkey, Opcode::IdChange.as_u8(), payload)
    }
}
