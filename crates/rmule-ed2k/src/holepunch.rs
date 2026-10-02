//! The **server punch** (ADR-0091): ed2k-server's LowID↔LowID introduction —
//! `OP_LOWID_HOLEPUNCH_REQUEST` (`0x60`), `OP_LOWID_HOLEPUNCH_INFO` (`0x61`),
//! `OP_LOWID_HOLEPUNCH_FAIL` (`0x62`) on the server TCP link, and the
//! `OP_SERVER_NATT_KEEPALIVE` (`0x9F`) datagram that keeps the server's view
//! of our UDP port true.
//!
//! The server is a **Rendezvous coordinator** and nothing more: it tells two
//! firewalled clients each other's address and gets out of the way. What they
//! then send each other is theirs to choose, and rmule chooses eMuleAI's punch
//! and Tunnel — never the `0xB3`/`0xD0`–`0xD7` family this server's own README
//! describes, which is eMule 0.72a-community's and has no Linux-buildable
//! counterparty.
//!
//! Layouts are ed2k-server's at `4da4774` — `src/server/holepunch.rs` and the
//! README's *Implementing a compatible client* — read for facts and
//! cite-and-rewritten (ADR-0004). `0x60`–`0x62` sit above the server TCP
//! opcode space (`0x01`–`0x44`) and `0x9F` was free in the server UDP one, so
//! a server that does not speak this ignores all four.

use std::net::Ipv4Addr;

use rmule_primitives::{ClientId, Ipv4Endpoint, Packet, PacketProtocol, UserHash};

use crate::{Ed2kError, Opcode, Result};

const REQUEST_LEN: usize = 4 + 2;
const INFO_LEN: usize = 4 + 2 + 2 + UserHash::BYTE_LEN + 1;
const FAIL_LEN: usize = 4 + 1;

/// `OP_LOWID_HOLEPUNCH_REQUEST` (`0x60`), client → server: introduce us to
/// the LowID client `target`. Body `<target_id 4 LE><our_udp_port 2 LE>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HolepunchRequest {
    /// The target's server-assigned Low-ID.
    pub target: ClientId,
    /// Our client-UDP port **as bound**. The server prefers the port it has
    /// *observed* our keepalive arrive from and falls back to this one, so
    /// behind a NAT this number is a last resort, not the answer.
    pub our_udp_port: u16,
}

impl HolepunchRequest {
    /// The packet form, ready to frame and send.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        let mut payload = Vec::with_capacity(REQUEST_LEN);
        payload.extend_from_slice(&self.target.as_u32().to_le_bytes());
        payload.extend_from_slice(&self.our_udp_port.to_le_bytes());
        Packet::new(
            PacketProtocol::Edonkey,
            Opcode::LowIdHolepunchRequest.as_u8(),
            payload,
        )
    }

    /// Decode the server's view of a request.
    ///
    /// # Errors
    /// [`Ed2kError::InvalidPayload`] unless the body is exactly six bytes
    /// under this opcode.
    pub fn decode_packet(packet: &Packet) -> Result<Self> {
        let body = body_of(packet, Opcode::LowIdHolepunchRequest, REQUEST_LEN)?;
        Ok(Self {
            target: ClientId::from_u32(u32::from_le_bytes([body[0], body[1], body[2], body[3]])),
            our_udp_port: u16::from_le_bytes([body[4], body[5]]),
        })
    }
}

/// Which side the server asks to fire first. **Advisory**: the server's own
/// documentation says both sides of its reference client initiate, and rmule
/// does the same — a punch that waited its turn would reach a NAT whose
/// mapping the other side had not opened yet. Kept because it arrives, and
/// because diagnostics should say what the server said.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HolepunchRole {
    /// `0` — the side with the lower server-assigned ID.
    Initiator,
    /// `1` — the other side.
    Responder,
    /// Any other byte. Not an error: the role changes nothing rmule does.
    Other(u8),
}

impl HolepunchRole {
    const fn from_u8(byte: u8) -> Self {
        match byte {
            0 => Self::Initiator,
            1 => Self::Responder,
            other => Self::Other(other),
        }
    }

    const fn as_u8(self) -> u8 {
        match self {
            Self::Initiator => 0,
            Self::Responder => 1,
            Self::Other(byte) => byte,
        }
    }
}

/// `OP_LOWID_HOLEPUNCH_INFO` (`0x61`), server → **both** clients: the other
/// side's coordinates. Body `<ip 4><tcp 2 LE><udp 2 LE><userhash 16><role 1>`
/// — the address in eD2k's dotted byte order.
///
/// This is the one rendezvous in the dialect where the address was **observed
/// by a third party**: the server writes the UDP port it last saw that
/// client's keepalive arrive from (fresh for 600 s), falling back to the port
/// the client announced. So unlike a buddy-relayed rendezvous body, nothing in
/// here is the peer's own claim about itself.
///
/// The server re-sends the same INFO about 1.2 s and 3 s later, best-effort,
/// so a consumer must treat a repeat as the same introduction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HolepunchInfo {
    /// The peer's address and the UDP port to punch at.
    pub peer_udp: Ipv4Endpoint,
    /// The peer's TCP listen port — informational for a LowID peer, which
    /// cannot be dialed on it.
    pub peer_tcp_port: u16,
    /// The peer's user hash: the key the Tunnel's session is matched on.
    pub peer_hash: UserHash,
    /// Who the server asked to fire first.
    pub role: HolepunchRole,
}

impl HolepunchInfo {
    /// The packet form — the server's side, used by the loopback fake server
    /// and the KATs.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        let mut payload = Vec::with_capacity(INFO_LEN);
        payload.extend_from_slice(&self.peer_udp.ip.octets());
        payload.extend_from_slice(&self.peer_tcp_port.to_le_bytes());
        payload.extend_from_slice(&self.peer_udp.port.to_le_bytes());
        payload.extend_from_slice(self.peer_hash.as_bytes());
        payload.push(self.role.as_u8());
        Packet::new(
            PacketProtocol::Edonkey,
            Opcode::LowIdHolepunchInfo.as_u8(),
            payload,
        )
    }

    /// Decode an introduction.
    ///
    /// # Errors
    /// [`Ed2kError::InvalidPayload`] unless the body is exactly 25 bytes under
    /// this opcode. A null address or port decodes: whether an endpoint is
    /// somewhere a punch may be aimed is the precedence rule's question, and
    /// it is asked where the punch is decided.
    pub fn decode_packet(packet: &Packet) -> Result<Self> {
        let body = body_of(packet, Opcode::LowIdHolepunchInfo, INFO_LEN)?;
        let ip = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
        let peer_tcp_port = u16::from_le_bytes([body[4], body[5]]);
        let udp_port = u16::from_le_bytes([body[6], body[7]]);
        let hash: [u8; UserHash::BYTE_LEN] = body[8..24].try_into().expect("fixed width");
        Ok(Self {
            peer_udp: Ipv4Endpoint::new(ip, udp_port),
            peer_tcp_port,
            peer_hash: UserHash::from_bytes(hash),
            role: HolepunchRole::from_u8(body[24]),
        })
    }
}

/// Why the server would not introduce us (`src/server/holepunch.rs:74-77`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HolepunchFailReason {
    /// `1` — no connected client holds that ID, or its session is dead.
    TargetNotConnected,
    /// `2` — the target is HighID: dial it, there is nothing to punch.
    TargetIsHighId,
    /// `3` — the request was malformed, or named ourselves.
    BadRequest,
    /// `4` — the server knows no UDP port for the target: it sent no `0xF9`
    /// and no keepalive, so it is not a NAT-T client at all.
    TargetNoUdp,
    /// A reason this build does not name. Kept, not rejected — a newer server
    /// may have more to say, and "refused" is actionable without the why.
    Other(u8),
}

impl HolepunchFailReason {
    const fn from_u8(byte: u8) -> Self {
        match byte {
            1 => Self::TargetNotConnected,
            2 => Self::TargetIsHighId,
            3 => Self::BadRequest,
            4 => Self::TargetNoUdp,
            other => Self::Other(other),
        }
    }

    const fn as_u8(self) -> u8 {
        match self {
            Self::TargetNotConnected => 1,
            Self::TargetIsHighId => 2,
            Self::BadRequest => 3,
            Self::TargetNoUdp => 4,
            Self::Other(byte) => byte,
        }
    }

    /// Whether asking again could change the answer. A HighID target and a
    /// non-NAT-T target stay that way for the session; a target that was not
    /// connected may connect.
    #[must_use]
    pub const fn is_permanent(self) -> bool {
        matches!(
            self,
            Self::TargetIsHighId | Self::TargetNoUdp | Self::BadRequest
        )
    }
}

/// `OP_LOWID_HOLEPUNCH_FAIL` (`0x62`), server → requester. Body
/// `<target_id 4 LE><reason 1>`. Only the requester hears it; the target is
/// told nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HolepunchFail {
    /// The target the refused request named — how the refusal is matched to
    /// an attempt.
    pub target: ClientId,
    /// Why.
    pub reason: HolepunchFailReason,
}

impl HolepunchFail {
    /// The packet form — the server's side.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        let mut payload = Vec::with_capacity(FAIL_LEN);
        payload.extend_from_slice(&self.target.as_u32().to_le_bytes());
        payload.push(self.reason.as_u8());
        Packet::new(
            PacketProtocol::Edonkey,
            Opcode::LowIdHolepunchFail.as_u8(),
            payload,
        )
    }

    /// Decode a refusal.
    ///
    /// # Errors
    /// [`Ed2kError::InvalidPayload`] unless the body is exactly five bytes
    /// under this opcode.
    pub fn decode_packet(packet: &Packet) -> Result<Self> {
        let body = body_of(packet, Opcode::LowIdHolepunchFail, FAIL_LEN)?;
        Ok(Self {
            target: ClientId::from_u32(u32::from_le_bytes([body[0], body[1], body[2], body[3]])),
            reason: HolepunchFailReason::from_u8(body[4]),
        })
    }
}

/// `OP_SERVER_NATT_KEEPALIVE` (`0x9F`): the datagram `[0xE3][0x9F]<hash 16>`,
/// sent **from the client-UDP socket** to the server's TCP port + 4.
///
/// Its source port is the message. The server records the port this datagram
/// arrives from and hands it to whoever asks to punch us, trusting it for
/// 600 s — so it must leave the socket the punch will arrive on, and a
/// keepalive from any other socket teaches the server a mapping nothing
/// listens behind. It also counts as session activity, refreshing the
/// server's 900 s idle backstop.
#[must_use]
pub fn natt_keepalive_datagram(our_hash: &UserHash) -> Vec<u8> {
    Packet::new(
        PacketProtocol::Edonkey,
        Opcode::ServerNattKeepalive.as_u8(),
        our_hash.as_bytes().to_vec(),
    )
    .encode_udp()
}

/// The server's UDP port for the keepalive: its TCP port + 4, the eD2k
/// server-UDP convention. `None` when that would leave the port space.
#[must_use]
pub const fn natt_keepalive_port(server_tcp_port: u16) -> Option<u16> {
    server_tcp_port.checked_add(4)
}

fn body_of(packet: &Packet, opcode: Opcode, len: usize) -> Result<&[u8]> {
    let invalid = |reason| Ed2kError::InvalidPayload {
        opcode: opcode.as_u8(),
        reason,
    };
    if packet.protocol() != PacketProtocol::Edonkey {
        return Err(invalid("unsupported packet protocol"));
    }
    if packet.opcode() != opcode.as_u8() {
        return Err(invalid("wrong opcode for a server-punch packet"));
    }
    if packet.payload().len() != len {
        return Err(invalid("server-punch payload has the wrong width"));
    }
    Ok(packet.payload())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// README §3's table, byte for byte: target ID then UDP port, both
    /// little-endian, six bytes.
    #[test]
    fn the_request_is_target_id_then_our_udp_port() {
        let packet = HolepunchRequest {
            target: ClientId::from_u32(0x0000_1234),
            our_udp_port: 4672,
        }
        .encode_packet();
        assert_eq!(packet.opcode(), 0x60);
        assert_eq!(packet.payload(), [0x34, 0x12, 0x00, 0x00, 0x40, 0x12]);
        assert_eq!(
            HolepunchRequest::decode_packet(&packet).map(|r| r.target.as_u32()),
            Ok(0x1234)
        );
    }

    /// `holepunch.rs:269-281`. The trap is the field order: **TCP port before
    /// UDP port**, and the UDP one is where the punch goes. A reader that
    /// took them in the natural order would punch at the listen port of a
    /// client that, being LowID, cannot be reached on it.
    #[test]
    fn the_info_carries_tcp_before_udp_and_the_punch_goes_to_udp() {
        let mut payload = vec![45, 55, 200, 7];
        payload.extend_from_slice(&4662u16.to_le_bytes());
        payload.extend_from_slice(&31999u16.to_le_bytes());
        payload.extend_from_slice(&[0x44; 16]);
        payload.push(1);
        let packet = Packet::new(PacketProtocol::Edonkey, 0x61, payload);

        let info = HolepunchInfo::decode_packet(&packet).expect("25 bytes");
        assert_eq!(
            info.peer_udp,
            Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 7), 31999)
        );
        assert_eq!(info.peer_tcp_port, 4662);
        assert_eq!(info.peer_hash, UserHash::from_bytes([0x44; 16]));
        assert_eq!(info.role, HolepunchRole::Responder);
        assert_eq!(info.encode_packet(), packet);
    }

    /// An unnamed role or reason is carried, not refused: neither changes
    /// what rmule does next, and a round trip keeps the byte.
    #[test]
    fn an_unnamed_role_or_reason_is_kept_not_rejected() {
        let mut info = vec![45, 55, 200, 7, 0, 0, 0, 0];
        info.extend_from_slice(&[0x44; 16]);
        info.push(9);
        let info = Packet::new(PacketProtocol::Edonkey, 0x61, info);
        let decoded = HolepunchInfo::decode_packet(&info).expect("decodes");
        assert_eq!(decoded.role, HolepunchRole::Other(9));
        assert_eq!(decoded.encode_packet(), info);

        let fail = Packet::new(PacketProtocol::Edonkey, 0x62, vec![7, 0, 0, 0, 0x2A]);
        let decoded = HolepunchFail::decode_packet(&fail).expect("decodes");
        assert_eq!(decoded.reason, HolepunchFailReason::Other(0x2A));
        assert!(!decoded.reason.is_permanent());
        assert_eq!(decoded.encode_packet(), fail);
    }

    /// The four reasons the server defines, and which of them end the matter:
    /// only "not connected" can change within a session.
    #[test]
    fn a_refusal_names_its_target_and_whether_asking_again_could_help() {
        for (byte, reason, permanent) in [
            (1, HolepunchFailReason::TargetNotConnected, false),
            (2, HolepunchFailReason::TargetIsHighId, true),
            (3, HolepunchFailReason::BadRequest, true),
            (4, HolepunchFailReason::TargetNoUdp, true),
        ] {
            let packet = Packet::new(PacketProtocol::Edonkey, 0x62, vec![0x39, 0x05, 0, 0, byte]);
            let fail = HolepunchFail::decode_packet(&packet).expect("five bytes");
            assert_eq!(fail.target.as_u32(), 1337);
            assert_eq!(fail.reason, reason);
            assert_eq!(fail.reason.is_permanent(), permanent, "{reason:?}");
        }
    }

    /// Fixed widths, no tolerance: these bodies have no length field and no
    /// extension point, so a short or long one is another message.
    #[test]
    fn a_body_of_the_wrong_width_is_not_a_server_punch_packet() {
        for (opcode, len) in [(0x60, 6), (0x61, 25), (0x62, 5)] {
            for wrong in [len - 1, len + 1] {
                let packet = Packet::new(PacketProtocol::Edonkey, opcode, vec![1; wrong]);
                let refused = match opcode {
                    0x60 => HolepunchRequest::decode_packet(&packet).is_err(),
                    0x61 => HolepunchInfo::decode_packet(&packet).is_err(),
                    _ => HolepunchFail::decode_packet(&packet).is_err(),
                };
                assert!(refused, "{opcode:#x} at {wrong} bytes");
            }
        }
    }

    /// `[0xE3][0x9F]` then the hash, no length prefix, to TCP port + 4.
    #[test]
    fn the_keepalive_is_our_hash_under_the_server_udp_header() {
        let datagram = natt_keepalive_datagram(&UserHash::from_bytes([0x5A; 16]));
        assert_eq!(datagram.len(), 18);
        assert_eq!(&datagram[..2], &[0xE3, 0x9F]);
        assert_eq!(&datagram[2..], &[0x5A; 16]);
        assert_eq!(natt_keepalive_port(4661), Some(4665));
        assert_eq!(natt_keepalive_port(65533), None);
    }
}
