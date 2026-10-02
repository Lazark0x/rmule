//! The peer-TCP **buddy relay output** (ADR-0061): the packet an open-node
//! buddy sends its firewalled client over their TCP link when it relays a reask.
//!
//! When the core buddy service (`rmule-core`'s `buddy`) verifies an inbound relay
//! against the registered buddy-ID, it enacts the verdict by framing the callback
//! here and sending it down the buddy link. [`ReaskCallbackTcp`] frames the
//! `OP_REASKCALLBACKTCP` (`0x9A`) output of the peer-UDP `0x94`→`0x9A` relay —
//! both ends of that relay are peer-surface ([`ReaskCallbackUdp`] is the input).
//! The `OP_CALLBACK` (`0x99`) output of the Kad `0x52`→`0x99` relay depends on the
//! `0x52` packet's fields, now decoded by the node into `CallbackRelayRequested`
//! — so [`Callback`] frames it from those structured fields (the `0x52`'s buddy-ID
//! and file-hash echoed, the datagram-source IP injected ahead of the `0x52`'s TCP
//! port, matching aMule `KademliaUDPListener.cpp#L1489`).
//!
//! ## Provenance
//!
//! aMule's relay
//! ([`ClientUDPSocket.cpp#L143`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientUDPSocket.cpp#L143))
//! rewrites the verified `0x94` into `OP_REASKCALLBACKTCP` by prefixing the
//! requester's endpoint — `WriteUInt32(ip)` then `WriteUInt16(port)` — ahead of
//! the forwarded reask tail (`packet + 16, size - 16`), so the firewalled client
//! learns where to answer. The IP rides rmule's documented eD2k byte convention
//! (`Ipv4Addr::octets` in order, the order the reachability `0x58` responder
//! pins). The exact relay bytes are capture-pending ratification (ADR-0045): this
//! frames the reconstructed shape and proves its round-trip, not a committed
//! golden vector.
//!
//! [`ReaskCallbackUdp`]: crate::reask::ReaskCallbackUdp

use std::net::Ipv4Addr;

use rmule_primitives::{
    FileHash, Ipv4Endpoint, Ipv6Endpoint, Packet, PacketProtocol, PeerEndpoint, PeerSource,
    is_usable_tag_identity, kad_wire_id,
};
use thiserror::Error;

use crate::opcode::PeerOpcode;
use crate::reask::BUDDY_ID_LEN;

/// The injected-endpoint prefix of a `0x9A` relay body: `<ip 4><port 2>`.
const ENDPOINT_LEN: usize = 6;

/// The injected endpoint's IPv6 form: the id field reads `0xFFFFFFFF`, the
/// requester's sixteen address bytes follow it, **then** the port, then the
/// forwarded reask tail — `<FFFFFFFF 4><ipv6 16><port 2>`. Both counterparties
/// agree: emule-qt writes it at `src/core/app/CoreSession.cpp:962-964` and
/// reads it at `src/core/client/UpDownClient.cpp:3572-3583` (its test
/// `tests/tst_CallbackAndQueueRank.cpp:1444-1449`) @ `73fff714`; eMuleAI writes
/// it at `srchybrid/ClientUDPSocket.cpp:1225-1228` and reads it at
/// `srchybrid/ListenSocket.cpp:4050-4059`. Unlike a source list's sentinel, the
/// address sits between id and port.
///
/// **The writer is reachable only through this codec, never through rmule's
/// own relay** (ADR-0087): the core's client-UDP front refuses a `0x94` from an
/// IPv6 requester outright, because a firewalled client on the far end of this
/// `0x9A` may be a stock one that reads `0xFFFFFFFF` as the requester's IP and
/// `0x9A` negotiates no capability that would say otherwise.
const SENTINEL_ENDPOINT_LEN: usize = 4 + Ipv6Endpoint::ADDR_WIRE_LEN + 2;

/// The buddy's `OP_REASKCALLBACKTCP` (`0x9A`) relay output. The firewalled client
/// answers the relayed reask **directly over UDP** to the requester (ADR-0061; an
/// asymmetric round trip, aMule's) — hence the requester's endpoint is injected
/// ahead of the reask context forwarded from the inbound `0x94`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaskCallbackTcp {
    /// The requester's endpoint (from the inbound `0x94`'s datagram source),
    /// injected so the firewalled client can answer it over UDP. An IPv6
    /// requester rides the `<FFFFFFFF><ipv6 16><port 2>` form both
    /// counterparties write — a shape this codec reads and writes
    /// symmetrically, and that rmule's own relay never produces: the core's
    /// client-UDP front refuses an IPv6 `0x94` outright (ADR-0087).
    pub requester: PeerEndpoint,
    /// The reask context forwarded verbatim from the inbound `0x94` (the bytes
    /// after its buddy-ID), opaque to the relay.
    pub forwarded: Vec<u8>,
}

impl ReaskCallbackTcp {
    /// Frame the `OP_REASKCALLBACKTCP` (`0x9A`) packet: `<reqIP 4><reqPort 2>
    /// <forwarded…>`, or `<FFFFFFFF 4><reqIPv6 16><reqPort 2><forwarded…>` for
    /// an IPv6 requester, under the eMule extension protocol.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        let mut body = Vec::with_capacity(SENTINEL_ENDPOINT_LEN + self.forwarded.len());
        match self.requester {
            PeerEndpoint::V4(endpoint) => body.extend_from_slice(&endpoint.ip.octets()),
            PeerEndpoint::V6(endpoint) => {
                body.extend_from_slice(&PeerSource::IPV6_SENTINEL.to_le_bytes());
                body.extend_from_slice(&endpoint.addr_bytes());
            }
        }
        body.extend_from_slice(&self.requester.port().to_le_bytes());
        body.extend_from_slice(&self.forwarded);
        Packet::new(
            PacketProtocol::Emule,
            PeerOpcode::ReaskCallbackTcp.as_u8(),
            body,
        )
    }

    /// Decode a `0x9A` relay body back into the requester endpoint and forwarded
    /// tail — the round-trip twin, and the read a firewalled-node consume
    /// builds on.
    ///
    /// # Errors
    /// [`BuddyRelayDecodeError`] for another frame, a body too short for its
    /// header, or an IPv6 requester that is not a usable identity.
    pub fn decode_packet(packet: &Packet) -> Result<Self, BuddyRelayDecodeError> {
        if packet.protocol() != PacketProtocol::Emule
            || packet.opcode() != PeerOpcode::ReaskCallbackTcp.as_u8()
        {
            return Err(BuddyRelayDecodeError::WrongFrame {
                opcode: packet.opcode(),
            });
        }
        let body = packet.payload();
        if body.len() < ENDPOINT_LEN {
            return Err(BuddyRelayDecodeError::Truncated {
                needed: ENDPOINT_LEN,
                actual: body.len(),
            });
        }
        // A sentinel id is all-ones in either byte order, so no convention
        // question arises.
        if body[..4] == PeerSource::IPV6_SENTINEL.to_le_bytes() {
            if body.len() < SENTINEL_ENDPOINT_LEN {
                return Err(BuddyRelayDecodeError::Truncated {
                    needed: SENTINEL_ENDPOINT_LEN,
                    actual: body.len(),
                });
            }
            let mut address = [0u8; Ipv6Endpoint::ADDR_WIRE_LEN];
            address.copy_from_slice(&body[4..4 + Ipv6Endpoint::ADDR_WIRE_LEN]);
            let port = u16::from_le_bytes([body[20], body[21]]);
            let endpoint = Ipv6Endpoint::from_addr_bytes(address, port);
            // The address is where the firewalled client sends its answer, so
            // it meets the gate every other IPv6 reader applies (ADR-0087).
            if !is_usable_tag_identity(endpoint.ip) {
                return Err(BuddyRelayDecodeError::UnusableRequester { endpoint });
            }
            return Ok(Self {
                requester: PeerEndpoint::V6(endpoint),
                forwarded: body[SENTINEL_ENDPOINT_LEN..].to_vec(),
            });
        }
        let port = u16::from_le_bytes([body[4], body[5]]);
        let requester = Ipv4Endpoint::new(Ipv4Addr::new(body[0], body[1], body[2], body[3]), port);
        Ok(Self {
            requester: PeerEndpoint::V4(requester),
            forwarded: body[ENDPOINT_LEN..].to_vec(),
        })
    }
}

/// The Kad `0x52`→`0x99` relay's TCP output: the `OP_CALLBACK` (`0x99`) packet an
/// open-node buddy sends its firewalled client over their TCP link, telling it a
/// peer wants a callback dial-back for a file (ADR-0061). aMule builds it
/// from the inbound `0x52 KADEMLIA_CALLBACK_REQ` — echoing that request's buddy-ID
/// and file-hash, then injecting the datagram-source IP ahead of the request's TCP
/// port
/// ([`KademliaUDPListener.cpp#L1489`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L1489)):
/// `WriteUInt128(check); WriteUInt128(file); WriteUInt32(ip); WriteUInt16(tcp)`.
///
/// Body `<buddyID 16><fileHash 16><reqIP 4><reqTCP 2 LE>` (38 bytes). The IP is
/// the Kad listener's **host-order** address through `WriteUInt32`, so its
/// octets ride **reversed** — unlike the `0x9A` relay, whose address comes off
/// the client UDP socket in eD2k order. The firewalled reader undoes it
/// (`new CUpDownClient(tcp, ip, …, ed2kID = false)` swaps a Kad-order ID back,
/// `BaseClient.cpp:125-129`), so octets written in order send the dial-back to
/// the mirrored address. Pinned by aMule's own relay (run `1790152605`,
/// `tests/fixtures/buddy_callback/captured/amule-233-callback-relay-20260923`).
///
/// # The file-hash field is word-swapped, and this codec is where that ends
///
/// Both 128-bit fields ride the relay in Kad's `WriteUInt128` order, because
/// the relay is a `ReadUInt128`/`WriteUInt128` round trip that changes no byte.
/// `buddy_id` stays in that order all the way to the firewalled end, which
/// compares it as a `CUInt128` against its own Kad ID and never as a hash. The
/// file hash does not: the firewalled end reads it with `ReadUInt128` and then
/// `ToByteArray`s it into a `CMD4Hash` before asking its shared files and
/// download queue about it
/// ([ClientTCPSocket.cpp#L1755](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L1755)).
/// That pair is exactly [`kad_wire_id`], so this codec applies it at the field
/// and [`Self::file_hash`] is a real eD2k file hash in memory — a `FileHash`
/// carrying Kad word order would fail every lookup it was handed to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Callback {
    /// The buddy-ID the requester addressed, echoed from the `0x52` (the core
    /// buddy service verifies it against the registered buddy before relay — the
    /// ADR-0061 tightening).
    pub buddy_id: [u8; BUDDY_ID_LEN],
    /// The file the callback is for, echoed from the `0x52`.
    pub file_hash: FileHash,
    /// The requester's endpoint: the `0x52` datagram's source IP with the TCP port
    /// from its body — injected so the firewalled client can dial the requester
    /// back for the transfer.
    pub requester: Ipv4Endpoint,
}

impl Callback {
    /// The fixed `0x99` body length: `<buddyID 16><fileHash 16><reqIP 4><reqTCP 2>`.
    const BODY_LEN: usize = BUDDY_ID_LEN + FileHash::BYTE_LEN + ENDPOINT_LEN;

    /// Frame the `OP_CALLBACK` (`0x99`) packet under the eMule extension protocol.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        let mut body = Vec::with_capacity(Self::BODY_LEN);
        body.extend_from_slice(&self.buddy_id);
        body.extend_from_slice(&kad_wire_id(*self.file_hash.as_bytes()));
        body.extend_from_slice(&u32::from(self.requester.ip).to_le_bytes());
        body.extend_from_slice(&self.requester.port.to_le_bytes());
        Packet::new(PacketProtocol::Emule, PeerOpcode::Callback.as_u8(), body)
    }

    /// Decode a `0x99` relay body back into its fields — the round-trip twin, and
    /// the read a firewalled-node `0x99` consume builds on.
    pub fn decode_packet(packet: &Packet) -> Result<Self, BuddyRelayDecodeError> {
        if packet.protocol() != PacketProtocol::Emule
            || packet.opcode() != PeerOpcode::Callback.as_u8()
        {
            return Err(BuddyRelayDecodeError::WrongFrame {
                opcode: packet.opcode(),
            });
        }
        let body = packet.payload();
        if body.len() < Self::BODY_LEN {
            return Err(BuddyRelayDecodeError::Truncated {
                needed: Self::BODY_LEN,
                actual: body.len(),
            });
        }
        let mut buddy_id = [0u8; BUDDY_ID_LEN];
        buddy_id.copy_from_slice(&body[..BUDDY_ID_LEN]);
        let hash_end = BUDDY_ID_LEN + FileHash::BYTE_LEN;
        let file_hash = FileHash::from_bytes(kad_wire_id(
            body[BUDDY_ID_LEN..hash_end]
                .try_into()
                .expect("validated 16-byte file hash"),
        ));
        let ep = &body[hash_end..Self::BODY_LEN];
        let requester = Ipv4Endpoint::new(
            Ipv4Addr::from(u32::from_le_bytes([ep[0], ep[1], ep[2], ep[3]])),
            u16::from_le_bytes([ep[4], ep[5]]),
        );
        Ok(Self {
            buddy_id,
            file_hash,
            requester,
        })
    }
}

/// Why a buddy relay output could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum BuddyRelayDecodeError {
    /// The decoder was handed some other opcode.
    #[error("not an OP_REASKCALLBACKTCP frame: opcode 0x{opcode:02X}")]
    WrongFrame {
        /// The opcode that arrived.
        opcode: u8,
    },
    /// The frame ended inside the relay header.
    #[error("buddy relay truncated: needed {needed} bytes, had {actual}")]
    Truncated {
        /// Bytes the header requires.
        needed: usize,
        /// Bytes present.
        actual: usize,
    },
    /// The IPv6 requester is not a usable identity (loopback, link-local,
    /// multicast, ULA, mapped, unspecified): nothing to answer.
    #[error("buddy relay names an unusable IPv6 requester {endpoint}")]
    UnusableRequester {
        /// The endpoint as the relay carried it.
        endpoint: Ipv6Endpoint,
    },
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;

    #[test]
    fn the_reask_callback_tcp_relay_prefixes_the_requester_then_round_trips() {
        // The 0x94→0x9A relay output: the requester's endpoint injected ahead of
        // the forwarded reask tail, so the firewalled client answers over UDP.
        let relay = ReaskCallbackTcp {
            requester: PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 9), 4662)),
            forwarded: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let packet = relay.encode_packet();
        assert_eq!(packet.protocol(), PacketProtocol::Emule);
        assert_eq!(packet.opcode(), 0x9A);
        // <reqIP 4 octets><reqPort 2 LE>: port 4662 = 0x1236 → 0x36,0x12.
        let mut body = vec![198, 51, 100, 9, 0x36, 0x12];
        body.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(packet.payload(), body);
        assert_eq!(ReaskCallbackTcp::decode_packet(&packet), Ok(relay));

        // A body too short to hold the injected endpoint is truncated, never a
        // partial address.
        let short = Packet::new(PacketProtocol::Emule, 0x9A, vec![0x00; ENDPOINT_LEN - 1]);
        assert_eq!(
            ReaskCallbackTcp::decode_packet(&short),
            Err(BuddyRelayDecodeError::Truncated {
                needed: ENDPOINT_LEN,
                actual: ENDPOINT_LEN - 1
            }),
        );
        // A different opcode is not a reask-callback relay.
        let wrong = Packet::new(PacketProtocol::Emule, 0x93, vec![0x00; ENDPOINT_LEN]);
        assert_eq!(
            ReaskCallbackTcp::decode_packet(&wrong),
            Err(BuddyRelayDecodeError::WrongFrame { opcode: 0x93 }),
        );
    }

    #[test]
    fn an_ipv6_requester_rides_address_then_port_as_both_counterparties_write_it() {
        // emule-qt `CoreSession.cpp:962-964` / eMuleAI `ClientUDPSocket.cpp:1225-1228`:
        // `PokeUInt32(out, 0xFFFFFFFF); memcpy(out + 4, v6, 16); PokeUInt16(out + 20, port)`,
        // then the forwarded tail at `out + 22`.
        let mut body = vec![0xFF, 0xFF, 0xFF, 0xFF];
        body.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x77).octets());
        body.extend_from_slice(&4672u16.to_le_bytes());
        body.extend_from_slice(&[0xEE; 16]);
        let packet = Packet::new(PacketProtocol::Emule, 0x9A, body.clone());

        let decoded = ReaskCallbackTcp::decode_packet(&packet).expect("decodes");
        assert_eq!(
            decoded.requester,
            PeerEndpoint::V6(Ipv6Endpoint::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x77),
                4672
            )),
            "not [db8::77:4012]:288"
        );
        assert_eq!(decoded.forwarded, [0xEE; 16]);
        assert_eq!(decoded.encode_packet().payload(), body.as_slice());

        // A sentinel whose address and port are not all there is a truncated
        // frame: there is no half of a requester to answer.
        let short = Packet::new(PacketProtocol::Emule, 0x9A, body[..21].to_vec());
        assert_eq!(
            ReaskCallbackTcp::decode_packet(&short),
            Err(BuddyRelayDecodeError::Truncated {
                needed: SENTINEL_ENDPOINT_LEN,
                actual: 21
            }),
        );
    }

    #[test]
    fn emule_qts_loopback_requester_is_refused_by_the_address_gate() {
        // emule-qt `tests/tst_CallbackAndQueueRank.cpp:1441-1449`: `::1` at the
        // requester's port (4672 standing in for its ephemeral one), then an
        // unknown file hash of 0xEE.
        let mut body = vec![0xFF, 0xFF, 0xFF, 0xFF];
        body.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        body.extend_from_slice(&4672u16.to_le_bytes());
        body.extend_from_slice(&[0xEE; 16]);
        let packet = Packet::new(PacketProtocol::Emule, 0x9A, body);
        assert_eq!(
            ReaskCallbackTcp::decode_packet(&packet),
            Err(BuddyRelayDecodeError::UnusableRequester {
                endpoint: Ipv6Endpoint::new(Ipv6Addr::LOCALHOST, 4672)
            }),
        );
    }

    #[test]
    fn the_callback_relay_echoes_the_kad_fields_injects_the_ip_then_round_trips() {
        // The 0x52→0x99 relay output: the Kad callback's buddy-ID and file-hash
        // echoed, then the requester's datagram-source IP injected ahead of its TCP
        // port (aMule's WriteUInt128(check); WriteUInt128(file); WriteUInt32(ip);
        // WriteUInt16(tcp)).
        //
        // The file hash goes out in Kad's `WriteUInt128` word order:
        // aMule's relay is a `ReadUInt128`/`WriteUInt128` round trip that
        // changes no byte, and the firewalled reader un-swaps. The captured
        // `0x34` pair below (`docs/reference/notes/kad-source-lookup.md`,
        // `KadEvidence::KadIdByteOrder`) is a file hash and the 128-bit Kad
        // field aMule wrote it into — the same `SetValueBE`/`WriteUInt128`
        // route this field takes.
        const CAPTURED_FILE_HASH: [u8; 16] = [
            0x8E, 0x30, 0x2D, 0xB5, 0xB8, 0x06, 0xA2, 0x5C, 0x93, 0x85, 0xFC, 0x23, 0xF2, 0x10,
            0x62, 0xD2,
        ];
        const CAPTURED_KAD_FIELD: [u8; 16] = [
            0xB5, 0x2D, 0x30, 0x8E, 0x5C, 0xA2, 0x06, 0xB8, 0x23, 0xFC, 0x85, 0x93, 0xD2, 0x62,
            0x10, 0xF2,
        ];
        let relay = Callback {
            buddy_id: [0x7A; BUDDY_ID_LEN],
            file_hash: FileHash::from_bytes(CAPTURED_FILE_HASH),
            requester: Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 5), 4662),
        };
        let packet = relay.encode_packet();
        assert_eq!(packet.protocol(), PacketProtocol::Emule);
        assert_eq!(packet.opcode(), 0x99);
        let mut body = vec![0x7A; 16];
        body.extend_from_slice(&CAPTURED_KAD_FIELD);
        body.extend_from_slice(&[5, 113, 0, 203]); // reqIP host-order, octets reversed
        body.extend_from_slice(&[0x36, 0x12]); // reqTCP 4662 little-endian
        assert_eq!(packet.payload(), body);
        assert_eq!(Callback::decode_packet(&packet), Ok(relay));

        // One byte short of the fixed 38-byte layout is truncated, never a partial.
        let short = Packet::new(
            PacketProtocol::Emule,
            0x99,
            vec![0x00; Callback::BODY_LEN - 1],
        );
        assert_eq!(
            Callback::decode_packet(&short),
            Err(BuddyRelayDecodeError::Truncated {
                needed: Callback::BODY_LEN,
                actual: Callback::BODY_LEN - 1
            }),
        );
        // A different opcode is not a callback relay.
        let wrong = Packet::new(PacketProtocol::Emule, 0x9A, vec![0x00; Callback::BODY_LEN]);
        assert_eq!(
            Callback::decode_packet(&wrong),
            Err(BuddyRelayDecodeError::WrongFrame { opcode: 0x9A }),
        );
    }
}
