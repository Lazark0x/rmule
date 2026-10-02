//! The server-packet umbrella: an opcode it does not know survives as the
//! unknown variant and re-encodes to the bytes it arrived as.

use std::net::Ipv4Addr;

use rmule_ed2k::ServerPacket;
use rmule_primitives::{Ipv4Endpoint, Packet, PacketProtocol};

#[test]
fn unknown_opcode_round_trips_via_unknown_variant() {
    let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let packet = Packet::new(PacketProtocol::Edonkey, 0xCC, payload.clone());
    let bytes = packet.encode();

    let server_packet = ServerPacket::decode(&packet).expect("unknown decodes");
    match &server_packet {
        ServerPacket::Unknown {
            opcode,
            payload: bytes_payload,
        } => {
            assert_eq!(*opcode, 0xCC);
            assert_eq!(bytes_payload, &payload);
        }
        other => panic!("expected Unknown, got {other:?}"),
    }
    assert_eq!(server_packet.encode().encode(), bytes);
}

#[test]
fn unknown_empty_payload_round_trips() {
    let packet = Packet::new(PacketProtocol::Edonkey, 0xAB, Vec::new());
    let server_packet = ServerPacket::decode(&packet).expect("unknown empty decodes");
    assert!(matches!(
        server_packet,
        ServerPacket::Unknown { opcode: 0xAB, .. }
    ));
    assert_eq!(server_packet.encode().encode(), packet.encode());
}

#[test]
fn peer_callback_decodes_via_umbrella_and_round_trips() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&[172, 16, 0, 9]);
    payload.extend_from_slice(&5555u16.to_le_bytes());
    let packet = Packet::new(PacketProtocol::Edonkey, 0x35, payload);
    let bytes = packet.encode();

    let server_packet = ServerPacket::decode(&packet).expect("peer callback dispatches");
    match &server_packet {
        ServerPacket::PeerCallback(cb) => assert_eq!(
            cb.peer,
            Ipv4Endpoint::new(Ipv4Addr::new(172, 16, 0, 9), 5555)
        ),
        other => panic!("expected PeerCallback, got {other:?}"),
    }
    assert_eq!(server_packet.encode().encode(), bytes);
}

#[test]
fn malformed_known_packet_rejects_rather_than_falling_through_to_unknown() {
    // OP_REJECT (0x05) with a non-empty payload is malformed per the typed
    // decoder. ADR-0018 says preserve unknown well-formed packets — known
    // opcodes with malformed payloads must still reject.
    let packet = Packet::new(PacketProtocol::Edonkey, 0x05, vec![0xFF]);
    assert!(ServerPacket::decode(&packet).is_err());
}
