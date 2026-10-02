//! The genuine **server-coordinated punch introduction** from
//! `andrey23127/ed2k-server` @ `4da4774`: the `OP_LOWID_HOLEPUNCH_INFO 0x61`
//! the server sent to **both** Low-ID rmule peers in answer to one
//! `OP_LOWID_HOLEPUNCH_REQUEST 0x60` (ADR-0091's second Rendezvous coordinator;
//! the cone and symmetric NAT bench rows, one consolidated run, 2026-09-22).
//!
//! Two sittings, one per NAT type, because the pair is the evidence. Behind two
//! `full-cone-pinned` gateways the server's observed port and the bound port
//! coincide (4672), so a decoder that read the *announced* port would pass the
//! cone pair by accident. Behind two `symmetric` gateways every destination
//! gets a fresh external port, the server can only write the one it saw the
//! peer's `0x9F` keepalive arrive from, and the `0x61` carries that port and
//! not the 4672 the requester's own `0x60` announced — the one fact that makes
//! this rendezvous the dialect's only *third-party-observed* address.
//! Provenance, taps and the keepalive sources in `meta.toml`.

use std::net::Ipv4Addr;

use rmule_ed2k::{HolepunchInfo, HolepunchRequest, HolepunchRole, ServerPacket};
use rmule_primitives::{ClientId, Ipv4Endpoint, Packet, PacketProtocol, UserHash};

const CAPTURE: &str = "ed2ksrv-holepunch-info-20260922";

/// The two peers' gateway WAN addresses on the fake-public bench WAN.
const REQUESTER_WAN: Ipv4Addr = Ipv4Addr::new(45, 55, 200, 3);
const TARGET_WAN: Ipv4Addr = Ipv4Addr::new(45, 55, 200, 4);

/// The pinned client-UDP port both rmule peers bind, and the TCP port their
/// logins advertised.
const PINNED_UDP: u16 = 4672;
const ADVERTISED_TCP: u16 = 4662;

/// The external ports the two `symmetric` gateways gave each peer's mapping
/// toward the server — read off the server's own tap as the source of the
/// peers' `0x9F` keepalives, not chosen by anyone.
const SYMMETRIC_REQUESTER_OBSERVED: u16 = 49_350;
const SYMMETRIC_TARGET_OBSERVED: u16 = 25_024;

fn packet(name: &str) -> Packet {
    let bytes = crate::fixture::captured(CAPTURE, name);
    let packet = Packet::decode_exact(&bytes).expect("frame decode");
    assert_eq!(
        packet.protocol(),
        PacketProtocol::Edonkey,
        "plain 0xE3 frame"
    );
    assert_eq!(
        packet.encode(),
        bytes,
        "{name}: frame round-trips byte-exact"
    );
    packet
}

fn info(name: &str) -> HolepunchInfo {
    let packet = packet(name);
    let ServerPacket::HolepunchInfo(from_umbrella) =
        ServerPacket::decode(&packet).expect("the server-packet umbrella decodes 0x61")
    else {
        panic!("{name}: the umbrella did not route 0x61 to HolepunchInfo");
    };
    let info = HolepunchInfo::decode_packet(&packet).expect("decode genuine 0x61");
    assert_eq!(
        from_umbrella, info,
        "{name}: umbrella and direct decode agree"
    );
    assert_eq!(
        info.encode_packet().encode(),
        packet.encode(),
        "{name}: re-encoding reproduces the server's bytes",
    );
    info
}

fn requester_hash() -> UserHash {
    UserHash::from_bytes([0x41; 16])
}

fn target_hash() -> UserHash {
    UserHash::from_bytes([0x42; 16])
}

/// Each side is told about the **other** one — address, both ports, user hash —
/// and the requester (the lower Low-ID) is named the initiator.
#[test]
fn the_cone_introduction_names_each_peer_to_the_other() {
    let to_requester = info("cone_initiator_info_0x61.bin");
    assert_eq!(
        to_requester.peer_udp,
        Ipv4Endpoint::new(TARGET_WAN, PINNED_UDP)
    );
    assert_eq!(to_requester.peer_tcp_port, ADVERTISED_TCP);
    assert_eq!(to_requester.peer_hash, target_hash());
    assert_eq!(to_requester.role, HolepunchRole::Initiator);

    let to_target = info("cone_responder_info_0x61.bin");
    assert_eq!(
        to_target.peer_udp,
        Ipv4Endpoint::new(REQUESTER_WAN, PINNED_UDP)
    );
    assert_eq!(to_target.peer_tcp_port, ADVERTISED_TCP);
    assert_eq!(to_target.peer_hash, requester_hash());
    assert_eq!(to_target.role, HolepunchRole::Responder);
}

/// Behind symmetric gateways the introduction carries the port the server
/// **observed**, not the one the requester announced — the decoder must keep
/// the two apart, because the punch is aimed at the first.
#[test]
fn the_symmetric_introduction_carries_the_observed_port_not_the_announced_one() {
    let request = HolepunchRequest::decode_packet(&packet("holepunch_request_0x60.bin"))
        .expect("decode rmule's own 0x60 stimulus");
    assert_eq!(request.target, ClientId::from_u32(2));
    assert_eq!(request.our_udp_port, PINNED_UDP);

    let to_target = info("symmetric_responder_info_0x61.bin");
    assert_eq!(
        to_target.peer_udp,
        Ipv4Endpoint::new(REQUESTER_WAN, SYMMETRIC_REQUESTER_OBSERVED),
    );
    assert_ne!(to_target.peer_udp.port, request.our_udp_port);
    assert_eq!(to_target.peer_hash, requester_hash());
    assert_eq!(to_target.role, HolepunchRole::Responder);

    let to_requester = info("symmetric_initiator_info_0x61.bin");
    assert_eq!(
        to_requester.peer_udp,
        Ipv4Endpoint::new(TARGET_WAN, SYMMETRIC_TARGET_OBSERVED),
    );
    assert_eq!(to_requester.peer_tcp_port, ADVERTISED_TCP);
    assert_eq!(to_requester.peer_hash, target_hash());
    assert_eq!(to_requester.role, HolepunchRole::Initiator);
}
