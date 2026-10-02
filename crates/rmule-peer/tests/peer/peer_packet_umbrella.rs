//! The umbrella decoder every inbound peer frame enters: each opcode reaches
//! its own typed message — including the two source-exchange directions, which
//! split by whether we are serving or consuming — and an opcode it does not
//! know is preserved as unknown rather than dropped.

use std::net::Ipv4Addr;

use rmule_peer::{
    AnswerSources, AnswerSources2, Hello, HelloAnswer, PeerHelloBody, PeerPacket, RequestSources2,
    SourceExchangeEntry, SourceExchangeVersion,
};
use rmule_primitives::{
    ClientId, ExchangedSource, FileHash, Ipv4Endpoint, Packet, PacketProtocol, PeerSource, UserHash,
};

fn empty_body() -> PeerHelloBody {
    PeerHelloBody {
        user_hash: UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
        client_id: ClientId::from_u32(0),
        tcp_port: 4662,
        tags: Vec::new(),
        connected_server: Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0),
    }
}

#[test]
fn umbrella_dispatches_op_hello() {
    let packet = Hello::new(empty_body()).encode_packet();
    match PeerPacket::decode(&packet).expect("hello") {
        PeerPacket::Hello(h) => assert_eq!(h.body().tcp_port, 4662),
        other => panic!("expected Hello, got {other:?}"),
    }
}

#[test]
fn umbrella_dispatches_op_hello_answer() {
    let packet = HelloAnswer::new(empty_body()).encode_packet();
    match PeerPacket::decode(&packet).expect("hello answer") {
        PeerPacket::HelloAnswer(h) => assert_eq!(h.body().tcp_port, 4662),
        other => panic!("expected HelloAnswer, got {other:?}"),
    }
}

#[test]
fn umbrella_decodes_answer_sources_at_the_default_advert_nibble() {
    // Regression anchor for the packet.rs wiring: a 0x82 whose geometry matches
    // rmule's own advertised SX1 nibble (aMule's own 3, ADR-0055)
    // decodes through the live `PeerPacket::decode` stand-in. A source is
    // needed — an *empty* answer only resolves at nibble 1 (the documented
    // zero-count corner), and the honest default is now 3.
    let fh = FileHash::from_bytes([0x91; 16]);
    let source = ExchangedSource::plain(PeerSource::new(ClientId::from_u32(0x0203_0405), 4662));
    let packet = AnswerSources {
        file_hash: fh,
        sources: vec![SourceExchangeEntry::plain(source)],
    }
    .encode_packet(SourceExchangeVersion::V3);
    match PeerPacket::decode(&packet).expect("v3 answer decodes at the nibble-3 default") {
        PeerPacket::AnswerSources(a) => assert_eq!(a.file_hash, fh),
        other => panic!("expected AnswerSources, got {other:?}"),
    }
}

#[test]
fn umbrella_dispatches_request_sources2_to_the_serve_path() {
    // ADR-0055: 0x83 does not park as Unknown — the serve callback
    // decodes it, and its `<ver>`/`<opts>` feed the aMule-exact serve-version
    // pick (`RequestSources` / `0x81` decodes for the same reason).
    let fh = FileHash::from_bytes([0x92; 16]);
    let packet = RequestSources2 {
        version: 4,
        options: 0,
        file_hash: fh,
    }
    .encode_packet();
    match PeerPacket::decode(&packet).expect("0x83 decodes for serving") {
        PeerPacket::RequestSources2(r) => {
            assert_eq!(r.file_hash, fh);
            assert_eq!(r.version, 4);
            assert_eq!(r.options, 0);
        }
        other => panic!("expected RequestSources2, got {other:?}"),
    }
}

#[test]
fn umbrella_dispatches_answer_sources2_for_the_requester_consume() {
    // ADR-0055 requester consume: 0x84 does not park as Unknown — the
    // umbrella decodes it to `AnswerSources2`, which the session routes through
    // the same consume core as 0x82.
    let fh = FileHash::from_bytes([0x93; 16]);
    let source = ExchangedSource::plain(PeerSource::new(ClientId::from_u32(0x0203_0405), 4662));
    let packet = AnswerSources2 {
        version: SourceExchangeVersion::V4,
        file_hash: fh,
        sources: vec![SourceExchangeEntry::plain(source)],
    }
    .encode_packet();
    match PeerPacket::decode(&packet).expect("0x84 decodes for the requester consume") {
        PeerPacket::AnswerSources2(a) => {
            assert_eq!(a.file_hash, fh);
            assert_eq!(a.version, SourceExchangeVersion::V4);
            assert_eq!(a.sources.len(), 1);
        }
        other => panic!("expected AnswerSources2, got {other:?}"),
    }
}

#[test]
fn umbrella_preserves_unknown_opcodes() {
    let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let packet = Packet::new(PacketProtocol::Edonkey, 0x77, payload.clone());
    match PeerPacket::decode(&packet).expect("unknown opcode") {
        PeerPacket::Unknown {
            protocol,
            opcode,
            payload: bytes,
        } => {
            assert_eq!(protocol, PacketProtocol::Edonkey);
            assert_eq!(opcode, 0x77);
            assert_eq!(bytes, payload);
        }
        other => panic!("expected Unknown, got {other:?}"),
    }
}

#[test]
fn umbrella_decodes_op_kad_fwtcpcheck_ack_as_a_typed_ack_not_unknown() {
    // `OP_KAD_FWTCPCHECK_ACK` is aMule byte `0xA8` (kad2/Client2Client/TCP.h
    // @4e8f2b3c) — the sibling of `OP_FWCHECKUDPREQ` (`0xA7`). A firewalled aMule
    // only counts our connect-back when the ack carries this exact byte.
    let packet = Packet::new(PacketProtocol::Emule, 0xA8, Vec::new());
    assert!(matches!(
        PeerPacket::decode(&packet).expect("fw ack"),
        PeerPacket::KadFirewallAck
    ));
    // It round-trips as a null eMule-protocol packet on `0xA8`.
    let reencoded = PeerPacket::KadFirewallAck.encode();
    assert_eq!(reencoded.protocol(), PacketProtocol::Emule);
    assert_eq!(reencoded.opcode(), 0xA8);
    assert!(reencoded.payload().is_empty());
    // Trailing bytes are tolerated on receive — the ack's meaning is its arrival
    // on the link, not any body (liberal receive, ADR-0018).
    let with_trailer = Packet::new(PacketProtocol::Emule, 0xA8, vec![0xFF]);
    assert!(matches!(
        PeerPacket::decode(&with_trailer).expect("fw ack tolerant"),
        PeerPacket::KadFirewallAck
    ));
    // Its sibling `0xA7` is `OP_FWCHECKUDPREQ` (aMule `ClientTCPSocket.cpp:1942`,
    // written by `BaseClient.cpp:3982-3986`): the body stays opaque here —
    // `<intern 2><extern 2><key 4>` is the Kad node's to read — and rides
    // back out byte for byte.
    let request = vec![0x40, 0x12, 0x88, 0x13, 0x78, 0x56, 0x34, 0x12];
    let udp_check = Packet::new(PacketProtocol::Emule, 0xA7, request.clone());
    assert_eq!(
        PeerPacket::decode(&udp_check).expect("0xA7"),
        PeerPacket::KadUdpFirewallRequest(request.clone())
    );
    assert_eq!(
        PeerPacket::KadUdpFirewallRequest(request).encode(),
        udp_check
    );
    // The old (wrong) `0xA9` reverts to Unknown — it was never on any wire.
    assert!(matches!(
        PeerPacket::decode(&Packet::new(PacketProtocol::Emule, 0xA9, Vec::new())).expect("0xA9"),
        PeerPacket::Unknown { opcode: 0xA9, .. }
    ));
}
