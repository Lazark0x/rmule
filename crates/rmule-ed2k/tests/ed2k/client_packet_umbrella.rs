//! The client-packet umbrella: every opcode we send decodes back through the
//! one enum, and an opcode it does not know survives as the unknown variant
//! rather than being dropped.

use std::{fs, path::Path};

use rmule_ed2k::ClientPacket;
use rmule_primitives::{Packet, PacketProtocol};

#[test]
fn login_request_fixture_decodes_via_client_packet_umbrella() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/login/handwritten_login_request.bin");
    let bytes = fs::read(&path).expect("read login request fixture");
    let packet = Packet::decode_exact(&bytes).expect("decode login packet");

    let client_packet = ClientPacket::decode(&packet).expect("decode via umbrella");
    assert!(matches!(client_packet, ClientPacket::LoginRequest(_)));
    assert_eq!(client_packet.encode().encode(), bytes);
}

#[test]
fn get_server_list_fixture_decodes_via_client_packet_umbrella() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/client/get_server_list.bin");
    let bytes = fs::read(&path).expect("read get_server_list fixture");
    let packet = Packet::decode_exact(&bytes).expect("decode get_server_list packet");

    let client_packet = ClientPacket::decode(&packet).expect("decode via umbrella");
    assert!(matches!(client_packet, ClientPacket::GetServerList(_)));
    assert_eq!(client_packet.encode().encode(), bytes);
}

#[test]
fn unknown_client_opcode_round_trips_via_unknown_variant() {
    let payload = vec![0xCA, 0xFE];
    let packet = Packet::new(PacketProtocol::Edonkey, 0x77, payload.clone());
    let client_packet = ClientPacket::decode(&packet).expect("unknown decodes");
    match &client_packet {
        ClientPacket::Unknown {
            opcode,
            payload: bytes,
        } => {
            assert_eq!(*opcode, 0x77);
            assert_eq!(bytes, &payload);
        }
        other => panic!("expected Unknown, got {other:?}"),
    }
    assert_eq!(client_packet.encode().encode(), packet.encode());
}

#[test]
fn malformed_known_client_packet_rejects() {
    // OP_GETSERVERLIST (0x14) requires empty payload — non-empty must reject
    let packet = Packet::new(PacketProtocol::Edonkey, 0x14, vec![0xAA]);
    assert!(ClientPacket::decode(&packet).is_err());
}

#[test]
fn offer_files_round_trips_via_client_packet_umbrella() {
    use rmule_ed2k::{OfferFiles, OfferedFile, ServerGrants};
    use rmule_primitives::{ClientId, Ed2kText, FileHash};

    let announce = OfferFiles::announce(
        ServerGrants::default(),
        ClientId::from_u32(0x0403_0201),
        ClientId::from_u32(0x0403_0201),
        4662,
        &[OfferedFile::new(
            FileHash::from_bytes([0x11; FileHash::BYTE_LEN]),
            42,
            Ed2kText::from_utf8("ab"),
        )],
    );
    let packet = announce.encode_packet();

    let client_packet = ClientPacket::decode(&packet).expect("decode via umbrella");
    assert!(matches!(client_packet, ClientPacket::OfferFiles(ref of) if *of == announce));
    assert_eq!(client_packet.encode().encode(), packet.encode());
}
