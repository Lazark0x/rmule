//! A captured `0xD4` packed server frame inflates to the ordinary server
//! message underneath it.

use std::{fs, path::Path};

use rmule_ed2k::ServerPacket;
use rmule_primitives::{Packet, PacketProtocol};

#[test]
fn captured_compressed_welcome_tail_inflates_to_server_message() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/server/captured/welcome-burst-2026-05-17/04_undecoded_tail.bin");
    let bytes = fs::read(path).expect("captured compressed tail");

    let raw = Packet::decode_exact(&bytes).expect("raw packed frame");
    assert_eq!(raw.protocol(), PacketProtocol::PackedEd2k);
    assert_eq!(raw.opcode(), 0x38);
    assert_eq!(raw.encode(), bytes, "raw Packet preserves compressed bytes");

    let decoded = ServerPacket::decode(&raw).expect("logical server packet");
    let ServerPacket::ServerMessage(message) = decoded else {
        panic!("expected logical ServerMessage, got {decoded:?}");
    };
    assert_eq!(message.text().as_bytes().len(), 875);
    assert!(
        message
            .text()
            .to_display_string()
            .starts_with("server version 17.15")
    );
}
