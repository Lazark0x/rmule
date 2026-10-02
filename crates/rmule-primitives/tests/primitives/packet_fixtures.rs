//! Packet framing against recorded cases: each `tests/fixtures/packets` pair
//! (a `.toml` describing the frame, a `.bin` holding it) must decode to the
//! described protocol, opcode and payload, and re-encode to the same bytes.

use std::fs;

use data_encoding::HEXUPPER;
use rmule_primitives::{Packet, PacketProtocol};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct PacketFixture {
    name: String,
    provenance: String,
    source_note: String,
    accepted: bool,
    expected: ExpectedPacket,
}

#[derive(Debug, Deserialize)]
struct ExpectedPacket {
    protocol: String,
    protocol_byte: u8,
    length: u32,
    opcode: u8,
    payload_hex: String,
}

#[test]
fn packet_fixtures_decode_and_reencode_exact_bytes() {
    for fixture_path in crate::fixture::case_paths("packets") {
        let fixture: PacketFixture = crate::fixture::case(&fixture_path);
        assert!(fixture.accepted, "{} should be accepted", fixture.name);
        assert!(
            !fixture.provenance.is_empty(),
            "{} provenance",
            fixture.name
        );
        assert!(
            !fixture.source_note.is_empty(),
            "{} source_note",
            fixture.name
        );

        let packet_bytes = fs::read(fixture_path.with_extension("bin")).expect("read packet bytes");
        assert_eq!(
            packet_bytes[0], fixture.expected.protocol_byte,
            "{} protocol byte",
            fixture.name
        );

        let packet = Packet::decode_exact(&packet_bytes)
            .unwrap_or_else(|error| panic!("{}: {error}", fixture.name));
        let expected_protocol = match fixture.expected.protocol.as_str() {
            "edonkey" => PacketProtocol::Edonkey,
            "emule" => PacketProtocol::Emule,
            "packed-ed2k" => PacketProtocol::PackedEd2k,
            other => panic!("{} unknown protocol fixture name {other}", fixture.name),
        };
        assert_eq!(
            packet.protocol(),
            expected_protocol,
            "{} protocol",
            fixture.name
        );
        assert_eq!(
            packet.encoded_payload_len(),
            fixture.expected.length,
            "{} length",
            fixture.name
        );
        assert_eq!(
            packet.opcode(),
            fixture.expected.opcode,
            "{} opcode",
            fixture.name
        );
        assert_eq!(
            packet.payload(),
            HEXUPPER
                .decode(fixture.expected.payload_hex.as_bytes())
                .expect("fixture payload hex"),
            "{} payload",
            fixture.name
        );
        assert_eq!(packet.encode(), packet_bytes, "{} re-encode", fixture.name);
    }
}
