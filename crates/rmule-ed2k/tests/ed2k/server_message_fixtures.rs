//! `OP_SERVERMESSAGE` against its recorded cases: round-trips byte-exact,
//! preserves non-UTF-8 text bytes, and rejects a length that disagrees with
//! the payload.

use std::fs;

use rmule_ed2k::ServerMessage;
use rmule_primitives::{Packet, PacketProtocol};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ServerMessageFixture {
    name: String,
    provenance: String,
    source_note: String,
    accepted: bool,
    // `[expected]` is intentionally not deserialised — field-by-field
    // projection asserts would be tautological with the round trip below.
}

#[test]
fn server_message_fixtures_round_trip_byte_exact() {
    for path in crate::fixture::case_paths_named("server", "server_message") {
        let raw = fs::read_to_string(&path).expect("read toml fixture");
        let fixture: ServerMessageFixture =
            toml::from_str(&raw).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
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

        let bytes = fs::read(path.with_extension("bin")).expect("read bin fixture");
        let packet = Packet::decode_exact(&bytes)
            .unwrap_or_else(|err| panic!("{} packet: {err}", fixture.name));
        let msg = ServerMessage::decode_packet(&packet)
            .unwrap_or_else(|err| panic!("{} decode: {err}", fixture.name));
        assert_eq!(
            msg.encode_packet().encode(),
            bytes,
            "{} re-encode",
            fixture.name
        );
    }
}

#[test]
fn server_message_rejects_size_below_three() {
    let packet = Packet::new(PacketProtocol::Edonkey, 0x38, vec![0x00]);
    assert!(ServerMessage::decode_packet(&packet).is_err());
}

#[test]
fn server_message_rejects_length_mismatch() {
    // declares 5 bytes of text but supplies 3
    let packet = Packet::new(
        PacketProtocol::Edonkey,
        0x38,
        vec![0x05, 0x00, b'a', b'b', b'c'],
    );
    assert!(ServerMessage::decode_packet(&packet).is_err());
}

#[test]
fn server_message_rejects_wrong_opcode() {
    let packet = Packet::new(PacketProtocol::Edonkey, 0x39, vec![0x00, 0x00]);
    assert!(ServerMessage::decode_packet(&packet).is_err());
}

#[test]
fn server_message_preserves_non_utf8_text_bytes() {
    let raw = vec![0x04, 0x00, 0xff, 0xfe, b'h', b'i'];
    let packet = Packet::new(PacketProtocol::Edonkey, 0x38, raw.clone());
    let msg = ServerMessage::decode_packet(&packet).expect("decode non-utf8 message");
    assert_eq!(msg.text().as_bytes(), &[0xff, 0xfe, b'h', b'i']);
    assert_eq!(msg.encode_packet().payload(), raw.as_slice());
}
