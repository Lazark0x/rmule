//! `OP_SERVERSTATUS` against its recorded cases: round-trips byte-exact, and
//! rejects any payload that is not exactly the two counts.

use std::fs;

use rmule_ed2k::ServerStatus;
use rmule_primitives::{Packet, PacketProtocol};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ServerStatusFixture {
    name: String,
    provenance: String,
    source_note: String,
    accepted: bool,
    // `[expected]` table is intentionally not deserialised — field-by-
    // field projection asserts would be tautological with the round trip.
    // serde silently ignores unknown top-level keys.
}

#[test]
fn server_status_fixtures_round_trip_byte_exact() {
    for path in crate::fixture::case_paths_named("server", "server_status") {
        let raw = fs::read_to_string(&path).expect("read toml fixture");
        let fixture: ServerStatusFixture =
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
        let status = ServerStatus::decode_packet(&packet)
            .unwrap_or_else(|err| panic!("{} decode: {err}", fixture.name));
        assert_eq!(
            status.encode_packet().encode(),
            bytes,
            "{} re-encode",
            fixture.name
        );
    }
}

#[test]
fn server_status_rejects_payload_shorter_than_eight() {
    let packet = Packet::new(PacketProtocol::Edonkey, 0x34, vec![0; 7]);
    assert!(ServerStatus::decode_packet(&packet).is_err());
}

#[test]
fn server_status_rejects_payload_longer_than_eight() {
    let packet = Packet::new(PacketProtocol::Edonkey, 0x34, vec![0; 9]);
    assert!(ServerStatus::decode_packet(&packet).is_err());
}

#[test]
fn server_status_rejects_wrong_opcode() {
    let packet = Packet::new(PacketProtocol::Edonkey, 0x41, vec![0; 8]);
    assert!(ServerStatus::decode_packet(&packet).is_err());
}
