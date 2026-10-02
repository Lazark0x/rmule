//! `OP_GETSERVERLIST` against its recorded cases: an empty payload round-trips
//! byte-exact, and anything else is rejected.

use std::fs;

use rmule_ed2k::GetServerList;
use rmule_primitives::{Packet, PacketProtocol};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct GetServerListFixture {
    name: String,
    provenance: String,
    source_note: String,
    accepted: bool,
    expected: ExpectedGetServerList,
}

#[derive(Debug, Deserialize)]
struct ExpectedGetServerList {
    protocol: String,
    opcode: u8,
}

#[test]
fn get_server_list_fixtures_round_trip_byte_exact() {
    for path in crate::fixture::case_paths_named("client", "get_server_list") {
        let raw = fs::read_to_string(&path).expect("read toml fixture");
        let fixture: GetServerListFixture =
            toml::from_str(&raw).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
        assert!(fixture.accepted, "{} accepted", fixture.name);
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
        assert_eq!(packet.protocol(), PacketProtocol::Edonkey);
        assert_eq!(fixture.expected.protocol, "edonkey");
        assert_eq!(packet.opcode(), fixture.expected.opcode);

        let request = GetServerList::decode_packet(&packet)
            .unwrap_or_else(|err| panic!("{} decode: {err}", fixture.name));
        assert_eq!(request.encode_packet().encode(), bytes);
    }
}

#[test]
fn get_server_list_rejects_non_empty_payload() {
    let packet = Packet::new(PacketProtocol::Edonkey, 0x14, vec![0x00]);
    assert!(GetServerList::decode_packet(&packet).is_err());
}

#[test]
fn get_server_list_rejects_wrong_opcode() {
    let packet = Packet::new(PacketProtocol::Edonkey, 0x15, Vec::new());
    assert!(GetServerList::decode_packet(&packet).is_err());
}
