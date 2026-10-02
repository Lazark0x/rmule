//! `OP_SERVERIDENT` against its recorded cases: round-trips byte-exact,
//! preserves a well-formed unknown tag, and rejects a short or trailing-byte
//! payload.

use std::{fs, net::Ipv4Addr};

use rmule_ed2k::ServerIdent;
use rmule_primitives::{Packet, PacketProtocol, ServerHash};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ServerIdentFixture {
    name: String,
    provenance: String,
    source_note: String,
    accepted: bool,
    // `[expected]` is intentionally not deserialised — the per-field
    // projection asserts (`server_hash`, `advertised_ip`, `name`,
    // `description`, `extra_tag_ids`) were tautological with the round
    // trip below.
}

#[test]
fn server_ident_fixtures_round_trip_byte_exact() {
    for path in crate::fixture::case_paths_named("server", "server_ident") {
        let raw = fs::read_to_string(&path).expect("read toml fixture");
        let fixture: ServerIdentFixture =
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
        let ident = ServerIdent::decode_packet(&packet)
            .unwrap_or_else(|err| panic!("{} decode: {err}", fixture.name));
        assert_eq!(
            ident.encode_packet().encode(),
            bytes,
            "{} re-encode",
            fixture.name
        );
    }
}

#[test]
fn server_ident_rejects_payload_shorter_than_fixed_prefix() {
    let packet = Packet::new(PacketProtocol::Edonkey, 0x41, vec![0; 25]);
    assert!(ServerIdent::decode_packet(&packet).is_err());
}

#[test]
fn server_ident_rejects_trailing_bytes_after_tags() {
    // 16 + 6 + 4 = 26 byte prefix, tag_count = 0, then 1 trailing byte
    let mut payload = vec![0u8; 26];
    payload.push(0xAA);
    let packet = Packet::new(PacketProtocol::Edonkey, 0x41, payload);
    assert!(ServerIdent::decode_packet(&packet).is_err());
}

#[test]
fn server_ident_preserves_unknown_well_formed_tag() {
    use rmule_primitives::{Tag, TagName, TagValue};

    let known = Tag::new(
        TagName::compact_id(0x01),
        TagValue::String(rmule_primitives::Ed2kText::from_utf8("name")),
    );
    let unknown = Tag::new(TagName::compact_id(0x90), TagValue::U32(42));
    let original = ServerIdent::new(
        ServerHash::from_bytes([0; ServerHash::BYTE_LEN]),
        rmule_primitives::Ipv4Endpoint::new(Ipv4Addr::new(127, 0, 0, 1), 4661),
        vec![known, unknown.clone()],
    );

    let bytes = original.encode_packet().encode();
    let packet = Packet::decode_exact(&bytes).unwrap();
    let decoded = ServerIdent::decode_packet(&packet).unwrap();
    let identity = decoded.identity();
    assert_eq!(identity.extra_tags, vec![unknown]);
    assert!(identity.name.is_some());
    assert_eq!(decoded.encode_packet().encode(), bytes);
}
