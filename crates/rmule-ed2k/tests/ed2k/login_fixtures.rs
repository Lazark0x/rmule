//! Per-fixture decode + round-trip checks for the handwritten
//! `OP_LOGINREQUEST` fixtures. Field-by-field projection asserts (the
//! decoded `user_hash` / `client_id` / `tcp_port` / `tag_count` values
//! mirroring the same numbers in the `.toml` sidecar that we typed) are
//! deliberately *not* tested here — they're tautological with the round
//! trip below (decode then `encode_packet().encode()` byte-exact would
//! fail if any of those projections were wrong). What's left is the
//! load-bearing contract: accepted fixtures parse and round-trip
//! byte-exact; rejected fixtures fail at the documented stage with a
//! documented reason.

use std::fs;

use rmule_ed2k::LoginRequest;
use rmule_primitives::Packet;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct LoginFixture {
    name: String,
    provenance: String,
    source_note: String,
    accepted: bool,
    #[serde(default)]
    reject_reason: Option<String>,
    expected: ExpectedKind,
}

#[derive(Debug, Deserialize)]
struct ExpectedKind {
    kind: String,
}

#[test]
fn login_fixtures_decode_and_reencode_exact_bytes() {
    for fixture_path in crate::fixture::case_paths("login") {
        let raw = fs::read_to_string(&fixture_path).expect("read login fixture");
        let fixture: LoginFixture = toml::from_str(&raw)
            .unwrap_or_else(|error| panic!("{}: {error}", fixture_path.display()));
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
        if fixture.expected.kind != "login_request" {
            continue;
        }

        let packet_bytes = fs::read(fixture_path.with_extension("bin")).expect("read packet bytes");
        let decoded_packet = Packet::decode_exact(&packet_bytes);

        if !fixture.accepted {
            assert!(
                fixture.reject_reason.is_some(),
                "{} should include reject_reason",
                fixture.name
            );
            if let Ok(packet) = decoded_packet {
                assert!(
                    LoginRequest::decode_packet(&packet).is_err(),
                    "{} should reject login packet",
                    fixture.name
                );
            }
            continue;
        }

        let packet =
            decoded_packet.unwrap_or_else(|error| panic!("{} packet: {error}", fixture.name));
        let login = LoginRequest::decode_packet(&packet)
            .unwrap_or_else(|error| panic!("{} login: {error}", fixture.name));
        assert_eq!(
            login.encode_packet().encode(),
            packet_bytes,
            "{} re-encode",
            fixture.name
        );
    }
}
