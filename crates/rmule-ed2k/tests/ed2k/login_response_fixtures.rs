//! What a server answers a login with — every `OP_IDCHANGE` and the rejection
//! that replaces it — decoded through the server-packet umbrella.

use std::fs;

use rmule_ed2k::ServerPacket;
use rmule_primitives::Packet;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct LoginResponseFixture {
    name: String,
    provenance: String,
    source_note: String,
    accepted: bool,
    expected: ExpectedLoginResponse,
}

#[derive(Debug, Deserialize)]
struct ExpectedLoginResponse {
    kind: String,
    #[serde(default)]
    client_id: Option<u32>,
    #[serde(default)]
    tcp_flags: Option<u32>,
    #[serde(default)]
    standard_tcp_port: Option<u32>,
    #[serde(default)]
    public_ip: Option<String>,
    #[serde(default)]
    obfuscation_tcp_port: Option<u32>,
    #[serde(default)]
    trailing_len: Option<usize>,
}

#[test]
fn login_response_fixtures_decode_via_server_packet_umbrella() {
    for fixture_path in crate::fixture::case_paths("login")
        .into_iter()
        .filter(|path| {
            // The login fixtures hold both directions; a response is an
            // `OP_IDCHANGE` or the rejection that replaces it.
            path.file_name().is_some_and(|name| {
                let name = name.to_string_lossy();
                name.starts_with("id_change_") || name.starts_with("op_reject")
            })
        })
    {
        let raw = fs::read_to_string(&fixture_path).expect("read login response fixture");
        let fixture: LoginResponseFixture =
            toml::from_str(&raw).unwrap_or_else(|err| panic!("{}: {err}", fixture_path.display()));
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

        let bytes = fs::read(fixture_path.with_extension("bin")).expect("read bin fixture");
        let packet = Packet::decode_exact(&bytes)
            .unwrap_or_else(|err| panic!("{} packet: {err}", fixture.name));
        let server_packet = ServerPacket::decode(&packet)
            .unwrap_or_else(|err| panic!("{} decode: {err}", fixture.name));
        // Real test: the umbrella dispatcher picked the variant the
        // fixture's opcode names. A wrong dispatch would silently land
        // in `Unknown`.
        let dispatched_kind = match server_packet {
            ServerPacket::IdChange(_) => "id_change",
            ServerPacket::Reject(_) => "reject",
            ref other => panic!(
                "{}: expected id_change or reject, decoded {other:?}",
                fixture.name
            ),
        };
        assert_eq!(
            dispatched_kind, fixture.expected.kind,
            "{} umbrella dispatch picked wrong variant",
            fixture.name
        );
        if let ServerPacket::IdChange(id) = &server_packet {
            if let Some(expected) = fixture.expected.client_id {
                assert_eq!(
                    id.client_id.as_u32(),
                    expected,
                    "{}: client_id",
                    fixture.name
                );
            }
            if let Some(expected) = fixture.expected.tcp_flags {
                let actual = id.tcp_flags.map(|f| f.bits()).unwrap_or(0);
                assert_eq!(actual, expected, "{}: tcp_flags", fixture.name);
            }
            if let Some(expected) = fixture.expected.standard_tcp_port {
                assert_eq!(
                    id.standard_tcp_port,
                    Some(expected),
                    "{}: standard_tcp_port",
                    fixture.name
                );
            }
            if let Some(expected) = &fixture.expected.public_ip {
                // Manifests write the dotted form; the codec field is the
                // wire's ip-as-u32 LE (octets in order).
                let octets = expected
                    .parse::<std::net::Ipv4Addr>()
                    .expect("manifest public_ip parses")
                    .octets();
                assert_eq!(
                    id.public_ip,
                    Some(u32::from_le_bytes(octets)),
                    "{}: public_ip",
                    fixture.name
                );
            }
            if let Some(expected) = fixture.expected.obfuscation_tcp_port {
                assert_eq!(
                    id.obfuscation_tcp_port,
                    Some(expected),
                    "{}: obfuscation_tcp_port",
                    fixture.name
                );
            }
            if let Some(expected) = fixture.expected.trailing_len {
                assert_eq!(
                    id.trailing.len(),
                    expected,
                    "{}: trailing_len",
                    fixture.name
                );
            }
        }
        assert_eq!(
            server_packet.encode().encode(),
            bytes,
            "{} re-encode",
            fixture.name
        );
    }
}
