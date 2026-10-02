//! `ed2k packet | login | server-packet | client-packet inspect`: captured
//! frames read back into typed fields. Every fixture comes from the eD2k
//! crate's tree, so the assertions are against real wire, not hand-built
//! bytes — the few synthetic frames here are encoded by the same crate that
//! decodes them.

use assert_cmd::Command;
use predicates::prelude::*;
use rmule_ed2k::{Opcode, SearchRequest, SearchResults};
use rmule_primitives::{
    ClientId, Ed2kFileClass, Ed2kText, FileHash, KeywordQuery, Packet, PacketProtocol, PeerSource,
    SearchResult,
};

use super::{client_fixture_path, login_fixture_path, server_fixture_path};

#[test]
fn packet_inspect_prints_frame_summary() {
    let fixture = login_fixture_path("handwritten_login_request.bin");
    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args(["ed2k", "packet", "inspect", fixture.to_str().unwrap()]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("protocol: edonkey"))
        .stdout(predicate::str::contains("opcode: 0x01"))
        .stdout(predicate::str::contains("length: 67"))
        .stdout(predicate::str::contains("payload_len: 66"));
}

#[test]
fn login_inspect_prints_login_summary() {
    let fixture = login_fixture_path("handwritten_login_request.bin");
    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args(["ed2k", "login", "inspect", fixture.to_str().unwrap()]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("kind: login_request"))
        .stdout(predicate::str::contains(
            "user_hash: 00112233445566778899AABBCCDDEEFF",
        ))
        .stdout(predicate::str::contains("client_id: 0"))
        .stdout(predicate::str::contains("tcp_port: 4662"))
        .stdout(predicate::str::contains("tag_count: 4"));
}

#[test]
fn server_packet_inspect_op_reject_prints_kind_reject() {
    let fixture = login_fixture_path("op_reject.bin");
    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args([
        "ed2k",
        "server-packet",
        "inspect",
        fixture.to_str().unwrap(),
    ]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("opcode: 0x05"))
        .stdout(predicate::str::contains("kind: reject"));
}

#[test]
fn server_packet_inspect_server_message_prints_text_and_length() {
    let fixture = server_fixture_path("server_message.bin");
    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args([
        "ed2k",
        "server-packet",
        "inspect",
        fixture.to_str().unwrap(),
    ]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("kind: server_message"))
        .stdout(predicate::str::contains("opcode: 0x38"))
        .stdout(predicate::str::contains("text_len: 22"))
        .stdout(predicate::str::contains("text: Welcome to test server"));
}

#[test]
fn server_packet_inspect_server_status_prints_counts() {
    let fixture = server_fixture_path("server_status.bin");
    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args([
        "ed2k",
        "server-packet",
        "inspect",
        fixture.to_str().unwrap(),
    ]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("kind: server_status"))
        .stdout(predicate::str::contains("user_count: 1000"))
        .stdout(predicate::str::contains("file_count: 50000"));
}

#[test]
fn server_packet_inspect_server_list_prints_each_entry() {
    let fixture = server_fixture_path("server_list.bin");
    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args([
        "ed2k",
        "server-packet",
        "inspect",
        fixture.to_str().unwrap(),
    ]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("kind: server_list"))
        .stdout(predicate::str::contains("server_count: 2"))
        .stdout(predicate::str::contains("0: 127.0.0.1:4661"))
        .stdout(predicate::str::contains("1: 192.168.0.1:4242"));
}

#[test]
fn server_packet_inspect_server_ident_prints_identity_fields() {
    let fixture = server_fixture_path("server_ident.bin");
    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args([
        "ed2k",
        "server-packet",
        "inspect",
        fixture.to_str().unwrap(),
    ]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("kind: server_ident"))
        .stdout(predicate::str::contains(
            "server_hash: 00112233445566778899AABBCCDDEEFF",
        ))
        .stdout(predicate::str::contains("advertised: 192.168.1.10:4661"))
        .stdout(predicate::str::contains("name: Test Server"))
        .stdout(predicate::str::contains("description: description"));
}

#[test]
fn server_packet_inspect_unknown_opcode_prints_kind_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unknown.bin");
    // 0xE3 + size=3 + opcode=0xCC + payload [0xDE, 0xAD]
    std::fs::write(&path, [0xE3, 0x03, 0x00, 0x00, 0x00, 0xCC, 0xDE, 0xAD]).unwrap();

    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args(["ed2k", "server-packet", "inspect", path.to_str().unwrap()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("kind: unknown"))
        .stdout(predicate::str::contains("unknown_opcode: 0xCC"))
        .stdout(predicate::str::contains("unknown_payload_len: 2"));
}

#[test]
fn client_packet_inspect_login_request_prints_login_fields() {
    let fixture = login_fixture_path("handwritten_login_request.bin");
    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args([
        "ed2k",
        "client-packet",
        "inspect",
        fixture.to_str().unwrap(),
    ]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("kind: login_request"))
        .stdout(predicate::str::contains(
            "user_hash: 00112233445566778899AABBCCDDEEFF",
        ))
        .stdout(predicate::str::contains("tcp_port: 4662"));
}

#[test]
fn client_packet_inspect_get_server_list_prints_kind() {
    let fixture = client_fixture_path("get_server_list.bin");
    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args([
        "ed2k",
        "client-packet",
        "inspect",
        fixture.to_str().unwrap(),
    ]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("kind: get_server_list"))
        .stdout(predicate::str::contains("opcode: 0x14"));
}

#[test]
fn client_packet_inspect_get_sources_prints_wire_form() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("get_sources.bin");
    let mut payload = vec![0xAA; 16];
    payload.extend_from_slice(&42u32.to_le_bytes());
    std::fs::write(
        &path,
        rmule_primitives::Packet::new(rmule_primitives::PacketProtocol::Edonkey, 0x19, payload)
            .encode(),
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args(["ed2k", "client-packet", "inspect", path.to_str().unwrap()]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("kind: get_sources"))
        .stdout(predicate::str::contains("wire_form: normal"))
        .stdout(predicate::str::contains("file_size: 42"));
}

#[test]
fn server_packet_inspect_found_sources_prints_peer_sources() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("found_sources.bin");
    let mut payload = vec![0xBB; 16];
    payload.push(1);
    payload.extend_from_slice(&16_777_216u32.to_le_bytes());
    payload.extend_from_slice(&4662u16.to_le_bytes());
    std::fs::write(
        &path,
        rmule_primitives::Packet::new(rmule_primitives::PacketProtocol::Edonkey, 0x42, payload)
            .encode(),
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args(["ed2k", "server-packet", "inspect", path.to_str().unwrap()]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("kind: found_sources"))
        .stdout(predicate::str::contains("source_count: 1"))
        .stdout(predicate::str::contains("client_id=16777216"))
        .stdout(predicate::str::contains("tcp_port=4662"))
        .stdout(predicate::str::contains("id_kind=high"));
}

#[test]
fn client_packet_inspect_search_request_prints_query_filters() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("search_request.bin");
    let query = KeywordQuery::new(Ed2kText::from_utf8("ubuntu"))
        .unwrap()
        .with_file_type(Ed2kFileClass::Video)
        .with_min_size(1024)
        .with_max_size(4096)
        .with_min_availability(2)
        .with_extension(Ed2kText::from_utf8("mkv"));
    std::fs::write(
        &path,
        SearchRequest::from_query(query).encode_packet().encode(),
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args(["ed2k", "client-packet", "inspect", path.to_str().unwrap()]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("kind: search_request"))
        .stdout(predicate::str::contains("phrase: ubuntu"))
        .stdout(predicate::str::contains("file_type: Video"))
        .stdout(predicate::str::contains("min_size: 1024"))
        .stdout(predicate::str::contains("max_size: 4096"))
        .stdout(predicate::str::contains("min_availability: 2"))
        .stdout(predicate::str::contains("extension: mkv"));
}

#[test]
fn server_packet_inspect_search_results_prints_result_summary() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("search_results.bin");
    let result = SearchResult::new(
        FileHash::from_bytes([0xAA; FileHash::BYTE_LEN]),
        2048,
        vec![Ed2kText::from_utf8("ubuntu.iso")],
        vec![PeerSource::new(ClientId::from_u32(0x0100_007F), 4662)],
    )
    .unwrap()
    .with_reported_availability(3);
    std::fs::write(
        &path,
        SearchResults::new(vec![result]).encode_packet().encode(),
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args(["ed2k", "server-packet", "inspect", path.to_str().unwrap()]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("kind: search_results"))
        .stdout(predicate::str::contains("result_count: 1"))
        .stdout(predicate::str::contains(
            "file_hash=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ))
        .stdout(predicate::str::contains("size=2048"))
        .stdout(predicate::str::contains("primary_name=ubuntu.iso"))
        .stdout(predicate::str::contains("source_count=1"))
        .stdout(predicate::str::contains("availability=3"));
}

#[test]
fn server_packet_inspect_malformed_search_result_reports_skip_reason() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("malformed_search_result.bin");
    std::fs::write(
        &path,
        Packet::new(
            PacketProtocol::Edonkey,
            Opcode::SearchResult.as_u8(),
            vec![0x01],
        )
        .encode(),
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args(["ed2k", "server-packet", "inspect", path.to_str().unwrap()]);

    cmd.assert().failure().stderr(predicate::str::contains(
        "malformed OP_SEARCHRESULT payload",
    ));
}
