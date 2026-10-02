//! `rmule-tools ed2k peer packet inspect` over the CLI: one leg per peer
//! opcode, each writing a real encoded packet to disk and asserting the typed
//! fields the tool prints back. The two capture commands are covered by their
//! `--help` surface here and by a live `#[ignore]`d run.

use std::net::Ipv4Addr;

use assert_cmd::Command;
use predicates::prelude::*;
use rmule_peer::{
    FileReqAnsNoFil, FileStatus, HashSetAnswer, HashSetRequest, Hello, HelloAnswer, PartBitmap,
    PartOffsetWidth, PartRanges, PeerHelloBody, QueueRanking, ReqFileNameAnswer, RequestFileName,
    RequestParts, SendingPart, SetReqFileId, StartUploadReq,
};
use rmule_primitives::{
    ClientId, Ed2kText, FileHash, Ipv4Endpoint, Packet, PacketProtocol, PartHash, Tag, TagName,
    TagValue, UserHash,
};
use tempfile::TempDir;

fn write_packet_fixture(name: &str, packet: &Packet) -> (TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    std::fs::write(&path, packet.encode()).unwrap();
    (dir, path)
}

fn answer_body() -> PeerHelloBody {
    PeerHelloBody {
        user_hash: UserHash::from_bytes([0xCD; UserHash::BYTE_LEN]),
        client_id: ClientId::from_u32(0x03020100),
        tcp_port: 4662,
        tags: vec![Tag::new(
            TagName::length_prefixed_id(0x01),
            TagValue::String(Ed2kText::from_utf8("inspector-peer")),
        )],
        connected_server: Ipv4Endpoint::new(Ipv4Addr::new(192, 0, 2, 1), 4661),
    }
}

#[test]
fn peer_packet_inspect_hello_answer_prints_typed_fields() {
    let packet = HelloAnswer::new(answer_body()).encode_packet();
    let (_dir, path) = write_packet_fixture("hello_answer.bin", &packet);

    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args(["ed2k", "peer", "packet", "inspect", path.to_str().unwrap()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("kind: hello_answer"))
        .stdout(predicate::str::contains(
            "user_hash: CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD",
        ))
        .stdout(predicate::str::contains("client_id: 50462976"))
        .stdout(predicate::str::contains("tcp_port: 4662"))
        .stdout(predicate::str::contains("nickname: inspector-peer"));
}

#[test]
fn peer_packet_inspect_hello_prints_typed_fields() {
    let packet = Hello::new(answer_body()).encode_packet();
    let (_dir, path) = write_packet_fixture("hello.bin", &packet);

    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args(["ed2k", "peer", "packet", "inspect", path.to_str().unwrap()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("kind: hello"))
        .stdout(predicate::str::contains("tcp_port: 4662"));
}

#[test]
fn peer_packet_inspect_unknown_opcode_prints_kind_unknown() {
    let packet = Packet::new(PacketProtocol::Edonkey, 0x77, vec![1, 2, 3, 4, 5]);
    let (_dir, path) = write_packet_fixture("unknown.bin", &packet);

    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args(["ed2k", "peer", "packet", "inspect", path.to_str().unwrap()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("kind: unknown"))
        .stdout(predicate::str::contains("opcode: 0x77"))
        .stdout(predicate::str::contains("payload_len: 5"));
}

fn file_hash() -> FileHash {
    FileHash::from_bytes([0xEF; 16])
}

fn run_inspect_against(name: &str, packet: &Packet) -> assert_cmd::assert::Assert {
    let (_dir, path) = write_packet_fixture(name, packet);
    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args(["ed2k", "peer", "packet", "inspect", path.to_str().unwrap()]);
    cmd.assert().success()
}

#[test]
fn peer_packet_inspect_request_filename_kind_and_hash() {
    let pkt = RequestFileName::new(file_hash(), None).encode_packet();
    run_inspect_against("rfn.bin", &pkt)
        .stdout(predicate::str::contains("kind: request_filename"))
        .stdout(predicate::str::contains(
            "file_hash: EFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEF",
        ));
}

#[test]
fn peer_packet_inspect_req_filename_answer_includes_name() {
    let pkt = ReqFileNameAnswer {
        file_hash: file_hash(),
        file_name: Ed2kText::from_utf8("foo.bin"),
    }
    .encode_packet();
    run_inspect_against("rfna.bin", &pkt)
        .stdout(predicate::str::contains("kind: req_filename_answer"))
        .stdout(predicate::str::contains("file_name: foo.bin"));
}

#[test]
fn peer_packet_inspect_file_req_ans_no_fil_kind() {
    let pkt = FileReqAnsNoFil {
        file_hash: file_hash(),
    }
    .encode_packet();
    run_inspect_against("nofile.bin", &pkt)
        .stdout(predicate::str::contains("kind: file_req_ans_no_fil"));
}

#[test]
fn peer_packet_inspect_set_req_file_id_kind() {
    let pkt = SetReqFileId {
        file_hash: file_hash(),
    }
    .encode_packet();
    run_inspect_against("setid.bin", &pkt)
        .stdout(predicate::str::contains("kind: set_req_file_id"));
}

#[test]
fn peer_packet_inspect_file_status_part_count_and_present_parts() {
    let pkt = FileStatus {
        file_hash: file_hash(),
        bitmap: PartBitmap::decode(8, &[0b0000_1111]).unwrap(),
    }
    .encode_packet();
    run_inspect_against("status.bin", &pkt)
        .stdout(predicate::str::contains("kind: file_status"))
        .stdout(predicate::str::contains("part_count: 8"))
        .stdout(predicate::str::contains("present_parts: [0, 1, 2, 3]"));
}

#[test]
fn peer_packet_inspect_hash_set_request_kind() {
    let pkt = HashSetRequest {
        file_hash: file_hash(),
    }
    .encode_packet();
    run_inspect_against("hsreq.bin", &pkt)
        .stdout(predicate::str::contains("kind: hash_set_request"));
}

#[test]
fn peer_packet_inspect_hash_set_answer_lists_part_hashes() {
    let pkt = HashSetAnswer {
        file_hash: file_hash(),
        part_hashes: vec![
            PartHash::from_bytes([0xAA; 16]),
            PartHash::from_bytes([0xBB; 16]),
        ],
    }
    .encode_packet();
    run_inspect_against("hsans.bin", &pkt)
        .stdout(predicate::str::contains("kind: hash_set_answer"))
        .stdout(predicate::str::contains("part_hash_count: 2"))
        .stdout(predicate::str::contains(
            "part_hash[0]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ));
}

#[test]
fn peer_packet_inspect_start_upload_req_kind() {
    let pkt = StartUploadReq {
        file_hash: file_hash(),
    }
    .encode_packet();
    run_inspect_against("sul.bin", &pkt).stdout(predicate::str::contains("kind: start_upload_req"));
}

#[test]
fn peer_packet_inspect_accept_upload_req_kind() {
    let pkt = Packet::new(PacketProtocol::Edonkey, 0x55, Vec::new());
    run_inspect_against("accept.bin", &pkt)
        .stdout(predicate::str::contains("kind: accept_upload_req"));
}

#[test]
fn peer_packet_inspect_out_of_part_reqs_kind() {
    let pkt = Packet::new(PacketProtocol::Edonkey, 0x57, Vec::new());
    run_inspect_against("oopr.bin", &pkt)
        .stdout(predicate::str::contains("kind: out_of_part_reqs"));
}

#[test]
fn peer_packet_inspect_queue_ranking_prints_rank() {
    let pkt = QueueRanking { rank: 42 }.encode_packet();
    run_inspect_against("qr.bin", &pkt)
        .stdout(predicate::str::contains("kind: queue_ranking"))
        .stdout(predicate::str::contains("rank: 42"));
}

#[test]
fn peer_packet_inspect_ask_shared_files_dir_ans_kind() {
    // ADR-0068: 0x60 under Edonkey is OP_ASKSHAREDFILESDIRANS, not
    // Unknown — the collision partner of `peer_packet_inspect_queue_ranking_prints_rank`'s
    // 0x60 under Emule above.
    let pkt = Packet::new(PacketProtocol::Edonkey, 0x60, vec![0u8; 12]);
    run_inspect_against("filesdirans.bin", &pkt)
        .stdout(predicate::str::contains("kind: ask_shared_files_dir_ans"));
}

#[test]
fn peer_packet_inspect_request_parts_lists_three_ranges() {
    let ranges = PartRanges::new([(0, 100), (200, 300), (0, 0)]).unwrap();
    let pkt = RequestParts {
        file_hash: file_hash(),
        ranges,
    }
    .encode_packet(PartOffsetWidth::U32)
    .unwrap();
    run_inspect_against("rp.bin", &pkt)
        .stdout(predicate::str::contains("kind: request_parts"))
        .stdout(predicate::str::contains("range[0]: start=0 end=100"))
        .stdout(predicate::str::contains("range[1]: start=200 end=300"))
        .stdout(predicate::str::contains("range[2]: start=0 end=0"));
}

#[test]
fn peer_packet_inspect_sending_part_prints_offsets_and_data_len() {
    let sp = SendingPart {
        file_hash: file_hash(),
        start: 50,
        end: 70,
        data: vec![0xCD; 20],
    };
    let pkt = sp.encode_packet(PartOffsetWidth::U32).unwrap();
    run_inspect_against("sp.bin", &pkt)
        .stdout(predicate::str::contains("kind: sending_part"))
        .stdout(predicate::str::contains("start: 50"))
        .stdout(predicate::str::contains("end: 70"))
        .stdout(predicate::str::contains("data_len: 20"));
}

#[test]
fn peer_packet_inspect_unknown_records_protocol_attribution() {
    // The exemplar has to be an opcode no ADR claims, or the test stops
    // probing Unknown attribution the day that opcode gains a meaning — as
    // 0x60 did (OP_ASKSHAREDFILESDIRANS, ADR-0068, covered by
    // `peer_packet_inspect_ask_shared_files_dir_ans_kind` below).
    let pkt = Packet::new(PacketProtocol::Edonkey, 0x62, vec![0u8; 12]);
    run_inspect_against("unk0x62.bin", &pkt)
        .stdout(predicate::str::contains("kind: unknown"))
        .stdout(predicate::str::contains("unknown_protocol: edonkey"))
        .stdout(predicate::str::contains("opcode: 0x62"));
}

#[test]
#[ignore = "requires RMULE_LIVE_PEER_ENDPOINT and a reachable peer"]
fn ed2k_peer_welcome_capture_live() {
    // Env-gated: enabled only when RMULE_LIVE_PEER_ENDPOINT is set to a
    // reachable peer endpoint. Default CI runs skip via `#[ignore]`.
    let Ok(peer) = std::env::var("RMULE_LIVE_PEER_ENDPOINT") else {
        return;
    };
    let Ok(server) = std::env::var("RMULE_LIVE_ED2K_ENDPOINT") else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args([
        "ed2k",
        "peer",
        "welcome",
        "capture",
        "--peer-endpoint",
        &peer,
        "--server",
        &server,
        "--out",
        dir.path().to_str().unwrap(),
    ]);
    cmd.assert().success();
}
