//! `ed2k parse-link`, `canonical-link`, `hash-file` and `part-hashes`: the
//! commands that need nothing but a string or a local file, asserted on the
//! `key: value` lines they print.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn parse_link_file_prints_structured_summary() {
    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args([
        "ed2k",
        "parse-link",
        "ed2k://|file|hello%20world.txt|11|AA010FBC1D14C795D86EF98C95479D17|/",
    ]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("kind: file"))
        .stdout(predicate::str::contains("name: hello world.txt"))
        .stdout(predicate::str::contains("size: 11"))
        .stdout(predicate::str::contains(
            "file_hash: AA010FBC1D14C795D86EF98C95479D17",
        ))
        .stdout(predicate::str::contains("part_hash_count: 0"))
        .stdout(predicate::str::contains("aich_root: none"))
        .stdout(predicate::str::contains(
            "canonical_link: ed2k://|file|hello%20world.txt|11|AA010FBC1D14C795D86EF98C95479D17|/",
        ));
}

#[test]
fn parse_link_prints_the_links_sources() {
    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args([
        "ed2k",
        "parse-link",
        "ed2k://|file|a.bin|11|AA010FBC1D14C795D86EF98C95479D17|s=http://example.invalid/a.bin|s6=[2001:db8::1]:4662|/|sources,198.51.100.23:4665,host.example.invalid:4662|/",
    ]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("source_count: 2"))
        .stdout(predicate::str::contains("source: 198.51.100.23:4665\n"))
        .stdout(predicate::str::contains(
            "source: host.example.invalid:4662\n",
        ))
        .stdout(predicate::str::contains("ipv6_source: [2001:db8::1]:4662"))
        .stdout(predicate::str::contains(
            "web_source: http://example.invalid/a.bin",
        ));
}

#[test]
fn parse_link_server_prints_host_and_port() {
    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args(["ed2k", "parse-link", "ed2k://|server|192.0.2.7|4661|/"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("kind: server"))
        .stdout(predicate::str::contains("host: 192.0.2.7"))
        .stdout(predicate::str::contains("port: 4661"))
        .stdout(predicate::str::contains(
            "canonical_link: ed2k://|server|192.0.2.7|4661|/",
        ));
}

#[test]
fn parse_link_serverlist_prints_address() {
    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args([
        "ed2k",
        "parse-link",
        "ed2k://|serverlist|http://example.invalid/list.met|/",
    ]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("kind: serverlist"))
        .stdout(predicate::str::contains(
            "address: http://example.invalid/list.met",
        ));
}

#[test]
fn part_hashes_under_one_part_prints_zero_count() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("small.bin");
    std::fs::write(&path, b"hello world").unwrap();

    Command::cargo_bin("rmule-tools")
        .unwrap()
        .args(["ed2k", "part-hashes", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("file_size: 11"))
        .stdout(predicate::str::contains("part_hash_count: 0"))
        .stdout(predicate::str::contains("0: ").not());
}

#[test]
fn part_hashes_multi_part_prints_indexed_hashes() {
    // 10 MiB > ED2K_PART_SIZE (9 500 000 B) → exactly 2 part hashes.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.bin");
    let bytes = vec![0u8; 10 * 1024 * 1024];
    std::fs::write(&path, &bytes).unwrap();

    Command::cargo_bin("rmule-tools")
        .unwrap()
        .args(["ed2k", "part-hashes", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("file_size: 10485760"))
        .stdout(predicate::str::contains("part_hash_count: 2"))
        .stdout(predicate::str::contains("0: "))
        .stdout(predicate::str::contains("1: "));
}

#[test]
fn canonical_link_prints_single_line() {
    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args([
        "ed2k",
        "canonical-link",
        "ed2k://|FILE|hello%20world.txt|00011|aa010fbc1d14c795d86ef98c95479d17|/",
    ]);

    cmd.assert()
        .success()
        .stdout("ed2k://|file|hello%20world.txt|11|AA010FBC1D14C795D86EF98C95479D17|/\n");
}

#[test]
fn invalid_link_exits_nonzero() {
    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args(["ed2k", "canonical-link", "not-an-ed2k-link"]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid link"));
}

#[test]
fn hash_file_prints_file_hash_and_canonical_link() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hello world.txt");
    std::fs::write(&path, b"hello world").unwrap();

    let mut cmd = Command::cargo_bin("rmule-tools").unwrap();
    cmd.args(["ed2k", "hash-file", path.to_str().unwrap()]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "file_hash: AA010FBC1D14C795D86EF98C95479D17",
        ))
        .stdout(predicate::str::contains("size: 11"))
        .stdout(predicate::str::contains(
            "canonical_link: ed2k://|file|hello%20world.txt|11|AA010FBC1D14C795D86EF98C95479D17|/",
        ));
}
