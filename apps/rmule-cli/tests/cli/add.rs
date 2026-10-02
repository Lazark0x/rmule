//! `add`: what an ed2k link needs in place before the CLI will take it —
//! a download directory, and a configured server unless the link names its
//! own sources — each refused by name.

use crate::fixture::cli;
use predicates::str::contains;
use tempfile::tempdir;

// A syntactically valid synthetic ed2k file link (16-byte hash, size 100).
const LINK: &str = "ed2k://|file|sample.bin|100|0123456789ABCDEF0123456789ABCDEF|/";

#[test]
fn add_without_a_server_fails_with_guidance() {
    let dir = tempdir().unwrap();
    cli(dir.path())
        .args(["config", "set-download-dir", dir.path().to_str().unwrap()])
        .assert()
        .success();
    cli(dir.path())
        .args(["add", LINK])
        .assert()
        .failure()
        .stderr(contains("no server configured"));
}

#[test]
fn add_without_a_download_dir_fails_with_guidance() {
    let dir = tempdir().unwrap();
    cli(dir.path())
        .args(["server", "add", "127.0.0.1:4661"])
        .assert()
        .success();
    cli(dir.path())
        .args(["add", LINK])
        .assert()
        .failure()
        .stderr(contains("no download directory configured"));
}

/// A field no client reads is skipped, as eMule and aMule skip it, and the
/// operator is told which — before anything else the add needs is checked.
#[test]
fn add_names_the_fields_the_link_carried_that_no_client_reads() {
    let dir = tempdir().unwrap();
    cli(dir.path())
        .args([
            "add",
            "ed2k://|file|sample.bin|100|0123456789ABCDEF0123456789ABCDEF|x=1|comment|/",
        ])
        .assert()
        .failure()
        .stdout(contains(
            "ignored the fields `x`, `comment` the link carried, which no client reads",
        ))
        .stderr(contains("no server configured"));
}

/// A link that names its own source needs no server (ADR-0089): the add
/// runs from the link, says so, and ends on what the source
/// did — here a port nothing listens on, so the run fails, not the add.
#[test]
fn add_without_a_server_runs_from_the_links_own_source() {
    let dir = tempdir().unwrap();
    cli(dir.path())
        .args(["config", "set-download-dir", dir.path().to_str().unwrap()])
        .assert()
        .success();
    cli(dir.path())
        .args([
            "add",
            "ed2k://|file|sample.bin|100|0123456789ABCDEF0123456789ABCDEF|/|sources,127.0.0.1:1|/",
        ])
        .timeout(std::time::Duration::from_secs(60))
        .assert()
        .failure()
        .stdout(contains(
            "no server configured; starting from the 1 source the link names",
        ))
        .stdout(contains("queued id="));
}
