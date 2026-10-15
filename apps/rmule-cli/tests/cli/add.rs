//! `add`: what an ed2k link needs in place before the CLI will take it —
//! a download directory, and a configured server unless the link names its
//! own sources — each refused by name.

use crate::fixture::{cli, off_the_host};
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use tempfile::tempdir;

// A syntactically valid synthetic ed2k file link (16-byte hash, size 100).
const LINK: &str = "ed2k://|file|sample.bin|100|0123456789ABCDEF0123456789ABCDEF|/";

// The same link naming one source, on a port nothing listens on: the add runs
// without a server and fails on the source.
const SOURCED_LINK: &str =
    "ed2k://|file|sample.bin|100|0123456789ABCDEF0123456789ABCDEF|/|sources,127.0.0.1:1|/";

#[test]
fn add_without_a_server_fails_with_guidance() {
    let dir = tempdir().unwrap();
    let downloads = tempdir().unwrap();
    cli(dir.path())
        .args([
            "config",
            "set-download-dir",
            downloads.path().to_str().unwrap(),
        ])
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

/// An add that ends in a refusal still quits the core (ADR-0093): the quit's
/// steps reach the Run Log and the credit checkpoint is written before the
/// process exits, whatever way the add ended.
#[test]
fn an_add_the_core_refuses_still_runs_quit_before_exiting() {
    let dir = tempdir().unwrap();
    off_the_host(dir.path());
    cli(dir.path())
        .args(["add", SOURCED_LINK])
        .timeout(std::time::Duration::from_secs(60))
        .assert()
        .failure()
        .stderr(contains("no download directory configured"));
    assert!(
        dir.path().join("clients.met").exists(),
        "quit's checkpoint must have written clients.met"
    );
    let log = std::fs::read_to_string(dir.path().join("rmule.log")).expect("rmule.log");
    assert!(
        log.contains("quit.step"),
        "no quit step in the run log:\n{log}"
    );
}

/// A link that names its own source needs no server (ADR-0089): the add
/// runs from the link, says so, and ends on what the source
/// did — here a port nothing listens on, so the run fails, not the add.
#[test]
fn add_without_a_server_runs_from_the_links_own_source() {
    let dir = tempdir().unwrap();
    let downloads = tempdir().unwrap();
    off_the_host(dir.path());
    cli(dir.path())
        .args([
            "config",
            "set-download-dir",
            downloads.path().to_str().unwrap(),
        ])
        .assert()
        .success();
    cli(dir.path())
        .args(["add", SOURCED_LINK])
        .timeout(std::time::Duration::from_secs(60))
        .assert()
        .failure()
        .stdout(contains(
            "no server configured; starting from the 1 source the link names",
        ))
        .stdout(contains("queued id="));
}

/// The share guards hold for the download directory (ADR-0101): rmule's data
/// directory is refused at the set, with the reason, and nothing is stored;
/// one that is the operator's home by the time the add's core scans it is
/// refused at attach and the operator told, and so is the download, which
/// would finish where it is shared.
#[test]
fn the_share_guards_refuse_the_data_dir_at_the_set_and_the_home_at_the_add() {
    let dir = tempdir().unwrap();
    off_the_host(dir.path());
    cli(dir.path())
        .args(["config", "set-download-dir", dir.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(contains(
            "is not set as the download directory: everything under it is shared, and it is rmule's own data directory",
        ));
    cli(dir.path())
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(contains("download_dir <unset>"));

    let home = tempdir().unwrap();
    cli(dir.path())
        .args(["config", "set-download-dir", home.path().to_str().unwrap()])
        .assert()
        .success();
    cli(dir.path())
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .args(["add", SOURCED_LINK])
        .timeout(std::time::Duration::from_secs(60))
        .assert()
        .failure()
        .stdout(contains(format!(
            "the download directory {} is not shared: it is your home directory",
            home.path().display()
        )))
        .stdout(contains("queued id=").not())
        .stderr(contains(
            "download refused: everything under the download directory is shared, and it is your home directory",
        ));
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}
