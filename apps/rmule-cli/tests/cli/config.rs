//! `config`: the server list, the minted identity, and the download
//! directory, each written by one invocation and read back by the next.

use crate::fixture::cli;
use predicates::str::contains;
use tempfile::tempdir;

#[test]
fn server_add_then_list_shows_endpoint() {
    let dir = tempdir().unwrap();
    cli(dir.path())
        .args(["server", "add", "1.2.3.4:4661"])
        .assert()
        .success();
    cli(dir.path())
        .args(["server", "list"])
        .assert()
        .success()
        .stdout(contains("1.2.3.4:4661"));
}

#[test]
fn identity_show_prints_a_32_hex_char_user_hash() {
    let dir = tempdir().unwrap();
    cli(dir.path())
        .args(["identity", "show"])
        .assert()
        .success()
        .stdout(predicates::function::function(|out: &str| {
            out.lines()
                .find_map(|l| l.strip_prefix("user_hash "))
                .map(|h| h.len() == 32 && h.chars().all(|c| c.is_ascii_hexdigit()))
                .unwrap_or(false)
        }));
}

#[test]
fn config_download_dir_round_trips_in_one_process_group() {
    let dir = tempdir().unwrap();
    cli(dir.path())
        .args(["config", "set-download-dir", "/tmp/dl"])
        .assert()
        .success();
    cli(dir.path())
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(contains("/tmp/dl"));
}
