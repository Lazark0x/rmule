//! `config`: the server list, the minted identity, the download directory
//! and the Temp Directory, each written by one invocation and read back by
//! the next.

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
    let download_dir = rmule_testkit::absolute_path("tmp/dl");
    cli(dir.path())
        .args(["config", "set-download-dir"])
        .arg(&download_dir)
        .assert()
        .success();
    cli(dir.path())
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(contains(download_dir.display().to_string()));
}

/// The Temp Directory reads as the default in the data directory until one
/// is set; a set one is made and shown, and one inside the download
/// directory is refused with its reason and not stored.
#[test]
fn config_temp_dir_is_made_shown_and_refused_inside_a_shared_directory() {
    let data = tempdir().unwrap();
    let elsewhere = tempdir().unwrap();
    let default = data.path().join("Temp");
    cli(data.path())
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(contains(format!(
            "temp_dir {} (default)",
            default.display()
        )));

    let parts = elsewhere.path().join("parts");
    cli(data.path())
        .args(["config", "set-temp-dir"])
        .arg(&parts)
        .assert()
        .success();
    assert!(parts.is_dir());

    let downloads = elsewhere.path().join("Downloads");
    cli(data.path())
        .args(["config", "set-download-dir"])
        .arg(&downloads)
        .assert()
        .success();
    cli(data.path())
        .args(["config", "set-temp-dir"])
        .arg(downloads.join("parts"))
        .assert()
        .failure()
        .stderr(contains(
            "is not set as the temp directory: it lies inside the shared directory",
        ));
    cli(data.path())
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(contains(format!("temp_dir {}", parts.display())));
}
