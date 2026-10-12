//! Persistence: identity, servers and preferences survive the process that
//! wrote them — every assertion crosses a process boundary.

use crate::fixture::cli;
use predicates::str::contains;
use tempfile::tempdir;

fn user_hash_line(data_dir: &std::path::Path) -> String {
    let out = cli(data_dir).args(["identity", "show"]).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    stdout
        .lines()
        .find(|l| l.starts_with("user_hash "))
        .unwrap()
        .to_owned()
}

#[test]
fn identity_servers_and_prefs_survive_a_restart() {
    let dir = tempdir().unwrap();

    // Process 1: mint identity, add a server, set the download dir.
    let minted = user_hash_line(dir.path());
    cli(dir.path())
        .args(["server", "add", "9.9.9.9:5000"])
        .assert()
        .success();
    let download_dir = rmule_testkit::absolute_path("tmp/rmule-dl");
    cli(dir.path())
        .args(["config", "set-download-dir"])
        .arg(&download_dir)
        .assert()
        .success();

    // Process 2 (fresh process, same data dir): everything is still there.
    assert_eq!(
        user_hash_line(dir.path()),
        minted,
        "identity must be stable across restart"
    );
    cli(dir.path())
        .args(["server", "list"])
        .assert()
        .success()
        .stdout(contains("9.9.9.9:5000"));
    cli(dir.path())
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(contains(download_dir.display().to_string()));
}
