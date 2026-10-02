//! The built `rmule` binary's front door (ADR-0076 §Arguments): every way an
//! invocation ends before the UI — help, version, a refused argument, no
//! terminal — leaves the data directory exactly as it found it.

use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

/// A scratch home: `HOME` and `RMULE_DATA` both point inside it, and no other
/// data-directory variable is set, so nothing the binary might write can land
/// outside it.
fn rmule(home: &Path) -> Command {
    let mut command = Command::cargo_bin("rmule").expect("the rmule binary is built");
    command
        .env_remove("XDG_DATA_HOME")
        .env_remove("RMULE_LOG")
        .env("HOME", home)
        .env("RMULE_DATA", home.join("data"))
        .write_stdin("");
    command
}

fn assert_untouched(home: &TempDir) {
    let left: Vec<_> = std::fs::read_dir(home.path())
        .expect("the scratch home is readable")
        .map(|entry| entry.expect("an entry").file_name())
        .collect();
    assert!(left.is_empty(), "the invocation wrote {left:?}");
}

#[test]
fn help_prints_where_the_data_lives_and_touches_nothing() {
    let home = TempDir::new().unwrap();
    rmule(home.path())
        .arg("--help")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Usage: rmule [--data-dir <path>]"))
        .stdout(predicate::str::contains(format!(
            "Data directory  {} (from RMULE_DATA)",
            home.path().join("data").display()
        )))
        .stdout(predicate::str::contains("RMULE_LOG"));
    let flag = home.path().join("elsewhere");
    rmule(home.path())
        .arg("--data-dir")
        .arg(&flag)
        .arg("-h")
        .assert()
        .code(0)
        .stdout(predicate::str::contains(format!(
            "Data directory  {} (from --data-dir)",
            flag.display()
        )));
    assert_untouched(&home);
}

/// On Unix `--data-dir=<path>` takes a path that is not UTF-8, as the
/// two-argument form does.
#[cfg(unix)]
#[test]
fn an_inline_data_dir_that_is_not_utf8_is_taken() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let home = TempDir::new().unwrap();
    let mut inline = b"--data-dir=".to_vec();
    inline.extend_from_slice(home.path().as_os_str().as_bytes());
    inline.extend_from_slice(b"/data-\xff");
    rmule(home.path())
        .arg(std::ffi::OsString::from_vec(inline))
        .arg("--help")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("(from --data-dir)"));
    assert_untouched(&home);
}

/// The binary prints the one version line the help overlay shows, and this
/// checkout's build names its commit's date.
#[test]
fn version_prints_the_one_version_line_and_touches_nothing() {
    let home = TempDir::new().unwrap();
    let line = rmule::words::front_door::version_line(rmule::args::BUILD);
    assert!(
        line.starts_with(&format!("rmule {} (", env!("CARGO_PKG_VERSION"))),
        "{line}"
    );
    assert!(line.contains(", committed "), "{line}");
    rmule(home.path())
        .arg("--version")
        .assert()
        .code(0)
        .stdout(format!("{line}\n"));
    assert_untouched(&home);
}

#[test]
fn an_unknown_argument_is_refused_with_the_usage_and_touches_nothing() {
    let home = TempDir::new().unwrap();
    rmule(home.path())
        .arg("--bogus")
        .assert()
        .code(2)
        .stdout("")
        .stderr(predicate::str::starts_with(
            "rmule: \"--bogus\" is not an option of rmule; nothing was started.",
        ))
        .stderr(predicate::str::contains("Usage: rmule"));
    assert_untouched(&home);
}

/// The regression: a run without a terminal used to open the store, the Run
/// Log and `clients.met` in the data directory before it panicked.
#[test]
fn a_run_without_a_terminal_ends_in_a_sentence_and_touches_nothing() {
    let home = TempDir::new().unwrap();
    rmule(home.path())
        .args(["--log-level", "detailed"])
        .assert()
        .code(1)
        .stdout("")
        .stderr(
            "rmule needs a terminal, and neither its input nor its output is one; nothing was started.\n",
        );
    assert_untouched(&home);
}
