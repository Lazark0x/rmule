//! The Run Log an `add` writes beside the store (ADR-0075): lean unless the
//! operator chose full, holding none of what a peer or a file is, and
//! mirrored to stderr with `--verbose`.

use crate::fixture::{cli, off_the_host};
use tempfile::tempdir;

/// A link naming a file and one source, on a port nothing listens on: the
/// run queues the download and ends on the source.
const LINK: &str =
    "ed2k://|file|holiday.bin|100|0123456789ABCDEF0123456789ABCDEF|/|sources,127.0.0.1:1|/";

/// What the link says of the peer and the file, none of which lean holds.
const WITHHELD: [&str; 3] = ["127.0.0.1:1", "holiday.bin", "0123456789ABCDEF"];

#[test]
fn add_writes_a_lean_run_log_with_no_peer_file_name_or_hash() {
    let data = tempdir().unwrap();
    let downloads = tempdir().unwrap();
    off_the_host(data.path());
    cli(data.path())
        .args(["config", "set-download-dir"])
        .arg(downloads.path())
        .assert()
        .success();
    let run = cli(data.path())
        .args(["--verbose", "add", LINK])
        .timeout(std::time::Duration::from_secs(60))
        .assert()
        .failure();

    let log = std::fs::read_to_string(data.path().join("rmule.log")).expect("rmule.log");
    assert!(log.contains("run_log: download.queued id="), "{log}");
    assert!(log.contains("run_log: reach.server server=none"), "{log}");
    for withheld in WITHHELD {
        assert!(!log.contains(withheld), "lean holds {withheld}:\n{log}");
    }

    let stderr = String::from_utf8_lossy(&run.get_output().stderr).into_owned();
    let mirrored: Vec<&str> = stderr
        .lines()
        .filter(|line| line.contains(" run_log: "))
        .collect();
    assert!(
        mirrored
            .iter()
            .any(|line| line.contains("download.queued id=")),
        "{stderr}"
    );
    for withheld in WITHHELD {
        assert!(
            mirrored.iter().all(|line| !line.contains(withheld)),
            "the mirror holds {withheld}:\n{stderr}"
        );
    }
}

/// The level is the *Full run log* preference the TUI's Settings tab writes:
/// with it on, the same run's log holds the peer, the file name and the hash.
#[test]
fn add_writes_the_full_level_the_shared_preference_chose() {
    let data = tempdir().unwrap();
    let downloads = tempdir().unwrap();
    off_the_host(data.path());
    rmule_core::CoreSettingsHandle::open(rmule_core::open_durable_store(data.path()).unwrap())
        .set_front_end_value(
            rmule_core::run_log::PREFERENCE_KEY,
            rmule_core::run_log::Level::Full.preference(),
        )
        .unwrap();
    cli(data.path())
        .args(["config", "set-download-dir"])
        .arg(downloads.path())
        .assert()
        .success();
    cli(data.path())
        .args(["add", LINK])
        .timeout(std::time::Duration::from_secs(60))
        .assert()
        .failure();

    let log = std::fs::read_to_string(data.path().join("rmule.log")).expect("rmule.log");
    for withheld in WITHHELD {
        assert!(log.contains(withheld), "full lacks {withheld}:\n{log}");
    }
}

/// `kad join` opens the Run Log like `add`, so the node's tracing has a
/// subscriber, and the run opens it with its `run_start` record.
#[test]
fn kad_join_opens_the_run_log_with_a_run_start() {
    let data = tempdir().unwrap();
    off_the_host(data.path());
    cli(data.path())
        .args([
            "kad",
            "join",
            "--bootstrap",
            "127.0.0.1:9",
            "--duration",
            "1",
        ])
        .timeout(std::time::Duration::from_secs(60))
        .assert()
        .success();

    let log = std::fs::read_to_string(data.path().join("rmule.log")).expect("rmule.log");
    assert!(
        log.lines()
            .next()
            .is_some_and(|line| line.contains(" run_log: run_start version=")),
        "{log}"
    );
}

/// `--verbose` puts the node's free-form lines on stderr; the lean file keeps
/// to records, and without `--verbose` stderr holds none of them.
#[test]
fn kad_join_verbose_streams_free_form_lines_to_stderr_and_not_to_a_lean_file() {
    let join = |verbose: bool| {
        let data = tempdir().unwrap();
        off_the_host(data.path());
        let mut command = cli(data.path());
        if verbose {
            command.arg("--verbose");
        }
        let run = command
            .args([
                "kad",
                "join",
                "--bootstrap",
                "127.0.0.1:9",
                "--duration",
                "1",
            ])
            .timeout(std::time::Duration::from_secs(60))
            .assert()
            .success();
        let stderr = String::from_utf8_lossy(&run.get_output().stderr).into_owned();
        let log = std::fs::read_to_string(data.path().join("rmule.log")).expect("rmule.log");
        (stderr, log)
    };

    let (stderr, log) = join(true);
    assert!(stderr.contains("kad join: bootstrapping"), "{stderr}");
    assert!(!log.contains("kad join: bootstrapping"), "{log}");

    let (stderr, _) = join(false);
    assert!(!stderr.contains("kad join: bootstrapping"), "{stderr}");
}
