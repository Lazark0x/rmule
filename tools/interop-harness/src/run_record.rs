//! The run record: `run.toml`, written by the harness itself into every run
//! dir, so a later reader can tell one run from another without trusting file
//! times or the operator's memory.
//!
//! `resolved-config.toml` holds the flow's options and nothing else. This file
//! holds what makes two runs with the same options differ or not: the commit
//! the harness was built from and whether the tree was dirty, the sha-256 of the
//! `rmule-tools` binary (or the id of the driver image) under test, the ids of
//! the counterparty images the flow started, and when the run began, ended and
//! how. "Mine before running" compares `harness_commit` + `dirty` +
//! `rmule_binary_sha256` / `rmule_image_id`: tags alone do not tell two builds
//! apart.
//!
//! The record is process-wide because a run is: [`begin`] opens it where the
//! run dir is created, the build steps note what they built, and [`finish`]
//! closes it whether the flow failed or not. A re-score of a retained run never
//! rewrites it; [`rescored`] adds its time to the top-level `rescored_at` list.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::docker::Docker;

/// The record's file name inside a run dir.
pub const FILE_NAME: &str = "run.toml";

/// What `run.toml` says. Plain values come first, the image table last.
#[derive(Debug, Default, Serialize)]
struct Record {
    started_unix_ms: u128,
    /// `git rev-parse HEAD` of the workspace the harness was built from.
    harness_commit: String,
    /// Whether `git status --porcelain` listed anything.
    dirty: bool,
    /// How many paths it listed (the paths themselves are not recorded).
    dirty_paths: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    rmule_binary_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rmule_image_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    finished_unix_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u128>,
    /// `pass`, `fail`, `skip` or `error`; see [`outcome`].
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<&'static str>,
    /// Image tag to image id, for every counterparty and driver image started.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    counterparty_images: BTreeMap<String, String>,
}

struct Open {
    run_dir: PathBuf,
    started: Instant,
    record: Record,
    /// A prebuilt binary the run will use, hashed at [`finish`] when no step
    /// hashed one right after building it.
    expected_binary: Option<PathBuf>,
}

static OPEN: Mutex<Option<Open>> = Mutex::new(None);

fn with_open(change: impl FnOnce(&mut Open)) {
    let mut guard = OPEN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(open) = guard.as_mut() {
        change(open);
        // Best effort: a record that cannot be written must not fail a flow.
        let _ = write(open);
    }
}

fn write(open: &Open) -> Result<()> {
    let text = toml::to_string_pretty(&open.record).context("serialize the run record")?;
    let path = open.run_dir.join(FILE_NAME);
    fs::write(&path, text).with_context(|| format!("write {}", path.display()))
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis())
}

/// The workspace this harness was built from.
fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(workspace())
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())?;
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Open the record for `run_dir` and write what is known at the start: the
/// time, the commit and whether the tree is dirty.
///
/// # Errors
/// If `run.toml` cannot be written.
pub fn begin(run_dir: &Path) -> Result<()> {
    let status = git(&["status", "--porcelain"]);
    let open = Open {
        run_dir: run_dir.to_owned(),
        started: Instant::now(),
        record: Record {
            started_unix_ms: unix_ms(),
            harness_commit: git(&["rev-parse", "HEAD"])
                .map_or_else(|| "unknown".to_owned(), |text| text.trim().to_owned()),
            dirty: status
                .as_deref()
                .is_some_and(|text| !text.trim().is_empty()),
            dirty_paths: status.as_deref().map_or(0, |text| text.lines().count()),
            ..Record::default()
        },
        expected_binary: None,
    };
    write(&open)?;
    *OPEN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(open);
    Ok(())
}

/// The sha-256 of `path`, or `None` where no hashing tool answers.
fn sha256(path: &Path) -> Option<String> {
    for (program, args) in [("shasum", &["-a", "256"][..]), ("sha256sum", &[][..])] {
        let output = Command::new(program).args(args).arg(path).output().ok();
        if let Some(output) = output.filter(|output| output.status.success()) {
            let text = String::from_utf8_lossy(&output.stdout);
            return text.split_whitespace().next().map(str::to_owned);
        }
    }
    None
}

/// Record the hash of the `rmule-tools` binary under test.
pub fn note_binary(path: &Path) {
    let hash = sha256(path);
    with_open(|open| open.record.rmule_binary_sha256 = hash);
}

/// Name the prebuilt `rmule-tools` binary this run's containers will run. It is
/// hashed when the run ends, by which time the prebuild has produced it; a step
/// that holds the built file calls [`note_binary`] instead and hashes at once.
pub fn expect_binary(path: &Path) {
    with_open(|open| open.expected_binary = Some(path.to_owned()));
}

/// Record the id of image `tag`, as a counterparty or driver image the run
/// started; `as_rmule` also makes it the `rmule_image_id`.
pub fn note_image(docker: &Docker, tag: &str, as_rmule: bool) {
    let id = docker
        .image_id(tag.to_owned())
        .to_command()
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|id| !id.is_empty());
    let Some(id) = id else { return };
    with_open(|open| {
        if open.record.counterparty_images.get(tag) == Some(&id) && !as_rmule {
            return;
        }
        if as_rmule {
            open.record.rmule_image_id = Some(id.clone());
        }
        open.record.counterparty_images.insert(tag.to_owned(), id);
    });
}

/// How a verdict body names the rmule under test: the commit (`+dirty` when the
/// tree was), and the binary hash prefix. Replaces a bare "this worktree".
#[must_use]
pub fn rmule_pin() -> String {
    let guard = OPEN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(open) = guard.as_ref() else {
        return "rmule, build unrecorded".to_owned();
    };
    let record = &open.record;
    let commit = record
        .harness_commit
        .get(..12)
        .unwrap_or(&record.harness_commit);
    let dirty = if record.dirty { "+dirty" } else { "" };
    let binary = record
        .rmule_binary_sha256
        .as_deref()
        .and_then(|hash| hash.get(..12))
        .map_or_else(
            || "binary unrecorded".to_owned(),
            |hash| format!("sha256 {hash}"),
        );
    format!("{commit}{dirty} {binary}")
}

/// The run's outcome from how it ended and what its verdict files say: `error`
/// when the flow returned an error, `fail` when any verdict reads `FAIL`,
/// `skip` when every verdict reads `SKIPPED`, `pass` otherwise (the flow
/// completed; the verdict files carry the finer reading).
fn outcome(run_dir: &Path, errored: bool) -> &'static str {
    if errored {
        return "error";
    }
    let mut verdicts = Vec::new();
    collect_verdicts(run_dir, &mut verdicts);
    if verdicts.iter().any(|verdict| verdict == "FAIL") {
        "fail"
    } else if !verdicts.is_empty() && verdicts.iter().all(|verdict| verdict == "SKIPPED") {
        "skip"
    } else {
        "pass"
    }
}

fn collect_verdicts(dir: &Path, found: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_verdicts(&path, found);
        } else if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with("-verdict.toml"))
            && let Ok(text) = fs::read_to_string(&path)
            && let Ok(value) = text.parse::<toml::Table>()
            && let Some(verdict) = value.get("verdict").and_then(toml::Value::as_str)
        {
            found.push(verdict.to_owned());
        }
    }
}

/// Close the record: when the run ended, how long it took and how it ended.
/// Called whether the flow failed or not.
pub fn finish(errored: bool) {
    with_open(|open| {
        if open.record.rmule_binary_sha256.is_none()
            && let Some(path) = open
                .expected_binary
                .as_deref()
                .filter(|path| path.is_file())
        {
            open.record.rmule_binary_sha256 = sha256(path);
        }
        open.record.finished_unix_ms = Some(unix_ms());
        open.record.duration_ms = Some(open.started.elapsed().as_millis());
        open.record.outcome = Some(outcome(&open.run_dir, errored));
    });
}

/// A re-score of a retained run: add its time to the `rescored_at` list of
/// its `run.toml` and change nothing else. A run dir without a record (one
/// from before the record existed) is left alone.
pub fn rescored(run_dir: &Path) {
    let path = run_dir.join(FILE_NAME);
    if let Ok(text) = fs::read_to_string(&path) {
        let _ = fs::write(&path, with_rescore(&text, unix_ms()));
    }
}

/// `text` with `at` added to its top-level `rescored_at` list. The list sits
/// ahead of the first table: a line appended at the end lands inside the last
/// table, and a second one there is a duplicate key no TOML reader accepts.
fn with_rescore(text: &str, at: u128) -> String {
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let tables = lines
        .iter()
        .position(|line| line.starts_with('['))
        .unwrap_or(lines.len());
    match lines[..tables]
        .iter()
        .position(|line| line.starts_with("rescored_at = ["))
    {
        Some(index) => {
            let listed = lines[index].trim_end().trim_end_matches(']').to_owned();
            lines[index] = format!("{listed}, {at}]");
        }
        None => lines.insert(tables, format!("rescored_at = [{at}]")),
    }
    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::{FILE_NAME, outcome, rescored};

    fn verdict(dir: &std::path::Path, name: &str, verdict: &str) {
        std::fs::write(
            dir.join(format!("{name}-verdict.toml")),
            format!("verdict = \"{verdict}\"\n"),
        )
        .unwrap();
    }

    /// Any FAIL fails the run, all-SKIPPED skips it, an error beats both, and
    /// verdicts under a flow's subdirectory count.
    #[test]
    fn the_outcome_reads_the_verdict_files_and_how_the_flow_ended() {
        let run = tempfile::tempdir().unwrap();
        let nested = run.path().join("nat");
        std::fs::create_dir(&nested).unwrap();
        verdict(&nested, "a", "SKIPPED");
        assert_eq!(outcome(run.path(), false), "skip");
        verdict(run.path(), "b", "OBSERVED");
        assert_eq!(outcome(run.path(), false), "pass");
        verdict(run.path(), "c", "FAIL");
        assert_eq!(outcome(run.path(), false), "fail");
        assert_eq!(outcome(run.path(), true), "error");
    }

    /// Two re-scores of a record with a table leave one top-level list of
    /// two times, the rest as it was, and a file a TOML reader accepts.
    #[test]
    fn rescores_list_their_times_ahead_of_every_table() {
        let run = tempfile::tempdir().unwrap();
        let path = run.path().join(FILE_NAME);
        let record =
            "harness_commit = \"abc\"\n\n[counterparty_images]\n\"a:local\" = \"sha256:1\"\n";
        std::fs::write(&path, record).unwrap();
        rescored(run.path());
        rescored(run.path());
        let text = std::fs::read_to_string(&path).unwrap();
        let table: toml::Table = text.parse().expect("a TOML record");
        assert_eq!(table["rescored_at"].as_array().map(Vec::len), Some(2));
        assert_eq!(
            table["counterparty_images"].as_table().map(|t| t.len()),
            Some(1)
        );
        assert!(text.starts_with("harness_commit = \"abc\"\n\nrescored_at = ["));
        assert!(text.ends_with("[counterparty_images]\n\"a:local\" = \"sha256:1\"\n"));
    }
}
