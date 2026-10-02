//! Captures what tells one `rmule` build from another (ADR-0076 §Arguments):
//! the commit it was built from, that commit's UTC date, and whether the
//! sources that build `rmule` differed from the commit. None of them may fail
//! the build — outside a git checkout, or without git, each is left empty and
//! the words module says "unknown".

use std::path::{Path, PathBuf};
use std::process::Command;

/// Crates under `crates/` that `rmule` never links: an edit there changes
/// no binary, so it neither reruns this script nor marks the build dirty.
const NOT_LINKED: &[&str] = &["rmule-testkit"];

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let dir = Path::new(&manifest_dir);

    let commit = git(dir, &["rev-parse", "--short=12", "HEAD"]);
    let date = git(dir, &["show", "-s", "--format=%ct", "HEAD"])
        .and_then(|seconds| seconds.parse::<u64>().ok())
        .map(utc_date)
        .unwrap_or_default();
    let sources = sources(dir);
    // Tracked files only, as `git describe --dirty` counts them.
    let dirty = commit.is_some() && {
        let mut args = vec!["status", "--porcelain", "--untracked-files=no", "--"];
        args.extend(sources.iter().filter_map(|path| path.to_str()));
        git(dir, &args).is_some()
    };
    println!(
        "cargo:rustc-env=RMULE_BUILD_COMMIT={}",
        commit.unwrap_or_default()
    );
    println!("cargo:rustc-env=RMULE_BUILD_COMMITTED={date}");
    println!("cargo:rustc-env=RMULE_BUILD_DIRTY={}", u8::from(dirty));

    // Rerun when HEAD moves — HEAD itself (a branch switch), the ref it names
    // (a commit), packed refs — or the index does (a stage, a commit). A
    // worktree's `.git` is a file, so the paths come from git rather than
    // being assumed.
    for path in ["HEAD", "packed-refs", "index"] {
        if let Some(path) = git(dir, &["rev-parse", "--git-path", path]) {
            println!("cargo:rerun-if-changed={}", dir.join(path).display());
        }
    }
    if let Some(reference) = git(dir, &["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = git(dir, &["rev-parse", "--git-path", &reference])
    {
        println!("cargo:rerun-if-changed={}", dir.join(path).display());
    }
    // …and when a source changes, which recompiles `rmule` anyway: the dirty
    // mark is decided from exactly these paths, so it cannot go stale while
    // cargo reuses a binary.
    for path in &sources {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

/// Every path whose tracked contents build `rmule`, relative to this crate
/// and existing — cargo reruns a script on every build for a missing one.
fn sources(dir: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = ["src", "build.rs", "Cargo.toml"]
        .iter()
        .map(PathBuf::from)
        .collect();
    let workspace = Path::new("../..");
    for file in ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"] {
        paths.push(workspace.join(file));
    }
    if let Ok(entries) = std::fs::read_dir(dir.join(workspace).join("crates")) {
        let mut crates: Vec<String> = entries
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| !NOT_LINKED.contains(&name.as_str()))
            .collect();
        crates.sort();
        for name in crates {
            for part in ["src", "build.rs", "Cargo.toml"] {
                paths.push(workspace.join("crates").join(&name).join(part));
            }
        }
    }
    paths.retain(|path| dir.join(path).exists());
    paths
}

/// `git <args>` in `dir`, trimmed, when it ran and printed something.
fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!text.is_empty()).then_some(text)
}

/// `seconds` after the Unix epoch as a UTC `YYYY-MM-DD`.
fn utc_date(seconds: u64) -> String {
    let (year, month, day) = civil_from_days(seconds / 86_400);
    format!("{year:04}-{month:02}-{day:02}")
}

/// The proleptic Gregorian date `days` after 1970-01-01 (Howard Hinnant's
/// `civil_from_days`, for non-negative day counts).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}
