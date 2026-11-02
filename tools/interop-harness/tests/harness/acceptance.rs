//! The end-to-end acceptance suite: thin `#[test]` wrappers, each driving a
//! harness *flow* through its CLI subcommand and asserting the run-dir
//! artifacts. Every test is `#[ignore]` **and** skips (with a clear message)
//! unless `RMULE_BENCH=1`, so the ordinary `cargo test` run never touches
//! Docker. This leg is one module of the crate's single integration binary, so
//! the target is `harness` and the module path selects it:
//!
//! ```bash
//! RMULE_BENCH=1 cargo test -p rmule-interop-harness --test harness \
//!   -- --ignored --test-threads=1 acceptance::
//! ```
//!
//! Covered here: flows A–K, plus the two extra legs of flow K's
//! `kad-firewalled-buddy` subcommand (`--requester-capture`, `--recruit-buddy`)
//! and ADR-0092's baseline rows ([`bench_baseline`]) — 16 wrappers. Flows M and N
//! (`kad-core-buddy`, `kad-direct-callback`) are run from their subcommands and
//! have no wrapper here, except flow M with its third
//! party ([`buddy_callback`]: `--callback-downloader` and `--amule-requester`),
//! flow R (`kad-required-check`, [`kad_required`]) and flow S
//! (`kad-dialed-link`, [`kad_dialed_link`]). Flow L's consume leg
//! (`peer-udp-reask`, [`peer_udp_reask`]) has wrappers that score a retained run
//! (~25 min live), and so has the Low-ID callback re-ask
//! (`peer-lowid-callback-reask`, [`lowid_callback_reask`], ~30 min live). The other ADR-0092
//! families are siblings: [`portmap`] (port mapping), [`ipv6_dialect`] (IPv6
//! dialect), [`natt`] (NAT traversal).
//!
//! The wrappers hold no orchestration logic — the flows live as library
//! functions behind the CLI subcommands (`flow::run_*`). Each helper here
//! only shells the subcommand, finds the `run_dir=` line, and reads back the
//! flow's own verdict/artifacts. The flow ↔ subcommand ↔ what-it-proves
//! table is in `tools/interop-harness/README.md`.

use std::path::{Path, PathBuf};

use crate::fixture::run_dir_from;

/// Gate: the acceptance flows stand up real Docker counterparties, so they only
/// run when the operator opts in with `RMULE_BENCH=1`. Absent the flag the test
/// prints a skip line and returns green (it asserts nothing) — combined with
/// `#[ignore]`, a plain `cargo test` never reaches this body.
fn bench_enabled(flow: &str) -> bool {
    if std::env::var("RMULE_BENCH").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("acceptance flow {flow} skipped: set RMULE_BENCH=1 to run the bench suite");
    false
}

/// Run a harness flow subcommand to completion and return its retained run
/// directory (parsed from the `run_dir=` stdout line) — unless
/// `RMULE_BENCH_VERDICT_DIR` names an already-driven run to score instead, in
/// which case the flow is never spawned at all. Panics on non-zero exit (or
/// on an unusable override) so a red flow, or a bad path, surfaces as a
/// failed test with the reason attached.
///
/// This is what makes a slow flow (`ipv6-kad-tags`'s ~10 min wall) affordable to
/// re-check: drive the CLI subcommand once in the foreground across polls
/// Then point every wrapper at the retained run dir instead of
/// re-running the flow for each assertion pass.
fn run_flow(flow: &str, extra_args: &[&str]) -> PathBuf {
    let configured = std::env::var("RMULE_BENCH_VERDICT_DIR").ok();
    match verdict_override_run_dir(configured.as_deref()) {
        Ok(Some(run_dir)) => {
            rmule_interop_harness::run_record::rescored(&run_dir);
            return run_dir;
        }
        Ok(None) => {}
        Err(message) => panic!("{message}"),
    }
    let mut cmd = assert_cmd::Command::cargo_bin("rmule-interop-harness").unwrap();
    let assert = cmd.arg(flow).args(extra_args).assert().success();
    run_dir_from(&assert.get_output().stdout)
}

/// Resolve `RMULE_BENCH_VERDICT_DIR` into the run dir a wrapper should read
/// verdicts from instead of driving the flow. `Ok(None)` when the knob is
/// unset — the caller drives the flow live, as before.
///
/// `configured` may name either a **run dir** — used unchanged, exactly as a
/// live run leaves it, flat or with a flow's verdict nested under a domain
/// subdirectory such as `kad/` — or a verdict file directly, whose parent
/// directory is used. Either way this function does no flow-specific lookup:
/// several flows can share one run dir (`kad-firewalled-buddy`'s three legs;
/// a wave's whole family under `ipv6-dialect`/`natt`/`portmap`), each writing
/// its own `<scenario>-verdict.toml`, but every wrapper already names the
/// exact relative path it wants in its own `read_string(&run_dir, "...")`
/// call — that pre-existing literal is what picks a run dir's file by name,
/// unchanged by this knob. A configured path that does not exist is an error
/// naming it; a run dir that turns out to lack the file a wrapper asked for
/// still panics with that path, from the pre-existing `read`/`read_string`.
fn verdict_override_run_dir(configured: Option<&str>) -> Result<Option<PathBuf>, String> {
    let configured = match configured {
        Some(value) if !value.is_empty() => value,
        _ => return Ok(None),
    };
    let path = PathBuf::from(configured);
    let metadata = std::fs::metadata(&path).map_err(|error| {
        format!("RMULE_BENCH_VERDICT_DIR={configured}: cannot stat this path: {error}")
    })?;
    if metadata.is_dir() {
        Ok(Some(path))
    } else {
        Ok(Some(path.parent().unwrap_or(Path::new(".")).to_path_buf()))
    }
}

/// The run root a bench wrapper should pass, when the operator set one.
///
/// A container runtime inside a VM can only bind-mount host paths the VM
/// mounts — colima mounts `$HOME` and nothing else — and a run dir outside them
/// silently becomes an anonymous volume, so every artifact a flow writes from a
/// container is lost. `RMULE_BENCH_RUN_ROOT` is how a checkout outside `$HOME`
/// points the NAT flows somewhere their mounts survive.
fn bench_run_root() -> Option<String> {
    std::env::var("RMULE_BENCH_RUN_ROOT")
        .ok()
        .filter(|root| !root.is_empty())
}

fn read(run_dir: &Path, relative: &str) -> Vec<u8> {
    std::fs::read(run_dir.join(relative))
        .unwrap_or_else(|error| panic!("read {}: {error}", run_dir.join(relative).display()))
}

fn read_string(run_dir: &Path, relative: &str) -> String {
    String::from_utf8(read(run_dir, relative)).unwrap()
}

/// `verdict_override_run_dir` scoring the knob's three real inputs: unset
/// (absent — the caller must drive the flow itself), a run dir (used
/// unchanged, nested subdirectory and all, so the claim it holds is still
/// readable through it), and a verdict file directly (its parent used, same
/// claim still readable) — plus the one input that is a named error rather
/// than a silent fallback: a configured path that does not exist.
#[test]
fn verdict_override_run_dir_scores_the_knobs_real_inputs() {
    let run_dir = tempfile::tempdir().unwrap();
    let kad_dir = run_dir.path().join("kad");
    std::fs::create_dir(&kad_dir).unwrap();
    let verdict_path = kad_dir.join("kad-buddy-callback-verdict.toml");
    std::fs::write(
        &verdict_path,
        "verdict = \"PASS\"\n\"rmule-recruited-a-buddy\" = true\n",
    )
    .unwrap();

    // Absent: the knob is unset, so there is no run to score — the caller
    // falls through and drives the flow live.
    assert_eq!(verdict_override_run_dir(None).unwrap(), None);

    // Held, as a run dir: returned unchanged, so the wrapper's own relative
    // `read_string(&run_dir, "kad/kad-buddy-callback-verdict.toml")` still
    // finds the same claim.
    let dir_configured = run_dir.path().to_str().unwrap();
    let dir_run_dir = verdict_override_run_dir(Some(dir_configured))
        .unwrap()
        .expect("a run dir resolves");
    assert_eq!(dir_run_dir, run_dir.path());
    assert!(
        read_string(&dir_run_dir, "kad/kad-buddy-callback-verdict.toml")
            .contains("rmule-recruited-a-buddy")
    );

    // Held, as the verdict file directly: its parent (`kad/`) is used, so a
    // flat relative lookup rooted there finds the same claim.
    let file_configured = verdict_path.to_str().unwrap();
    let file_run_dir = verdict_override_run_dir(Some(file_configured))
        .unwrap()
        .expect("a verdict file resolves to its parent dir");
    assert_eq!(file_run_dir, kad_dir);
    assert!(
        read_string(&file_run_dir, "kad-buddy-callback-verdict.toml")
            .contains("rmule-recruited-a-buddy")
    );

    // A path that is neither is a named error, not a silent `None`.
    let missing = run_dir.path().join("no-such-run");
    let error = verdict_override_run_dir(Some(missing.to_str().unwrap())).unwrap_err();
    assert!(
        error.contains(missing.to_str().unwrap()),
        "the error must name the configured path:\n{error}",
    );
}

mod bench_baseline;
mod buddy_callback;
mod flows_a_to_k;
mod ipv6_dialect;
mod kad_dialed_link;
mod kad_legs;
mod kad_required;
mod lowid_callback_reask;
mod natt;
mod peer_udp_reask;
mod portmap;
mod search_wire;
