//! Readiness gates: the bounded waits that hold a flow until a counterparty is
//! genuinely up.
//!
//! Every gate polls a real signal the container itself emits — an aMule log
//! line, rmule's `files_announced` marker, a Kad node's log, `amulecmd Status`
//! reporting "Kad: Connected" — against a deadline. No blind sleeps: a flow
//! either observes the readiness fact or fails with the logs that explain why.
//! The one sanctioned fixed wait is the tap window, whose length is the flow's
//! own knob and whose purpose is observation, not readiness. The rmule-serve
//! login gate additionally retries the whole start+login cycle, because the
//! Lugdunum eserver's login is intermittently flaky.

use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::docker::Docker;
use crate::flow::bench::{amulecmd_command, run_checked};
use crate::flow::logs::{collect_amule_logs, collect_kad_logs, collect_rmule_logs};
use crate::readiness::retry_with_backoff;
use crate::rmule::{BenchStaging, RmuleServeContainer, ServeKnobs};

/// What a bounded poll ended on: the text that carried the pattern, or the last
/// text observed when the deadline passed.
enum Polled {
    Matched(String),
    TimedOut(String),
}

/// Poll `observe` every `tick` until its text contains `pattern` or `timeout`
/// elapses. The first observation is immediate; the last sleep is clamped to
/// the deadline so the gate never overshoots its budget.
fn poll_until(
    timeout: Duration,
    tick: Duration,
    pattern: &str,
    mut observe: impl FnMut() -> Result<String>,
) -> Result<Polled> {
    let deadline = Instant::now() + timeout;
    loop {
        let text = observe()?;
        if text.contains(pattern) {
            return Ok(Polled::Matched(text));
        }
        if Instant::now() >= deadline {
            return Ok(Polled::TimedOut(text));
        }
        thread::sleep(tick.min(deadline.saturating_duration_since(Instant::now())));
    }
}

/// Poll `docker logs` until `pattern` appears, the container exits without it,
/// or `timeout` elapses. Generic over container role (unlike
/// [`wait_for_amule_ready`], which reads the aMule log files) — used for the
/// rust-image registrant container.
pub(crate) fn wait_for_container_log(
    docker: &Docker,
    container: &str,
    pattern: &str,
    timeout: Duration,
) -> Result<String> {
    let polled = poll_until(timeout, Duration::from_millis(500), pattern, || {
        // The state is read before the logs: logs read after an exit are
        // whole, so an exited container whose logs lack the pattern will never
        // print it, and the wait ends there instead of at its deadline.
        let state = docker
            .inspect_state(container)
            .to_command()
            .output()
            .with_context(|| format!("docker inspect {container}"))?;
        let exited = matches!(
            String::from_utf8_lossy(&state.stdout).trim(),
            "exited" | "dead"
        );
        let output = docker
            .logs(container)
            .to_command()
            .output()
            .with_context(|| format!("docker logs {container}"))?;
        let mut logs = String::from_utf8_lossy(&output.stdout).into_owned();
        logs.push_str(&String::from_utf8_lossy(&output.stderr));
        if exited && !logs.contains(pattern) {
            bail!(
                "container {container} exited before its log carried {pattern:?}; last logs:\n{logs}"
            );
        }
        Ok(logs)
    })?;
    match polled {
        Polled::Matched(logs) => Ok(logs),
        Polled::TimedOut(logs) => bail!(
            "container {container} log pattern {pattern:?} timed out after {} ms; last logs:\n{logs}",
            timeout.as_millis()
        ),
    }
}

/// Hold until a Kad node's collected log carries `pattern`.
pub(crate) fn wait_for_kad_log(
    docker: &Docker,
    layout: &RunLayout,
    role: &str,
    container: &str,
    pattern: &str,
    timeout: Duration,
) -> Result<()> {
    match poll_until(timeout, Duration::from_millis(100), pattern, || {
        collect_kad_logs(docker, layout, role, container)
    })? {
        Polled::Matched(_) => Ok(()),
        Polled::TimedOut(_) => bail!(
            "kad {role} log pattern {pattern:?} timed out after {} ms",
            timeout.as_millis()
        ),
    }
}

/// Poll a Kad role's collected stdout **and** stderr until `pattern` appears
/// or `timeout` elapses: a Core-pumped node writes its `tracing` trail to
/// stderr, which [`wait_for_kad_log`] never reads. Whether it matched is the
/// answer, not an error — a gate a flow records rather than dies on.
pub(crate) fn wait_for_kad_trail(
    docker: &Docker,
    layout: &RunLayout,
    role: &str,
    container: &str,
    pattern: &str,
    timeout: Duration,
) -> Result<bool> {
    let polled = poll_until(timeout, Duration::from_secs(5), pattern, || {
        let mut trail = collect_kad_logs(docker, layout, role, container)?;
        trail.push_str(
            &std::fs::read_to_string(layout.kad_node_stderr_log(role)).unwrap_or_default(),
        );
        Ok(trail)
    })?;
    Ok(matches!(polled, Polled::Matched(_)))
}

/// Hold until the aMule role's collected log carries `ready_log_pattern`.
pub(crate) fn wait_for_amule_ready(
    docker: &Docker,
    layout: &RunLayout,
    container: &str,
    timeout: Duration,
    ready_log_pattern: &str,
) -> Result<()> {
    match poll_until(
        timeout,
        Duration::from_millis(100),
        ready_log_pattern,
        || collect_amule_logs(docker, layout, container),
    )? {
        Polled::Matched(_) => Ok(()),
        Polled::TimedOut(_) => bail!(
            "aMule log pattern {ready_log_pattern:?} timed out after {} ms",
            timeout.as_millis()
        ),
    }
}

/// Hold until the serving rmule's log carries `files_announced` — the
/// `serve.files_announced file_count=N` line rmule-tools emits once the
/// offered files are announced to the server.
pub(crate) fn wait_for_rmule_ready(
    docker: &Docker,
    layout: &RunLayout,
    container: &str,
    timeout: Duration,
) -> Result<()> {
    match poll_until(
        timeout,
        Duration::from_millis(100),
        "files_announced",
        || collect_rmule_logs(docker, layout, container),
    )? {
        Polled::Matched(_) => Ok(()),
        Polled::TimedOut(_) => bail!(
            "rmule serve readiness timed out after {} ms",
            timeout.as_millis()
        ),
    }
}

/// Attempts for the rmule-serve eserver-login retry: the Lugdunum eserver's
/// login is intermittently unreliable, so one timed-out `files_announced` wait
/// does not yet mean rmule (or the eserver) is genuinely broken. Small and
/// bounded — a real failure still surfaces within a few container restarts
/// instead of the flow hanging, and instead of masking a real regression as a
/// pass.
pub(crate) const RMULE_SERVE_LOGIN_ATTEMPTS: u32 = 3;
/// Backoff between rmule-serve login retries. Short: the flake is a
/// login-layer hiccup (a dropped first packet, a momentary accept-queue stall
/// on the eserver), not a multi-minute counterparty outage.
pub(crate) const RMULE_SERVE_LOGIN_BACKOFF: Duration = Duration::from_secs(2);

/// Start the rmule serve container and wait for its `files_announced` gate
/// (rmule's own eserver-login-then-announce readiness signal), retrying the
/// whole start+login cycle if the eserver login flakes.
///
/// On a timeout the stalled container is torn down (`docker rm -f`, freeing
/// the fixed `name` for the next `docker run`) and a fresh one launched — a
/// fresh login attempt — after `RMULE_SERVE_LOGIN_BACKOFF`. A genuinely-down
/// eserver still fails clearly: `RMULE_SERVE_LOGIN_ATTEMPTS` timeouts in a
/// row surface the last one's error instead of retrying forever or silently
/// passing.
///
/// The container outlives a failed call: the caller must own it for teardown
/// *before* calling, which is why the bench's own
/// `Bench::start_rmule_serve` is the normal entry point.
pub fn start_rmule_serve_with_login_retry(
    staging: BenchStaging<'_>,
    serve_container: &RmuleServeContainer,
    name: &str,
    server_endpoint: &str,
    knobs: ServeKnobs<'_>,
    timeout: Duration,
) -> Result<String> {
    // One compile into the host-persisted cache, foreground and warm after the
    // first run, so the serve container starts a binary instead of building.
    run_checked(
        serve_container.prebuild_command(staging.docker)?,
        "prebuild rmule-tools for the serve container",
    )?;
    retry_with_backoff(
        RMULE_SERVE_LOGIN_ATTEMPTS,
        RMULE_SERVE_LOGIN_BACKOFF,
        |attempt| {
            if attempt > 1 {
                eprintln!(
                    "eserver-login retry: rmule serve container {name} did not reach \
                 files_announced; restarting for attempt {attempt}/{RMULE_SERVE_LOGIN_ATTEMPTS}"
                );
                // Best-effort: the previous attempt's container is stalled, not
                // gone, so free its fixed name before the next `docker run`.
                let _ = staging.docker.remove_container(name).to_command().output();
            }
            let container_id = run_checked(
                serve_container.start_command_with_knobs(staging, name, server_endpoint, knobs)?,
                "run rmule serve container",
            )?;
            wait_for_rmule_ready(staging.docker, staging.layout, name, timeout)?;
            Ok(container_id)
        },
    )
    .with_context(|| {
        format!(
            "rmule serve did not reach files_announced after {RMULE_SERVE_LOGIN_ATTEMPTS} \
             eserver-login attempts; the counterparty may be genuinely down"
        )
    })
}

/// Poll `amulecmd Status` on the counterparty until it reports "Kad: Connected"
/// (either `(ok)` or `(firewalled)` counts — the node is reachable-in-network
/// either way), or the deadline elapses. A transient exec failure (a node
/// mid-restart) skips that round rather than aborting the gate.
pub(crate) fn wait_for_amule_kad_connected(
    docker: &Docker,
    container: &str,
    deadline_secs: u64,
) -> Result<bool> {
    wait_for_amule_status(docker, container, "Kad: Connected", deadline_secs)
}

/// Poll `amulecmd Status` until its text contains `pattern` or the deadline
/// elapses — the narrower form of [`wait_for_amule_kad_connected`] for a gate
/// that needs one verdict, such as `Kad: Connected (ok)`.
pub(crate) fn wait_for_amule_status(
    docker: &Docker,
    container: &str,
    pattern: &str,
    deadline_secs: u64,
) -> Result<bool> {
    let polled = poll_until(
        Duration::from_secs(deadline_secs),
        Duration::from_secs(2),
        pattern,
        || {
            Ok(docker
                .exec(container.to_owned(), amulecmd_command("Status"))
                .to_command()
                .output()
                .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
                .unwrap_or_default())
        },
    )?;
    Ok(matches!(polled, Polled::Matched(_)))
}

/// Poll a host-side file until it contains `pattern` or `timeout` elapses —
/// the gate for a fact a container writes onto its bind mount rather than its
/// stdout (a Kad member's `events.log`, a driver's row file). A file that does
/// not exist yet reads as empty. Returns whether the pattern was seen.
pub(crate) fn wait_for_host_file(
    path: &std::path::Path,
    pattern: &str,
    timeout: Duration,
) -> Result<bool> {
    let polled = poll_until(timeout, Duration::from_secs(5), pattern, || {
        Ok(std::fs::read_to_string(path).unwrap_or_default())
    })?;
    Ok(matches!(polled, Polled::Matched(_)))
}

/// Sit a tap window: the flow's own observation budget, during which the
/// capture sidecar records whatever the counterparty does of its own accord.
/// Not a readiness gate — nothing is polled — so it is bounded by the window
/// alone and reports progress every 30 s under `label`.
pub(crate) fn sit_tap_window(label: &str, window: Duration) {
    let started_at = Instant::now();
    while started_at.elapsed() < window {
        thread::sleep(Duration::from_secs(30).min(window - started_at.elapsed()));
        println!(
            "{label} waiting elapsed={}s / {}s",
            started_at.elapsed().as_secs(),
            window.as_secs()
        );
    }
}
