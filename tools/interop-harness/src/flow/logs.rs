//! Collecting each container's own account of the run into the run dir.
//!
//! Every counterparty and every rmule container is drained through `docker logs`
//! (plus, for aMule, an `amulecmd` diagnostics sweep) into a per-role file under
//! the run dir, on success and on failure alike. Log collection is best-effort
//! on the failure path so a collection error never masks the error that caused
//! the failure.

use std::ffi::OsString;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::docker::Docker;
use crate::flow::bench::amulecmd_command;
use crate::flow::mesh::KadNode;

pub(crate) fn collect_kad_logs(
    docker: &Docker,
    layout: &RunLayout,
    role: &str,
    container: &str,
) -> Result<String> {
    fs::create_dir_all(layout.kad_node_logs_dir(role)).with_context(|| {
        format!(
            "create kad log directory {}",
            layout.kad_node_logs_dir(role).display()
        )
    })?;
    collect_logs(
        docker,
        container,
        &layout.kad_node_stdout_log(role),
        &layout.kad_node_stderr_log(role),
        "collect kad node logs",
    )
}

pub(crate) fn collect_kad_node_logs(docker: &Docker, layout: &RunLayout, nodes: &[KadNode]) {
    for node in nodes {
        if let Err(error) = collect_kad_logs(docker, layout, &node.role, &node.container) {
            eprintln!(
                "warning: failed to collect kad logs for {}: {error:#}",
                node.role
            );
        }
    }
}

pub(crate) fn collect_server_logs(
    docker: &Docker,
    layout: &RunLayout,
    container: &str,
) -> Result<()> {
    collect_logs(
        docker,
        container,
        &layout.server_stdout_log(),
        &layout.server_stderr_log(),
        "collect server container logs",
    )
    .map(|_| ())
}

pub(crate) fn collect_amule_logs(
    docker: &Docker,
    layout: &RunLayout,
    container: &str,
) -> Result<String> {
    collect_logs(
        docker,
        container,
        &layout.amule_stdout_log(),
        &layout.amule_stderr_log(),
        "collect aMule container logs",
    )
}

pub(crate) fn collect_rmule_logs(
    docker: &Docker,
    layout: &RunLayout,
    container: &str,
) -> Result<String> {
    collect_logs(
        docker,
        container,
        &layout.rmule_stdout_log(),
        &layout.rmule_stderr_log(),
        "collect rmule container logs",
    )
}

pub(crate) fn collect_amule_diagnostics(
    docker: &Docker,
    layout: &RunLayout,
    container: &str,
) -> Result<()> {
    let script = r#"
set +e
ec_password="${AMULE_EC_PASSWORD:-rmule}"
for command in "Status" "Show log" "Show ul" "Show shared" "Statistics"; do
    printf '===== amulecmd %s =====\n' "$command"
    amulecmd -v -P "$ec_password" -c "$command" 2>&1
done
printf '===== /root/.aMule/logfile =====\n'
sed -n '1,800p' /root/.aMule/logfile 2>&1
printf '===== logging-related config =====\n'
grep -niE 'log|debug|verbose|upload|queue|client|message|trace|packet|filter|kad|server' /root/.aMule/amule.conf 2>&1
"#;
    let output = docker
        .exec(
            container,
            [
                OsString::from("sh"),
                OsString::from("-lc"),
                OsString::from(script),
            ],
        )
        .to_command()
        .output()
        .context("collect aMule diagnostics")?;
    fs::write(layout.amule_diagnostics_stdout_log(), &output.stdout)
        .with_context(|| format!("write {}", layout.amule_diagnostics_stdout_log().display()))?;
    fs::write(layout.amule_diagnostics_stderr_log(), &output.stderr)
        .with_context(|| format!("write {}", layout.amule_diagnostics_stderr_log().display()))?;
    if !output.status.success() {
        bail!("collect aMule diagnostics: container runtime exited unsuccessfully");
    }
    Ok(())
}

pub(crate) fn collect_logs(
    docker: &Docker,
    container: &str,
    stdout_path: &Path,
    stderr_path: &Path,
    phase: &str,
) -> Result<String> {
    let output = docker
        .logs(container)
        .to_command()
        .output()
        .with_context(|| phase.to_owned())?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    fs::write(stdout_path, &output.stdout)
        .with_context(|| format!("write {}", stdout_path.display()))?;
    fs::write(stderr_path, &output.stderr)
        .with_context(|| format!("write {}", stderr_path.display()))?;
    if !output.status.success() {
        bail!("{phase}: container runtime exited unsuccessfully");
    }
    Ok(stdout)
}

/// Retain a diagnostic artifact under the run dir. A failed write warns on
/// stderr instead of failing the flow: the artifact is context beside the
/// verdict, so a write error must not mask the flow's own result — but a Run
/// Dir is a flow's entire output, so it must never vanish silently either.
pub(crate) fn retain_artifact(path: &Path, bytes: &[u8]) {
    if let Err(error) = fs::write(path, bytes) {
        eprintln!("warning: failed to retain {}: {error}", path.display());
    }
}

/// Best-effort amulecmd diagnostics for a stuck node, dumped into its kad log dir.
pub(crate) fn dump_kad_diagnostics(
    docker: &Docker,
    layout: &RunLayout,
    node: &KadNode,
) -> Result<()> {
    let output = docker
        .exec(node.container.clone(), amulecmd_command("Status"))
        .to_command()
        .output()
        .context("amulecmd Status diagnostics")?;
    let path = layout.kad_node_logs_dir(&node.role).join("status.log");
    fs::create_dir_all(layout.kad_node_logs_dir(&node.role))
        .with_context(|| format!("create {}", layout.kad_node_logs_dir(&node.role).display()))?;
    fs::write(&path, &output.stdout).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Lift a stock aMule's **own** debug logfile out of a container, beside the
/// stdout/stderr the harness already collects.
///
/// `AMULE_KAD_VERBOSE=1` turns on `VerboseDebug`, which is where aMule writes
/// the `logKadSearch` / `logKadPrefs` trails — the only place that says *which*
/// of `CSharedFileList::Publish`'s four gates refused, or whether a publish
/// walk ran at all. stdout carries the entrypoint's own lines and nothing of
/// aMule's, so without this a publish that never happened looks identical to
/// one that happened off-tap.
///
/// **Known limitation on the DEFAULT (release) image, measured.
/// ** The packaged `amule-daemon` is a *release* build, and aMule gates
/// both the loading of its debug categories (`Preferences.cpp`, under
/// `#ifdef __DEBUG__`) and `CLogger::IsEnabled(DebugType)` itself
/// (`Logger.h:183-187`, which returns a literal `false` when `__DEBUG__` is
/// unset) on that macro. So every `AddDebugLogLineN` is dead code in this
/// image and `AMULE_KAD_VERBOSE=1` cannot unlock a single `logKad*` line,
/// whatever it writes into `amule.conf`. What this collector lifts there is
/// the ordinary startup and connection log — useful (it is where "Found N
/// known shared files" and "Connected to Kad (firewalled)" live) but never
/// the counterparty's own reasoning about a gate.
///
/// **Resolved on the DEBUG image.** `--build-arg AMULE_DEBUG=1`
/// (`images/amule/Dockerfile`) builds `amuled`/`amulecmd` from the same
/// upstream 2.3.3 pin with `-DCMAKE_BUILD_TYPE=Debug`, which defines
/// `__DEBUG__`; the entrypoint's `enable_kad_debug_categories` then also
/// writes the `/Debug/Cat_*` keys `CLogger::IsEnabled` ANDs with
/// `VerboseDebug` (`Logger.cpp`), so this same collector lifts a genuine
/// `logKad*` trail from that image, unchanged code.
///
/// Best-effort by design: a node that wrote no logfile is not a flow failure.
pub(crate) fn collect_amule_logfile(
    docker: &Docker,
    layout: &RunLayout,
    role: &str,
    container: &str,
) {
    let destination = layout.kad_node_logs_dir(role).join("amule-logfile.log");
    if let Err(error) = fs::create_dir_all(layout.kad_node_logs_dir(role)) {
        eprintln!("warning: kad log dir for {role}: {error:#}");
        return;
    }
    let output = docker
        .exec(
            container.to_owned(),
            [
                std::ffi::OsString::from("sh"),
                std::ffi::OsString::from("-c"),
                std::ffi::OsString::from("cat /root/.aMule/logfile 2>/dev/null || true"),
            ],
        )
        .to_command()
        .output();
    match output {
        Ok(output) => {
            if let Err(error) = fs::write(&destination, &output.stdout) {
                eprintln!("warning: write {}: {error:#}", destination.display());
            }
        }
        Err(error) => eprintln!("warning: read aMule logfile for {role}: {error:#}"),
    }
}
