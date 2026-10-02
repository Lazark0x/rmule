//! Drives one rmule stimulus run to completion and returns what it reported —
//! on the host (`RmuleToolsCommand`) or inside the bench (`RmuleClientContainer`).
//! Each entry point owns its own deadline and failure text; the parsing of
//! rmule's stdout into a summary lives in `summary`.

use std::fs;
use std::process::Stdio;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;

use super::BenchStaging;
use super::client::RmuleClientContainer;
use super::summary::{
    CallbackCapabilityReport, DownloadSummary, SearchSummary, judge_callback_capability,
    parse_download_output, parse_search_output,
};
use super::tools_command::RmuleToolsCommand;

/// Dial `peer_endpoint` directly with `--secure-ident`: the
/// rmule-tools capture command fails unless the SUI exchange completes, so a
/// zero exit *is* the secured-identity assertion; the stdout check keeps the
/// claim visible in the run artifacts. Full-mode capture artifacts land in the
/// layout's rmule dir — the SUI golden-vector source.
pub fn run_rmule_sui_capture(
    layout: &RunLayout,
    command: &RmuleToolsCommand,
    peer_endpoint: &str,
    max_seconds: u64,
    obfuscation_policy: Option<&str>,
) -> Result<()> {
    let ed2k_link = fs::read_to_string(layout.synthetic_ed2k_file())
        .with_context(|| format!("read {}", layout.synthetic_ed2k_file().display()))?;
    let ed2k_link = ed2k_link.trim();
    // Obfuscation: learn the aMule's runtime User Hash from a plaintext
    // hello (it ignores a pinned amule.conf hash), then obfuscate-dial with it.
    let learned_hash = match obfuscation_policy {
        Some(_) => Some(probe_amule_user_hash(
            layout,
            command,
            peer_endpoint,
            ed2k_link,
        )?),
        None => None,
    };
    let obfuscation = match (obfuscation_policy, &learned_hash) {
        (Some(policy), Some(hash)) => Some((policy, hash.as_str())),
        _ => None,
    };
    let output = command
        .sui_capture_command(layout, peer_endpoint, ed2k_link, max_seconds, obfuscation)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("run rmule SUI capture command")?;

    fs::write(layout.rmule_stdout_log(), &output.stdout)
        .with_context(|| format!("write {}", layout.rmule_stdout_log().display()))?;
    fs::write(layout.rmule_stderr_log(), &output.stderr)
        .with_context(|| format!("write {}", layout.rmule_stderr_log().display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("rmule SUI capture exited unsuccessfully: {stderr}");
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("peer identity_verified") {
        bail!("rmule SUI capture succeeded but reported no verified identity:\n{stdout}");
    }
    Ok(())
}

/// Learn the aMule peer's runtime User Hash from a short plaintext hello, so the
/// obfuscated dial can key on it. The probe may exit non-zero (no
/// shared file to pull), but it prints `peer identified user_hash=<HEX>` first;
/// that line is the only thing this parses.
fn probe_amule_user_hash(
    layout: &RunLayout,
    command: &RmuleToolsCommand,
    peer_endpoint: &str,
    ed2k_link: &str,
) -> Result<String> {
    fs::create_dir_all(layout.rmule_dir().join("probe"))
        .context("create rmule probe output dir")?;
    let output = command
        .probe_user_hash_command(layout, peer_endpoint, ed2k_link)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("run rmule plaintext hash probe")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .split("user_hash=")
        .nth(1)
        .map(|rest| {
            rest.split(|c: char| !c.is_ascii_hexdigit())
                .next()
                .unwrap_or("")
                .to_string()
        })
        .filter(|hash| hash.len() == 32)
        .with_context(|| format!("aMule User Hash not found in plaintext probe output:\n{stdout}"))
}

/// Run a host `ed2k download start` against `server_endpoint`, retaining its
/// stdout/stderr under the run dir, and parse what it reported.
pub fn run_rmule_download(
    layout: &RunLayout,
    command: &RmuleToolsCommand,
    server_endpoint: &str,
    serve: bool,
) -> Result<DownloadSummary> {
    let ed2k_link = fs::read_to_string(layout.synthetic_ed2k_file())
        .with_context(|| format!("read {}", layout.synthetic_ed2k_file().display()))?;
    let output = command
        .download_start_command(layout, server_endpoint, ed2k_link.trim(), serve)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("run rmule download command")?;

    fs::write(layout.rmule_stdout_log(), &output.stdout)
        .with_context(|| format!("write {}", layout.rmule_stdout_log().display()))?;
    fs::write(layout.rmule_stderr_log(), &output.stderr)
        .with_context(|| format!("write {}", layout.rmule_stderr_log().display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("rmule download command exited unsuccessfully: {stderr}");
    }

    let stdout = String::from_utf8(output.stdout).context("rmule download emitted non-utf8")?;
    parse_download_output(&stdout)
}

/// [`run_rmule_download`], but inside the bench network.
pub fn run_rmule_download_in_container(
    staging: BenchStaging<'_>,
    client: &RmuleClientContainer,
    server_endpoint: &str,
    serve: bool,
) -> Result<DownloadSummary> {
    let layout = staging.layout;
    let ed2k_link = fs::read_to_string(layout.synthetic_ed2k_file())
        .with_context(|| format!("read {}", layout.synthetic_ed2k_file().display()))?;
    let output = client
        .download_start_command(staging, server_endpoint, ed2k_link.trim(), serve, None)
        .to_command()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("run rmule download container")?;

    fs::write(layout.rmule_stdout_log(), &output.stdout)
        .with_context(|| format!("write {}", layout.rmule_stdout_log().display()))?;
    fs::write(layout.rmule_stderr_log(), &output.stderr)
        .with_context(|| format!("write {}", layout.rmule_stderr_log().display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("rmule download container exited unsuccessfully: {stderr}");
    }

    let stdout = String::from_utf8(output.stdout).context("rmule download emitted non-utf8")?;
    parse_download_output(&stdout)
}

/// Run rmule `download start --serve` bounded by `max_seconds` and judge its
/// callback capability from the run logs. `--serve` binds the inbound listener
/// (HighID + callback-capable, ADR-0039); the deadline is the honest terminal
/// because the Lugdunum eserver never surfaces the Low-ID source (ADR-0040).
pub fn run_rmule_callback_capability_in_container(
    staging: BenchStaging<'_>,
    client: &RmuleClientContainer,
    server_endpoint: &str,
    max_seconds: u64,
) -> Result<CallbackCapabilityReport> {
    let layout = staging.layout;
    let ed2k_link = fs::read_to_string(layout.synthetic_ed2k_file())
        .with_context(|| format!("read {}", layout.synthetic_ed2k_file().display()))?;
    let output = client
        .download_start_command(
            staging,
            server_endpoint,
            ed2k_link.trim(),
            true,
            Some(max_seconds),
        )
        .to_command()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("run rmule callback-capability container")?;

    fs::write(layout.rmule_stdout_log(), &output.stdout)
        .with_context(|| format!("write {}", layout.rmule_stdout_log().display()))?;
    fs::write(layout.rmule_stderr_log(), &output.stderr)
        .with_context(|| format!("write {}", layout.rmule_stderr_log().display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("rmule callback-capability container exited unsuccessfully: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let server_ip = server_endpoint
        .rsplit_once(':')
        .map_or(server_endpoint, |(ip, _)| ip);
    Ok(judge_callback_capability(&stdout, &stderr, server_ip))
}

/// Run a host `ed2k search` for `query` and parse what it reported.
pub fn run_rmule_search(
    layout: &RunLayout,
    command: &RmuleToolsCommand,
    server_endpoint: &str,
    query: &str,
) -> Result<SearchSummary> {
    let output = command
        .search_command(server_endpoint, query)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("run rmule search command")?;

    fs::write(layout.rmule_stdout_log(), &output.stdout)
        .with_context(|| format!("write {}", layout.rmule_stdout_log().display()))?;
    fs::write(layout.rmule_stderr_log(), &output.stderr)
        .with_context(|| format!("write {}", layout.rmule_stderr_log().display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("rmule search command exited unsuccessfully: {stderr}");
    }

    let stdout = String::from_utf8(output.stdout).context("rmule search emitted non-utf8")?;
    parse_search_output(&stdout, query)
}

/// [`run_rmule_search`], but inside the bench network.
pub fn run_rmule_search_in_container(
    staging: BenchStaging<'_>,
    client: &RmuleClientContainer,
    server_endpoint: &str,
    query: &str,
) -> Result<SearchSummary> {
    let layout = staging.layout;
    let output = client
        .search_command(staging, server_endpoint, query)
        .to_command()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("run rmule search container")?;

    fs::write(layout.rmule_stdout_log(), &output.stdout)
        .with_context(|| format!("write {}", layout.rmule_stdout_log().display()))?;
    fs::write(layout.rmule_stderr_log(), &output.stderr)
        .with_context(|| format!("write {}", layout.rmule_stderr_log().display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("rmule search container exited unsuccessfully: {stderr}");
    }

    let stdout = String::from_utf8(output.stdout).context("rmule search emitted non-utf8")?;
    parse_search_output(&stdout, query)
}
