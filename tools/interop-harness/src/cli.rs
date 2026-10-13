//! The harness command line: one subcommand per flow.
//!
//! Each flow's subcommand owns a clap `*Args` value and a handler that turns it
//! into the flow's `*Options` — resolving defaults, creating the run dir, writing
//! the resolved config, staging the synthetic file, and validating the build
//! contexts before any container starts. The handlers hold no orchestration: the
//! flow itself is the library function they call. Subcommand and flag names are
//! part of the harness's contract with Dockerfiles, docs and other tooling, so
//! they change only deliberately. The shared flag groups and image defaults
//! live in [`bench`]; each family file owns its flow names and window defaults.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use rmule_interop_harness::docker::Docker;
use serde::Serialize;

pub(crate) mod announce_switch;
pub(crate) mod ask_budget;
pub(crate) mod bench;
pub(crate) mod bootstrap;
pub(crate) mod ed2k_server;
pub(crate) mod kad_buddy;
pub(crate) mod kad_capture;
pub(crate) mod kad_dialed_link;
pub(crate) mod kad_network;
pub(crate) mod lowid_callback_reask;
pub(crate) mod nat;
pub(crate) mod packed_source_exchange;
pub(crate) mod partial_share;
pub(crate) mod peer;
pub(crate) mod server_callback_serve;
pub(crate) mod streaming_window;
pub(crate) mod sweep_follows_list;

/// A build context must be a directory; checked before the run dir exists so a
/// typo costs no retained run.
pub(crate) fn validate_build_context_dir(label: &str, build_context: &Path) -> Result<()> {
    if !build_context.is_dir() {
        bail!(
            "{label} build context does not exist or is not a directory: {}",
            build_context.display()
        );
    }
    Ok(())
}

/// `<runtime> --version` must succeed before anything is staged: an absent
/// runtime is a configuration error, not a flow failure.
pub(crate) fn ensure_runtime_available(runtime: &str) -> Result<()> {
    let status = Docker::new(runtime)
        .version()
        .to_command()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("container runtime `{runtime}` is not available"))?;

    if !status.success() {
        bail!("container runtime `{runtime}` exited unsuccessfully during availability check");
    }
    Ok(())
}

/// Allocate a fresh, timestamp-named run dir under `run_root`; a same-second
/// collision takes a `-N` suffix rather than reusing a directory.
pub(crate) fn create_run_dir(run_root: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(run_root)
        .with_context(|| format!("create run root {}", run_root.display()))?;
    let base = unix_timestamp_secs()?;
    for suffix in 0..1000_u16 {
        let name = if suffix == 0 {
            base.to_string()
        } else {
            format!("{base}-{suffix}")
        };
        let run_dir = run_root.join(name);
        match std::fs::create_dir(&run_dir) {
            Ok(()) => {
                rmule_interop_harness::run_record::begin(&run_dir)?;
                return Ok(run_dir);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("create run dir {}", run_dir.display()));
            }
        }
    }
    bail!(
        "could not allocate unique run directory under {}",
        run_root.display()
    )
}

/// Write the flow's resolved configuration as `resolved-config.toml` — the
/// first artifact in every run dir, so a run is reproducible from its own
/// record.
pub(crate) fn write_resolved_config<C: Serialize>(run_dir: &Path, config: &C) -> Result<()> {
    let text = toml::to_string_pretty(config).context("serialize resolved config")?;
    let path = run_dir.join("resolved-config.toml");
    std::fs::write(&path, text).with_context(|| format!("write {}", path.display()))
}

fn unix_timestamp_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| anyhow!("system clock is before unix epoch: {error}"))?
        .as_secs())
}

/// clap value parser for `KEY=VALUE` environment passthrough.
pub(crate) fn parse_env_assignment(value: &str) -> std::result::Result<String, String> {
    let Some((key, env_value)) = value.split_once('=') else {
        return Err("expected KEY=VALUE".to_owned());
    };
    if key.is_empty() {
        return Err("environment key cannot be empty".to_owned());
    }
    if key.contains('\0') || env_value.contains('\0') {
        return Err("environment assignment cannot contain NUL bytes".to_owned());
    }
    Ok(value.to_owned())
}
