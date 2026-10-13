//! rmule's own participation in a flow — the **Stimulus**: the argv, the
//! containers and the knobs that provoke a counterparty into answering, plus
//! the summaries rmule reports back about its own run. Stimulus is retained for
//! context and is never evidence (ADR-0045), so nothing here decides a flow; a
//! verdict is written from the counterparty's bytes.
//!
//! The constants below are the container contract every rmule container shares
//! — one workspace mount, one run root, one pair of build caches, one serve
//! port — so a flow can read one container's artifacts out of the run dir
//! another wrote them to, and a wire row can name the port a counterparty dials.

mod client;
mod run;
mod serve;
mod summary;
mod tools_command;

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::artifacts::RunLayout;
use crate::docker::{Docker, DockerCommand, RunContainer};

pub use client::{
    DownloadCrypt, REGISTRANT_ANNOUNCE_TIMEOUT_SECS, REGISTRANT_PORT_BASE, Registrant,
    RmuleClientContainer, release_held_download,
};
pub use run::{
    run_rmule_callback_capability_in_container, run_rmule_download,
    run_rmule_download_in_container, run_rmule_search, run_rmule_search_in_container,
    run_rmule_sui_capture,
};
pub use serve::{KadStimulusKnobs, RmuleServeContainer, ServeKnobs, crypt_flip_arg};
pub use summary::{
    CallbackCapabilityReport, DownloadSummary, SearchSummary, parse_download_output,
    parse_search_output,
};
pub use tools_command::RmuleToolsCommand;

/// Where an rmule container is staged on the **Bench**: the container runtime
/// that starts it, the **Run Dir** it mounts, and the private network it joins.
/// Every rmule container builder needs exactly these three and nothing else
/// about the bench, so they travel as one value instead of three parallel
/// arguments repeated at every call.
#[derive(Clone, Copy, Debug)]
pub struct BenchStaging<'a> {
    /// The container runtime the command is issued to.
    pub docker: &'a Docker,
    /// The run dir mounted into the container; its artifacts land under it.
    pub layout: &'a RunLayout,
    /// The private bench network the container joins.
    pub network: &'a str,
}

/// The TCP port every serving rmule binds inside its container: the `--listen`
/// / `--tcp-port` argument, the TCP port a Kad seed contact advertises for it,
/// and the `dst port` the buddy/callback wire rows count a counterparty's dial
/// on. One value, so a change cannot leave a BPF row silently counting zero.
pub const RMULE_SERVE_TCP_PORT: u16 = 4663;
/// The runner's Kad node UDP bind port inside its container: request/response
/// bootstrap needs no externally-known port, so it is fixed rather than a knob.
const HANDOFF_RUNNER_KAD_UDP_PORT: u16 = 4680;
/// Where the repository is mounted inside every rmule container.
pub(crate) const CONTAINER_WORKSPACE: &str = "/workspace";
/// Where the run dir is mounted inside every rmule container, so paths a
/// container writes are readable back out of the layout by another.
pub(crate) const CONTAINER_RUN_ROOT: &str = "/interop-run";
/// The cargo target dir inside the container: the host's own `target/` is a
/// different platform and must never be shared.
const CONTAINER_TARGET_DIR: &str = "/tmp/rmule-target";
/// The container `CARGO_HOME` (registry + toolchain state) when it is
/// host-persisted.
const CONTAINER_CARGO_HOME: &str = "/tmp/rmule-cargo-home";
/// The `--server` a Kad-only stimulus run points at: a closed local port, so the
/// non-fatal login failure lands immediately instead of hanging.
const STIMULUS_CLOSED_SERVER_ENDPOINT: &str = "127.0.0.1:4661";

/// The rust image `rmule-tools` compiles in for every container flow. Its
/// glibc is the driver image's (Debian bookworm), so the binary it leaves
/// runs there unchanged.
pub const DRIVER_PREBUILD_IMAGE: &str = "rust:1.94.0-bookworm";

/// Compile `rmule-tools` for the container platform into the host-persisted
/// cache under `workspace` (once cold, seconds warm) and return the binary.
/// The driver image takes this file instead of compiling inside `docker build`.
///
/// # Errors
/// If the workspace cannot be resolved or the prebuild container fails; the
/// error carries the container's stderr.
pub fn prebuild_driver_binary(docker: &Docker, workspace: &Path) -> Result<PathBuf> {
    let root = workspace
        .canonicalize()
        .with_context(|| format!("resolve the workspace {}", workspace.display()))?;
    let workspace = RmuleWorkspace::new(DRIVER_PREBUILD_IMAGE, root);
    let output = workspace
        .prebuild_command(docker)?
        .to_command()
        .stdin(std::process::Stdio::null())
        .output()
        .context("run the rmule-tools prebuild for the driver image")?;
    if !output.status.success() {
        anyhow::bail!(
            "the rmule-tools prebuild for the driver image failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(workspace.target_cache()?.join("debug/rmule-tools"))
}

/// The `RMULE_LOG` level an rmule container runs at: `RMULE_SERVE_LOG` from the
/// harness's own environment when set (the serve-side tracing knob),
/// else `default` so a green run stays quiet.
fn rmule_log_level(default: &str) -> String {
    std::env::var("RMULE_SERVE_LOG").unwrap_or_else(|_| default.to_owned())
}

/// The mounted workspace an rmule container runs `rmule-tools` from: the image,
/// the repository root it mounts, and the three container shapes every builder
/// starts from — an ephemeral in-container `cargo run`, a `cargo run` against the
/// host-persisted caches, and the pre-built binary those caches hold.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RmuleWorkspace {
    image: OsString,
    root: PathBuf,
}

/// The `sh -c` script a held container runs: wait for the file its `$0`
/// names, then exec the rest of its arguments untouched (an ed2k link's
/// `|` included).
const HOLD_UNTIL_GATE: &str = r#"while [ ! -e "$0" ]; do sleep 0.1; done; exec "$@""#;

/// The `rmule-tools` image's own entrypoint (`images/rmule-tools/entrypoint.sh`).
const RMULE_TOOLS_IMAGE_ENTRYPOINT: &str = "/entrypoint.sh";

/// Hold an `rmule-tools` image container until [`release_held_download`]
/// writes its gate, then run the image's own entrypoint (so its env knobs
/// still apply) with the `rmule-tools` arguments appended after this call.
/// `run_root_mount` is where the container mounts the run dir. A flow whose
/// tap must hold rmule's first login and dial starts the container, starts
/// the tap, and only then releases it.
pub(crate) fn hold_image_until_released(
    container: RunContainer,
    run_root_mount: &str,
) -> RunContainer {
    container
        .entrypoint("sh")
        .arg("-c")
        .arg(HOLD_UNTIL_GATE)
        .arg(format!("{run_root_mount}/{}", client::DOWNLOAD_START_GATE))
        .arg(RMULE_TOOLS_IMAGE_ENTRYPOINT)
}

impl RmuleWorkspace {
    fn new(image: impl Into<OsString>, root: impl Into<PathBuf>) -> Self {
        Self {
            image: image.into(),
            root: root.into(),
        }
    }

    /// The workspace this harness was built from (`CARGO_MANIFEST_DIR/../..`).
    fn from_manifest(image: impl Into<OsString>, role: &str) -> Result<Self> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .with_context(|| format!("resolve workspace root for rmule {role} container"))?;
        Ok(Self::new(image, root))
    }

    /// The base every rmule container shares: the workspace as workdir plus the
    /// run-dir mount.
    fn container(&self, layout: &RunLayout) -> RunContainer {
        RunContainer::new(self.image.clone())
            .workdir(CONTAINER_WORKSPACE)
            .volume(&self.root, CONTAINER_WORKSPACE)
            .volume(layout.root(), CONTAINER_RUN_ROOT)
    }

    /// `cargo run -p rmule-tools --` compiling into an ephemeral in-container
    /// target: a cold build per container, on a network that can reach the
    /// registry.
    fn cargo_run(&self, layout: &RunLayout) -> RunContainer {
        self.container(layout)
            .env("CARGO_TARGET_DIR", CONTAINER_TARGET_DIR)
            .arg("cargo")
            .arg("run")
            .arg("-p")
            .arg("rmule-tools")
            .arg("--")
    }

    /// `cargo run -p rmule-tools --` against the host-persisted target and
    /// `CARGO_HOME` caches: one cold build per host, seconds thereafter.
    fn cached_cargo_run(&self, layout: &RunLayout) -> Result<RunContainer> {
        Ok(self
            .container(layout)
            .volume(self.target_cache()?, CONTAINER_TARGET_DIR)
            .volume(self.cargo_home_cache()?, CONTAINER_CARGO_HOME)
            .env("CARGO_TARGET_DIR", CONTAINER_TARGET_DIR)
            .env("CARGO_HOME", CONTAINER_CARGO_HOME)
            .arg("cargo")
            .arg("run")
            .arg("-p")
            .arg("rmule-tools")
            .arg("--"))
    }

    /// The `rmule-tools` binary [`prebuild_command`](Self::prebuild_command)
    /// produced, run without cargo: the shape for a Docker `internal` network,
    /// where no DNS or egress exists for rustup to fetch anything.
    fn prebuilt(&self, layout: &RunLayout) -> Result<RunContainer> {
        Ok(self
            .container(layout)
            .volume(self.target_cache()?, CONTAINER_TARGET_DIR)
            .arg(format!("{CONTAINER_TARGET_DIR}/debug/rmule-tools")))
    }

    /// [`Self::prebuilt`], held until the file `gate` names inside the
    /// container exists. The prebuilt binary logs in and dials within a second
    /// of starting, so a flow whose tap must hold that first exchange starts
    /// the container, starts the tap, and only then writes the gate.
    fn prebuilt_held(&self, layout: &RunLayout, gate: &str) -> Result<RunContainer> {
        Ok(self
            .container(layout)
            .volume(self.target_cache()?, CONTAINER_TARGET_DIR)
            .arg("sh")
            .arg("-c")
            .arg(HOLD_UNTIL_GATE)
            .arg(gate)
            .arg(format!("{CONTAINER_TARGET_DIR}/debug/rmule-tools")))
    }

    /// Compile `rmule-tools` for the container's platform into the
    /// host-persisted cache, on the runtime's DEFAULT network so cargo and
    /// rustup reach the registry. Foreground and cached: a warm run returns in
    /// seconds.
    fn prebuild_command(&self, docker: &Docker) -> Result<DockerCommand> {
        crate::run_record::expect_binary(&self.target_cache()?.join("debug/rmule-tools"));
        Ok(docker.run_container(
            RunContainer::new(self.image.clone())
                .remove_after_exit()
                .workdir(CONTAINER_WORKSPACE)
                .volume(&self.root, CONTAINER_WORKSPACE)
                .volume(self.target_cache()?, CONTAINER_TARGET_DIR)
                .volume(self.cargo_home_cache()?, CONTAINER_CARGO_HOME)
                .env("CARGO_TARGET_DIR", CONTAINER_TARGET_DIR)
                .env("CARGO_HOME", CONTAINER_CARGO_HOME)
                .arg("cargo")
                .arg("build")
                .arg("-p")
                .arg("rmule-tools"),
        ))
    }

    /// The host-persisted container-target directory, shared by every rmule
    /// container (same platform, same workspace) and gitignored.
    fn target_cache(&self) -> Result<PathBuf> {
        self.scratch_dir(".scratch/interop-target-cache")
    }

    /// The host-persisted container `CARGO_HOME` (registry + toolchain state).
    fn cargo_home_cache(&self) -> Result<PathBuf> {
        self.scratch_dir(".scratch/interop-cargo-home")
    }

    fn scratch_dir(&self, relative: &str) -> Result<PathBuf> {
        let dir = self.root.join(relative);
        fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        Ok(dir)
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::{Duration, Instant};

    use super::HOLD_UNTIL_GATE;

    /// The held command runs nothing until the gate exists, then runs with
    /// its arguments exactly as given.
    #[test]
    fn a_held_command_waits_for_its_gate_then_runs_its_arguments_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let gate = dir.path().join("gate");
        let link = "ed2k://|file|a b.bin|1|00112233445566778899AABBCCDDEEFF|/";
        let mut held = Command::new("sh")
            .args(["-c", HOLD_UNTIL_GATE])
            .arg(&gate)
            .args(["printf", "%s"])
            .arg(link)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let until = Instant::now() + Duration::from_millis(400);
        while Instant::now() < until {
            assert!(held.try_wait().unwrap().is_none(), "ran before its gate");
            std::thread::sleep(Duration::from_millis(20));
        }
        std::fs::write(&gate, b"").unwrap();
        let output = held.wait_with_output().unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8(output.stdout).unwrap(), link);
    }
}
