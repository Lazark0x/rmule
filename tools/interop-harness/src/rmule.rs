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
    REGISTRANT_ANNOUNCE_TIMEOUT_SECS, REGISTRANT_PORT_BASE, Registrant, RmuleClientContainer,
};
pub use run::{
    run_rmule_callback_capability_in_container, run_rmule_download,
    run_rmule_download_in_container, run_rmule_search, run_rmule_search_in_container,
    run_rmule_sui_capture,
};
pub use serve::{KadStimulusKnobs, RmuleServeContainer, ServeKnobs};
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

    /// Compile `rmule-tools` for the container's platform into the
    /// host-persisted cache, on the runtime's DEFAULT network so cargo and
    /// rustup reach the registry. Foreground and cached: a warm run returns in
    /// seconds.
    fn prebuild_command(&self, docker: &Docker) -> Result<DockerCommand> {
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
