//! The flags every flow shares, as clap groups a subcommand flattens in: the
//! bench fabric (`BenchArgs`), the eserver (`EserverArgs`), the aMule
//! (`AmuleArgs`), the capture sidecar (`CaptureArgs`), the rmule node image
//! (`RmuleNodeArgs`) and the fake-public Kad bench (`KadBenchArgs`) — plus the
//! image defaults they carry. Flag names are part of the harness's contract with
//! Dockerfiles, docs and other tooling, so a group's names never change per
//! subcommand; only the fields a flow does not have stay out of its struct.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use clap::Args;
use rmule_interop_harness::artifacts::{
    Ed2kHashCommand, RunLayout, write_incompressible_file, write_sparse_file,
    write_synthetic_ed2k_link, write_synthetic_file,
};
use rmule_interop_harness::flow::KadCaptureOptions;
use serde::Serialize;

use crate::cli::{
    create_run_dir, ensure_runtime_available, parse_env_assignment, validate_build_context_dir,
};

/// Where run dirs are retained; never committed.
pub(crate) const DEFAULT_RUN_ROOT: &str = ".scratch/interop-runs";
/// The synthetic file's size for a transfer that need only prove bytes.
pub(crate) const DEFAULT_FILE_SIZE: u64 = 64 * 1024;
/// The per-step readiness budget most flows run under.
pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 300;
/// The rust image rmule containers compile and run `rmule-tools` in.
pub(crate) const DEFAULT_RMULE_CLIENT_IMAGE: &str =
    rmule_interop_harness::rmule::DRIVER_PREBUILD_IMAGE;
/// The project-owned Lugdunum eserver image and its recipe.
pub(crate) const DEFAULT_ESERVER_IMAGE: &str = "rmule/interop-eserver:local";
pub(crate) const DEFAULT_ESERVER_BUILD_CONTEXT: &str = "tools/interop-harness/images/server";
/// The project-owned stock aMule image and its recipe.
pub(crate) const DEFAULT_AMULE_IMAGE: &str = "rmule/interop-amule:local";
pub(crate) const DEFAULT_AMULE_BUILD_CONTEXT: &str = "tools/interop-harness/images/amule";
/// The project-owned tcpdump capture-sidecar image and its recipe.
pub(crate) const DEFAULT_CAPTURE_IMAGE: &str = "rmule/interop-capture:local";
pub(crate) const DEFAULT_CAPTURE_BUILD_CONTEXT: &str = "tools/interop-harness/images/capture";
/// The rmule Kad node image (`rmule-tools kad join-node`), built from the repo
/// root so it tracks the workspace sources.
pub(crate) const DEFAULT_RMULE_NODE_IMAGE: &str = "rmule/interop-rmule-node:local";
pub(crate) const DEFAULT_RMULE_NODE_DOCKERFILE: &str =
    "tools/interop-harness/images/rmule-node/Dockerfile";
/// The first Kad UDP port a mesh's nodes listen on; `+ span` bounds the capture.
pub(crate) const DEFAULT_KAD_UDP_PORT_BASE: u16 = 4672;
pub(crate) const DEFAULT_KAD_UDP_PORT_SPAN: u16 = 10;

/// The bench fabric flags every flow carries.
#[derive(Debug, Args)]
pub(crate) struct BenchArgs {
    /// Build the project-owned interop images before running the flow.
    #[arg(long)]
    pub(crate) build_images: bool,
    /// Reuse existing images without building.
    #[arg(long)]
    pub(crate) skip_build: bool,
    /// Keep containers after the run for debugging.
    #[arg(long)]
    pub(crate) keep_containers: bool,
    /// Docker-compatible CLI to invoke.
    #[arg(long, default_value = "docker")]
    pub(crate) container_runtime: String,
    /// Root directory for retained interop run artifacts.
    #[arg(long, default_value = DEFAULT_RUN_ROOT)]
    pub(crate) run_root: PathBuf,
}

impl BenchArgs {
    /// Everything that must hold before a run dir exists: the build flags do
    /// not contradict, the runtime answers, and — when building — every
    /// `(role, context)` build context is a directory.
    pub(crate) fn prepare(&self, build_contexts: &[(&str, &Path)]) -> Result<()> {
        if self.build_images && self.skip_build {
            bail!("--build-images and --skip-build are mutually exclusive");
        }
        ensure_runtime_available(&self.container_runtime)?;
        if self.build_images {
            for (role, context) in build_contexts {
                validate_build_context_dir(role, context)?;
            }
        }
        Ok(())
    }

    /// Allocate the run dir under `--run-root` and lay it out.
    pub(crate) fn create_run(&self) -> Result<(PathBuf, RunLayout)> {
        let run_dir = create_run_dir(&self.run_root)?;
        let layout = RunLayout::create(&run_dir)?;
        Ok((run_dir, layout))
    }
}

/// What the **Synthetic File** holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum FileContent {
    /// The `offset % 251` pattern every flow defaults to.
    #[default]
    Pattern,
    /// One hole of zero bytes: no block on disk, so a file past 4 GiB costs
    /// nothing to stage.
    Sparse,
    /// A xorshift stream no compressor shrinks, so a throttled sharer cannot
    /// send it compressed at many times its cap.
    Incompressible,
}

/// Stage the **Synthetic File** and its ed2k link in the run dir; `hash_hook`
/// is the test seam that replaces `cargo run -p rmule-tools -- ed2k hash-file`.
pub(crate) fn stage_synthetic(
    layout: &RunLayout,
    file_size: u64,
    hash_hook: Option<&Path>,
) -> Result<()> {
    stage_synthetic_content(layout, file_size, FileContent::Pattern, hash_hook)
}

/// [`stage_synthetic`] with the file's `content` chosen.
pub(crate) fn stage_synthetic_content(
    layout: &RunLayout,
    file_size: u64,
    content: FileContent,
    hash_hook: Option<&Path>,
) -> Result<()> {
    let path = layout.synthetic_shared_file();
    match content {
        FileContent::Pattern => write_synthetic_file(layout, file_size)?,
        FileContent::Sparse => write_sparse_file(&path, file_size)?,
        FileContent::Incompressible => write_incompressible_file(&path, file_size, 0x5EED_0531)?,
    }
    let hash_command = hash_hook.map_or_else(Ed2kHashCommand::cargo_rmule_tools, |path| {
        Ed2kHashCommand::new(path)
    });
    write_synthetic_ed2k_link(layout, &hash_command)?;
    Ok(())
}

/// The eserver a flow stands up: image, recipe, host-published port, env.
#[derive(Debug, Args)]
pub(crate) struct EserverArgs {
    /// Real eD2k server container image to run.
    #[arg(long, default_value = DEFAULT_ESERVER_IMAGE)]
    pub(crate) server_image: String,
    /// Build context directory for the real eD2k server image.
    #[arg(long, default_value = DEFAULT_ESERVER_BUILD_CONTEXT)]
    pub(crate) server_build_context: PathBuf,
    /// Host TCP port mapped to the real eD2k server container (readiness probe).
    #[arg(long, default_value_t = 4661)]
    pub(crate) server_host_port: u16,
    /// Extra environment variable for the real eD2k server container.
    #[arg(long = "server-env", value_parser = parse_env_assignment)]
    pub(crate) server_env: Vec<String>,
}

impl EserverArgs {
    /// Port 0 would mean "let docker pick", which the host readiness probe
    /// cannot discover.
    pub(crate) fn reject_zero_host_port(&self) -> Result<()> {
        if self.server_host_port == 0 {
            bail!("--server-host-port must be non-zero; mapped-port discovery is not implemented");
        }
        Ok(())
    }

    pub(crate) fn build_context(&self) -> (&str, &Path) {
        ("server", &self.server_build_context)
    }
}

/// The stock aMule a flow stands up: image, recipe, env passthrough.
#[derive(Debug, Args)]
pub(crate) struct AmuleArgs {
    /// aMule/amuled container image to run.
    #[arg(long, default_value = DEFAULT_AMULE_IMAGE)]
    pub(crate) amule_image: String,
    /// Build context directory for the aMule image.
    #[arg(long, default_value = DEFAULT_AMULE_BUILD_CONTEXT)]
    pub(crate) amule_build_context: PathBuf,
    /// Extra environment variable for the aMule container(s).
    #[arg(long = "amule-env", value_parser = parse_env_assignment)]
    pub(crate) amule_env: Vec<String>,
}

impl AmuleArgs {
    pub(crate) fn build_context(&self) -> (&str, &Path) {
        ("aMule", &self.amule_build_context)
    }
}

/// The tcpdump capture sidecar: image and recipe.
#[derive(Debug, Args)]
pub(crate) struct CaptureArgs {
    /// Packet-capture sidecar container image to run.
    #[arg(long, default_value = DEFAULT_CAPTURE_IMAGE)]
    pub(crate) capture_image: String,
    /// Build context directory for the capture sidecar image.
    #[arg(long, default_value = DEFAULT_CAPTURE_BUILD_CONTEXT)]
    pub(crate) capture_build_context: PathBuf,
}

impl CaptureArgs {
    pub(crate) fn build_context(&self) -> (&str, &Path) {
        ("capture", &self.capture_build_context)
    }
}

/// The rmule Kad node image a flow builds from the workspace.
#[derive(Debug, Args)]
pub(crate) struct RmuleNodeArgs {
    /// rmule Kad node image tag (always rebuilt from the workspace).
    #[arg(long, default_value = DEFAULT_RMULE_NODE_IMAGE)]
    pub(crate) rmule_image: String,
    /// Dockerfile for the rmule Kad node image.
    #[arg(long, default_value = DEFAULT_RMULE_NODE_DOCKERFILE)]
    pub(crate) rmule_dockerfile: PathBuf,
    /// Build context for the rmule Kad node image (the repo root).
    #[arg(long, default_value = ".")]
    pub(crate) rmule_build_context: PathBuf,
}

impl RmuleNodeArgs {
    /// The node image is always rebuilt, so its Dockerfile must exist whatever
    /// `--build-images` says.
    pub(crate) fn validate(&self) -> Result<()> {
        if !self.rmule_dockerfile.is_file() {
            bail!(
                "rmule node dockerfile {} not found",
                self.rmule_dockerfile.display()
            );
        }
        Ok(())
    }
}

/// The fake-public Kad bench (Config A): a stock aMule, a capture sidecar and
/// the mesh's UDP port base.
#[derive(Debug, Args)]
pub(crate) struct KadBenchArgs {
    #[command(flatten)]
    pub(crate) amule: AmuleArgs,
    #[command(flatten)]
    pub(crate) capture: CaptureArgs,
    /// Base UDP port the Kad nodes listen on.
    #[arg(long, default_value_t = DEFAULT_KAD_UDP_PORT_BASE)]
    pub(crate) kad_udp_port_base: u16,
}

impl KadBenchArgs {
    /// The build contexts `BenchArgs::prepare` validates.
    pub(crate) fn build_contexts(&self) -> [(&str, &Path); 2] {
        [self.amule.build_context(), self.capture.build_context()]
    }

    /// The flow's `KadCaptureOptions` on this bench.
    pub(crate) fn capture_options<'a>(
        &'a self,
        bench: &'a BenchArgs,
        layout: &'a RunLayout,
        timeout: u64,
        routing_nodes: u32,
    ) -> KadCaptureOptions<'a> {
        KadCaptureOptions {
            layout,
            container_runtime: &bench.container_runtime,
            build_images: bench.build_images,
            amule_image: &self.amule.amule_image,
            capture_image: &self.capture.capture_image,
            amule_build_context: &self.amule.amule_build_context,
            capture_build_context: &self.capture.capture_build_context,
            keep_containers: bench.keep_containers,
            timeout_secs: timeout,
            routing_nodes,
            amule_env: &self.amule.amule_env,
            kad_udp_port_base: self.kad_udp_port_base,
            kad_udp_port_span: DEFAULT_KAD_UDP_PORT_SPAN,
        }
    }

    /// The `resolved-config.toml` record for a flow on this bench.
    pub(crate) fn resolved_config(
        &self,
        flow: &'static str,
        bench: &BenchArgs,
        file_size: u64,
        timeout: u64,
        routing_nodes: u32,
    ) -> KadResolvedConfig {
        KadResolvedConfig {
            flow,
            build_images: bench.build_images,
            skip_build: bench.skip_build,
            amule_image: self.amule.amule_image.clone(),
            capture_image: self.capture.capture_image.clone(),
            amule_build_context: self.amule.amule_build_context.clone(),
            capture_build_context: self.capture.capture_build_context.clone(),
            keep_containers: bench.keep_containers,
            container_runtime: bench.container_runtime.clone(),
            file_size,
            timeout_secs: timeout,
            routing_nodes,
            amule_env: self.amule.amule_env.clone(),
            kad_udp_port_base: self.kad_udp_port_base,
            kad_udp_port_span: DEFAULT_KAD_UDP_PORT_SPAN,
            public_kad_used: false,
        }
    }
}

/// The `resolved-config.toml` a Kad flow writes. `public_kad_used` is always
/// false: no flow ever touches the public network.
#[derive(Debug, Serialize)]
pub(crate) struct KadResolvedConfig {
    #[serde(rename = "scenario")]
    pub(crate) flow: &'static str,
    pub(crate) build_images: bool,
    pub(crate) skip_build: bool,
    pub(crate) amule_image: String,
    pub(crate) capture_image: String,
    pub(crate) amule_build_context: PathBuf,
    pub(crate) capture_build_context: PathBuf,
    pub(crate) keep_containers: bool,
    pub(crate) container_runtime: String,
    pub(crate) file_size: u64,
    pub(crate) timeout_secs: u64,
    pub(crate) routing_nodes: u32,
    pub(crate) amule_env: Vec<String>,
    pub(crate) kad_udp_port_base: u16,
    pub(crate) kad_udp_port_span: u16,
    pub(crate) public_kad_used: bool,
}
