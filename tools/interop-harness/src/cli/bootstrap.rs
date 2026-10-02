//! Subcommands for the bootstrap family.
//!
//! The golden-authoring legs reuse the eD2k-server args shape (they only need an
//! eserver and one aMule); the consuming legs reuse the handoff args, because a
//! cold start and an ed2k→Kad handoff stand up the same swarm.

use std::path::PathBuf;

use crate::cli::bench::{
    AmuleArgs, BenchArgs, CaptureArgs, DEFAULT_ESERVER_BUILD_CONTEXT, DEFAULT_ESERVER_IMAGE,
    DEFAULT_RMULE_CLIENT_IMAGE, DEFAULT_RMULE_NODE_DOCKERFILE, DEFAULT_RMULE_NODE_IMAGE,
    DEFAULT_TIMEOUT_SECS,
};
use crate::cli::ed2k_server::AmuleServesRmuleDownloadsArgs;
use crate::cli::kad_network::DEFAULT_KAD_SMOKE_CONNECT_DEADLINE_SECS;
use anyhow::Result;
use clap::Args;
use rmule_interop_harness::flow::{
    Ed2kKadHandoffOptions, HttpBootstrapColdStartOptions, HttpBootstrapGoldensOptions,
    V2NodesDatHarvestOptions, run_ed2k_kad_handoff, run_http_bootstrap_cold_start,
    run_http_bootstrap_goldens, run_v2_nodes_dat_harvest,
};
use rmule_interop_harness::rmule::RmuleClientContainer;

pub(crate) const FLOW_HTTP_BOOTSTRAP_GOLDENS: &str = "http-bootstrap-goldens";

/// The swarm flow G and flow H stand up: an eserver and a Kad-running aMule on
/// static fake-public addresses (no host-published port), an rmule Kad seed
/// built from the workspace, the rmule-tools runner, and — for the cold start
/// only — the capture sidecar on the aMule's netns.
#[derive(Debug, Args)]
pub(crate) struct Ed2kKadHandoffArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    /// Real eD2k server container image.
    #[arg(long, default_value = DEFAULT_ESERVER_IMAGE)]
    pub(crate) server_image: String,
    /// Build context for the eD2k server image.
    #[arg(long, default_value = DEFAULT_ESERVER_BUILD_CONTEXT)]
    pub(crate) server_build_context: PathBuf,
    #[command(flatten)]
    pub(crate) amule: AmuleArgs,
    /// The rmule Kad-seed image (the `rmule-tools kad join-node` runner), always rebuilt
    /// from the workspace like the flow-F stimulus node.
    #[arg(long, default_value = DEFAULT_RMULE_NODE_IMAGE)]
    pub(crate) seed_image: String,
    /// Dockerfile for the rmule Kad-seed image.
    #[arg(long, default_value = DEFAULT_RMULE_NODE_DOCKERFILE)]
    pub(crate) seed_dockerfile: PathBuf,
    /// Build context for the rmule Kad-seed image (the repo root).
    #[arg(long, default_value = ".")]
    pub(crate) seed_build_context: PathBuf,
    /// Rust image used to run the rmule-tools handoff runner in-network.
    #[arg(long, default_value = DEFAULT_RMULE_CLIENT_IMAGE)]
    pub(crate) rmule_client_image: String,
    /// Per-step readiness timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
    /// Budget for the aMule to reach "Kad: Connected" after the seed bootstraps.
    #[arg(long, default_value_t = DEFAULT_KAD_SMOKE_CONNECT_DEADLINE_SECS)]
    pub(crate) kad_connect_deadline: u64,
    /// Seconds the runner waits for the node to reach contact post-handoff.
    #[arg(long, default_value_t = 60)]
    pub(crate) handoff_window: u64,
    #[command(flatten)]
    pub(crate) capture: CaptureArgs,
}

/// `v2-nodes-dat-harvest`: one aMule in kad-node mode, flushed for its
/// `nodes.dat`.
#[derive(Debug, Args)]
pub(crate) struct V2NodesDatHarvestArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) amule: AmuleArgs,
    /// Per-step readiness timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
}

pub(crate) fn ed2k_kad_handoff(args: Ed2kKadHandoffArgs) -> Result<()> {
    args.bench.prepare(&[])?;
    let (run_dir, layout) = args.bench.create_run()?;
    println!("run_dir={}", run_dir.display());

    let rmule_client_container = RmuleClientContainer::cargo_rmule_tools(&args.rmule_client_image)?;
    run_ed2k_kad_handoff(Ed2kKadHandoffOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        build_images: args.bench.build_images,
        server_image: &args.server_image,
        amule_image: &args.amule.amule_image,
        seed_image: &args.seed_image,
        server_build_context: &args.server_build_context,
        amule_build_context: &args.amule.amule_build_context,
        seed_dockerfile: &args.seed_dockerfile,
        seed_build_context: &args.seed_build_context,
        rmule_client_container: &rmule_client_container,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        kad_connect_deadline_secs: args.kad_connect_deadline,
        handoff_window_secs: args.handoff_window,
        amule_env: &args.amule.amule_env,
    })
}

pub(crate) fn v2_nodes_dat_harvest(args: V2NodesDatHarvestArgs) -> Result<()> {
    args.bench.prepare(&[])?;
    let (run_dir, layout) = args.bench.create_run()?;
    println!("run_dir={}", run_dir.display());

    run_v2_nodes_dat_harvest(V2NodesDatHarvestOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        build_images: args.bench.build_images,
        amule_image: &args.amule.amule_image,
        amule_build_context: &args.amule.amule_build_context,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        amule_env: &args.amule.amule_env,
    })
}

/// The golden-authoring half of flow H: no synthetic file, the aMule only
/// connects to the eserver and is flushed.
pub(crate) fn http_bootstrap_goldens(args: AmuleServesRmuleDownloadsArgs) -> Result<()> {
    args.eserver.reject_zero_host_port()?;
    args.bench
        .prepare(&[args.eserver.build_context(), args.amule.build_context()])?;
    let (run_dir, layout) = args.bench.create_run()?;
    crate::cli::write_resolved_config(
        &run_dir,
        &args.resolved_config(FLOW_HTTP_BOOTSTRAP_GOLDENS),
    )?;
    println!("run_dir={}", run_dir.display());

    run_http_bootstrap_goldens(HttpBootstrapGoldensOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        build_images: args.bench.build_images,
        server_image: &args.eserver.server_image,
        amule_image: &args.amule.amule_image,
        server_build_context: &args.eserver.server_build_context,
        amule_build_context: &args.amule.amule_build_context,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        server_host_port: args.eserver.server_host_port,
        server_env: &args.eserver.server_env,
        amule_env: &args.amule.amule_env,
        amule_ready_log_pattern: &args.amule_ready_log_pattern,
    })
}

pub(crate) fn http_bootstrap_cold_start(args: Ed2kKadHandoffArgs) -> Result<()> {
    args.bench.prepare(&[])?;
    let (run_dir, layout) = args.bench.create_run()?;
    println!("run_dir={}", run_dir.display());

    let rmule_client_container = RmuleClientContainer::cargo_rmule_tools(&args.rmule_client_image)?;
    run_http_bootstrap_cold_start(HttpBootstrapColdStartOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        build_images: args.bench.build_images,
        server_image: &args.server_image,
        amule_image: &args.amule.amule_image,
        seed_image: &args.seed_image,
        // busybox `httpd` (built into alpine) serves the fixture payload.
        fixture_image: "alpine:3",
        capture_image: &args.capture.capture_image,
        server_build_context: &args.server_build_context,
        amule_build_context: &args.amule.amule_build_context,
        seed_dockerfile: &args.seed_dockerfile,
        seed_build_context: &args.seed_build_context,
        capture_build_context: &args.capture.capture_build_context,
        rmule_client_container: &rmule_client_container,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        kad_connect_deadline_secs: args.kad_connect_deadline,
        join_window_secs: args.handoff_window,
        amule_env: &args.amule.amule_env,
    })
}
