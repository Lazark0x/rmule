//! The `ed2ksrv-server-surface` subcommand and its re-scorer: the rows only the
//! pinned server can draw now, a crypt-pong under a learned key and a Sentinel
//! Source, and the two it writes none of.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use rmule_interop_harness::flow::{ServerSurfaceOptions, run_server_surface, score_server_surface};
use serde::Serialize;

use crate::cli::bench::{BenchArgs, CaptureArgs};
use crate::cli::nat::{
    DEFAULT_ED2KSRV_BUILD_CONTEXT, DEFAULT_ED2KSRV_IMAGE, DEFAULT_RMULE_TOOLS_IMAGE,
};
use crate::cli::write_resolved_config;

const FLOW: &str = "ed2ksrv-server-surface";
/// The bench config that turns the server's IPv6 surface on.
const DEFAULT_ED2KSRV_IPV6_CONFIG: &str = "tools/interop-harness/images/ed2ksrv/config-ipv6.toml";

/// `ed2ksrv-server-surface`: `ed2ksrv` on its IPv6 config, a crypt-pong driver
/// and three login probes; the verdict reads their rows and the server's tap.
#[derive(Debug, Args)]
pub(crate) struct ServerSurfaceArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) capture: CaptureArgs,
    /// The ed2k-server image (refused unless its commit label matches the pin).
    #[arg(long, default_value = DEFAULT_ED2KSRV_IMAGE)]
    pub(crate) ed2ksrv_image: String,
    /// The ed2k-server recipe directory.
    #[arg(long, default_value = DEFAULT_ED2KSRV_BUILD_CONTEXT)]
    pub(crate) ed2ksrv_build_context: PathBuf,
    /// The ed2k-server bench config; its `this_ip` is rendered per run.
    #[arg(long, default_value = DEFAULT_ED2KSRV_IPV6_CONFIG)]
    pub(crate) ed2ksrv_config: PathBuf,
    /// The `rmule-tools` image, built from the tip under test.
    #[arg(long, default_value = DEFAULT_RMULE_TOOLS_IMAGE)]
    pub(crate) rmule_tools_image: String,
    /// Per-step readiness budget in seconds.
    #[arg(long, default_value_t = 600)]
    pub(crate) timeout: u64,
}

#[derive(Debug, Serialize)]
struct ResolvedConfig {
    #[serde(rename = "scenario")]
    flow: &'static str,
    ed2ksrv_image: String,
    ed2ksrv_config: PathBuf,
    rmule_tools_image: String,
    capture_image: String,
    container_runtime: String,
    timeout_secs: u64,
}

pub(crate) fn server_surface(args: ServerSurfaceArgs) -> Result<()> {
    args.bench.prepare(&[
        args.capture.build_context(),
        ("ed2ksrv", &args.ed2ksrv_build_context),
    ])?;
    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &ResolvedConfig {
            flow: FLOW,
            ed2ksrv_image: args.ed2ksrv_image.clone(),
            ed2ksrv_config: args.ed2ksrv_config.clone(),
            rmule_tools_image: args.rmule_tools_image.clone(),
            capture_image: args.capture.capture_image.clone(),
            container_runtime: args.bench.container_runtime.clone(),
            timeout_secs: args.timeout,
        },
    )?;
    println!("run_dir={}", run_dir.display());
    run_server_surface(ServerSurfaceOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        build_images: args.bench.build_images,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        ed2ksrv_image: &args.ed2ksrv_image,
        ed2ksrv_build_context: &args.ed2ksrv_build_context,
        ed2ksrv_config: &args.ed2ksrv_config,
        capture_image: &args.capture.capture_image,
        capture_build_context: &args.capture.capture_build_context,
        rmule_tools_image: &args.rmule_tools_image,
    })
}

/// `ed2ksrv-server-surface-score`: score a finished or archived run dir from its
/// own tap and rows, without driving the leg again.
#[derive(Debug, Args)]
pub(crate) struct ServerSurfaceScoreArgs {
    /// The run dir to score (the one holding `server-surface/`).
    #[arg(long)]
    pub(crate) run_dir: PathBuf,
}

pub(crate) fn server_surface_score(args: ServerSurfaceScoreArgs) -> Result<()> {
    let verdict = score_server_surface(&args.run_dir)?;
    println!("run_dir={}", args.run_dir.display());
    println!("verdict={verdict}");
    Ok(())
}
