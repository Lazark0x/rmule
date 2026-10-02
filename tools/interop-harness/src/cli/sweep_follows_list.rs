//! The `sweep-follows-list` subcommand: a server listed mid-run is reached
//! by the next search's Global Search Sweep.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use rmule_interop_harness::flow::{SweepFollowsListOptions, run_sweep_follows_list};
use serde::Serialize;

use crate::cli::bench::{BenchArgs, CaptureArgs, DEFAULT_TIMEOUT_SECS, EserverArgs};
use crate::cli::nat::{DEFAULT_ED2KSRV_CONFIG, DEFAULT_ED2KSRV_IMAGE, DEFAULT_RMULE_TOOLS_IMAGE};
use crate::cli::write_resolved_config;

/// `sweep-follows-list`: rmule searches on Lugdunum, lists ed2k-server, and
/// searches again; a tap on ed2k-server's UDP port says whether the sweep
/// reached it.
#[derive(Debug, Args)]
pub(crate) struct SweepFollowsListArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) eserver: EserverArgs,
    #[command(flatten)]
    pub(crate) capture: CaptureArgs,
    /// The ed2k-server image (refused unless its commit label matches the pin).
    #[arg(long, default_value = DEFAULT_ED2KSRV_IMAGE)]
    pub(crate) ed2ksrv_image: String,
    /// The ed2k-server bench config; its `this_ip` is rendered per run.
    #[arg(long, default_value = DEFAULT_ED2KSRV_CONFIG)]
    pub(crate) ed2ksrv_config: PathBuf,
    /// The `rmule-tools` image (build it from the tip under test).
    #[arg(long, default_value = DEFAULT_RMULE_TOOLS_IMAGE)]
    pub(crate) rmule_tools_image: String,
    /// Per-step readiness budget in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
}

#[derive(Debug, Serialize)]
struct SweepFollowsListResolvedConfig {
    #[serde(rename = "scenario")]
    flow: &'static str,
    server_image: String,
    ed2ksrv_image: String,
    ed2ksrv_config: PathBuf,
    rmule_tools_image: String,
    capture_image: String,
    container_runtime: String,
    timeout_secs: u64,
}

pub(crate) fn sweep_follows_list(args: SweepFollowsListArgs) -> Result<()> {
    args.bench
        .prepare(&[args.eserver.build_context(), args.capture.build_context()])?;
    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &SweepFollowsListResolvedConfig {
            flow: "sweep-follows-list",
            server_image: args.eserver.server_image.clone(),
            ed2ksrv_image: args.ed2ksrv_image.clone(),
            ed2ksrv_config: args.ed2ksrv_config.clone(),
            rmule_tools_image: args.rmule_tools_image.clone(),
            capture_image: args.capture.capture_image.clone(),
            container_runtime: args.bench.container_runtime.clone(),
            timeout_secs: args.timeout,
        },
    )?;
    println!("run_dir={}", run_dir.display());
    run_sweep_follows_list(SweepFollowsListOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        server_image: &args.eserver.server_image,
        server_env: &args.eserver.server_env,
        ed2ksrv_image: &args.ed2ksrv_image,
        ed2ksrv_config: &args.ed2ksrv_config,
        rmule_tools_image: &args.rmule_tools_image,
        capture_image: &args.capture.capture_image,
    })
}
