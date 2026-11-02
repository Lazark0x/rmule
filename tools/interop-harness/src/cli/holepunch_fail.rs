//! The `ed2ksrv-holepunch-fail` subcommand and its re-scorer: one server
//! probe asks `ed2ksrv` for a punch toward a Low ID nobody holds, and the
//! server's `OP_LOWID_HOLEPUNCH_FAIL` (`0x62`) is cut from its tap.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use rmule_interop_harness::flow::{HolepunchFailOptions, run_holepunch_fail, score_holepunch_fail};
use rmule_interop_harness::rmule::RmuleClientContainer;
use serde::Serialize;

use crate::cli::bench::{BenchArgs, CaptureArgs, DEFAULT_RMULE_CLIENT_IMAGE};
use crate::cli::nat::{
    DEFAULT_ED2KSRV_BUILD_CONTEXT, DEFAULT_ED2KSRV_CONFIG, DEFAULT_ED2KSRV_IMAGE,
};
use crate::cli::write_resolved_config;

const FLOW: &str = "ed2ksrv-holepunch-fail";

/// `ed2ksrv-holepunch-fail`: `ed2ksrv` and one in-network server probe asking
/// a punch toward a Low ID nobody holds; the verdict reads the server tap.
#[derive(Debug, Args)]
pub(crate) struct HolepunchFailArgs {
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
    #[arg(long, default_value = DEFAULT_ED2KSRV_CONFIG)]
    pub(crate) ed2ksrv_config: PathBuf,
    /// Rust image the probe runs in inside the interop network.
    #[arg(long, default_value = DEFAULT_RMULE_CLIENT_IMAGE)]
    pub(crate) rmule_client_image: String,
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
    rmule_client_image: String,
    capture_image: String,
    container_runtime: String,
    timeout_secs: u64,
}

pub(crate) fn holepunch_fail(args: HolepunchFailArgs) -> Result<()> {
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
            rmule_client_image: args.rmule_client_image.clone(),
            capture_image: args.capture.capture_image.clone(),
            container_runtime: args.bench.container_runtime.clone(),
            timeout_secs: args.timeout,
        },
    )?;
    println!("run_dir={}", run_dir.display());
    let rmule_client_container = RmuleClientContainer::cargo_rmule_tools(&args.rmule_client_image)?;
    run_holepunch_fail(HolepunchFailOptions {
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
        rmule_client_container: &rmule_client_container,
    })
}

/// `ed2ksrv-holepunch-fail-score`: score a finished or archived run dir from
/// its own tap, without driving the leg again.
#[derive(Debug, Args)]
pub(crate) struct HolepunchFailScoreArgs {
    /// The run dir to score (the one holding `holepunch-fail/`).
    #[arg(long)]
    pub(crate) run_dir: PathBuf,
}

pub(crate) fn holepunch_fail_score(args: HolepunchFailScoreArgs) -> Result<()> {
    let verdict = score_holepunch_fail(&args.run_dir)?;
    println!("run_dir={}", args.run_dir.display());
    println!("verdict={verdict}");
    Ok(())
}
