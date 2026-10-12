//! The `peer-lowid-callback-reask` subcommand and its re-scorer: a queued
//! rmule pings a Low-ID stock aMule it reached by callback, and the answer
//! keeps its standing past the `FILEREASKTIME` instant. CLI-only — no knob
//! shortens rmule's reask period, so a run takes about 30 minutes.

use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::Args;
use rmule_interop_harness::artifacts::Ed2kHashCommand;
use rmule_interop_harness::flow::{
    DEFAULT_REASK_WINDOW_SECS, PeerLowIdCallbackReaskOptions, run_peer_lowid_callback_reask,
    score_lowid_callback_reask, stage_reask_emit_files,
};
use serde::Serialize;

use crate::cli::bench::{AmuleArgs, BenchArgs, CaptureArgs};
use crate::cli::nat::{
    DEFAULT_ED2KSRV_BUILD_CONTEXT, DEFAULT_ED2KSRV_CONFIG, DEFAULT_ED2KSRV_IMAGE,
    DEFAULT_RMULE_TOOLS_DOCKERFILE, DEFAULT_RMULE_TOOLS_IMAGE,
};
use crate::cli::write_resolved_config;

const FLOW: &str = "peer-lowid-callback-reask";

/// The shared file's size: large, so no slot-holder finishes a part at about
/// 1.5 KB/s inside the window and rmule stays queued.
const DEFAULT_FILE_SIZE: u64 = 40 * 1024 * 1024;

/// `peer-lowid-callback-reask`: `ed2ksrv`, a Low-ID stock aMule sharer whose
/// two upload slots two stock aMules hold, and rmule downloading through the
/// sharer's callback; the verdict reads both taps after `FILEREASKTIME`.
#[derive(Debug, Args)]
pub(crate) struct PeerLowIdCallbackReaskArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) amule: AmuleArgs,
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
    /// The `rmule-tools` image rmule downloads from; rebuilt from the
    /// workspace unless `--skip-build`.
    #[arg(long, default_value = DEFAULT_RMULE_TOOLS_IMAGE)]
    pub(crate) rmule_tools_image: String,
    /// Dockerfile for the `rmule-tools` image.
    #[arg(long, default_value = DEFAULT_RMULE_TOOLS_DOCKERFILE)]
    pub(crate) rmule_tools_dockerfile: PathBuf,
    /// Build context for the `rmule-tools` image (the repo root).
    #[arg(long, default_value = ".")]
    pub(crate) rmule_tools_build_context: PathBuf,
    /// Shared file size in bytes.
    #[arg(long, default_value_t = DEFAULT_FILE_SIZE)]
    pub(crate) file_size: u64,
    /// Per-step readiness budget in seconds: the holders' callbacks and
    /// rmule's login, callback and queueing each run under it.
    #[arg(long, default_value_t = 600)]
    pub(crate) timeout: u64,
    /// Seconds to sit past rmule's queueing, covering FILEREASKTIME (1300 s)
    /// plus margin.
    #[arg(long, default_value_t = DEFAULT_REASK_WINDOW_SECS)]
    pub(crate) reask_window_secs: u64,
    /// Test hook for the ED2K hash command.
    #[arg(long, hide = true)]
    pub(crate) ed2k_hash_command: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct ResolvedConfig {
    #[serde(rename = "scenario")]
    flow: &'static str,
    amule_image: String,
    amule_env: Vec<String>,
    ed2ksrv_image: String,
    ed2ksrv_config: PathBuf,
    rmule_tools_image: String,
    capture_image: String,
    container_runtime: String,
    file_size: u64,
    timeout_secs: u64,
    reask_window_secs: u64,
}

pub(crate) fn peer_lowid_callback_reask(args: PeerLowIdCallbackReaskArgs) -> Result<()> {
    if args.reask_window_secs <= 1300 {
        bail!("--reask-window-secs must run past FILEREASKTIME (1300 s)");
    }
    args.bench.prepare(&[
        args.amule.build_context(),
        args.capture.build_context(),
        ("ed2ksrv", &args.ed2ksrv_build_context),
    ])?;
    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &ResolvedConfig {
            flow: FLOW,
            amule_image: args.amule.amule_image.clone(),
            amule_env: args.amule.amule_env.clone(),
            ed2ksrv_image: args.ed2ksrv_image.clone(),
            ed2ksrv_config: args.ed2ksrv_config.clone(),
            rmule_tools_image: args.rmule_tools_image.clone(),
            capture_image: args.capture.capture_image.clone(),
            container_runtime: args.bench.container_runtime.clone(),
            file_size: args.file_size,
            timeout_secs: args.timeout,
            reask_window_secs: args.reask_window_secs,
        },
    )?;
    let hash_command = args
        .ed2k_hash_command
        .as_deref()
        .map_or_else(Ed2kHashCommand::cargo_rmule_tools, Ed2kHashCommand::new);
    stage_reask_emit_files(&layout, args.file_size, &hash_command, false)?;
    println!("run_dir={}", run_dir.display());

    run_peer_lowid_callback_reask(PeerLowIdCallbackReaskOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        build_images: args.bench.build_images,
        skip_build: args.bench.skip_build,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        reask_window_secs: args.reask_window_secs,
        amule_image: &args.amule.amule_image,
        amule_build_context: &args.amule.amule_build_context,
        amule_env: &args.amule.amule_env,
        ed2ksrv_image: &args.ed2ksrv_image,
        ed2ksrv_build_context: &args.ed2ksrv_build_context,
        ed2ksrv_config: &args.ed2ksrv_config,
        capture_image: &args.capture.capture_image,
        capture_build_context: &args.capture.capture_build_context,
        rmule_tools_image: &args.rmule_tools_image,
        rmule_tools_dockerfile: &args.rmule_tools_dockerfile,
        rmule_tools_build_context: &args.rmule_tools_build_context,
    })
}

/// `peer-lowid-callback-reask-score`: score a finished or archived run dir
/// from its own taps and logs, without driving the flow again.
#[derive(Debug, Args)]
pub(crate) struct PeerLowIdCallbackReaskScoreArgs {
    /// The run dir to score (the one holding `lowid-callback-reask/`).
    #[arg(long)]
    pub(crate) run_dir: PathBuf,
}

pub(crate) fn peer_lowid_callback_reask_score(args: PeerLowIdCallbackReaskScoreArgs) -> Result<()> {
    let verdict = score_lowid_callback_reask(&args.run_dir)?;
    println!("run_dir={}", args.run_dir.display());
    println!("verdict={verdict}");
    Ok(())
}
