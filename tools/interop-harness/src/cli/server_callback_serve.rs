//! The `server-callback-serve` subcommand and its re-scorer: a High-ID stock
//! aMule downloads from a Low-ID rmule through the server's callback relay,
//! rmule dialing the downloader back (ADR-0061).

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use rmule_interop_harness::artifacts::Ed2kHashCommand;
use rmule_interop_harness::flow::{
    ServerCallbackServeOptions, run_server_callback_serve, score_server_callback_serve,
    stage_reask_emit_files,
};
use serde::Serialize;

use crate::cli::bench::{AmuleArgs, BenchArgs, CaptureArgs};
use crate::cli::nat::{
    DEFAULT_ED2KSRV_BUILD_CONTEXT, DEFAULT_ED2KSRV_CONFIG, DEFAULT_ED2KSRV_IMAGE,
    DEFAULT_RMULE_TOOLS_DOCKERFILE, DEFAULT_RMULE_TOOLS_IMAGE,
};
use crate::cli::write_resolved_config;

const FLOW: &str = "server-callback-serve";

/// The shared file's size: several parts, so the transfer is a real upload
/// rather than one block.
const DEFAULT_FILE_SIZE: u64 = 4 * 1024 * 1024;

/// `server-callback-serve`: `ed2ksrv`, a Low-ID rmule sharing the synthetic
/// file, and a High-ID stock aMule downloading it through the server's
/// callback relay; the verdict reads both taps and the aMule's copy.
#[derive(Debug, Args)]
pub(crate) struct ServerCallbackServeArgs {
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
    /// The `rmule-tools` image rmule serves from; rebuilt from the workspace
    /// unless `--skip-build`.
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
    /// Per-step readiness budget in seconds: rmule's offer and the
    /// downloader's whole transfer each run under it.
    #[arg(long, default_value_t = 600)]
    pub(crate) timeout: u64,
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
}

pub(crate) fn server_callback_serve(args: ServerCallbackServeArgs) -> Result<()> {
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
        },
    )?;
    let hash_command = args
        .ed2k_hash_command
        .as_deref()
        .map_or_else(Ed2kHashCommand::cargo_rmule_tools, Ed2kHashCommand::new);
    stage_reask_emit_files(&layout, args.file_size, &hash_command, false)?;
    println!("run_dir={}", run_dir.display());

    run_server_callback_serve(ServerCallbackServeOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        build_images: args.bench.build_images,
        skip_build: args.bench.skip_build,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
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

/// `server-callback-serve-score`: score a finished or archived run dir from
/// its own taps and the downloader's copy, without driving the flow again.
#[derive(Debug, Args)]
pub(crate) struct ServerCallbackServeScoreArgs {
    /// The run dir to score (the one holding `server-callback-serve/`).
    #[arg(long)]
    pub(crate) run_dir: PathBuf,
}

pub(crate) fn server_callback_serve_score(args: ServerCallbackServeScoreArgs) -> Result<()> {
    let verdict = score_server_callback_serve(&args.run_dir)?;
    println!("run_dir={}", args.run_dir.display());
    println!("verdict={verdict}");
    Ok(())
}
