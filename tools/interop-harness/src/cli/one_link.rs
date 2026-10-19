//! The `peer-one-link` subcommand and its re-scorer: one rmule core downloads
//! two files from one stock aMule sharer over one link (ADR-0107, "One peer,
//! one link").

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use rmule_interop_harness::artifacts::Ed2kHashCommand;
use rmule_interop_harness::flow::{
    PeerOneLinkOptions, run_peer_one_link, score_peer_one_link, score_peer_one_link_severed,
    stage_reask_emit_files,
};
use rmule_interop_harness::rmule::RmuleClientContainer;
use serde::Serialize;

use crate::cli::bench::{
    AmuleArgs, BenchArgs, CaptureArgs, DEFAULT_RMULE_CLIENT_IMAGE, EserverArgs,
};
use crate::cli::write_resolved_config;

const FLOW: &str = "peer-one-link";
/// The verdict a severed run writes; its presence picks the severed re-score.
const SEVERED_VERDICT: &str = "peer-one-link-severed-verdict.toml";

/// Each file's size: at the sharer's 64 KiB/s cap the first takes about a
/// minute, so the second download asks for the sharer while it still rides.
const DEFAULT_FILE_SIZE: u64 = 4 * 1024 * 1024;

/// `peer-one-link`: the eserver, a High-ID stock aMule sharing two files, and
/// one rmule core downloading both; a tap on rmule's namespace.
#[derive(Debug, Args)]
pub(crate) struct PeerOneLinkArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) eserver: EserverArgs,
    #[command(flatten)]
    pub(crate) amule: AmuleArgs,
    #[command(flatten)]
    pub(crate) capture: CaptureArgs,
    /// Rust image used to run the rmule download container inside the network.
    #[arg(long, default_value = DEFAULT_RMULE_CLIENT_IMAGE)]
    pub(crate) rmule_client_image: String,
    /// Each staged file's size in bytes; no compressor shrinks them.
    #[arg(long, default_value_t = DEFAULT_FILE_SIZE)]
    pub(crate) file_size: u64,
    /// Per-step budget in seconds; each download's completion waits under it.
    #[arg(long, default_value_t = 900)]
    pub(crate) timeout: u64,
    /// The severed leg: stop the sharer this many seconds after rmule's first
    /// part assignment, so its link ends mid-transfer, then watch rmule keep
    /// the source queued (verdict `peer-one-link-severed-verdict.toml`)
    /// instead of waiting for the downloads.
    #[arg(long)]
    pub(crate) sever_after_secs: Option<u64>,
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
    server_image: String,
    rmule_client_image: String,
    capture_image: String,
    container_runtime: String,
    file_size: u64,
    timeout_secs: u64,
    sever_after_secs: Option<u64>,
}

pub(crate) fn peer_one_link(args: PeerOneLinkArgs) -> Result<()> {
    args.eserver.reject_zero_host_port()?;
    args.bench.prepare(&[
        args.eserver.build_context(),
        args.amule.build_context(),
        args.capture.build_context(),
    ])?;
    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &ResolvedConfig {
            flow: FLOW,
            amule_image: args.amule.amule_image.clone(),
            amule_env: args.amule.amule_env.clone(),
            server_image: args.eserver.server_image.clone(),
            rmule_client_image: args.rmule_client_image.clone(),
            capture_image: args.capture.capture_image.clone(),
            container_runtime: args.bench.container_runtime.clone(),
            file_size: args.file_size,
            timeout_secs: args.timeout,
            sever_after_secs: args.sever_after_secs,
        },
    )?;
    let hash_command = args
        .ed2k_hash_command
        .as_deref()
        .map_or_else(Ed2kHashCommand::cargo_rmule_tools, Ed2kHashCommand::new);
    stage_reask_emit_files(&layout, args.file_size, &hash_command, true)?;
    let rmule_client_container = RmuleClientContainer::cargo_rmule_tools(&args.rmule_client_image)?;
    println!("run_dir={}", run_dir.display());

    run_peer_one_link(PeerOneLinkOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        build_images: args.bench.build_images,
        server_image: &args.eserver.server_image,
        amule_image: &args.amule.amule_image,
        capture_image: &args.capture.capture_image,
        server_build_context: &args.eserver.server_build_context,
        amule_build_context: &args.amule.amule_build_context,
        capture_build_context: &args.capture.capture_build_context,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        server_host_port: args.eserver.server_host_port,
        rmule_client_container: &rmule_client_container,
        amule_env: &args.amule.amule_env,
        sever_after_secs: args.sever_after_secs,
    })
}

/// `peer-one-link-score`: score a finished or archived run dir from its tap,
/// its copies and rmule's log, without driving the flow again.
#[derive(Debug, Args)]
pub(crate) struct PeerOneLinkScoreArgs {
    /// The run dir to score (the one holding `peer-one-link/`).
    #[arg(long)]
    pub(crate) run_dir: PathBuf,
}

pub(crate) fn peer_one_link_score(args: PeerOneLinkScoreArgs) -> Result<()> {
    let verdict = if args.run_dir.join(SEVERED_VERDICT).exists() {
        score_peer_one_link_severed(&args.run_dir)?
    } else {
        score_peer_one_link(&args.run_dir)?
    };
    println!("run_dir={}", args.run_dir.display());
    println!("verdict={verdict}");
    Ok(())
}
