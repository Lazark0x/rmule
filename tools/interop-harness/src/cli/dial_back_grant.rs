//! The `peer-dial-back-grant` subcommand and its re-scorer: a stock aMule
//! promotes a queued rmule by dialing it back, and rmule takes the grant into
//! its download (ADR-0057, "A grant by dial-back is taken").

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use rmule_interop_harness::artifacts::Ed2kHashCommand;
use rmule_interop_harness::flow::{
    PeerDialBackGrantOptions, run_peer_dial_back_grant, score_peer_dial_back_grant,
    stage_dial_back_files,
};
use rmule_interop_harness::rmule::RmuleClientContainer;
use serde::Serialize;

use crate::cli::bench::{
    AmuleArgs, BenchArgs, CaptureArgs, DEFAULT_RMULE_CLIENT_IMAGE, EserverArgs,
};
use crate::cli::write_resolved_config;

const FLOW: &str = "peer-dial-back-grant";

/// rmule's file: at the sharer's 8 KiB/s it moves in about a minute once
/// granted.
const DEFAULT_RMULE_FILE_SIZE: u64 = 256 * 1024;
/// The holders' file: more than a part, so no holder finishes and frees its
/// slot before the flow stops one.
const DEFAULT_HOLDER_FILE_SIZE: u64 = 12 * 1024 * 1024;

/// `peer-dial-back-grant`: the eserver, a High-ID stock aMule sharer held to
/// two slots by two stock aMule holders, and one rmule core queued behind
/// them; a holder is stopped and the sharer dials rmule back. A tap on
/// rmule's namespace.
#[derive(Debug, Args)]
pub(crate) struct PeerDialBackGrantArgs {
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
    /// rmule's file size in bytes; no compressor shrinks it.
    #[arg(long, default_value_t = DEFAULT_RMULE_FILE_SIZE)]
    pub(crate) rmule_file_size: u64,
    /// The holders' file size in bytes; no compressor shrinks it.
    #[arg(long, default_value_t = DEFAULT_HOLDER_FILE_SIZE)]
    pub(crate) holder_file_size: u64,
    /// Per-step readiness budget in seconds.
    #[arg(long, default_value_t = 600)]
    pub(crate) timeout: u64,
    /// Seconds from the holder's stop to the end of the window the grant is
    /// read in.
    #[arg(long, default_value_t = 300)]
    pub(crate) grant_window: u64,
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
    rmule_file_size: u64,
    holder_file_size: u64,
    timeout_secs: u64,
    grant_window_secs: u64,
}

pub(crate) fn peer_dial_back_grant(args: PeerDialBackGrantArgs) -> Result<()> {
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
            rmule_file_size: args.rmule_file_size,
            holder_file_size: args.holder_file_size,
            timeout_secs: args.timeout,
            grant_window_secs: args.grant_window,
        },
    )?;
    let hash_command = args
        .ed2k_hash_command
        .as_deref()
        .map_or_else(Ed2kHashCommand::cargo_rmule_tools, Ed2kHashCommand::new);
    stage_dial_back_files(
        &layout,
        args.rmule_file_size,
        args.holder_file_size,
        &hash_command,
    )?;
    let rmule_client_container = RmuleClientContainer::cargo_rmule_tools(&args.rmule_client_image)?;
    println!("run_dir={}", run_dir.display());

    run_peer_dial_back_grant(PeerDialBackGrantOptions {
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
        grant_window_secs: args.grant_window,
        server_host_port: args.eserver.server_host_port,
        rmule_client_container: &rmule_client_container,
        amule_env: &args.amule.amule_env,
    })
}

/// `peer-dial-back-grant-score`: score a finished or archived run dir from
/// its tap, its copy and rmule's log, without driving the flow again.
#[derive(Debug, Args)]
pub(crate) struct PeerDialBackGrantScoreArgs {
    /// The run dir to score (the one holding `peer-dial-back-grant/`).
    #[arg(long)]
    pub(crate) run_dir: PathBuf,
}

pub(crate) fn peer_dial_back_grant_score(args: PeerDialBackGrantScoreArgs) -> Result<()> {
    let verdict = score_peer_dial_back_grant(&args.run_dir)?;
    println!("run_dir={}", args.run_dir.display());
    println!("verdict={verdict}");
    Ok(())
}
