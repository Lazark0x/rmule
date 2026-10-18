//! The `peer-queue-fanout` subcommand and its re-scorer: one rmule download
//! against many stock aMule sharers, some queuing it and some granting late
//! (ADR-0116, asking and transferring).

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use rmule_interop_harness::artifacts::Ed2kHashCommand;
use rmule_interop_harness::flow::{
    FanoutShape, PeerQueueFanoutOptions, run_peer_queue_fanout, score_peer_queue_fanout,
    stage_queue_fanout_files,
};
use rmule_interop_harness::rmule::RmuleClientContainer;
use serde::Serialize;

use crate::cli::bench::{
    AmuleArgs, BenchArgs, CaptureArgs, DEFAULT_RMULE_CLIENT_IMAGE, EserverArgs,
};
use crate::cli::write_resolved_config;

const FLOW: &str = "peer-queue-fanout";

/// rmule's file: three parts, so several sharers carry it at once.
const DEFAULT_RMULE_FILE_SIZE: u64 = 3 * 9_728_000;
/// Each holder file: more than a holder fetches at its cap in a run.
const DEFAULT_HOLDER_FILE_SIZE: u64 = 12 * 1024 * 1024;

/// `peer-queue-fanout`: the eserver, `--sharers` High-ID stock aMule sharers
/// of rmule's file, the first `--queued` of them held to their two slots by
/// two stock aMule holders each, and one rmule core; `--late-after` seconds
/// after rmule's first rank one holder of each of the first `--late` queued
/// sharers stops. A tap on rmule's namespace.
#[derive(Debug, Args)]
pub(crate) struct PeerQueueFanoutArgs {
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
    /// Each holder file's size in bytes; no compressor shrinks it.
    #[arg(long, default_value_t = DEFAULT_HOLDER_FILE_SIZE)]
    pub(crate) holder_file_size: u64,
    /// Stock aMule sharers of rmule's file.
    #[arg(long, default_value_t = 6)]
    pub(crate) sharers: usize,
    /// The first this many sharers queue rmule behind two holders.
    #[arg(long, default_value_t = 4)]
    pub(crate) queued: usize,
    /// The first this many queued sharers lose a holder and grant late.
    #[arg(long, default_value_t = 2)]
    pub(crate) late: usize,
    /// Seconds from rmule's first rank to the late holders' stop.
    #[arg(long, default_value_t = 60)]
    pub(crate) late_after: u64,
    /// Each sharer's upload slot, KiB/s; every sharer keeps two.
    #[arg(long, default_value_t = 50)]
    pub(crate) slot_kib: u32,
    /// Each holder's download cap, KiB/s.
    #[arg(long, default_value_t = 2)]
    pub(crate) holder_kib: u32,
    /// Seconds the flow waits for the download to complete.
    #[arg(long, default_value_t = 900)]
    pub(crate) run_window: u64,
    /// rmule's Connection Ceiling (ADR-0116); unset keeps the core's.
    #[arg(long)]
    pub(crate) max_connections: Option<usize>,
    /// rmule's Dial Window (ADR-0116); unset keeps the core's.
    #[arg(long)]
    pub(crate) dials_per_window: Option<u32>,
    /// Per-step readiness budget in seconds.
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
    server_image: String,
    rmule_client_image: String,
    capture_image: String,
    container_runtime: String,
    rmule_file_size: u64,
    holder_file_size: u64,
    shape: FanoutShape,
    timeout_secs: u64,
}

pub(crate) fn peer_queue_fanout(args: PeerQueueFanoutArgs) -> Result<()> {
    args.eserver.reject_zero_host_port()?;
    let shape = FanoutShape {
        sharers: args.sharers,
        queued: args.queued,
        late: args.late,
        late_after_secs: args.late_after,
        slot_kib: args.slot_kib,
        holder_kib: args.holder_kib,
        run_window_secs: args.run_window,
        max_connections: args.max_connections,
        dials_per_window: args.dials_per_window,
    };
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
            shape,
            timeout_secs: args.timeout,
        },
    )?;
    let hash_command = args
        .ed2k_hash_command
        .as_deref()
        .map_or_else(Ed2kHashCommand::cargo_rmule_tools, Ed2kHashCommand::new);
    stage_queue_fanout_files(
        &layout,
        args.rmule_file_size,
        args.holder_file_size,
        args.queued,
        &hash_command,
    )?;
    let rmule_client_container = RmuleClientContainer::cargo_rmule_tools(&args.rmule_client_image)?;
    println!("run_dir={}", run_dir.display());

    run_peer_queue_fanout(PeerQueueFanoutOptions {
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
        shape,
    })
}

/// `peer-queue-fanout-score`: score a finished or archived run dir from its
/// tap, its copy and rmule's log, without driving the flow again.
#[derive(Debug, Args)]
pub(crate) struct PeerQueueFanoutScoreArgs {
    /// The run dir to score (the one holding `peer-queue-fanout/`).
    #[arg(long)]
    pub(crate) run_dir: PathBuf,
}

pub(crate) fn peer_queue_fanout_score(args: PeerQueueFanoutScoreArgs) -> Result<()> {
    let verdict = score_peer_queue_fanout(&args.run_dir)?;
    println!("run_dir={}", args.run_dir.display());
    println!("verdict={verdict}");
    Ok(())
}
