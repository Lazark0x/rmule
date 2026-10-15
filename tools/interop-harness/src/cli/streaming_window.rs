//! The `peer-streaming-window` subcommand and its re-scorer: one Streaming
//! Priority file held in part by stock aMule seeds, downloaded by rmule with a
//! chosen Streaming Window (ADR-0112). A run with every part held ends when
//! the file does — a few minutes at the default seed cap; one that leaves a
//! part unheld runs its whole `--hold-secs`, so a hand-driven run keeps its
//! containers, returns after `--wait-secs`, and is collected and scored later.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use rmule_interop_harness::flow::{
    SeedHolding, StreamingWindowOptions, collect_streaming_window_run, default_seeds,
    run_streaming_window, score_streaming_window, seed_holding_arg,
};
use rmule_primitives::{ED2K_PART_SIZE, part_count};
use serde::Serialize;

use crate::cli::bench::{AmuleArgs, BenchArgs, CaptureArgs, EserverArgs};
use crate::cli::nat::{DEFAULT_RMULE_TOOLS_DOCKERFILE, DEFAULT_RMULE_TOOLS_IMAGE};
use crate::cli::write_resolved_config;

const FLOW: &str = "peer-streaming-window";
/// Twelve parts exactly, so a partial seed's status carries the phantom
/// thirteenth (ADR-0112 §1).
const DEFAULT_FILE_SIZE: u64 = 12 * ED2K_PART_SIZE;

/// `peer-streaming-window`: an eserver, one stock aMule per `--seed`, and
/// rmule downloading the file from them.
#[derive(Debug, Args)]
pub(crate) struct PeerStreamingWindowArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) eserver: EserverArgs,
    #[command(flatten)]
    pub(crate) amule: AmuleArgs,
    #[command(flatten)]
    pub(crate) capture: CaptureArgs,
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
    /// The stream file's size in bytes.
    #[arg(long, default_value_t = DEFAULT_FILE_SIZE)]
    pub(crate) file_size: u64,
    /// One seed: `complete`, or the parts it holds, as `0-6,11`; repeat for
    /// each. Unset, two partial seeds, each holding parts the other lacks and
    /// both holding the Preview Band's ends and the middle part.
    #[arg(long = "seed", value_parser = seed_holding_arg)]
    pub(crate) seeds: Vec<SeedHolding>,
    /// rmule's Streaming Window width `N`, in parts.
    #[arg(long, default_value_t = 4)]
    pub(crate) streaming_window: u32,
    /// rmule's peer workers per download; unset keeps the core's default.
    #[arg(long)]
    pub(crate) peer_concurrency: Option<usize>,
    /// The seeds' upload caps in KiB/s, so the file takes minutes: one for
    /// every seed, or a comma list with one per `--seed`.
    #[arg(long, value_delimiter = ',', default_value = "200")]
    pub(crate) seed_max_upload_kib: Vec<u32>,
    /// rmule's part-map tick, in milliseconds.
    #[arg(long, default_value_t = 1_000)]
    pub(crate) report_parts_every_ms: u64,
    /// rmule's bounded run, in seconds. A run whose seeds leave a part unheld
    /// needs it past twice FILEREASKTIME (2,600 s) after its retirements.
    #[arg(long, default_value_t = 1_800)]
    pub(crate) hold_secs: u64,
    /// How long this call waits for rmule's run to end; with
    /// `--keep-containers` it then returns, and `peer-streaming-window-score
    /// --collect` finishes the run. Unset, the whole `--hold-secs`.
    #[arg(long)]
    pub(crate) wait_secs: Option<u64>,
    /// Also name every seed as a source in rmule's link, beside the server's
    /// get-sources.
    #[arg(long)]
    pub(crate) link_sources: bool,
    /// Hold every packet each seed sends by this many ms with `tc netem`, so
    /// the links carry a WAN round trip.
    #[arg(long)]
    pub(crate) seed_netem_delay_ms: Option<u32>,
    /// Per-step readiness budget in seconds.
    #[arg(long, default_value_t = 600)]
    pub(crate) timeout: u64,
}

#[derive(Debug, Serialize)]
struct ResolvedConfig {
    #[serde(rename = "scenario")]
    flow: &'static str,
    server_image: String,
    amule_image: String,
    amule_env: Vec<String>,
    capture_image: String,
    rmule_tools_image: String,
    container_runtime: String,
    file_size: u64,
    seeds: Vec<String>,
    streaming_window: u32,
    peer_concurrency: Option<usize>,
    seed_max_upload_kib: Vec<u32>,
    report_parts_every_ms: u64,
    hold_secs: u64,
    wait_secs: Option<u64>,
    link_sources: bool,
    seed_netem_delay_ms: Option<u32>,
    timeout_secs: u64,
}

pub(crate) fn peer_streaming_window(args: PeerStreamingWindowArgs) -> Result<()> {
    args.eserver.reject_zero_host_port()?;
    args.bench.prepare(&[
        args.eserver.build_context(),
        args.amule.build_context(),
        args.capture.build_context(),
    ])?;
    let seeds = if args.seeds.is_empty() {
        default_seeds(part_count(args.file_size))
    } else {
        args.seeds.clone()
    };
    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &ResolvedConfig {
            flow: FLOW,
            server_image: args.eserver.server_image.clone(),
            amule_image: args.amule.amule_image.clone(),
            amule_env: args.amule.amule_env.clone(),
            capture_image: args.capture.capture_image.clone(),
            rmule_tools_image: args.rmule_tools_image.clone(),
            container_runtime: args.bench.container_runtime.clone(),
            file_size: args.file_size,
            seeds: seeds.iter().map(SeedHolding::spec).collect(),
            streaming_window: args.streaming_window,
            peer_concurrency: args.peer_concurrency,
            seed_max_upload_kib: args.seed_max_upload_kib.clone(),
            report_parts_every_ms: args.report_parts_every_ms,
            hold_secs: args.hold_secs,
            wait_secs: args.wait_secs,
            link_sources: args.link_sources,
            seed_netem_delay_ms: args.seed_netem_delay_ms,
            timeout_secs: args.timeout,
        },
    )?;
    println!("run_dir={}", run_dir.display());

    run_streaming_window(StreamingWindowOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        build_images: args.bench.build_images,
        skip_build: args.bench.skip_build,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        server_image: &args.eserver.server_image,
        server_build_context: &args.eserver.server_build_context,
        server_host_port: args.eserver.server_host_port,
        amule_image: &args.amule.amule_image,
        amule_build_context: &args.amule.amule_build_context,
        amule_env: &args.amule.amule_env,
        capture_image: &args.capture.capture_image,
        capture_build_context: &args.capture.capture_build_context,
        rmule_tools_image: &args.rmule_tools_image,
        rmule_tools_dockerfile: &args.rmule_tools_dockerfile,
        rmule_tools_build_context: &args.rmule_tools_build_context,
        file_size: args.file_size,
        seeds: &seeds,
        window_parts: args.streaming_window,
        peer_concurrency: args.peer_concurrency,
        seed_max_upload_kib: &args.seed_max_upload_kib,
        parts_every_ms: args.report_parts_every_ms,
        hold_secs: args.hold_secs,
        link_sources: args.link_sources,
        wait_secs: args.wait_secs,
        seed_netem_delay_ms: args.seed_netem_delay_ms,
    })
}

/// `peer-streaming-window-score`: score a finished or archived run dir from
/// its own tap and logs, without driving the flow again.
#[derive(Debug, Args)]
pub(crate) struct PeerStreamingWindowScoreArgs {
    /// The run dir to score (the one holding `streaming-window/`).
    #[arg(long)]
    pub(crate) run_dir: PathBuf,
    /// First collect the logs of a kept run's still-standing containers.
    #[arg(long)]
    pub(crate) collect: bool,
    /// The Docker-compatible CLI `--collect` reads the logs with.
    #[arg(long, default_value = "docker")]
    pub(crate) container_runtime: String,
}

pub(crate) fn peer_streaming_window_score(args: PeerStreamingWindowScoreArgs) -> Result<()> {
    if args.collect {
        collect_streaming_window_run(&args.container_runtime, &args.run_dir)?;
    }
    let verdict = score_streaming_window(&args.run_dir)?;
    println!("run_dir={}", args.run_dir.display());
    println!("verdict={verdict}");
    Ok(())
}
