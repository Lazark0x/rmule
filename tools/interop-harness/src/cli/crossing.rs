//! The `peer-crossing` subcommand and its re-scorer: a stock aMule's own link
//! lands while rmule's dial to it is in flight, staged with `iptables` holds
//! in both namespaces (ADR-0107's Peer Links rules).

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, ValueEnum};
use rmule_interop_harness::artifacts::Ed2kHashCommand;
use rmule_interop_harness::flow::{
    CrossingLeg, CrossingShape, PeerCrossingOptions, run_peer_crossing, score_peer_crossing,
    stage_reciprocity_files,
};
use rmule_interop_harness::rmule::RmuleClientContainer;
use serde::Serialize;

use crate::cli::bench::{
    AmuleArgs, BenchArgs, CaptureArgs, DEFAULT_RMULE_CLIENT_IMAGE, FirstServerArgs,
};
use crate::cli::write_resolved_config;

const FLOW: &str = "peer-crossing";
/// rmule's own download: about 16 s at the seed's 64 KiB/s.
const RMULE_FILE_SIZE: u64 = 1024 * 1024;
/// The slot and wait files: larger than X's first burst at its cap, so X
/// still holds the slot when it is stopped.
const SERVED_FILE_SIZE: u64 = 32 * 1024 * 1024;
/// The file a seed downloads back on the download legs: done well inside the
/// seconds a stock aMule reads a link both ways at full rate. Past them it
/// stops reading that link, its own ask and rmule's last one unread (run
/// `1793367749`).
const SEED_FILE_SIZE: u64 = 4 * 1024 * 1024;

/// The race the flow stages.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum LegArg {
    /// rmule's dial-back held at its SYN while the waiter comes back.
    ServeCalledOff,
    /// rmule's dial-back has written its hello when the waiter's link lands,
    /// the waiter's client new: it refuses the attach.
    ServeCrossed,
    /// The same with the waiter's client alive: its own reask, at its period.
    ServeReask,
    /// A Low-ID waiter comes back while rmule's slot sits free.
    LowIdReturn,
    /// The waiter holds its slot on rmule's dial-back and drops that link
    /// with no close reaching rmule, then comes back on its own.
    ServeDeadDial,
    /// The same with the waiter's proof of its key held back on the dial, so
    /// rmule lets the dial go with its verification unfinished.
    ServeIdentifying,
    /// rmule's download dial held at its SYN while its seed's link lands.
    DownloadYield,
    /// rmule's download dial has written its hello when its seed's link lands.
    DownloadCrossed,
    /// kno, knowing rmule from a hello and holding no link to it, dials first
    /// (run with `--amule-image rmule/interop-amule-kno:local`).
    KnoDialsFirst,
}

impl From<LegArg> for CrossingLeg {
    fn from(leg: LegArg) -> Self {
        match leg {
            LegArg::ServeCalledOff => Self::ServeCalledOff,
            LegArg::ServeCrossed => Self::ServeCrossed,
            LegArg::ServeReask => Self::ServeReask,
            LegArg::LowIdReturn => Self::LowIdReturn,
            LegArg::ServeDeadDial => Self::ServeDeadDial,
            LegArg::ServeIdentifying => Self::ServeIdentifying,
            LegArg::DownloadYield => Self::DownloadYield,
            LegArg::DownloadCrossed => Self::DownloadCrossed,
            LegArg::KnoDialsFirst => Self::KnoDialsFirst,
        }
    }
}

/// `peer-crossing`: the eserver, a stock aMule seed of rmule's download, and
/// on the serve side a slot holder X and a waiter W; a tap in rmule's namespace.
#[derive(Debug, Args)]
pub(crate) struct PeerCrossingArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) eserver: FirstServerArgs,
    #[command(flatten)]
    pub(crate) amule: AmuleArgs,
    #[command(flatten)]
    pub(crate) capture: CaptureArgs,
    /// Rust image used to run the rmule download container inside the network.
    #[arg(long, default_value = DEFAULT_RMULE_CLIENT_IMAGE)]
    pub(crate) rmule_client_image: String,
    /// Which race to stage.
    #[arg(long, value_enum)]
    pub(crate) leg: LegArg,
    /// An image carrying `python3`, which holds the slot on the reask leg.
    #[arg(long, default_value = crate::cli::nat::DEFAULT_NATPROBE_IMAGE)]
    pub(crate) probe_image: String,
    /// Seconds W stays queued before X stops: past aMule's 40 s idle close.
    #[arg(long, default_value_t = 45)]
    pub(crate) idle: u64,
    /// Seconds each hold stands before it is lifted; `0` on the two crossed
    /// legs draws the race with no hold.
    #[arg(long, default_value_t = 4)]
    pub(crate) hold: u64,
    /// Seconds the flow watches after the last hold is lifted.
    #[arg(long, default_value_t = 30)]
    pub(crate) watch: u64,
    /// Per-step readiness budget in seconds.
    #[arg(long, default_value_t = 300)]
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
    shape: CrossingShape,
    timeout_secs: u64,
}

pub(crate) fn peer_crossing(args: PeerCrossingArgs) -> Result<()> {
    args.eserver.reject_zero_host_port()?;
    let shape = CrossingShape {
        leg: args.leg.into(),
        idle_secs: args.idle,
        hold_secs: args.hold,
        watch_secs: args.watch,
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
            shape,
            timeout_secs: args.timeout,
        },
    )?;
    let hash_command = args
        .ed2k_hash_command
        .as_deref()
        .map_or_else(Ed2kHashCommand::cargo_rmule_tools, Ed2kHashCommand::new);
    // The holders' file is unused here; it is staged small.
    stage_reciprocity_files(
        &layout,
        RMULE_FILE_SIZE,
        1024,
        if shape.leg.serves() {
            SERVED_FILE_SIZE
        } else {
            SEED_FILE_SIZE
        },
        &hash_command,
    )?;
    let rmule_client_container = RmuleClientContainer::cargo_rmule_tools(&args.rmule_client_image)?;
    println!("run_dir={}", run_dir.display());

    run_peer_crossing(PeerCrossingOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        build_images: args.bench.build_images,
        server_image: &args.eserver.server_image,
        amule_image: &args.amule.amule_image,
        capture_image: &args.capture.capture_image,
        probe_image: &args.probe_image,
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

/// `peer-crossing-score`: score a finished or archived run dir from its tap,
/// its copy and rmule's log, without driving the flow again.
#[derive(Debug, Args)]
pub(crate) struct PeerCrossingScoreArgs {
    /// The run dir to score (the one holding `peer-crossing/`).
    #[arg(long)]
    pub(crate) run_dir: PathBuf,
}

pub(crate) fn peer_crossing_score(args: PeerCrossingScoreArgs) -> Result<()> {
    let verdict = score_peer_crossing(&args.run_dir)?;
    println!("run_dir={}", args.run_dir.display());
    println!("verdict={verdict}");
    Ok(())
}
