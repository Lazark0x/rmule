//! The `peer-reciprocity` subcommand and its re-scorer: a queued stock aMule
//! uploader that honours credits — rmule's upload preference and the credit
//! it earns, or a Low-ID rmule's 15-minute reask (ADR-0116).

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, ValueEnum};
use rmule_interop_harness::artifacts::Ed2kHashCommand;
use rmule_interop_harness::flow::{
    PeerReciprocityOptions, ReciprocityLeg, ReciprocityShape, run_peer_reciprocity,
    score_peer_reciprocity, stage_reciprocity_files,
};
use rmule_interop_harness::rmule::RmuleClientContainer;
use serde::Serialize;

use crate::cli::bench::{
    AmuleArgs, BenchArgs, CaptureArgs, DEFAULT_RMULE_CLIENT_IMAGE, EserverArgs,
};
use crate::cli::write_resolved_config;

const FLOW: &str = "peer-reciprocity";

/// rmule's file: moves in about a minute at one slot once granted.
const DEFAULT_RMULE_FILE_SIZE: u64 = 1024 * 1024;
/// The holders' file: more than a holder fetches at S's slot in a run (12 MiB
/// at 10 KiB/s is over twenty minutes).
const DEFAULT_HOLDER_FILE_SIZE: u64 = 12 * 1024 * 1024;
/// The gift: more than X's first burst at link speed, before its cap takes
/// hold (3 MiB reached X whole in 0.6 s), and it lifts S's credit for rmule
/// to `sqrt(32 + 2)` ≈ 5.83.
const DEFAULT_GIFT_FILE_SIZE: u64 = 32 * 1024 * 1024;

/// The leg, as the command line names it.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum LegArg {
    /// rmule's upload preference, then S's credit for rmule.
    Credit,
    /// A Low-ID rmule's 15-minute reask.
    LowId,
}

impl From<LegArg> for ReciprocityLeg {
    fn from(leg: LegArg) -> Self {
        match leg {
            LegArg::Credit => Self::Credit,
            LegArg::LowId => Self::LowId,
        }
    }
}

/// `peer-reciprocity`: the eserver, a High-ID stock aMule sharer held to two
/// slots, and one rmule core queued at it; `--leg credit` adds two waiters
/// ahead of rmule and three stock aMules downloading rmule's gift, `--leg
/// low-id` drops inbound connections to rmule's listener, so its server
/// gives it a Low ID. Taps on rmule's and the sharer's namespaces.
#[derive(Debug, Args)]
pub(crate) struct PeerReciprocityArgs {
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
    /// Which leg to drive.
    #[arg(long, value_enum)]
    pub(crate) leg: LegArg,
    /// rmule's file size in bytes; no compressor shrinks it.
    #[arg(long, default_value_t = DEFAULT_RMULE_FILE_SIZE)]
    pub(crate) rmule_file_size: u64,
    /// The holders' file size in bytes.
    #[arg(long, default_value_t = DEFAULT_HOLDER_FILE_SIZE)]
    pub(crate) holder_file_size: u64,
    /// The gift's size in bytes.
    #[arg(long, default_value_t = DEFAULT_GIFT_FILE_SIZE)]
    pub(crate) gift_file_size: u64,
    /// The sharer's upload slot, KiB/s; it keeps two. A holder's session
    /// past 10 MB is kicked once someone waits, so the slot is slow enough
    /// that neither holder reaches it before its stop.
    #[arg(long, default_value_t = 10)]
    pub(crate) slot_kib: u32,
    /// Each of the sharer's holders' download cap, KiB/s. Unset, the
    /// sharer's slot paces them; a cap below the slot loses it to aMule's
    /// 40 s socket timeout.
    #[arg(long)]
    pub(crate) holder_kib: Option<u32>,
    /// X's download cap, KiB/s: slow enough that X holds rmule's one upload
    /// slot until the flow stops it.
    #[arg(long, default_value_t = 2)]
    pub(crate) x_kib: u32,
    /// Credit leg: the sharer fetches the gift on rmule's free slot before
    /// X or W start, drawing its credit for rmule without rmule's choice.
    #[arg(long)]
    pub(crate) gift_first: bool,
    /// Seconds between one body joining a queue and the next, and before a
    /// stop.
    #[arg(long, default_value_t = 60)]
    pub(crate) step: u64,
    /// Seconds the flow waits for the outcome it reads; the Low-ID leg needs
    /// more than its 900 s reask.
    #[arg(long, default_value_t = 1200)]
    pub(crate) run_window: u64,
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
    gift_file_size: u64,
    shape: ReciprocityShape,
    timeout_secs: u64,
}

pub(crate) fn peer_reciprocity(args: PeerReciprocityArgs) -> Result<()> {
    args.eserver.reject_zero_host_port()?;
    let shape = ReciprocityShape {
        leg: args.leg.into(),
        slot_kib: args.slot_kib,
        holder_kib: args.holder_kib,
        x_kib: args.x_kib,
        gift_first: args.gift_first,
        step_secs: args.step,
        run_window_secs: args.run_window,
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
            gift_file_size: args.gift_file_size,
            shape,
            timeout_secs: args.timeout,
        },
    )?;
    let hash_command = args
        .ed2k_hash_command
        .as_deref()
        .map_or_else(Ed2kHashCommand::cargo_rmule_tools, Ed2kHashCommand::new);
    stage_reciprocity_files(
        &layout,
        args.rmule_file_size,
        args.holder_file_size,
        args.gift_file_size,
        &hash_command,
    )?;
    let rmule_client_container = RmuleClientContainer::cargo_rmule_tools(&args.rmule_client_image)?;
    println!("run_dir={}", run_dir.display());

    run_peer_reciprocity(PeerReciprocityOptions {
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

/// `peer-reciprocity-score`: score a finished or archived run dir from its
/// taps, its copy and rmule's log, without driving the flow again.
#[derive(Debug, Args)]
pub(crate) struct PeerReciprocityScoreArgs {
    /// The run dir to score (the one holding `peer-reciprocity/`).
    #[arg(long)]
    pub(crate) run_dir: PathBuf,
}

pub(crate) fn peer_reciprocity_score(args: PeerReciprocityScoreArgs) -> Result<()> {
    let verdict = score_peer_reciprocity(&args.run_dir)?;
    println!("run_dir={}", args.run_dir.display());
    println!("verdict={verdict}");
    Ok(())
}
