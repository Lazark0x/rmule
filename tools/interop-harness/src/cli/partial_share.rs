//! The `peer-partial-share` subcommand and its re-scorer: rmule serves a
//! download it is still fetching to stock aMule (ADR-0113), and carries the
//! upload across its completion move (ADR-0115). One topology, run with the
//! knobs a claim needs: the serve-and-complete run ends a few minutes after
//! the download does; the queued run waits out aMule's reask timer
//! (`FILEREASKTIME`, 1,300 s) and takes its half hour.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use rmule_interop_harness::flow::{
    PartialShareOptions, SeedHolding, run_partial_share, score_partial_share, seed_holding_arg,
};
use rmule_primitives::ED2K_PART_SIZE;
use serde::Serialize;

use crate::cli::bench::{AmuleArgs, BenchArgs, CaptureArgs, EserverArgs};
use crate::cli::nat::{
    DEFAULT_ED2KSRV_CONFIG, DEFAULT_ED2KSRV_IMAGE, DEFAULT_RMULE_TOOLS_DOCKERFILE,
    DEFAULT_RMULE_TOOLS_IMAGE,
};
use crate::cli::write_resolved_config;

const FLOW: &str = "peer-partial-share";
/// Six parts, the last one short, so no phantom part enters the count.
const DEFAULT_FILE_SIZE: u64 = 5 * ED2K_PART_SIZE + 4_000_000;
/// Two parts: a file large enough that aMule asks its status.
const DEFAULT_WHOLE_SIZE: u64 = ED2K_PART_SIZE + 2_000_000;
/// aMule's `FILEREASKTIME` (1,300 s) and a margin for its process tick.
const DEFAULT_REASK_WAIT_SECS: u64 = 1_360;

/// `peer-partial-share`: an eserver, stock aMule seeds rmule alone reaches,
/// rmule downloading and serving, and stock aMule downloaders fetching from
/// it.
#[derive(Debug, Args)]
pub(crate) struct PeerPartialShareArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) eserver: EserverArgs,
    #[command(flatten)]
    pub(crate) amule: AmuleArgs,
    #[command(flatten)]
    pub(crate) capture: CaptureArgs,
    /// The `rmule-tools` image rmule and the stimuli run from; rebuilt from
    /// the workspace unless `--skip-build`.
    #[arg(long, default_value = DEFAULT_RMULE_TOOLS_IMAGE)]
    pub(crate) rmule_tools_image: String,
    /// Dockerfile for the `rmule-tools` image.
    #[arg(long, default_value = DEFAULT_RMULE_TOOLS_DOCKERFILE)]
    pub(crate) rmule_tools_dockerfile: PathBuf,
    /// Build context for the `rmule-tools` image (the repo root).
    #[arg(long, default_value = ".")]
    pub(crate) rmule_tools_build_context: PathBuf,
    /// The downloaders' aMule image; unset, the seeds' (`--amule-image`).
    /// kno's image is built apart, by its own recipe.
    #[arg(long)]
    pub(crate) downloader_image: Option<String>,
    /// The stream file's size in bytes; more than one part.
    #[arg(long, default_value_t = DEFAULT_FILE_SIZE)]
    pub(crate) file_size: u64,
    /// The whole file rmule shares beside the download, in bytes; `0` for
    /// none.
    #[arg(long, default_value_t = DEFAULT_WHOLE_SIZE)]
    pub(crate) whole_size: u64,
    /// One seed: `complete`, or the parts it holds, as `0,3`; repeat for
    /// each. Unset, one seed holding parts 0 and 3 and one complete.
    #[arg(long = "seed", value_parser = seed_holding_arg)]
    pub(crate) seeds: Vec<SeedHolding>,
    /// The seeds' upload caps in KiB/s (`0` uncapped): one for every seed,
    /// or a comma list with one per `--seed`.
    #[arg(long, value_delimiter = ',', default_value = "100,150")]
    pub(crate) seed_max_upload_kib: Vec<u32>,
    /// The slot-holding downloader's own download cap in KiB/s (`0`
    /// uncapped).
    #[arg(long, default_value_t = 0)]
    pub(crate) downloader_max_download_kib: u32,
    /// rmule's egress to the slot-holding downloader in kbit/s (`0`
    /// unshaped), a `tc` token bucket in rmule's namespace: aMule's own
    /// download cap reacts only after a burst, and a part crosses the bench
    /// network in half a second. The default, 8 KB/s, fetches even the short
    /// last part well past the download's completion.
    #[arg(long, default_value_t = 64)]
    pub(crate) downloader_link_kbit: u32,
    /// Let rmule's download dial the downloaders it serves. Unset, those
    /// dials are dropped on rmule's link: rmule takes an asker for a source
    /// and dials it on a second link, and stock aMule then closes the first
    /// one, ending the upload the claims read.
    #[arg(long)]
    pub(crate) dial_downloaders: bool,
    /// rmule's peer workers per download; unset keeps the core's.
    #[arg(long)]
    pub(crate) peer_concurrency: Option<usize>,
    /// Log rmule and the seeds in to ed2k-server instead of Lugdunum (the
    /// downloaders stay on Lugdunum): the seeds then hold High IDs, so
    /// rmule's download pool has sources to exchange, and the announce is
    /// read on ed2k-server.
    #[arg(long)]
    pub(crate) rmule_on_ed2ksrv: bool,
    /// The ed2k-server image (pinned; see `images/ed2ksrv`).
    #[arg(long, default_value = DEFAULT_ED2KSRV_IMAGE)]
    pub(crate) ed2ksrv_image: String,
    /// The ed2k-server bench config; its `this_ip` is rendered per run.
    #[arg(long, default_value = DEFAULT_ED2KSRV_CONFIG)]
    pub(crate) ed2ksrv_config: PathBuf,
    /// Leave out the prober that asks before rmule holds a part.
    #[arg(long)]
    pub(crate) no_prober: bool,
    /// Give rmule one upload slot and queue a second downloader behind the
    /// first, to draw its UDP reask.
    #[arg(long)]
    pub(crate) queued: bool,
    /// Pause rmule's download once the downloader has held its slot
    /// `--pause-after-secs`, then share the whole file to draw an announce.
    #[arg(long)]
    pub(crate) pause: bool,
    /// Restart rmule with the download paused (needs `--pause`): the second
    /// leg reopens its store and offers the download after its Offer Check.
    #[arg(long, requires = "pause")]
    pub(crate) restart: bool,
    /// Restart rmule once the download has completed and `--linger-secs`
    /// passed, so the reopened node's first pass over the download directory
    /// rules the finished file (trusted, not hashed).
    #[arg(long, conflicts_with = "restart")]
    pub(crate) reopen_after_completion: bool,
    /// Leave out the `rmule-tools` stimuli (the pre-part slot ask, the
    /// straddling request, the ask during the Offer Check).
    #[arg(long)]
    pub(crate) no_stimuli: bool,
    /// The downloader's link goes out once rmule holds this many parts.
    #[arg(long, default_value_t = 1)]
    pub(crate) ask_after_verified: usize,
    /// Seconds from the downloader's slot to the pause.
    #[arg(long, default_value_t = 60)]
    pub(crate) pause_after_secs: u64,
    /// Seconds from the queued downloader's queueing to the next step: its
    /// reask comes `FILEREASKTIME` after its ask.
    #[arg(long, default_value_t = DEFAULT_REASK_WAIT_SECS)]
    pub(crate) reask_wait_secs: u64,
    /// Seconds the run serves on after the download completes.
    #[arg(long, default_value_t = 120)]
    pub(crate) linger_secs: u64,
    /// rmule's second leg, in seconds.
    #[arg(long, default_value_t = 600)]
    pub(crate) reopen_secs: u64,
    /// Per-step readiness budget in seconds.
    #[arg(long, default_value_t = 900)]
    pub(crate) timeout: u64,
}

#[derive(Debug, Serialize)]
struct ResolvedConfig {
    #[serde(rename = "scenario")]
    flow: &'static str,
    server_image: String,
    amule_image: String,
    downloader_image: String,
    amule_env: Vec<String>,
    capture_image: String,
    rmule_tools_image: String,
    container_runtime: String,
    file_size: u64,
    whole_size: u64,
    seeds: Vec<String>,
    seed_max_upload_kib: Vec<u32>,
    downloader_max_download_kib: u32,
    downloader_link_kbit: u32,
    dial_downloaders: bool,
    peer_concurrency: Option<usize>,
    rmule_on_ed2ksrv: bool,
    prober: bool,
    queued: bool,
    pause: bool,
    restart: bool,
    reopen_after_completion: bool,
    stimuli: bool,
    ask_after_verified: usize,
    pause_after_secs: u64,
    reask_wait_secs: u64,
    linger_secs: u64,
    reopen_secs: u64,
    timeout_secs: u64,
}

pub(crate) fn peer_partial_share(args: PeerPartialShareArgs) -> Result<()> {
    args.eserver.reject_zero_host_port()?;
    args.bench.prepare(&[
        args.eserver.build_context(),
        args.amule.build_context(),
        args.capture.build_context(),
    ])?;
    let seeds = if args.seeds.is_empty() {
        vec![SeedHolding::parse("0,3")?, SeedHolding::parse("complete")?]
    } else {
        args.seeds.clone()
    };
    let downloader_image = args
        .downloader_image
        .clone()
        .unwrap_or_else(|| args.amule.amule_image.clone());
    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &ResolvedConfig {
            flow: FLOW,
            server_image: args.eserver.server_image.clone(),
            amule_image: args.amule.amule_image.clone(),
            downloader_image: downloader_image.clone(),
            amule_env: args.amule.amule_env.clone(),
            capture_image: args.capture.capture_image.clone(),
            rmule_tools_image: args.rmule_tools_image.clone(),
            container_runtime: args.bench.container_runtime.clone(),
            file_size: args.file_size,
            whole_size: args.whole_size,
            seeds: seeds.iter().map(SeedHolding::spec).collect(),
            seed_max_upload_kib: args.seed_max_upload_kib.clone(),
            downloader_max_download_kib: args.downloader_max_download_kib,
            downloader_link_kbit: args.downloader_link_kbit,
            dial_downloaders: args.dial_downloaders,
            peer_concurrency: args.peer_concurrency,
            rmule_on_ed2ksrv: args.rmule_on_ed2ksrv,
            prober: !args.no_prober,
            queued: args.queued,
            pause: args.pause,
            restart: args.restart,
            reopen_after_completion: args.reopen_after_completion,
            stimuli: !args.no_stimuli,
            ask_after_verified: args.ask_after_verified,
            pause_after_secs: args.pause_after_secs,
            reask_wait_secs: args.reask_wait_secs,
            linger_secs: args.linger_secs,
            reopen_secs: args.reopen_secs,
            timeout_secs: args.timeout,
        },
    )?;
    println!("run_dir={}", run_dir.display());

    run_partial_share(PartialShareOptions {
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
        downloader_image: &downloader_image,
        capture_image: &args.capture.capture_image,
        capture_build_context: &args.capture.capture_build_context,
        rmule_tools_image: &args.rmule_tools_image,
        rmule_tools_dockerfile: &args.rmule_tools_dockerfile,
        rmule_tools_build_context: &args.rmule_tools_build_context,
        file_size: args.file_size,
        whole_size: args.whole_size,
        seeds: &seeds,
        seed_max_upload_kib: &args.seed_max_upload_kib,
        downloader_max_download_kib: args.downloader_max_download_kib,
        downloader_link_kbit: args.downloader_link_kbit,
        dial_downloaders: args.dial_downloaders,
        peer_concurrency: args.peer_concurrency,
        rmule_on_ed2ksrv: args
            .rmule_on_ed2ksrv
            .then_some((args.ed2ksrv_image.as_str(), args.ed2ksrv_config.as_path())),
        prober: !args.no_prober,
        queued: args.queued,
        pause: args.pause,
        restart: args.restart,
        reopen_after_completion: args.reopen_after_completion,
        straddle: !args.no_stimuli,
        ask_after_verified: args.ask_after_verified,
        pause_after_secs: args.pause_after_secs,
        reask_wait_secs: args.reask_wait_secs,
        linger_secs: args.linger_secs,
        reopen_secs: args.reopen_secs,
    })
}

/// `peer-partial-share-score`: score a finished or archived run dir from its
/// own tap and logs, without driving the flow again.
#[derive(Debug, Args)]
pub(crate) struct PeerPartialShareScoreArgs {
    /// The run dir to score (the one holding `partial-share/`).
    #[arg(long)]
    pub(crate) run_dir: PathBuf,
}

pub(crate) fn peer_partial_share_score(args: PeerPartialShareScoreArgs) -> Result<()> {
    let verdict = score_partial_share(&args.run_dir)?;
    println!("run_dir={}", args.run_dir.display());
    println!("verdict={verdict}");
    Ok(())
}
