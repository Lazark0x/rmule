//! Subcommands for the Kad-network family.
//!
//! The inverted keyword store, the mesh join, and the stock-aMule connectivity
//! smoke — the flows whose subject is rmule's standing in a Kad swarm rather than
//! one captured opcode.

use std::path::PathBuf;

use crate::cli::bench::{
    AmuleArgs, BenchArgs, DEFAULT_FILE_SIZE, DEFAULT_KAD_UDP_PORT_BASE, DEFAULT_TIMEOUT_SECS,
    KadBenchArgs, RmuleNodeArgs, stage_synthetic,
};
use crate::cli::kad_capture::KadSourceLookupCaptureArgs;
use crate::cli::write_resolved_config;
use anyhow::Result;
use clap::Args;
use rmule_interop_harness::flow::{
    KadInvertedKeywordOptions, KadJoinOptions, KadSmokeOptions, run_kad_inverted_keyword,
    run_kad_join, run_kad_smoke,
};
use serde::Serialize;

pub(crate) const FLOW_KAD_JOIN: &str = "kad-join";
pub(crate) const FLOW_KAD_SMOKE: &str = "kad-smoke";
pub(crate) const FLOW_KAD_INVERTED_KEYWORD: &str = "kad-inverted-keyword";

/// How long the joined mesh runs before the join verdict is read: passive
/// observation of the hub's own maintenance traffic toward rmule.
pub(crate) const DEFAULT_KAD_JOIN_WINDOW_SECS: u64 = 90;

/// The keyword aMule shares (as `<keyword>.dat`) and searches for; rmule's KadID
/// is pinned to its target. Long/unique so it never collides, all-lowercase ASCII
/// so the fold is unambiguous.
pub(crate) const DEFAULT_KAD_INVERTED_KEYWORD: &str = "rmulekadkeyword";
/// A second word appended to one search so aMule emits a restrictive tree (recipe
/// 4's tree-decode vector).
pub(crate) const DEFAULT_KAD_INVERTED_FILTER_WORD: &str = "parityprobe";
/// Two stock aMule helpers give the publisher ≥ 2 TCP connect-backs so it earns
/// TCP-open and runs its autonomous keyword publisher (recipe 2's gate).
pub(crate) const DEFAULT_KAD_INVERTED_HELPERS: usize = 2;
/// The storer window must cover swarm boot + Kad-connect + publish-wait + search
/// landing; the search walk alone can run ~45 s (ADR-0062 requester lifetime).
pub(crate) const DEFAULT_KAD_INVERTED_WINDOW_SECS: u64 = 360;
pub(crate) const DEFAULT_KAD_INVERTED_CONNECT_DEADLINE_SECS: u64 = 150;

/// The stock-aMule cold-boot → "Kad: Connected" window on the fake-public swarm
/// is ~3–6 min; the budget sits past it so a non-connect is a
/// finding, not an impatient harness.
pub(crate) const DEFAULT_KAD_SMOKE_CONNECT_DEADLINE_SECS: u64 = 360;

/// `kad-inverted-keyword`: a stock aMule publishes and searches toward rmule's
/// keyword store.
#[derive(Debug, Args)]
pub(crate) struct KadInvertedKeywordArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) kad: KadBenchArgs,
    #[command(flatten)]
    pub(crate) node: RmuleNodeArgs,
    /// Deterministic synthetic file size in bytes (the shared file aMule serves).
    #[arg(long, default_value_t = DEFAULT_FILE_SIZE)]
    pub(crate) file_size: u64,
    /// The keyword aMule shares (as `<keyword>.dat`) and searches for; rmule's
    /// KadID is pinned to its target.
    #[arg(long, default_value = DEFAULT_KAD_INVERTED_KEYWORD)]
    pub(crate) keyword: String,
    /// A second word for the restrictive-tree search (recipe 4 tree vector).
    #[arg(long, default_value = DEFAULT_KAD_INVERTED_FILTER_WORD)]
    pub(crate) filter_word: String,
    /// Stock aMule helper nodes so the publisher earns TCP-open (recipe 2 gate).
    #[arg(long, default_value_t = DEFAULT_KAD_INVERTED_HELPERS)]
    pub(crate) helpers: usize,
    /// Per-step readiness timeout in seconds (a node's Kad-started log).
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
    /// Seconds the rmule storer serves (boot + connect + publish + search).
    #[arg(long, default_value_t = DEFAULT_KAD_INVERTED_WINDOW_SECS)]
    pub(crate) storer_window: u64,
    /// Budget for the aMule publisher to reach "Kad: Connected".
    #[arg(long, default_value_t = DEFAULT_KAD_INVERTED_CONNECT_DEADLINE_SECS)]
    pub(crate) connect_deadline: u64,
    /// Test hook for the ED2K hash command.
    #[arg(long, hide = true)]
    pub(crate) ed2k_hash_command: Option<PathBuf>,
}

/// `kad-smoke`: two stock aMules on the fake-public swarm, no capture.
#[derive(Debug, Args)]
pub(crate) struct KadSmokeArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) amule: AmuleArgs,
    /// Per-step readiness timeout in seconds (a node's Kad-started log).
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
    /// Budget in seconds for a node to reach "Kad: Connected".
    #[arg(long, default_value_t = DEFAULT_KAD_SMOKE_CONNECT_DEADLINE_SECS)]
    pub(crate) connect_deadline: u64,
    /// Base UDP port the Kad nodes listen on.
    #[arg(long, default_value_t = DEFAULT_KAD_UDP_PORT_BASE)]
    pub(crate) kad_udp_port_base: u16,
}

#[derive(Debug, Serialize)]
pub(crate) struct KadSmokeResolvedConfig {
    #[serde(rename = "scenario")]
    pub(crate) flow: &'static str,
    pub(crate) build_images: bool,
    pub(crate) skip_build: bool,
    pub(crate) amule_image: String,
    pub(crate) amule_build_context: PathBuf,
    pub(crate) keep_containers: bool,
    pub(crate) container_runtime: String,
    pub(crate) timeout_secs: u64,
    pub(crate) connect_deadline_secs: u64,
    pub(crate) amule_env: Vec<String>,
    pub(crate) kad_udp_port_base: u16,
}

/// `kad-join`: the private mesh's hub plus rmule as the join node.
#[derive(Debug, Args)]
pub(crate) struct KadJoinArgs {
    #[command(flatten)]
    pub(crate) base: KadSourceLookupCaptureArgs,
    #[command(flatten)]
    pub(crate) node: RmuleNodeArgs,
    /// Seconds the joined mesh runs before the verdict is read.
    #[arg(long, default_value_t = DEFAULT_KAD_JOIN_WINDOW_SECS)]
    pub(crate) join_window: u64,
}

pub(crate) fn kad_inverted_keyword(args: KadInvertedKeywordArgs) -> Result<()> {
    args.bench.prepare(&args.kad.build_contexts())?;
    args.node.validate()?;
    let (run_dir, layout) = args.bench.create_run()?;
    // The shared file the aMule publisher serves (staged as `<keyword>.dat`).
    stage_synthetic(&layout, args.file_size, args.ed2k_hash_command.as_deref())?;
    let helpers = u32::try_from(args.helpers).unwrap_or(u32::MAX);
    write_resolved_config(
        &run_dir,
        &args.kad.resolved_config(
            FLOW_KAD_INVERTED_KEYWORD,
            &args.bench,
            args.file_size,
            args.timeout,
            helpers,
        ),
    )?;
    println!("run_dir={}", run_dir.display());

    run_kad_inverted_keyword(KadInvertedKeywordOptions {
        base: args
            .kad
            .capture_options(&args.bench, &layout, args.timeout, helpers),
        rmule_image: &args.node.rmule_image,
        rmule_dockerfile: &args.node.rmule_dockerfile,
        rmule_build_context: &args.node.rmule_build_context,
        keyword: &args.keyword,
        filter_word: &args.filter_word,
        helper_count: args.helpers,
        storer_window_secs: args.storer_window,
        kad_connect_deadline_secs: args.connect_deadline,
    })
}

pub(crate) fn kad_smoke(args: KadSmokeArgs) -> Result<()> {
    args.bench.prepare(&[args.amule.build_context()])?;
    let (run_dir, layout) = args.bench.create_run()?;
    let config = KadSmokeResolvedConfig {
        flow: FLOW_KAD_SMOKE,
        build_images: args.bench.build_images,
        skip_build: args.bench.skip_build,
        amule_image: args.amule.amule_image.clone(),
        amule_build_context: args.amule.amule_build_context.clone(),
        keep_containers: args.bench.keep_containers,
        container_runtime: args.bench.container_runtime.clone(),
        timeout_secs: args.timeout,
        connect_deadline_secs: args.connect_deadline,
        amule_env: args.amule.amule_env.clone(),
        kad_udp_port_base: args.kad_udp_port_base,
    };
    write_resolved_config(&run_dir, &config)?;
    println!("run_dir={}", run_dir.display());

    run_kad_smoke(KadSmokeOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        build_images: args.bench.build_images,
        amule_image: &args.amule.amule_image,
        amule_build_context: &args.amule.amule_build_context,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        connect_deadline_secs: args.connect_deadline,
        amule_env: &args.amule.amule_env,
        kad_udp_port_base: args.kad_udp_port_base,
    })
}

/// No synthetic file: this flow proves routability, not source lookup.
pub(crate) fn kad_join(args: KadJoinArgs) -> Result<()> {
    let base = &args.base;
    args.node.validate()?;
    let (run_dir, layout) = base.prepare()?;
    write_resolved_config(&run_dir, &base.resolved_config(FLOW_KAD_JOIN, 0, 0))?;
    println!("run_dir={}", run_dir.display());

    run_kad_join(KadJoinOptions {
        base: base.capture_options(&layout, 0),
        rmule_image: &args.node.rmule_image,
        rmule_dockerfile: &args.node.rmule_dockerfile,
        rmule_build_context: &args.node.rmule_build_context,
        join_window_secs: args.join_window,
    })
}
