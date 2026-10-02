//! The `packed-source-exchange` subcommand (flow I).
//!
//! Carries the registrant count, the large-file size that keeps the downloading
//! aMule a partfile at dial time, and the source-exchange nibble the capture dial
//! asks with — the three knobs the packed answer's geometry depends on.

use std::path::PathBuf;

use crate::cli::bench::{
    AmuleArgs, BenchArgs, DEFAULT_RMULE_CLIENT_IMAGE, EserverArgs, stage_synthetic,
};
use anyhow::Result;
use clap::Args;
use rmule_interop_harness::flow::{PackedSourceExchangeOptions, run_packed_source_exchange};
use rmule_interop_harness::rmule::RmuleClientContainer;

/// `packed-source-exchange`: N registrants, one downloading aMule, one capture dial.
#[derive(Debug, Args)]
pub(crate) struct PackedSourceExchangeArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) eserver: EserverArgs,
    #[command(flatten)]
    pub(crate) amule: AmuleArgs,
    /// Rust image running the rmule-tools registrant + capture containers.
    #[arg(long, default_value = DEFAULT_RMULE_CLIENT_IMAGE)]
    pub(crate) rmule_client_image: String,
    /// Deterministic synthetic file size in bytes. Sized so the downloading
    /// aMule cannot finish inside the capture window: aMule's `MaxDownload`
    /// throttle is a lagging feedback controller, so its opening burst runs at
    /// LAN speed and a small file completes in seconds — and a *completed*
    /// file has no source list left to answer with. 200 MiB (≈22 ED2K parts)
    /// leaves the aMule a partfile holding every established source.
    #[arg(long, default_value_t = 200 * 1024 * 1024)]
    pub(crate) file_size: u64,
    /// Per-step readiness timeout in seconds. Must outlast a cold rmule-tools
    /// build in the registrant container (~5 min) — pass ≥600.
    #[arg(long, default_value_t = 900)]
    pub(crate) timeout: u64,
    /// How many fabricated source identities to register (≥12 crosses aMule's
    /// 354-byte pack threshold at the v4 row geometry).
    #[arg(long, default_value_t = 15)]
    pub(crate) registrant_count: u16,
    /// Source-exchange nibble rmule advertises on the capture dial (`3` = v3, the
    /// geometry aMule's own advert reconciles with; `0` leaves honest v1).
    #[arg(long, default_value_t = 3)]
    pub(crate) sx_nibble: u8,
    /// Seconds the capture dial holds the connection to receive the answer.
    #[arg(long, default_value_t = 45)]
    pub(crate) capture_window: u64,
    /// Test hook for the ED2K hash command.
    #[arg(long, hide = true)]
    pub(crate) ed2k_hash_command: Option<PathBuf>,
}

pub(crate) fn packed_source_exchange(args: PackedSourceExchangeArgs) -> Result<()> {
    args.eserver.reject_zero_host_port()?;
    args.bench
        .prepare(&[args.eserver.build_context(), args.amule.build_context()])?;
    let (run_dir, layout) = args.bench.create_run()?;
    stage_synthetic(&layout, args.file_size, args.ed2k_hash_command.as_deref())?;
    let rmule_client_container = RmuleClientContainer::cargo_rmule_tools(&args.rmule_client_image)?;
    println!("run_dir={}", run_dir.display());

    run_packed_source_exchange(PackedSourceExchangeOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        build_images: args.bench.build_images,
        server_image: &args.eserver.server_image,
        amule_image: &args.amule.amule_image,
        server_build_context: &args.eserver.server_build_context,
        amule_build_context: &args.amule.amule_build_context,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        server_host_port: args.eserver.server_host_port,
        server_env: &args.eserver.server_env,
        amule_env: &args.amule.amule_env,
        rmule_client_container: &rmule_client_container,
        registrant_count: args.registrant_count,
        sx_nibble: args.sx_nibble,
        capture_window_secs: args.capture_window,
    })
}
