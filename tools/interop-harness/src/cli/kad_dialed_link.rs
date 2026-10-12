//! The `kad-dialed-link` subcommand (flow S): its arguments and staging.

use anyhow::Result;
use clap::Args;
use rmule_interop_harness::flow::{KadDialedLinkOptions, run_kad_dialed_link};

use crate::cli::bench::{BenchArgs, DEFAULT_TIMEOUT_SECS, KadBenchArgs};
use crate::cli::write_resolved_config;

const FLOW_KAD_DIALED_LINK: &str = "kad-dialed-link";

/// 64 MiB: at the ~300 KB/s a stock helper serves one client on this bench, the
/// download is still running when the window ends.
const DEFAULT_FILE_SIZE: u64 = 67_108_864;

/// How long rmule's TCP verdict may take to read Open once the Core is up.
const DEFAULT_WINDOW_SECS: u64 = 180;

/// `kad-dialed-link` (flow S).
#[derive(Debug, Args)]
pub(crate) struct KadDialedLinkArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) kad: KadBenchArgs,
    /// The image whose entrypoint is `rmule-tools`; the Core runs in it.
    #[arg(long, default_value = crate::cli::nat::DEFAULT_RMULE_TOOLS_IMAGE)]
    pub(crate) rmule_tools_image: String,
    /// Per-step readiness timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
    /// The shared file's size in bytes.
    #[arg(long, default_value_t = DEFAULT_FILE_SIZE)]
    pub(crate) file_size: u64,
    /// Seconds rmule's TCP verdict may take to read Open.
    #[arg(long, default_value_t = DEFAULT_WINDOW_SECS)]
    pub(crate) window: u64,
}

pub(crate) fn kad_dialed_link(args: KadDialedLinkArgs) -> Result<()> {
    args.bench.prepare(&args.kad.build_contexts())?;
    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &args.kad.resolved_config(
            FLOW_KAD_DIALED_LINK,
            &args.bench,
            args.file_size,
            args.timeout,
            0,
        ),
    )?;
    println!("run_dir={}", run_dir.display());
    run_kad_dialed_link(KadDialedLinkOptions {
        base: args
            .kad
            .capture_options(&args.bench, &layout, args.timeout, 0),
        rmule_tools_image: &args.rmule_tools_image,
        file_size: args.file_size,
        window_secs: args.window,
    })
}
