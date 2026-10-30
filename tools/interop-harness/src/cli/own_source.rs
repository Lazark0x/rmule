//! The `own-source` subcommand: a server's answer names rmule for a file it
//! shares and downloads, and rmule does not dial itself.

use anyhow::Result;
use clap::Args;

use rmule_interop_harness::flow::{OwnSourceOptions, run_own_source};
use serde::Serialize;

use crate::cli::bench::{BenchArgs, CaptureArgs, DEFAULT_TIMEOUT_SECS, EserverArgs};
use crate::cli::nat::DEFAULT_RMULE_TOOLS_IMAGE;
use crate::cli::write_resolved_config;

/// `own-source`: one rmule core sharing and downloading one file on Lugdunum.
#[derive(Debug, Args)]
pub(crate) struct OwnSourceArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) eserver: EserverArgs,
    #[command(flatten)]
    pub(crate) capture: CaptureArgs,
    /// The `rmule-tools` image (build it from the tip under test).
    #[arg(long, default_value = DEFAULT_RMULE_TOOLS_IMAGE)]
    pub(crate) rmule_tools_image: String,
    /// Per-step readiness budget in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
}

#[derive(Debug, Serialize)]
struct OwnSourceResolvedConfig {
    #[serde(rename = "scenario")]
    flow: &'static str,
    server_image: String,
    rmule_tools_image: String,
    capture_image: String,
    container_runtime: String,
    timeout_secs: u64,
}

pub(crate) fn own_source(args: OwnSourceArgs) -> Result<()> {
    args.bench
        .prepare(&[args.eserver.build_context(), args.capture.build_context()])?;
    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &OwnSourceResolvedConfig {
            flow: "own-source",
            server_image: args.eserver.server_image.clone(),
            rmule_tools_image: args.rmule_tools_image.clone(),
            capture_image: args.capture.capture_image.clone(),
            container_runtime: args.bench.container_runtime.clone(),
            timeout_secs: args.timeout,
        },
    )?;
    println!("run_dir={}", run_dir.display());
    run_own_source(OwnSourceOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        server_image: &args.eserver.server_image,
        server_env: &args.eserver.server_env,
        rmule_tools_image: &args.rmule_tools_image,
        capture_image: &args.capture.capture_image,
    })
}
