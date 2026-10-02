//! The `ask-budget` subcommand: sixteen downloads in one rmule core put
//! fifteen source asks on Lugdunum at once and the sixteenth about 300 s
//! later.

use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

use rmule_interop_harness::flow::{AskBudgetOptions, rescore_ask_budget, run_ask_budget};
use serde::Serialize;

use crate::cli::bench::{BenchArgs, CaptureArgs, DEFAULT_TIMEOUT_SECS, EserverArgs};
use crate::cli::nat::{DEFAULT_NATPROBE_IMAGE, DEFAULT_RMULE_TOOLS_IMAGE};
use crate::cli::write_resolved_config;

/// `ask-budget`: one rmule core, sixteen downloads, a tap on Lugdunum.
#[derive(Debug, Args)]
pub(crate) struct AskBudgetArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) eserver: EserverArgs,
    #[command(flatten)]
    pub(crate) capture: CaptureArgs,
    /// The `rmule-tools` image (build it from the tip under test).
    #[arg(long, default_value = DEFAULT_RMULE_TOOLS_IMAGE)]
    pub(crate) rmule_tools_image: String,
    /// An image carrying `python3`, which runs the fake sharer.
    #[arg(long, default_value = DEFAULT_NATPROBE_IMAGE)]
    pub(crate) probe_image: String,
    /// Per-step readiness budget in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
    /// Score this retained run dir's tap again instead of driving the flow.
    #[arg(long)]
    pub(crate) rescore: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct AskBudgetResolvedConfig {
    #[serde(rename = "scenario")]
    flow: &'static str,
    server_image: String,
    rmule_tools_image: String,
    probe_image: String,
    capture_image: String,
    container_runtime: String,
    timeout_secs: u64,
}

pub(crate) fn ask_budget(args: AskBudgetArgs) -> Result<()> {
    if let Some(run_dir) = &args.rescore {
        return rescore_ask_budget(run_dir);
    }
    args.bench
        .prepare(&[args.eserver.build_context(), args.capture.build_context()])?;
    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &AskBudgetResolvedConfig {
            flow: "ask-budget",
            server_image: args.eserver.server_image.clone(),
            rmule_tools_image: args.rmule_tools_image.clone(),
            probe_image: args.probe_image.clone(),
            capture_image: args.capture.capture_image.clone(),
            container_runtime: args.bench.container_runtime.clone(),
            timeout_secs: args.timeout,
        },
    )?;
    println!("run_dir={}", run_dir.display());
    run_ask_budget(AskBudgetOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        server_image: &args.eserver.server_image,
        server_env: &args.eserver.server_env,
        rmule_tools_image: &args.rmule_tools_image,
        probe_image: &args.probe_image,
        capture_image: &args.capture.capture_image,
    })
}
