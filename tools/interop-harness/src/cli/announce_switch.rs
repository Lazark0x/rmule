//! The `announce-switch` subcommand: the offer-set probe against Lugdunum
//! and ed2k-server, every party inside the bench network.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use rmule_interop_harness::flow::{AnnounceSwitchOptions, run_announce_switch};
use serde::Serialize;

use crate::cli::bench::{BenchArgs, CaptureArgs, DEFAULT_TIMEOUT_SECS, EserverArgs};
use crate::cli::nat::{
    DEFAULT_ED2KSRV_CONFIG, DEFAULT_ED2KSRV_IMAGE, DEFAULT_NATPROBE_IMAGE,
    DEFAULT_RMULE_TOOLS_IMAGE,
};
use crate::cli::write_resolved_config;

pub(crate) const FLOW_ANNOUNCE_SWITCH: &str = "announce-switch";

/// `announce-switch`: what each server does with a client's offered files
/// when it offers again, offers nothing, and hangs up.
#[derive(Debug, Args)]
pub(crate) struct AnnounceSwitchArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) eserver: EserverArgs,
    /// The ed2k-server image (refused unless its commit label matches the pin).
    #[arg(long, default_value = DEFAULT_ED2KSRV_IMAGE)]
    pub(crate) ed2ksrv_image: String,
    /// The ed2k-server bench config; its `this_ip` is rendered per run.
    #[arg(long, default_value = DEFAULT_ED2KSRV_CONFIG)]
    pub(crate) ed2ksrv_config: PathBuf,
    /// An image carrying `python3`, which runs the probe.
    #[arg(long, default_value = DEFAULT_NATPROBE_IMAGE)]
    pub(crate) probe_image: String,
    /// Skip the offer probes (their result stands); run rmule's legs only.
    #[arg(long, default_value_t = false, requires = "rmule_legs")]
    pub(crate) skip_probes: bool,
    /// Also run the markers probe against each server: one whole file and
    /// one part-file offered the way aMule marks them, and the ID, port and
    /// counters each result row carries for either.
    #[arg(long, default_value_t = false)]
    pub(crate) markers: bool,
    /// After the probes, run rmule's own legs against both servers: two files
    /// on Lugdunum, a third added, a switch to ed2k-server; then the same
    /// withholding from a server that grants related search.
    #[arg(long, default_value_t = false)]
    pub(crate) rmule_legs: bool,
    /// The `rmule-tools` image rmule's legs run (build it from the tip under
    /// test).
    #[arg(long, default_value = DEFAULT_RMULE_TOOLS_IMAGE)]
    pub(crate) rmule_tools_image: String,
    #[command(flatten)]
    pub(crate) capture: CaptureArgs,
    /// Per-step readiness budget in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
}

#[derive(Debug, Serialize)]
struct AnnounceSwitchResolvedConfig {
    #[serde(rename = "scenario")]
    flow: &'static str,
    server_image: String,
    ed2ksrv_image: String,
    ed2ksrv_config: PathBuf,
    probe_image: String,
    probes: bool,
    markers: bool,
    rmule_tools_image: Option<String>,
    capture_image: String,
    container_runtime: String,
    timeout_secs: u64,
}

pub(crate) fn announce_switch(args: AnnounceSwitchArgs) -> Result<()> {
    args.bench
        .prepare(&[args.eserver.build_context(), args.capture.build_context()])?;
    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &AnnounceSwitchResolvedConfig {
            flow: FLOW_ANNOUNCE_SWITCH,
            server_image: args.eserver.server_image.clone(),
            ed2ksrv_image: args.ed2ksrv_image.clone(),
            ed2ksrv_config: args.ed2ksrv_config.clone(),
            probe_image: args.probe_image.clone(),
            probes: !args.skip_probes,
            markers: args.markers,
            rmule_tools_image: args.rmule_legs.then(|| args.rmule_tools_image.clone()),
            capture_image: args.capture.capture_image.clone(),
            container_runtime: args.bench.container_runtime.clone(),
            timeout_secs: args.timeout,
        },
    )?;
    println!("run_dir={}", run_dir.display());
    run_announce_switch(AnnounceSwitchOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        server_image: &args.eserver.server_image,
        server_env: &args.eserver.server_env,
        ed2ksrv_image: &args.ed2ksrv_image,
        ed2ksrv_config: &args.ed2ksrv_config,
        probe_image: &args.probe_image,
        probes: !args.skip_probes,
        markers: args.markers,
        rmule_tools_image: args.rmule_legs.then_some(args.rmule_tools_image.as_str()),
        capture_image: &args.capture.capture_image,
    })
}
