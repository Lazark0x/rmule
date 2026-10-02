//! Subcommands for the peer family.
//!
//! Direct SUI and both peer-UDP reask legs. The reask subcommands carry the
//! long window these flows need (the counterparty's `FILEREASKTIME` clock is
//! ~21.4 minutes), which is why they stay CLI/sweep-only rather than joining
//! the `RMULE_BENCH` fast suite. The reverse serve flow rides the eD2k-server
//! family's args shape and lives there.

use std::path::PathBuf;

use crate::cli::bench::{
    AmuleArgs, BenchArgs, CaptureArgs, DEFAULT_FILE_SIZE, DEFAULT_RMULE_CLIENT_IMAGE,
    DEFAULT_TIMEOUT_SECS, EserverArgs, stage_synthetic,
};
use crate::cli::write_resolved_config;
use anyhow::{Result, bail};
use clap::Args;
use rmule_interop_harness::artifacts::Ed2kHashCommand;
use rmule_interop_harness::flow::{
    DEFAULT_REASK_WINDOW_SECS, DirectSuiOptions, PeerUdpReaskEmitOptions, PeerUdpReaskOptions,
    Sx1GateOptions, TwoHellosOptions, run_amule_direct_sui, run_peer_udp_reask,
    run_peer_udp_reask_emit, run_sx1_gate, run_two_hellos, stage_reask_emit_files,
};
use rmule_interop_harness::rmule::{RmuleClientContainer, RmuleServeContainer, RmuleToolsCommand};
use serde::Serialize;

pub(crate) const FLOW_AMULE_DIRECT_SUI: &str = "amule-direct-sui";

/// Shared file size for the reask legs: large, so a throttled slot-holder
/// cannot complete inside the reask window and the queued side stays queued.
const DEFAULT_REASK_FILE_SIZE: u64 = 40 * 1024 * 1024;

/// `amule-direct-sui`: one aMule in `direct-peer` mode, dialed from the host.
#[derive(Debug, Args)]
pub(crate) struct AmuleDirectSuiArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) amule: AmuleArgs,
    /// Deterministic synthetic file size in bytes (shared by the aMule peer).
    #[arg(long, default_value_t = DEFAULT_FILE_SIZE)]
    pub(crate) file_size: u64,
    /// Overall flow timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
    /// Host TCP port published to the aMule container's peer port.
    #[arg(long, default_value_t = 14662)]
    pub(crate) amule_host_port: u16,
    /// Log substring that marks the aMule container ready.
    #[arg(long, default_value = "rmule-amule-direct-peer-ready")]
    pub(crate) amule_ready_log_pattern: String,
    /// Obfuscate the rmule→aMule dial (ADR-0042): one of
    /// `supported`/`requested`/`required`. Auto-configures the aMule (crypt
    /// supported + a pinned User Hash) and dials rmule obfuscated toward it —
    /// `required` makes a completing SUI exchange the byte-compat proof.
    #[arg(long)]
    pub(crate) obfuscation: Option<String>,
    /// Test hook for the ED2K hash command.
    #[arg(long, hide = true)]
    pub(crate) ed2k_hash_command: Option<PathBuf>,
    /// Test hook for the rmule-tools command.
    #[arg(long, hide = true)]
    pub(crate) rmule_tools_command: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DirectSuiResolvedConfig {
    #[serde(rename = "scenario")]
    pub(crate) flow: &'static str,
    pub(crate) build_images: bool,
    pub(crate) skip_build: bool,
    pub(crate) amule_image: String,
    pub(crate) amule_build_context: PathBuf,
    pub(crate) keep_containers: bool,
    pub(crate) container_runtime: String,
    pub(crate) file_size: u64,
    pub(crate) timeout_secs: u64,
    pub(crate) amule_host_port: u16,
    pub(crate) amule_env: Vec<String>,
    pub(crate) amule_ready_log_pattern: String,
}

/// `peer-udp-reask`: the consume leg — rmule serves one slot, a queued aMule
/// should reask over UDP.
#[derive(Debug, Args)]
pub(crate) struct PeerUdpReaskArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) eserver: EserverArgs,
    #[command(flatten)]
    pub(crate) amule: AmuleArgs,
    #[command(flatten)]
    pub(crate) capture: CaptureArgs,
    /// Rust image used to run rmule-tools inside the interop Docker network.
    #[arg(long, default_value = DEFAULT_RMULE_CLIENT_IMAGE)]
    pub(crate) rmule_client_image: String,
    /// Shared file size in bytes. Large by default so the throttled slot-holder
    /// cannot complete inside the reask window and the reasker stays queued.
    #[arg(long, default_value_t = DEFAULT_REASK_FILE_SIZE)]
    pub(crate) file_size: u64,
    /// Per-container bring-up timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
    /// Seconds to sit past the queue, covering FILEREASKTIME (~1300 s) + margin.
    #[arg(long, default_value_t = DEFAULT_REASK_WINDOW_SECS)]
    pub(crate) reask_window_secs: u64,
    /// Arm the serving rmule's peer obfuscation policy (`ed2k serve start
    /// --peer-crypt`). Unset, the run is the plaintext one. Set to `supported`
    /// together with `--amule-env AMULE_CRYPT_REQUESTED=1`, this is the
    /// peer-UDP crypt capture: rmule's hello then claims
    /// `SupportsCryptLayer`, which is what aMule's
    /// `ShouldReceiveCryptUDPPackets()` gate reads before it obfuscates its own
    /// `OP_REASKFILEPING`.
    #[arg(long, value_parser = ["supported", "requested", "required"])]
    pub(crate) peer_crypt: Option<String>,
    /// Test hook for the ED2K hash command.
    #[arg(long, hide = true)]
    pub(crate) ed2k_hash_command: Option<PathBuf>,
}

/// `peer-udp-reask-emit`: the emit leg — a stock aMule serves one slot, a
/// queued rmule must reask over UDP.
#[derive(Debug, Args)]
pub(crate) struct PeerUdpReaskEmitArgs {
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
    /// Shared file size in bytes. Large by default so the slot-holder's throttled
    /// download from the sharer cannot complete inside the reask window and the
    /// sole upload slot stays occupied (rmule stays queued).
    #[arg(long, default_value_t = DEFAULT_REASK_FILE_SIZE)]
    pub(crate) file_size: u64,
    /// Per-container bring-up timeout in seconds. Must outlast a cold rmule-tools
    /// build in the download container (~5 min) plus the login/dial/queue before
    /// `download peer_queued` — pass ≥600.
    #[arg(long, default_value_t = 900)]
    pub(crate) timeout: u64,
    /// Seconds to sit past the queue, covering FILEREASKTIME (~1300 s) + margin.
    #[arg(long, default_value_t = DEFAULT_REASK_WINDOW_SECS)]
    pub(crate) reask_window_secs: u64,
    /// Stage a second file on the sharer and run two downloads in the one
    /// rmule core, both queued on the one stock aMule.
    #[arg(long, default_value_t = false)]
    pub(crate) two_downloads: bool,
    /// Give the sharer a source to name (ADR-0107's reask-attribution
    /// topology): each slot-holder first takes a complete part from a seeder
    /// that then stops. Needs the debug aMule image.
    #[arg(long, default_value_t = false)]
    pub(crate) known_sources: bool,
    /// Test hook for the ED2K hash command.
    #[arg(long, hide = true)]
    pub(crate) ed2k_hash_command: Option<PathBuf>,
}

pub(crate) fn amule_direct_sui(args: AmuleDirectSuiArgs) -> Result<()> {
    if args.amule_host_port == 0 {
        bail!("--amule-host-port must be non-zero; mapped-port discovery is not implemented");
    }
    args.bench.prepare(&[args.amule.build_context()])?;
    let (run_dir, layout) = args.bench.create_run()?;
    stage_synthetic(&layout, args.file_size, args.ed2k_hash_command.as_deref())?;
    let rmule_tools_command = args
        .rmule_tools_command
        .map(RmuleToolsCommand::new)
        .unwrap_or_else(RmuleToolsCommand::cargo_rmule_tools);
    // Obfuscation mode: the aMule accepts crypt, and rmule dials it
    // obfuscated after learning its runtime User Hash from a plaintext hello (the
    // aMule ignores a pinned amule.conf hash and generates its own). One flag
    // drives both sides so the flow is reproducible.
    let mut amule_env = args.amule.amule_env.clone();
    let obfuscation = args.obfuscation.clone();
    if obfuscation.is_some() {
        amule_env.push("AMULE_CRYPT_SUPPORTED=1".to_owned());
    }
    let config = DirectSuiResolvedConfig {
        flow: FLOW_AMULE_DIRECT_SUI,
        build_images: args.bench.build_images,
        skip_build: args.bench.skip_build,
        amule_image: args.amule.amule_image.clone(),
        amule_build_context: args.amule.amule_build_context.clone(),
        keep_containers: args.bench.keep_containers,
        container_runtime: args.bench.container_runtime.clone(),
        file_size: args.file_size,
        timeout_secs: args.timeout,
        amule_host_port: args.amule_host_port,
        amule_env: amule_env.clone(),
        amule_ready_log_pattern: args.amule_ready_log_pattern.clone(),
    };
    write_resolved_config(&run_dir, &config)?;
    println!("run_dir={}", run_dir.display());

    run_amule_direct_sui(DirectSuiOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        build_images: args.bench.build_images,
        amule_image: &args.amule.amule_image,
        amule_build_context: &args.amule.amule_build_context,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        amule_host_port: args.amule_host_port,
        amule_env: &amule_env,
        amule_ready_log_pattern: &args.amule_ready_log_pattern,
        rmule_tools_command: &rmule_tools_command,
        obfuscation,
    })
}

pub(crate) fn peer_udp_reask(args: PeerUdpReaskArgs) -> Result<()> {
    args.eserver.reject_zero_host_port()?;
    args.bench.prepare(&[
        args.eserver.build_context(),
        args.amule.build_context(),
        args.capture.build_context(),
    ])?;
    let (run_dir, layout) = args.bench.create_run()?;
    stage_synthetic(&layout, args.file_size, args.ed2k_hash_command.as_deref())?;
    let rmule_serve_container = RmuleServeContainer::cargo_rmule_tools(&args.rmule_client_image)?;
    println!("run_dir={}", run_dir.display());

    run_peer_udp_reask(PeerUdpReaskOptions {
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
        rmule_serve_container: &rmule_serve_container,
        reask_window_secs: args.reask_window_secs,
        peer_crypt: args.peer_crypt.as_deref(),
        amule_env: &args.amule.amule_env,
    })
}

pub(crate) fn peer_udp_reask_emit(args: PeerUdpReaskEmitArgs) -> Result<()> {
    args.eserver.reject_zero_host_port()?;
    args.bench.prepare(&[
        args.eserver.build_context(),
        args.amule.build_context(),
        args.capture.build_context(),
    ])?;
    let (run_dir, layout) = args.bench.create_run()?;
    let hash_command = args
        .ed2k_hash_command
        .as_deref()
        .map_or_else(Ed2kHashCommand::cargo_rmule_tools, Ed2kHashCommand::new);
    stage_reask_emit_files(&layout, args.file_size, &hash_command, args.two_downloads)?;
    let rmule_client_container = RmuleClientContainer::cargo_rmule_tools(&args.rmule_client_image)?;
    println!("run_dir={}", run_dir.display());

    run_peer_udp_reask_emit(PeerUdpReaskEmitOptions {
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
        reask_window_secs: args.reask_window_secs,
        amule_env: &args.amule.amule_env,
        two_downloads: args.two_downloads,
        known_sources: args.known_sources,
    })
}

/// `two-hellos`: two connections from one address say the same hello to a
/// High-ID aMule; does the second close the first?
#[derive(Debug, Args)]
pub(crate) struct TwoHellosArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) eserver: EserverArgs,
    #[command(flatten)]
    pub(crate) amule: AmuleArgs,
    /// An image carrying `python3`, which runs the probe.
    #[arg(long, default_value = crate::cli::nat::DEFAULT_NATPROBE_IMAGE)]
    pub(crate) probe_image: String,
    /// Per-step readiness budget in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
    /// Log substring that marks the aMule container ready.
    #[arg(long, default_value = "rmule-amule-ready")]
    pub(crate) amule_ready_log_pattern: String,
}

#[derive(Debug, Serialize)]
struct TwoHellosResolvedConfig {
    #[serde(rename = "scenario")]
    flow: &'static str,
    server_image: String,
    amule_image: String,
    amule_env: Vec<String>,
    probe_image: String,
    container_runtime: String,
    timeout_secs: u64,
}

pub(crate) fn two_hellos(args: TwoHellosArgs) -> Result<()> {
    args.bench
        .prepare(&[args.eserver.build_context(), args.amule.build_context()])?;
    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &TwoHellosResolvedConfig {
            flow: "two-hellos",
            server_image: args.eserver.server_image.clone(),
            amule_image: args.amule.amule_image.clone(),
            amule_env: args.amule.amule_env.clone(),
            probe_image: args.probe_image.clone(),
            container_runtime: args.bench.container_runtime.clone(),
            timeout_secs: args.timeout,
        },
    )?;
    println!("run_dir={}", run_dir.display());
    run_two_hellos(TwoHellosOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        server_image: &args.eserver.server_image,
        server_env: &args.eserver.server_env,
        amule_image: &args.amule.amule_image,
        amule_env: &args.amule.amule_env,
        amule_ready_log_pattern: &args.amule_ready_log_pattern,
        probe_image: &args.probe_image,
    })
}

/// `sx1-gate`: fake sources stating SX1 version 1 and 3; rmule must ask only
/// the second. Fake-backed.
#[derive(Debug, Args)]
pub(crate) struct Sx1GateArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) eserver: EserverArgs,
    /// The `rmule-tools` image (build it from the tip under test).
    #[arg(long, default_value = crate::cli::nat::DEFAULT_RMULE_TOOLS_IMAGE)]
    pub(crate) rmule_tools_image: String,
    /// An image carrying `python3`, which runs the fake.
    #[arg(long, default_value = crate::cli::nat::DEFAULT_NATPROBE_IMAGE)]
    pub(crate) probe_image: String,
    /// Per-step readiness budget in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
}

#[derive(Debug, Serialize)]
struct Sx1GateResolvedConfig {
    #[serde(rename = "scenario")]
    flow: &'static str,
    server_image: String,
    rmule_tools_image: String,
    probe_image: String,
    container_runtime: String,
    timeout_secs: u64,
}

pub(crate) fn sx1_gate(args: Sx1GateArgs) -> Result<()> {
    args.bench.prepare(&[args.eserver.build_context()])?;
    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &Sx1GateResolvedConfig {
            flow: "sx1-gate",
            server_image: args.eserver.server_image.clone(),
            rmule_tools_image: args.rmule_tools_image.clone(),
            probe_image: args.probe_image.clone(),
            container_runtime: args.bench.container_runtime.clone(),
            timeout_secs: args.timeout,
        },
    )?;
    println!("run_dir={}", run_dir.display());
    run_sx1_gate(Sx1GateOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        server_image: &args.eserver.server_image,
        server_env: &args.eserver.server_env,
        rmule_tools_image: &args.rmule_tools_image,
        probe_image: &args.probe_image,
    })
}
