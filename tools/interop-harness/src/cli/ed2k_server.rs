//! Subcommands for the eD2k-server family.
//!
//! The shared `AmuleServesRmuleDownloadsArgs` shape — eserver, aMule, host
//! port, timeout, env passthrough — drives every skeleton leg plus the
//! server-cycle and wire-smoke flows; each skeleton handler differs only in the
//! `RmuleClientAction` it selects and the posture it drives it with.

use std::path::PathBuf;

use crate::cli::bench::{
    AmuleArgs, BenchArgs, CaptureArgs, DEFAULT_FILE_SIZE, DEFAULT_RMULE_CLIENT_IMAGE,
    DEFAULT_TIMEOUT_SECS, EserverArgs, stage_synthetic,
};
use crate::cli::nat::{
    DEFAULT_ED2KSRV_BUILD_CONTEXT, DEFAULT_ED2KSRV_CONFIG, DEFAULT_ED2KSRV_IMAGE,
};
use crate::cli::write_resolved_config;
use anyhow::Result;
use clap::Args;
use rmule_interop_harness::artifacts::RunLayout;
use rmule_interop_harness::flow::{
    BenchSmokeOptions, CryptPingPortOptions, DEFAULT_HELLO_DELAY_MS, LatePortTestOptions,
    RmuleClientAction, SearchSpacingOptions, SearchWireOptions, SearchWireServer,
    ServerCycleOptions, ServerLoginCryptOptions, ServerSkeletonOptions, run_bench_smoke,
    run_crypt_ping_port, run_late_port_test, run_rmule_serves_amule_downloads, run_search_spacing,
    run_search_wire, run_server_cycle, run_server_login_crypt, run_server_skeleton,
};
use rmule_interop_harness::rmule::{RmuleClientContainer, RmuleServeContainer, RmuleToolsCommand};
use serde::Serialize;

pub(crate) const FLOW_BENCH_SMOKE: &str = "bench-smoke";
pub(crate) const FLOW_SERVER_CYCLE: &str = "server-cycle";
pub(crate) const FLOW_AMULE_SERVES_RMULE_DOWNLOADS: &str = "amule-serves-rmule-downloads";
pub(crate) const FLOW_AMULE_SERVES_RMULE_SEARCHES: &str = "amule-serves-rmule-searches";
pub(crate) const FLOW_AMULE_LOW_ID_CALLBACK: &str = "amule-low-id-callback";
pub(crate) const FLOW_RMULE_SERVES_AMULE_DOWNLOADS: &str = "rmule-serves-amule-downloads";
pub(crate) const FLOW_SEARCH_WIRE: &str = "search-wire";
pub(crate) const FLOW_SEARCH_SPACING: &str = "search-spacing";

/// `bench-smoke`: the eserver alone, probed from an in-network rmule.
#[derive(Debug, Args)]
pub(crate) struct BenchSmokeArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) eserver: EserverArgs,
    /// Rust image used to run the rmule probe inside the interop network.
    #[arg(long, default_value = DEFAULT_RMULE_CLIENT_IMAGE)]
    pub(crate) rmule_client_image: String,
    /// Overall flow timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
    /// Ride `CT_EMULE_UDPPORTS` (`0xF9`, ADR-0091) on the probe's login, naming
    /// this client-UDP port: asks the server body whether it still accepts the
    /// login a running core sends.
    #[arg(long)]
    pub(crate) udp_ports_advert: Option<u16>,
    /// Ride `CT_MOD_IP_V6` (`0xAE`) with its `SRVCAP_IPV6` bit on the
    /// probe's login, naming this address. Beside `--udp-ports-advert` the
    /// login carries six tags, the shape a dual-stack core sends.
    #[arg(long)]
    pub(crate) advertise_ipv6: Option<std::net::Ipv6Addr>,
}

#[derive(Debug, Serialize)]
pub(crate) struct BenchSmokeResolvedConfig {
    #[serde(rename = "scenario")]
    pub(crate) flow: &'static str,
    pub(crate) build_images: bool,
    pub(crate) skip_build: bool,
    pub(crate) server_image: String,
    pub(crate) rmule_client_image: String,
    pub(crate) server_build_context: PathBuf,
    pub(crate) keep_containers: bool,
    pub(crate) container_runtime: String,
    pub(crate) timeout_secs: u64,
    pub(crate) server_host_port: u16,
    pub(crate) server_env: Vec<String>,
    pub(crate) udp_ports_advert: Option<u16>,
    pub(crate) advertise_ipv6: Option<std::net::Ipv6Addr>,
}

/// The eserver + one aMule shape every skeleton leg, the server cycle, the
/// reverse download and the golden-authoring flow share.
#[derive(Debug, Args)]
pub(crate) struct AmuleServesRmuleDownloadsArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) eserver: EserverArgs,
    #[command(flatten)]
    pub(crate) amule: AmuleArgs,
    /// Rust image used to run rmule-tools inside the interop Docker network.
    #[arg(long, default_value = DEFAULT_RMULE_CLIENT_IMAGE)]
    pub(crate) rmule_client_image: String,
    /// Deterministic synthetic file size in bytes.
    #[arg(long, default_value_t = DEFAULT_FILE_SIZE)]
    pub(crate) file_size: u64,
    /// Overall flow timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
    /// Log substring that marks the aMule container ready.
    #[arg(long, default_value = "rmule-amule-ready")]
    pub(crate) amule_ready_log_pattern: String,
    /// Arm the serving rmule's obfuscation policy (`ed2k serve start
    /// --peer-crypt`); read only by `rmule-serves-amule-downloads`. With
    /// `required` that flow also demands the login landed a High ID — the
    /// eserver's plain port test admitted as a Test Connection (ADR-0046).
    #[arg(long, value_parser = ["supported", "requested", "required"])]
    pub(crate) peer_crypt: Option<String>,
    /// Change the serving rmule's obfuscation policy mid-run, as
    /// `<secs>:<off|supported|requested|required>`; repeat for several (`ed2k
    /// serve start --peer-crypt-flip`). Read only by
    /// `rmule-serves-amule-downloads`, whose net then takes a fake-public
    /// subnet so the server crypt-ping's public-IP gate can open. The flips
    /// rmule marked are printed as `obfuscation_flips`.
    #[arg(long, value_parser = rmule_interop_harness::rmule::crypt_flip_arg)]
    pub(crate) peer_crypt_flip: Vec<String>,
    /// Test hook for the ED2K hash command.
    #[arg(long, hide = true)]
    pub(crate) ed2k_hash_command: Option<PathBuf>,
    /// Test hook for the rmule-tools command.
    #[arg(long, hide = true)]
    pub(crate) rmule_tools_command: Option<PathBuf>,
}

impl AmuleServesRmuleDownloadsArgs {
    /// Validate, allocate the run dir, stage the synthetic file and write the
    /// resolved config — the prologue every flow on this shape shares.
    pub(crate) fn stage(&self, flow: &'static str) -> Result<(PathBuf, RunLayout)> {
        self.eserver.reject_zero_host_port()?;
        self.bench
            .prepare(&[self.eserver.build_context(), self.amule.build_context()])?;
        let (run_dir, layout) = self.bench.create_run()?;
        stage_synthetic(&layout, self.file_size, self.ed2k_hash_command.as_deref())?;
        write_resolved_config(&run_dir, &self.resolved_config(flow))?;
        println!("run_dir={}", run_dir.display());
        Ok((run_dir, layout))
    }

    pub(crate) fn resolved_config(&self, flow: &'static str) -> ResolvedConfig {
        ResolvedConfig {
            flow,
            build_images: self.bench.build_images,
            skip_build: self.bench.skip_build,
            server_image: self.eserver.server_image.clone(),
            amule_image: self.amule.amule_image.clone(),
            rmule_client_image: self.rmule_client_image.clone(),
            server_build_context: self.eserver.server_build_context.clone(),
            amule_build_context: self.amule.amule_build_context.clone(),
            keep_containers: self.bench.keep_containers,
            container_runtime: self.bench.container_runtime.clone(),
            file_size: self.file_size,
            timeout_secs: self.timeout,
            server_host_port: self.eserver.server_host_port,
            server_env: self.eserver.server_env.clone(),
            amule_env: self.amule.amule_env.clone(),
            amule_ready_log_pattern: self.amule_ready_log_pattern.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ResolvedConfig {
    #[serde(rename = "scenario")]
    pub(crate) flow: &'static str,
    pub(crate) build_images: bool,
    pub(crate) skip_build: bool,
    pub(crate) server_image: String,
    pub(crate) amule_image: String,
    pub(crate) rmule_client_image: String,
    pub(crate) server_build_context: PathBuf,
    pub(crate) amule_build_context: PathBuf,
    pub(crate) keep_containers: bool,
    pub(crate) container_runtime: String,
    pub(crate) file_size: u64,
    pub(crate) timeout_secs: u64,
    pub(crate) server_host_port: u16,
    pub(crate) server_env: Vec<String>,
    pub(crate) amule_env: Vec<String>,
    pub(crate) amule_ready_log_pattern: String,
}

/// Which skeleton leg a subcommand drives and with what posture.
struct SkeletonLeg {
    flow: &'static str,
    action: RmuleClientAction,
    /// Force the aMule sharer to Low-ID (ADR-0039).
    amule_low_id: bool,
    /// Run rmule's download with `--serve` (High-ID, callback-capable).
    rmule_serve: bool,
    /// Honour the host-run rmule-tools test hook; the reverse flow ignores it.
    host_tools: bool,
    run: fn(ServerSkeletonOptions<'_>) -> Result<()>,
}

/// Stage the run and drive one skeleton leg.
fn skeleton(args: AmuleServesRmuleDownloadsArgs, leg: SkeletonLeg) -> Result<()> {
    let (_run_dir, layout) = args.stage(leg.flow)?;
    let rmule_tools_command = if leg.host_tools {
        args.rmule_tools_command
            .as_ref()
            .map(RmuleToolsCommand::new)
    } else {
        None
    };
    let rmule_client_container = RmuleClientContainer::cargo_rmule_tools(&args.rmule_client_image)?;
    let rmule_serve_container = RmuleServeContainer::cargo_rmule_tools(&args.rmule_client_image)?;
    (leg.run)(ServerSkeletonOptions {
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
        amule_ready_log_pattern: &args.amule_ready_log_pattern,
        rmule_tools_command: rmule_tools_command.as_ref(),
        rmule_client_container: &rmule_client_container,
        rmule_serve_container: &rmule_serve_container,
        amule_low_id: leg.amule_low_id,
        rmule_serve: leg.rmule_serve,
        rmule_peer_crypt: args.peer_crypt.as_deref(),
        rmule_peer_crypt_flip: &args.peer_crypt_flip,
        rmule_client_action: leg.action,
    })
}

pub(crate) fn bench_smoke(args: BenchSmokeArgs) -> Result<()> {
    args.eserver.reject_zero_host_port()?;
    args.bench.prepare(&[args.eserver.build_context()])?;
    let (run_dir, layout) = args.bench.create_run()?;
    let rmule_client_container = RmuleClientContainer::cargo_rmule_tools(&args.rmule_client_image)?;
    let config = BenchSmokeResolvedConfig {
        flow: FLOW_BENCH_SMOKE,
        build_images: args.bench.build_images,
        skip_build: args.bench.skip_build,
        server_image: args.eserver.server_image.clone(),
        rmule_client_image: args.rmule_client_image.clone(),
        server_build_context: args.eserver.server_build_context.clone(),
        keep_containers: args.bench.keep_containers,
        container_runtime: args.bench.container_runtime.clone(),
        timeout_secs: args.timeout,
        server_host_port: args.eserver.server_host_port,
        server_env: args.eserver.server_env.clone(),
        udp_ports_advert: args.udp_ports_advert,
        advertise_ipv6: args.advertise_ipv6,
    };
    write_resolved_config(&run_dir, &config)?;
    println!("run_dir={}", run_dir.display());

    run_bench_smoke(BenchSmokeOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        build_images: args.bench.build_images,
        server_image: &args.eserver.server_image,
        server_build_context: &args.eserver.server_build_context,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        server_host_port: args.eserver.server_host_port,
        server_env: &args.eserver.server_env,
        rmule_client_container: &rmule_client_container,
        udp_ports_advert: args.udp_ports_advert,
        advertise_ipv6: args.advertise_ipv6,
    })
}

pub(crate) fn server_cycle(args: AmuleServesRmuleDownloadsArgs) -> Result<()> {
    let (_run_dir, layout) = args.stage(FLOW_SERVER_CYCLE)?;
    let rmule_client_container = RmuleClientContainer::cargo_rmule_tools(&args.rmule_client_image)?;
    run_server_cycle(ServerCycleOptions {
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
        amule_ready_log_pattern: &args.amule_ready_log_pattern,
        rmule_client_container: &rmule_client_container,
    })
}

pub(crate) fn amule_serves_rmule_downloads(args: AmuleServesRmuleDownloadsArgs) -> Result<()> {
    skeleton(
        args,
        SkeletonLeg {
            flow: FLOW_AMULE_SERVES_RMULE_DOWNLOADS,
            action: RmuleClientAction::Download,
            amule_low_id: false,
            rmule_serve: false,
            host_tools: true,
            run: run_server_skeleton,
        },
    )
}

pub(crate) fn amule_serves_rmule_searches(args: AmuleServesRmuleDownloadsArgs) -> Result<()> {
    skeleton(
        args,
        SkeletonLeg {
            flow: FLOW_AMULE_SERVES_RMULE_SEARCHES,
            action: RmuleClientAction::Search,
            amule_low_id: false,
            rmule_serve: false,
            host_tools: true,
            run: run_server_skeleton,
        },
    )
}

/// Same wiring as `amule-serves-rmule-downloads`, but the aMule sharer is
/// forced to Low-ID and rmule serves while it downloads, so the only way rmule
/// reaches the source is a server-relayed callback it adopts (ADR-0039).
pub(crate) fn amule_low_id_callback(args: AmuleServesRmuleDownloadsArgs) -> Result<()> {
    skeleton(
        args,
        SkeletonLeg {
            flow: FLOW_AMULE_LOW_ID_CALLBACK,
            action: RmuleClientAction::CallbackCapability,
            amule_low_id: true,
            rmule_serve: true,
            host_tools: true,
            run: run_server_skeleton,
        },
    )
}

/// The reverse flow (flow C): rmule serves, the aMule downloads. Always drives
/// rmule inside the bench network, so the host-run tools hook is ignored.
pub(crate) fn rmule_serves_amule_downloads(args: AmuleServesRmuleDownloadsArgs) -> Result<()> {
    skeleton(
        args,
        SkeletonLeg {
            flow: FLOW_RMULE_SERVES_AMULE_DOWNLOADS,
            action: RmuleClientAction::Download,
            amule_low_id: false,
            rmule_serve: false,
            host_tools: false,
            run: run_rmule_serves_amule_downloads,
        },
    )
}

/// `search-wire`: Lugdunum, then ed2k-server, each with five aMule
/// sharers, probed by rmule's `search-wire` as a High-ID and a Low-ID
/// requester. Every party runs inside the bench network, so the eserver is
/// never published to the host and `--server-host-port` goes unused.
#[derive(Debug, Args)]
pub(crate) struct SearchWireArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) eserver: EserverArgs,
    #[command(flatten)]
    pub(crate) amule: AmuleArgs,
    /// The ed2k-server image.
    #[arg(long, default_value = DEFAULT_ED2KSRV_IMAGE)]
    pub(crate) ed2ksrv_image: String,
    /// Build context for the ed2k-server image.
    #[arg(long, default_value = DEFAULT_ED2KSRV_BUILD_CONTEXT)]
    pub(crate) ed2ksrv_build_context: PathBuf,
    /// The ed2k-server bench config; its `this_ip` is rendered per run.
    #[arg(long, default_value = DEFAULT_ED2KSRV_CONFIG)]
    pub(crate) ed2ksrv_config: PathBuf,
    /// Rust image the probe runs in inside the interop network.
    #[arg(long, default_value = DEFAULT_RMULE_CLIENT_IMAGE)]
    pub(crate) rmule_client_image: String,
    /// Per-step readiness budget in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
    /// Log substring that marks a sharer ready.
    #[arg(long, default_value = "rmule-amule-ready")]
    pub(crate) amule_ready_log_pattern: String,
    #[command(flatten)]
    pub(crate) capture: CaptureArgs,
    /// The servers to run against, in order (one run per server keeps a run
    /// inside one polling window).
    #[arg(long = "server", value_enum, default_values_t = [SearchWireServerArg::Lugdunum, SearchWireServerArg::Ed2kServer])]
    pub(crate) servers: Vec<SearchWireServerArg>,
    /// Also share several hundred files under one word and walk
    /// `OP_QUERY_MORE_RESULT` over them from each probe.
    #[arg(long)]
    pub(crate) more_results: bool,
    /// The reconnect leg's gaps, milliseconds, widest first: a search, a drop
    /// and fresh login, and a second search this long after the first.
    #[arg(long, value_delimiter = ',', default_values_t = [1500_u64, 300])]
    pub(crate) reconnect_gaps_ms: Vec<u64>,
}

/// A server `search-wire` runs against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SearchWireServerArg {
    /// The Lugdunum eserver.
    Lugdunum,
    /// ed2k-server.
    Ed2kServer,
}

impl From<SearchWireServerArg> for SearchWireServer {
    fn from(server: SearchWireServerArg) -> Self {
        match server {
            SearchWireServerArg::Lugdunum => Self::Lugdunum,
            SearchWireServerArg::Ed2kServer => Self::Ed2kServer,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct SearchWireResolvedConfig {
    #[serde(rename = "scenario")]
    pub(crate) flow: &'static str,
    pub(crate) server_image: String,
    pub(crate) ed2ksrv_image: String,
    pub(crate) ed2ksrv_config: PathBuf,
    pub(crate) amule_image: String,
    pub(crate) rmule_client_image: String,
    pub(crate) container_runtime: String,
    pub(crate) timeout_secs: u64,
    pub(crate) server_env: Vec<String>,
    pub(crate) amule_env: Vec<String>,
    pub(crate) servers: Vec<SearchWireServerArg>,
    pub(crate) more_results: bool,
    pub(crate) reconnect_gaps_ms: Vec<u64>,
}

pub(crate) fn search_wire(args: SearchWireArgs) -> Result<()> {
    args.bench.prepare(&[
        args.eserver.build_context(),
        args.amule.build_context(),
        args.capture.build_context(),
        ("ed2ksrv", args.ed2ksrv_build_context.as_path()),
    ])?;
    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &SearchWireResolvedConfig {
            flow: FLOW_SEARCH_WIRE,
            server_image: args.eserver.server_image.clone(),
            ed2ksrv_image: args.ed2ksrv_image.clone(),
            ed2ksrv_config: args.ed2ksrv_config.clone(),
            amule_image: args.amule.amule_image.clone(),
            rmule_client_image: args.rmule_client_image.clone(),
            container_runtime: args.bench.container_runtime.clone(),
            timeout_secs: args.timeout,
            server_env: args.eserver.server_env.clone(),
            amule_env: args.amule.amule_env.clone(),
            servers: args.servers.clone(),
            more_results: args.more_results,
            reconnect_gaps_ms: args.reconnect_gaps_ms.clone(),
        },
    )?;
    let servers: Vec<SearchWireServer> = args.servers.iter().copied().map(Into::into).collect();
    println!("run_dir={}", run_dir.display());
    let rmule_client_container = RmuleClientContainer::cargo_rmule_tools(&args.rmule_client_image)?;
    run_search_wire(SearchWireOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        build_images: args.bench.build_images,
        server_image: &args.eserver.server_image,
        server_build_context: &args.eserver.server_build_context,
        server_env: &args.eserver.server_env,
        ed2ksrv_image: &args.ed2ksrv_image,
        ed2ksrv_build_context: &args.ed2ksrv_build_context,
        ed2ksrv_config: &args.ed2ksrv_config,
        amule_image: &args.amule.amule_image,
        amule_build_context: &args.amule.amule_build_context,
        amule_env: &args.amule.amule_env,
        amule_ready_log_pattern: &args.amule_ready_log_pattern,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        rmule_client_container: &rmule_client_container,
        capture_image: &args.capture.capture_image,
        servers: &servers,
        more_results: args.more_results,
        reconnect_gaps_ms: &args.reconnect_gaps_ms,
    })
}

/// `search-spacing`: many sweeps of four searches a set gap apart against a
/// fresh Lugdunum per round, each sweep from its own address, every party
/// inside the bench network (`--server-host-port` goes unused).
#[derive(Debug, Args)]
pub(crate) struct SearchSpacingArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) eserver: EserverArgs,
    #[command(flatten)]
    pub(crate) amule: AmuleArgs,
    /// Rust image the probe runs in inside the interop network.
    #[arg(long, default_value = DEFAULT_RMULE_CLIENT_IMAGE)]
    pub(crate) rmule_client_image: String,
    /// Per-step readiness budget in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
    /// Log substring that marks the sharer ready.
    #[arg(long, default_value = "rmule-amule-ready")]
    pub(crate) amule_ready_log_pattern: String,
    #[command(flatten)]
    pub(crate) capture: CaptureArgs,
    /// Gaps swept on a fresh login, milliseconds.
    #[arg(long, value_delimiter = ',', num_args = 0.., default_values_t = [900_u64, 1000, 1100, 1250, 1500])]
    pub(crate) alone_gaps_ms: Vec<u64>,
    /// Gaps swept after the search-wire leg's reconnect history, milliseconds.
    #[arg(long, value_delimiter = ',', num_args = 0.., default_values_t = [1000_u64, 1250])]
    pub(crate) after_reconnect_gaps_ms: Vec<u64>,
    /// Gaps swept after the search-wire probe's whole sequence, milliseconds.
    #[arg(long, value_delimiter = ',', num_args = 0..)]
    pub(crate) search_wire_gaps_ms: Vec<u64>,
    /// Sweeps per condition, over all rounds.
    #[arg(long, default_value_t = 20)]
    pub(crate) sweeps: usize,
    /// Fresh servers the sweeps are spread over.
    #[arg(long, default_value_t = 4)]
    pub(crate) rounds: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct SearchSpacingResolvedConfig {
    #[serde(rename = "scenario")]
    pub(crate) flow: &'static str,
    pub(crate) server_image: String,
    pub(crate) amule_image: String,
    pub(crate) rmule_client_image: String,
    pub(crate) timeout_secs: u64,
    pub(crate) server_env: Vec<String>,
    pub(crate) amule_env: Vec<String>,
    pub(crate) alone_gaps_ms: Vec<u64>,
    pub(crate) after_reconnect_gaps_ms: Vec<u64>,
    pub(crate) search_wire_gaps_ms: Vec<u64>,
    pub(crate) sweeps: usize,
    pub(crate) rounds: usize,
}

pub(crate) fn search_spacing(args: SearchSpacingArgs) -> Result<()> {
    args.bench.prepare(&[
        args.eserver.build_context(),
        args.amule.build_context(),
        args.capture.build_context(),
    ])?;
    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &SearchSpacingResolvedConfig {
            flow: FLOW_SEARCH_SPACING,
            server_image: args.eserver.server_image.clone(),
            amule_image: args.amule.amule_image.clone(),
            rmule_client_image: args.rmule_client_image.clone(),
            timeout_secs: args.timeout,
            server_env: args.eserver.server_env.clone(),
            amule_env: args.amule.amule_env.clone(),
            alone_gaps_ms: args.alone_gaps_ms.clone(),
            after_reconnect_gaps_ms: args.after_reconnect_gaps_ms.clone(),
            search_wire_gaps_ms: args.search_wire_gaps_ms.clone(),
            sweeps: args.sweeps,
            rounds: args.rounds,
        },
    )?;
    println!("run_dir={}", run_dir.display());
    let rmule_client_container = RmuleClientContainer::cargo_rmule_tools(&args.rmule_client_image)?;
    run_search_spacing(SearchSpacingOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        build_images: args.bench.build_images,
        server_image: &args.eserver.server_image,
        server_build_context: &args.eserver.server_build_context,
        server_env: &args.eserver.server_env,
        amule_image: &args.amule.amule_image,
        amule_build_context: &args.amule.amule_build_context,
        amule_env: &args.amule.amule_env,
        amule_ready_log_pattern: &args.amule_ready_log_pattern,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        rmule_client_container: &rmule_client_container,
        capture_image: &args.capture.capture_image,
        alone_gaps_ms: &args.alone_gaps_ms,
        after_reconnect_gaps_ms: &args.after_reconnect_gaps_ms,
        search_wire_gaps_ms: &args.search_wire_gaps_ms,
        sweeps: args.sweeps,
        rounds: args.rounds,
    })
}

/// `late-port-test`: stock Lugdunum's port test held past its login answer
/// by a network condition on its own attachment; rmule serves under
/// `--peer-crypt required`.
#[derive(Debug, Args)]
pub(crate) struct LatePortTestArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) eserver: EserverArgs,
    /// The `rmule-tools` image (build it from the tip under test).
    #[arg(long, default_value = crate::cli::nat::DEFAULT_RMULE_TOOLS_IMAGE)]
    pub(crate) rmule_tools_image: String,
    /// How long Lugdunum's segments to port 4662 with PSH set are held, ms.
    #[arg(long, default_value_t = DEFAULT_HELLO_DELAY_MS)]
    pub(crate) hello_delay_ms: u64,
    /// Per-step readiness budget in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
}

#[derive(Debug, Serialize)]
struct LatePortTestResolvedConfig {
    #[serde(rename = "scenario")]
    flow: &'static str,
    server_image: String,
    rmule_tools_image: String,
    hello_delay_ms: u64,
    container_runtime: String,
    timeout_secs: u64,
}

pub(crate) fn late_port_test(args: LatePortTestArgs) -> Result<()> {
    args.bench.prepare(&[args.eserver.build_context()])?;
    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &LatePortTestResolvedConfig {
            flow: "late-port-test",
            server_image: args.eserver.server_image.clone(),
            rmule_tools_image: args.rmule_tools_image.clone(),
            hello_delay_ms: args.hello_delay_ms,
            container_runtime: args.bench.container_runtime.clone(),
            timeout_secs: args.timeout,
        },
    )?;
    println!("run_dir={}", run_dir.display());
    run_late_port_test(LatePortTestOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        server_image: &args.eserver.server_image,
        server_env: &args.eserver.server_env,
        rmule_tools_image: &args.rmule_tools_image,
        hello_delay_ms: args.hello_delay_ms,
    })
}

/// `crypt-ping-port`: which port Lugdunum answers rmule's crypt ping from,
/// and whether rmule reads the answer.
#[derive(Debug, Args)]
pub(crate) struct CryptPingPortArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) eserver: EserverArgs,
    #[command(flatten)]
    pub(crate) capture: CaptureArgs,
    /// The `rmule-tools` image (build it from the tip under test).
    #[arg(long, default_value = crate::cli::nat::DEFAULT_RMULE_TOOLS_IMAGE)]
    pub(crate) rmule_tools_image: String,
    /// Per-step readiness budget in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
    /// Also score the sealed exchange after the answered crypt-ping: the
    /// datagrams rmule seals under the server's UDP key to its obfuscation
    /// port, and the server's sealed answers.
    #[arg(long)]
    pub(crate) sealed: bool,
}

#[derive(Debug, Serialize)]
struct CryptPingPortResolvedConfig {
    #[serde(rename = "scenario")]
    flow: &'static str,
    server_image: String,
    rmule_tools_image: String,
    capture_image: String,
    container_runtime: String,
    timeout_secs: u64,
    sealed: bool,
}

pub(crate) fn crypt_ping_port(args: CryptPingPortArgs) -> Result<()> {
    args.bench
        .prepare(&[args.eserver.build_context(), args.capture.build_context()])?;
    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &CryptPingPortResolvedConfig {
            flow: "crypt-ping-port",
            server_image: args.eserver.server_image.clone(),
            rmule_tools_image: args.rmule_tools_image.clone(),
            capture_image: args.capture.capture_image.clone(),
            container_runtime: args.bench.container_runtime.clone(),
            timeout_secs: args.timeout,
            sealed: args.sealed,
        },
    )?;
    println!("run_dir={}", run_dir.display());
    run_crypt_ping_port(CryptPingPortOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        server_image: &args.eserver.server_image,
        server_env: &args.eserver.server_env,
        rmule_tools_image: &args.rmule_tools_image,
        capture_image: &args.capture.capture_image,
        sealed: args.sealed,
    })
}

/// `server-login-crypt`: whether rmule's server login opens its link as the
/// obfuscation policy says, and whether Lugdunum serves it.
#[derive(Debug, Args)]
pub(crate) struct ServerLoginCryptArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) eserver: EserverArgs,
    #[command(flatten)]
    pub(crate) capture: CaptureArgs,
    /// The `rmule-tools` image (build it from the tip under test).
    #[arg(long, default_value = crate::cli::nat::DEFAULT_RMULE_TOOLS_IMAGE)]
    pub(crate) rmule_tools_image: String,
    /// rmule's obfuscation policy: off, supported, requested or required.
    #[arg(long, default_value = "requested")]
    pub(crate) policy: String,
    /// Log in to ed2k-server at its pin instead of Lugdunum.
    #[arg(long)]
    pub(crate) ed2ksrv: bool,
    /// The ed2k-server image (refused unless its commit label matches the pin).
    #[arg(long, default_value = DEFAULT_ED2KSRV_IMAGE)]
    pub(crate) ed2ksrv_image: String,
    /// The ed2k-server bench config; its `this_ip` is rendered per run.
    #[arg(long, default_value = DEFAULT_ED2KSRV_CONFIG)]
    pub(crate) ed2ksrv_config: PathBuf,
    /// Dial the server by its container DNS name, not its address, and skip
    /// the status-sweep wait: only the login's `OP_IDCHANGE` extension (or
    /// server.met) can then teach the obfuscation port.
    #[arg(long)]
    pub(crate) by_name: bool,
    /// Per-step readiness budget in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
}

#[derive(Debug, Serialize)]
struct ServerLoginCryptResolvedConfig {
    #[serde(rename = "scenario")]
    flow: &'static str,
    policy: String,
    by_name: bool,
    server_image: String,
    rmule_tools_image: String,
    capture_image: String,
    container_runtime: String,
    timeout_secs: u64,
}

pub(crate) fn server_login_crypt(args: ServerLoginCryptArgs) -> Result<()> {
    args.bench
        .prepare(&[args.eserver.build_context(), args.capture.build_context()])?;
    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &ServerLoginCryptResolvedConfig {
            flow: "server-login-crypt",
            policy: args.policy.clone(),
            by_name: args.by_name,
            server_image: if args.ed2ksrv {
                args.ed2ksrv_image.clone()
            } else {
                args.eserver.server_image.clone()
            },
            rmule_tools_image: args.rmule_tools_image.clone(),
            capture_image: args.capture.capture_image.clone(),
            container_runtime: args.bench.container_runtime.clone(),
            timeout_secs: args.timeout,
        },
    )?;
    println!("run_dir={}", run_dir.display());
    run_server_login_crypt(ServerLoginCryptOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        server_image: &args.eserver.server_image,
        server_env: &args.eserver.server_env,
        rmule_tools_image: &args.rmule_tools_image,
        capture_image: &args.capture.capture_image,
        policy: &args.policy,
        ed2ksrv: args
            .ed2ksrv
            .then_some((args.ed2ksrv_image.as_str(), args.ed2ksrv_config.as_path())),
        by_name: args.by_name,
    })
}
