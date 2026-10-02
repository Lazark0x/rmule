//! Subcommands for the Kad capture family.
//!
//! All four share the Kad bench shape — the patched or stock aMule image, the
//! capture sidecar image, the UDP port range the mesh uses, and the stimulus
//! window a publish/search round trip has to close inside.

use std::path::PathBuf;

use crate::cli::bench::{
    BenchArgs, CaptureArgs, DEFAULT_FILE_SIZE, DEFAULT_KAD_UDP_PORT_BASE,
    DEFAULT_KAD_UDP_PORT_SPAN, DEFAULT_TIMEOUT_SECS, KadBenchArgs, KadResolvedConfig,
    RmuleNodeArgs, stage_synthetic,
};
use crate::cli::{parse_env_assignment, write_resolved_config};
use anyhow::{Result, bail};
use clap::Args;
use rmule_interop_harness::artifacts::RunLayout;
use rmule_interop_harness::flow::{
    KAD_PUBLISHER_USER_HASH_HEX, KadCaptureOptions, KadFakePublicSourceOptions,
    KadSourceCaptureOptions, run_kad_distance_ordering_capture, run_kad_fake_public_source,
    run_kad_source_capture, run_kad_source_lookup_capture,
};

pub(crate) const FLOW_KAD_SOURCE_LOOKUP_CAPTURE: &str = "kad-source-lookup-capture";
pub(crate) const FLOW_KAD_DISTANCE_ORDERING_CAPTURE: &str = "kad-distance-ordering-capture";
pub(crate) const FLOW_KAD_SOURCE_CAPTURE: &str = "kad-source-capture";
pub(crate) const FLOW_KAD_FAKE_PUBLIC_SOURCE: &str = "kad-fake-public-source";

/// The LAN-mode Kad capture needs the `IsGoodIPPort → IsGoodIP` patch, so the
/// private-mesh flows default to the patched aMule image; every fake-public
/// flow keeps the stock image.
pub(crate) const DEFAULT_KAD_AMULE_IMAGE: &str = "rmule/interop-amule-kad-patched:local";
pub(crate) const DEFAULT_KAD_AMULE_BUILD_CONTEXT: &str =
    "tools/interop-harness/images/amule-kad-patched";

/// The stimulus node must publish (retrying until aMule reaches LAN mode ~10-25s
/// after boot and acks), then search and record the 0x3B — so its window is
/// longer than the join window's passive observation.
pub(crate) const DEFAULT_KAD_STIMULUS_WINDOW_SECS: u64 = 120;

/// Flow F's publish→search round trip closes in seconds once the storer is up
/// (fresh nodes accept stores immediately); the window only needs
/// to cover bootstrap + a couple of publish/search retries.
pub(crate) const DEFAULT_KAD_FAKE_PUBLIC_WINDOW_SECS: u64 = 150;

/// The private LAN-mode Kad mesh: patched aMule nodes on RFC1918 addresses.
/// The source-lookup and distance-ordering captures use it directly; the
/// source capture and the join flatten it.
#[derive(Debug, Args)]
pub(crate) struct KadSourceLookupCaptureArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    /// aMule/amuled container image to run as private Kad nodes (defaults to the
    /// LAN-patched image required for private-mesh routing).
    #[arg(long, default_value = DEFAULT_KAD_AMULE_IMAGE)]
    pub(crate) amule_image: String,
    /// Build context directory for the aMule image.
    #[arg(long, default_value = DEFAULT_KAD_AMULE_BUILD_CONTEXT)]
    pub(crate) amule_build_context: PathBuf,
    #[command(flatten)]
    pub(crate) capture: CaptureArgs,
    /// Deterministic synthetic file size in bytes (the Source Lookup Target).
    #[arg(long, default_value_t = DEFAULT_FILE_SIZE)]
    pub(crate) file_size: u64,
    /// Overall flow timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
    /// Extra private routing nodes for Phase 2; must be 0 (Phase 1) or >= 3.
    #[arg(long, default_value_t = 0)]
    pub(crate) routing_nodes: u32,
    /// Extra environment variable for the aMule containers.
    #[arg(long = "amule-env", value_parser = parse_env_assignment)]
    pub(crate) amule_env: Vec<String>,
    /// Base UDP port the private Kad nodes listen on.
    #[arg(long, default_value_t = DEFAULT_KAD_UDP_PORT_BASE)]
    pub(crate) kad_udp_port_base: u16,
    /// Number of contiguous UDP ports captured above the base port.
    #[arg(long, default_value_t = DEFAULT_KAD_UDP_PORT_SPAN)]
    pub(crate) kad_udp_port_span: u16,
    /// Test hook for the ED2K hash command.
    #[arg(long, hide = true)]
    pub(crate) ed2k_hash_command: Option<PathBuf>,
}

impl KadSourceLookupCaptureArgs {
    /// Validate and allocate the run dir; the caller stages what its flow needs.
    pub(crate) fn prepare(&self) -> Result<(PathBuf, RunLayout)> {
        self.bench.prepare(&[
            ("aMule", &self.amule_build_context),
            self.capture.build_context(),
        ])?;
        self.bench.create_run()
    }

    /// The flow's `KadCaptureOptions` on the private mesh.
    pub(crate) fn capture_options<'a>(
        &'a self,
        layout: &'a RunLayout,
        routing_nodes: u32,
    ) -> KadCaptureOptions<'a> {
        KadCaptureOptions {
            layout,
            container_runtime: &self.bench.container_runtime,
            build_images: self.bench.build_images,
            amule_image: &self.amule_image,
            capture_image: &self.capture.capture_image,
            amule_build_context: &self.amule_build_context,
            capture_build_context: &self.capture.capture_build_context,
            keep_containers: self.bench.keep_containers,
            timeout_secs: self.timeout,
            routing_nodes,
            amule_env: &self.amule_env,
            kad_udp_port_base: self.kad_udp_port_base,
            kad_udp_port_span: self.kad_udp_port_span,
        }
    }

    /// The `resolved-config.toml` record for a flow on the private mesh.
    pub(crate) fn resolved_config(
        &self,
        flow: &'static str,
        file_size: u64,
        routing_nodes: u32,
    ) -> KadResolvedConfig {
        KadResolvedConfig {
            flow,
            build_images: self.bench.build_images,
            skip_build: self.bench.skip_build,
            amule_image: self.amule_image.clone(),
            capture_image: self.capture.capture_image.clone(),
            amule_build_context: self.amule_build_context.clone(),
            capture_build_context: self.capture.capture_build_context.clone(),
            keep_containers: self.bench.keep_containers,
            container_runtime: self.bench.container_runtime.clone(),
            file_size,
            timeout_secs: self.timeout,
            routing_nodes,
            amule_env: self.amule_env.clone(),
            kad_udp_port_base: self.kad_udp_port_base,
            kad_udp_port_span: self.kad_udp_port_span,
            public_kad_used: false,
        }
    }
}

/// `kad-source-capture`: the private mesh plus rmule as the stimulus node.
#[derive(Debug, Args)]
pub(crate) struct KadSourceCaptureArgs {
    #[command(flatten)]
    pub(crate) base: KadSourceLookupCaptureArgs,
    #[command(flatten)]
    pub(crate) node: RmuleNodeArgs,
    /// The Kad Publisher User Hash (hex): the captured source row's 16-byte ID
    /// should equal it word-swapped.
    #[arg(long, default_value = KAD_PUBLISHER_USER_HASH_HEX)]
    pub(crate) user_hash_hex: String,
    /// Seconds the stimulus node runs (publish retries + search + capture).
    #[arg(long, default_value_t = DEFAULT_KAD_STIMULUS_WINDOW_SECS)]
    pub(crate) stimulus_window: u64,
}

/// `kad-fake-public-source`: a stock storer on the fake-public swarm plus rmule
/// as the stimulus node.
#[derive(Debug, Args)]
pub(crate) struct KadFakePublicSourceArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) kad: KadBenchArgs,
    #[command(flatten)]
    pub(crate) node: RmuleNodeArgs,
    /// Deterministic synthetic file size in bytes (the publish/search target).
    #[arg(long, default_value_t = DEFAULT_FILE_SIZE)]
    pub(crate) file_size: u64,
    /// Per-step readiness timeout in seconds (a node's Kad-started log).
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
    /// Seconds the rmule stimulus node runs (bootstrap + publish + search).
    #[arg(long, default_value_t = DEFAULT_KAD_FAKE_PUBLIC_WINDOW_SECS)]
    pub(crate) stimulus_window: u64,
    /// The Kad Publisher User Hash (hex) rmule advertises as the source.
    #[arg(long, default_value = KAD_PUBLISHER_USER_HASH_HEX)]
    pub(crate) user_hash_hex: String,
    /// Run the ADR-0062 KEYWORD legs instead of the source legs:
    /// rmule publishes this shared name's keyword (`0x43`) then searches it back
    /// (`0x33`). The stock aMule storer is pinned to the keyword target (not the
    /// file key) so it clears the publish tolerance zone. Absent = source legs.
    #[arg(long)]
    pub(crate) keyword: Option<String>,
    /// With `--keyword`: rmule searches while its publish walk still holds the
    /// keyword, so the search takes the target and the publish runs after it.
    #[arg(long, requires = "keyword")]
    pub(crate) search_during_publish: bool,
    /// Test hook for the ED2K hash command.
    #[arg(long, hide = true)]
    pub(crate) ed2k_hash_command: Option<PathBuf>,
}

pub(crate) fn kad_source_lookup_capture(args: KadSourceLookupCaptureArgs) -> Result<()> {
    if args.routing_nodes != 0 && args.routing_nodes < 3 {
        bail!(
            "--routing-nodes must be 0 (Phase 1) or at least 3 (Phase 2 needs five private nodes)"
        );
    }
    let (run_dir, layout) = args.prepare()?;
    stage_synthetic(&layout, args.file_size, args.ed2k_hash_command.as_deref())?;
    write_resolved_config(
        &run_dir,
        &args.resolved_config(
            FLOW_KAD_SOURCE_LOOKUP_CAPTURE,
            args.file_size,
            args.routing_nodes,
        ),
    )?;
    println!("run_dir={}", run_dir.display());

    run_kad_source_lookup_capture(args.capture_options(&layout, args.routing_nodes))
}

/// No synthetic file or ed2k link: this flow proves routing distance, not
/// source lookup, so nothing here parses a file hash.
pub(crate) fn kad_distance_ordering_capture(args: KadSourceLookupCaptureArgs) -> Result<()> {
    let (run_dir, layout) = args.prepare()?;
    write_resolved_config(
        &run_dir,
        &args.resolved_config(FLOW_KAD_DISTANCE_ORDERING_CAPTURE, args.file_size, 0),
    )?;
    println!("run_dir={}", run_dir.display());

    run_kad_distance_ordering_capture(args.capture_options(&layout, 0))
}

pub(crate) fn kad_source_capture(args: KadSourceCaptureArgs) -> Result<()> {
    let base = &args.base;
    args.node.validate()?;
    let (run_dir, layout) = base.prepare()?;
    // The synthetic file rmule publishes and searches for is the Source Lookup
    // Target: its hash drives the storer's Kad ID and the publish/search key.
    stage_synthetic(&layout, base.file_size, base.ed2k_hash_command.as_deref())?;
    write_resolved_config(
        &run_dir,
        &base.resolved_config(FLOW_KAD_SOURCE_CAPTURE, base.file_size, 0),
    )?;
    println!("run_dir={}", run_dir.display());

    run_kad_source_capture(KadSourceCaptureOptions {
        base: base.capture_options(&layout, 0),
        rmule_image: &args.node.rmule_image,
        rmule_dockerfile: &args.node.rmule_dockerfile,
        rmule_build_context: &args.node.rmule_build_context,
        user_hash_hex: &args.user_hash_hex,
        stimulus_window_secs: args.stimulus_window,
    })
}

pub(crate) fn kad_fake_public_source(args: KadFakePublicSourceArgs) -> Result<()> {
    args.bench.prepare(&args.kad.build_contexts())?;
    args.node.validate()?;
    let (run_dir, layout) = args.bench.create_run()?;
    stage_synthetic(&layout, args.file_size, args.ed2k_hash_command.as_deref())?;
    write_resolved_config(
        &run_dir,
        &args.kad.resolved_config(
            FLOW_KAD_FAKE_PUBLIC_SOURCE,
            &args.bench,
            args.file_size,
            args.timeout,
            0,
        ),
    )?;
    println!("run_dir={}", run_dir.display());

    run_kad_fake_public_source(KadFakePublicSourceOptions {
        base: args
            .kad
            .capture_options(&args.bench, &layout, args.timeout, 0),
        rmule_image: &args.node.rmule_image,
        rmule_dockerfile: &args.node.rmule_dockerfile,
        rmule_build_context: &args.node.rmule_build_context,
        user_hash_hex: &args.user_hash_hex,
        stimulus_window_secs: args.stimulus_window,
        keyword: args.keyword.as_deref(),
        search_during_publish: args.search_during_publish,
    })
}
