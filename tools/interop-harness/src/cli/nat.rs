//! Subcommands for the NAT and IPv6 family (ADR-0092).
//!
//! Three flows whose subject is the *bench* rather than a protocol exchange:
//! that each **NAT Gateway** builds the RFC 4787 behaviour it claims, that each
//! counterparty body admits a **Fake-Public v6 Plan** address, and — under
//! `--drive-legacy` — that a stock aMule 2.3.3 reads a **Sentinel
//! Source**-bearing list without desyncing while rmule's own reader parses it
//! (ADR-0092's sentinel row as amended, since the pinned `ed2ksrv` cannot emit
//! such a row at all).

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;
use rmule_interop_harness::flow::{
    Ipv6DialectOptions, Ipv6Flow, Ipv6NetAcceptOptions, LegacyDrive, NatGatewaySelfProofOptions,
    NattFlow, NattOptions, PortMapFlow, PortMapOptions, SentinelSourcesLegacyOptions,
    run_ipv6_dialect, run_ipv6_net_accept, run_natgw_selfproof, run_natt, run_portmap,
    run_sentinel_sources_legacy,
};
use rmule_interop_harness::nat::NatType;
use serde::Serialize;

use crate::cli::bench::{
    AmuleArgs, BenchArgs, CaptureArgs, DEFAULT_FILE_SIZE, DEFAULT_TIMEOUT_SECS, stage_synthetic,
};
use crate::cli::{parse_env_assignment, validate_build_context_dir, write_resolved_config};

pub(crate) const FLOW_NATGW_SELFPROOF: &str = "natgw-selfproof";
pub(crate) const FLOW_IPV6_NET_ACCEPT: &str = "ipv6-net-accept";
pub(crate) const FLOW_SENTINEL_SOURCES_LEGACY: &str = "sentinel-sources-legacy";

/// The project-owned **NAT Gateway** image and its recipe.
pub(crate) const DEFAULT_NATGW_IMAGE: &str = "rmule/interop-natgw:local";
pub(crate) const DEFAULT_NATGW_BUILD_CONTEXT: &str = "tools/interop-harness/images/natgw";
/// The `miniupnpd` **Port-Mapping Gateway** image and its recipe (ADR-0092):
/// a NAT gateway that also speaks UPnP-IGD2, NAT-PMP and PCP.
pub(crate) const DEFAULT_MINIUPNPD_IMAGE: &str = "rmule/interop-miniupnpd:local";
pub(crate) const DEFAULT_MINIUPNPD_BUILD_CONTEXT: &str = "tools/interop-harness/images/miniupnpd";
/// The project-owned **Reflector Probe** image and its recipe.
pub(crate) const DEFAULT_NATPROBE_IMAGE: &str = "rmule/interop-natprobe:local";
pub(crate) const DEFAULT_NATPROBE_BUILD_CONTEXT: &str = "tools/interop-harness/images/natprobe";
/// The `rmule-tools` driver image the probe runs from, always rebuilt from the
/// workspace because the probe subcommand is workspace code.
pub(crate) const DEFAULT_RMULE_TOOLS_IMAGE: &str = "rmule/interop-rmule-tools:local";
pub(crate) const DEFAULT_RMULE_TOOLS_DOCKERFILE: &str =
    "tools/interop-harness/images/rmule-tools/Dockerfile";
/// kno's aMule at its **Fork Pin** — the only body carrying IPv6 activation.
pub(crate) const DEFAULT_AMULE_KNO_IMAGE: &str = "rmule/interop-amule-kno:local";
/// Stock aMule 2.3.3 rebuilt with `--enable-debug`: built by hand
/// with `--build-arg AMULE_DEBUG=1`, never by `--build-images`.
pub(crate) const DEFAULT_AMULE_DEBUG_IMAGE: &str = "rmule/interop-amule-debug:local";
pub(crate) const DEFAULT_AMULE_KNO_BUILD_CONTEXT: &str = "tools/interop-harness/images/amule-kno";
/// emule-qt's headless `emulecored`, the IPv6 reference body.
pub(crate) const DEFAULT_EMULEQT_IMAGE: &str = "rmule/interop-emuleqt:local";
pub(crate) const DEFAULT_EMULEQT_BUILD_CONTEXT: &str = "tools/interop-harness/images/emuleqt";

/// How long a body with no readiness marker is left to talk before its log is
/// read. Long enough for a daemon to finish its address detection, short enough
/// that four bodies do not turn a fast-tier flow into a slow one.
pub(crate) const DEFAULT_IPV6_SETTLE_SECS: u64 = 25;

/// emule-qt's `direct-peer` mode is the one that needs no eD2k server: this flow
/// measures an address, not an exchange, and pointing the body at a server it
/// does not need would only add a way for the run to fail.
const EMULEQT_IPV6_MODE: &str = "EMULEQT_SCENARIO_MODE=direct-peer";

/// The `direct-peer` readiness marker its entrypoint prints, so the flow gates
/// on the body rather than on a stopwatch.
const EMULEQT_READY_MARKER: &str = "rmule-emuleqt-direct-peer-ready";

/// kno's aMule prints this once its daemon is up; the address lines the flow
/// reads come after it.
const AMULE_KNO_READY_MARKER: &str = "rmule-amule-kno-ready";

/// `natgw-selfproof`: prove every gateway type against the reflector.
#[derive(Debug, Args)]
pub(crate) struct NatgwSelfProofArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) capture: CaptureArgs,
    /// The NAT gateway image.
    #[arg(long, default_value = DEFAULT_NATGW_IMAGE)]
    pub(crate) natgw_image: String,
    /// Build context for the NAT gateway image.
    #[arg(long, default_value = DEFAULT_NATGW_BUILD_CONTEXT)]
    pub(crate) natgw_build_context: PathBuf,
    /// The reflector image.
    #[arg(long, default_value = DEFAULT_NATPROBE_IMAGE)]
    pub(crate) natprobe_image: String,
    /// Build context for the reflector image.
    #[arg(long, default_value = DEFAULT_NATPROBE_BUILD_CONTEXT)]
    pub(crate) natprobe_build_context: PathBuf,
    /// The rmule-tools driver image the probe runs from.
    #[arg(long, default_value = DEFAULT_RMULE_TOOLS_IMAGE)]
    pub(crate) rmule_tools_image: String,
    /// Dockerfile for the rmule-tools driver image.
    #[arg(long, default_value = DEFAULT_RMULE_TOOLS_DOCKERFILE)]
    pub(crate) rmule_tools_dockerfile: PathBuf,
    /// Build context for the rmule-tools driver image (the repo root).
    #[arg(long, default_value = ".")]
    pub(crate) rmule_tools_build_context: PathBuf,
    /// Gateway types to prove; repeat the flag to select a subset. Every type
    /// by default, because a partial proof is what a NAT-traversal negative row cannot
    /// cite.
    #[arg(long = "nat-type", value_parser = parse_nat_type)]
    pub(crate) nat_types: Vec<NatType>,
    /// Per-step readiness timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
}

fn parse_nat_type(value: &str) -> std::result::Result<NatType, String> {
    NatType::from_knob(value).map_err(|error| error.to_string())
}

/// `ipv6-net-accept`: measure each body's acceptance of the v6 plan.
#[derive(Debug, Args)]
pub(crate) struct Ipv6NetAcceptArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    /// kno's aMule image (Fork Pin `ab483654`).
    #[arg(long, default_value = DEFAULT_AMULE_KNO_IMAGE)]
    pub(crate) amule_kno_image: String,
    /// Build context for kno's aMule image.
    #[arg(long, default_value = DEFAULT_AMULE_KNO_BUILD_CONTEXT)]
    pub(crate) amule_kno_build_context: PathBuf,
    /// The emule-qt `emulecored` image.
    #[arg(long, default_value = DEFAULT_EMULEQT_IMAGE)]
    pub(crate) emuleqt_image: String,
    /// Build context for the emule-qt image.
    #[arg(long, default_value = DEFAULT_EMULEQT_BUILD_CONTEXT)]
    pub(crate) emuleqt_build_context: PathBuf,
    /// The natgw image, which bench-doctor probes the kernel with.
    #[arg(long, default_value = DEFAULT_NATGW_IMAGE)]
    pub(crate) natgw_image: String,
    /// The image the IPv6 dialer runs from; the natprobe recipe already carries
    /// a python3, and reusing it keeps the flow from inventing a body.
    #[arg(long, default_value = DEFAULT_NATPROBE_IMAGE)]
    pub(crate) natprobe_image: String,
    /// Build context for the dialer's natprobe image.
    #[arg(long, default_value = DEFAULT_NATPROBE_BUILD_CONTEXT)]
    pub(crate) natprobe_build_context: PathBuf,
    /// Skip kno's aMule (it is a long from-source build).
    #[arg(long)]
    pub(crate) skip_amule_kno: bool,
    /// Skip emule-qt.
    #[arg(long)]
    pub(crate) skip_emuleqt: bool,
    /// Extra environment for kno's aMule container.
    #[arg(long = "amule-kno-env", value_parser = parse_env_assignment)]
    pub(crate) amule_kno_env: Vec<String>,
    /// Extra environment for the emule-qt container.
    #[arg(long = "emuleqt-env", value_parser = parse_env_assignment)]
    pub(crate) emuleqt_env: Vec<String>,
    /// Per-step readiness timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
    /// Seconds a body with no readiness marker is left to talk.
    #[arg(long, default_value_t = DEFAULT_IPV6_SETTLE_SECS)]
    pub(crate) settle: u64,
}

/// How long the legacy leg watches the stock aMule after the scripted list goes
/// out. aMule paces new source connections a few per second, so this only has
/// to cover the pacing plus its own retry — not a transfer.
pub(crate) const DEFAULT_LEGACY_WINDOW_SECS: u64 = 45;

/// `sentinel-sources-legacy`: rmule's sentinel-safe reader gate, plus — with
/// `--drive-legacy` — the live leg that hands the same shape to a stock aMule
/// 2.3.3 and records what it does.
#[derive(Debug, Args)]
pub(crate) struct SentinelSourcesLegacyArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) amule: AmuleArgs,
    #[command(flatten)]
    pub(crate) capture: CaptureArgs,
    /// Argv that must succeed for rmule's sentinel-safe reader to count as
    /// present, e.g. `<path-to>/rmule-tools ed2k sentinel-probe`. Unset (or a
    /// probe that fails) is what makes the flow skip with a documented reason
    /// instead of measuring an absence it caused.
    #[arg(long = "sentinel-reader-probe", num_args = 1..)]
    pub(crate) sentinel_reader_probe: Vec<String>,
    /// Stand the live legacy topology up: an rmule-authored stimulus hands the
    /// sentinel-bearing list to a stock aMule 2.3.3 and the flow judges aMule's
    /// own behaviour. Without it the flow is the reader gate alone.
    #[arg(long)]
    pub(crate) drive_legacy: bool,
    /// The rmule-tools driver image the stimulus runs from.
    #[arg(long, default_value = DEFAULT_RMULE_TOOLS_IMAGE)]
    pub(crate) rmule_tools_image: String,
    /// Dockerfile for the rmule-tools driver image.
    #[arg(long, default_value = DEFAULT_RMULE_TOOLS_DOCKERFILE)]
    pub(crate) rmule_tools_dockerfile: PathBuf,
    /// Build context for the rmule-tools driver image (the repo root).
    #[arg(long, default_value = ".")]
    pub(crate) rmule_tools_build_context: PathBuf,
    /// Synthetic file size; its ed2k link is the hash the scripted list answers.
    #[arg(long, default_value_t = DEFAULT_FILE_SIZE)]
    pub(crate) file_size: u64,
    /// Per-step readiness timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
    /// Seconds the stock aMule is watched after the scripted list goes out.
    #[arg(long, default_value_t = DEFAULT_LEGACY_WINDOW_SECS)]
    pub(crate) window: u64,
}

/// The `resolved-config.toml` a NAT-family flow writes.
#[derive(Debug, Serialize)]
struct NatResolvedConfig {
    #[serde(rename = "scenario")]
    flow: &'static str,
    build_images: bool,
    skip_build: bool,
    keep_containers: bool,
    container_runtime: String,
    timeout_secs: u64,
    images: Vec<String>,
    detail: Vec<String>,
    public_kad_used: bool,
}

/// Run `natgw-selfproof`.
///
/// # Errors
/// If the bench cannot be built or a gateway cannot be probed.
pub(crate) fn natgw_selfproof(args: NatgwSelfProofArgs) -> Result<()> {
    let contexts: [(&str, &Path); 1] = [args.capture.build_context()];
    args.bench.prepare(&contexts)?;
    // `natgw` and `natprobe` rebuild on every run regardless of
    // `--build-images`, so their contexts are validated unconditionally
    // too, not just when `--build-images` is passed.
    validate_build_context_dir("natgw", &args.natgw_build_context)?;
    validate_build_context_dir("natprobe", &args.natprobe_build_context)?;
    let nat_types = if args.nat_types.is_empty() {
        NatType::ALL.to_vec()
    } else {
        args.nat_types.clone()
    };

    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &NatResolvedConfig {
            flow: FLOW_NATGW_SELFPROOF,
            build_images: args.bench.build_images,
            skip_build: args.bench.skip_build,
            keep_containers: args.bench.keep_containers,
            container_runtime: args.bench.container_runtime.clone(),
            timeout_secs: args.timeout,
            images: vec![
                args.natgw_image.clone(),
                args.natprobe_image.clone(),
                args.capture.capture_image.clone(),
                args.rmule_tools_image.clone(),
            ],
            detail: nat_types
                .iter()
                .map(|nat_type| nat_type.knob().to_owned())
                .collect(),
            public_kad_used: false,
        },
    )?;
    println!("run_dir={}", run_dir.display());

    run_natgw_selfproof(NatGatewaySelfProofOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        build_images: args.bench.build_images,
        natgw_image: &args.natgw_image,
        natgw_build_context: &args.natgw_build_context,
        natprobe_image: &args.natprobe_image,
        natprobe_build_context: &args.natprobe_build_context,
        capture_image: &args.capture.capture_image,
        capture_build_context: &args.capture.capture_build_context,
        rmule_tools_image: &args.rmule_tools_image,
        rmule_tools_dockerfile: &args.rmule_tools_dockerfile,
        rmule_tools_build_context: &args.rmule_tools_build_context,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        nat_types: &nat_types,
    })
}

/// Run `ipv6-net-accept`.
///
/// # Errors
/// If the bench cannot be built or a body's log cannot be collected.
pub(crate) fn ipv6_net_accept(args: Ipv6NetAcceptArgs) -> Result<()> {
    let mut contexts: Vec<(&str, &Path)> = Vec::new();
    if !args.skip_amule_kno {
        contexts.push(("amule-kno", &args.amule_kno_build_context));
    }
    if !args.skip_emuleqt {
        contexts.push(("emuleqt", &args.emuleqt_build_context));
    }
    args.bench.prepare(&contexts)?;
    // `natprobe` rebuilds on every run regardless of `--build-images`,
    // so its context is validated unconditionally too, not just when
    // `--build-images` is passed.
    validate_build_context_dir("natprobe", &args.natprobe_build_context)?;

    // The mode knob rides ahead of the operator's own `--emuleqt-env`, so a run
    // can still override it.
    let emuleqt_env: Vec<String> = std::iter::once(EMULEQT_IPV6_MODE.to_owned())
        .chain(args.emuleqt_env.iter().cloned())
        .collect();

    let mut bodies = Vec::new();
    if !args.skip_amule_kno {
        bodies.push(rmule_interop_harness::flow::Ipv6Body {
            name: "amule-kno",
            image: &args.amule_kno_image,
            build_context: &args.amule_kno_build_context,
            env: &args.amule_kno_env,
            ready_marker: AMULE_KNO_READY_MARKER,
        });
    }
    if !args.skip_emuleqt {
        bodies.push(rmule_interop_harness::flow::Ipv6Body {
            name: "emuleqt",
            image: &args.emuleqt_image,
            build_context: &args.emuleqt_build_context,
            env: &emuleqt_env,
            ready_marker: EMULEQT_READY_MARKER,
        });
    }

    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &NatResolvedConfig {
            flow: FLOW_IPV6_NET_ACCEPT,
            build_images: args.bench.build_images,
            skip_build: args.bench.skip_build,
            keep_containers: args.bench.keep_containers,
            container_runtime: args.bench.container_runtime.clone(),
            timeout_secs: args.timeout,
            images: bodies.iter().map(|body| body.image.to_owned()).collect(),
            detail: bodies.iter().map(|body| body.name.to_owned()).collect(),
            public_kad_used: false,
        },
    )?;
    println!("run_dir={}", run_dir.display());

    run_ipv6_net_accept(Ipv6NetAcceptOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        build_images: args.bench.build_images,
        natgw_image: &args.natgw_image,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        settle_secs: args.settle,
        bodies: &bodies,
        dialer_image: &args.natprobe_image,
        dialer_build_context: &args.natprobe_build_context,
    })
}

/// Run `sentinel-sources-legacy`.
///
/// # Errors
/// If the verdict cannot be written.
pub(crate) fn sentinel_sources_legacy(args: SentinelSourcesLegacyArgs) -> Result<()> {
    if args.drive_legacy {
        args.bench
            .prepare(&[args.amule.build_context(), args.capture.build_context()])?;
    }
    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &NatResolvedConfig {
            flow: FLOW_SENTINEL_SOURCES_LEGACY,
            build_images: args.bench.build_images,
            skip_build: args.bench.skip_build,
            keep_containers: args.bench.keep_containers,
            container_runtime: args.bench.container_runtime.clone(),
            timeout_secs: if args.drive_legacy { args.timeout } else { 0 },
            images: if args.drive_legacy {
                vec![
                    args.amule.amule_image.clone(),
                    args.capture.capture_image.clone(),
                    args.rmule_tools_image.clone(),
                ]
            } else {
                Vec::new()
            },
            detail: args.sentinel_reader_probe.clone(),
            public_kad_used: false,
        },
    )?;
    println!("run_dir={}", run_dir.display());

    // The legacy leg answers a lookup for the synthetic file's own hash, so the
    // file and its link have to exist before the stimulus argv is composed.
    if args.drive_legacy {
        stage_synthetic(&layout, args.file_size, None)?;
    }

    let legacy = args.drive_legacy.then(|| LegacyDrive {
        build_images: args.bench.build_images,
        amule_image: &args.amule.amule_image,
        amule_build_context: &args.amule.amule_build_context,
        capture_image: &args.capture.capture_image,
        capture_build_context: &args.capture.capture_build_context,
        rmule_tools_image: &args.rmule_tools_image,
        rmule_tools_dockerfile: &args.rmule_tools_dockerfile,
        rmule_tools_build_context: &args.rmule_tools_build_context,
        amule_env: &args.amule.amule_env,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
        window_secs: args.window,
    });

    run_sentinel_sources_legacy(SentinelSourcesLegacyOptions {
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        sentinel_reader_probe: &args.sentinel_reader_probe,
        legacy,
    })
}

/// The three **Port Mapping** flows (ADR-0092). One subcommand with a
/// flow argument rather than three: the bench is identical and only the driver's
/// knobs differ, so three copies would let the topology drift between rows a
/// verdict cites against each other.
#[derive(Debug, Args)]
pub(crate) struct PortMapArgs {
    /// Which flow to run.
    #[arg(value_parser = parse_portmap_flow)]
    pub(crate) flow: PortMapFlow,
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) capture: CaptureArgs,
    #[command(flatten)]
    pub(crate) amule: AmuleArgs,
    /// The miniupnpd gateway image.
    #[arg(long, default_value = DEFAULT_MINIUPNPD_IMAGE)]
    pub(crate) miniupnpd_image: String,
    /// Build context for the miniupnpd gateway image.
    #[arg(long, default_value = DEFAULT_MINIUPNPD_BUILD_CONTEXT)]
    pub(crate) miniupnpd_build_context: PathBuf,
    /// The reflector image the NAT Type Proof is measured with.
    #[arg(long, default_value = DEFAULT_NATPROBE_IMAGE)]
    pub(crate) natprobe_image: String,
    /// Build context for the reflector image.
    #[arg(long, default_value = DEFAULT_NATPROBE_BUILD_CONTEXT)]
    pub(crate) natprobe_build_context: PathBuf,
    /// The rmule-tools driver image.
    #[arg(long, default_value = DEFAULT_RMULE_TOOLS_IMAGE)]
    pub(crate) rmule_tools_image: String,
    /// Dockerfile for the rmule-tools driver image.
    #[arg(long, default_value = DEFAULT_RMULE_TOOLS_DOCKERFILE)]
    pub(crate) rmule_tools_dockerfile: PathBuf,
    /// Build context for the rmule-tools driver image (the repo root).
    #[arg(long, default_value = ".")]
    pub(crate) rmule_tools_build_context: PathBuf,
    /// Per-step readiness timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
}

fn parse_portmap_flow(value: &str) -> std::result::Result<PortMapFlow, String> {
    PortMapFlow::from_name(value).map_err(|error| error.to_string())
}

/// Run one port-mapping flow.
///
/// # Errors
/// If the bench cannot be built or the driver never produced a row.
pub(crate) fn portmap(args: PortMapArgs) -> Result<()> {
    let contexts: [(&str, &Path); 3] = [
        ("miniupnpd", &args.miniupnpd_build_context),
        args.capture.build_context(),
        // Only `portmap-highid` stands Kad helpers up, but the recipe is
        // prepared unconditionally: `prepare` is a context check, and gating it
        // per flow would only make a missing recipe surface later.
        args.amule.build_context(),
    ];
    args.bench.prepare(&contexts)?;
    // `natprobe` rebuilds on every run regardless of `--build-images`,
    // so its context is validated unconditionally too.
    validate_build_context_dir("natprobe", &args.natprobe_build_context)?;

    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &NatResolvedConfig {
            flow: args.flow.name(),
            build_images: args.bench.build_images,
            skip_build: args.bench.skip_build,
            keep_containers: args.bench.keep_containers,
            container_runtime: args.bench.container_runtime.clone(),
            timeout_secs: args.timeout,
            images: vec![
                args.miniupnpd_image.clone(),
                args.natprobe_image.clone(),
                args.capture.capture_image.clone(),
                args.rmule_tools_image.clone(),
                args.amule.amule_image.clone(),
            ],
            detail: vec![args.flow.name().to_owned()],
            public_kad_used: false,
        },
    )?;
    println!("run_dir={}", run_dir.display());

    run_portmap(PortMapOptions {
        flow: args.flow,
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        build_images: args.bench.build_images,
        miniupnpd_image: &args.miniupnpd_image,
        miniupnpd_build_context: &args.miniupnpd_build_context,
        amule_image: &args.amule.amule_image,
        amule_build_context: &args.amule.amule_build_context,
        natprobe_image: &args.natprobe_image,
        natprobe_build_context: &args.natprobe_build_context,
        capture_image: &args.capture.capture_image,
        capture_build_context: &args.capture.capture_build_context,
        rmule_tools_image: &args.rmule_tools_image,
        rmule_tools_dockerfile: &args.rmule_tools_dockerfile,
        rmule_tools_build_context: &args.rmule_tools_build_context,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
    })
}

/// The `ed2ksrv` counterparty image and its recipe. The recipe's build context
/// is the server's own source tree, not this directory, so a bench that has not
/// built it simply has no image — which `ipv6-server-sentinel` records rather
/// than fails on.
pub(crate) const DEFAULT_ED2KSRV_IMAGE: &str = "rmule/interop-ed2ksrv:local";
pub(crate) const DEFAULT_ED2KSRV_BUILD_CONTEXT: &str = "tools/interop-harness/images/ed2ksrv";
/// The bench `config.toml` the coordinator runs on.
pub(crate) const DEFAULT_ED2KSRV_CONFIG: &str = "tools/interop-harness/images/ed2ksrv/config.toml";

/// The six **IPv6 dialect** flows (ADR-0087/ADR-0092). One subcommand
/// with a flow argument, for the same reason `portmap` has one: the bench is
/// the same dual-stack WAN and only the bodies and the drive sequence differ.
#[derive(Debug, Args)]
pub(crate) struct Ipv6DialectArgs {
    /// Which flow to run.
    #[arg(value_parser = parse_ipv6_flow)]
    pub(crate) flow: Ipv6Flow,
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) capture: CaptureArgs,
    #[command(flatten)]
    pub(crate) amule: AmuleArgs,
    /// kno's aMule image (Fork Pin `ab483654`).
    #[arg(long, default_value = DEFAULT_AMULE_KNO_IMAGE)]
    pub(crate) amule_kno_image: String,
    /// Build context for kno's aMule image.
    #[arg(long, default_value = DEFAULT_AMULE_KNO_BUILD_CONTEXT)]
    pub(crate) amule_kno_build_context: PathBuf,
    /// The emule-qt `emulecored` image (cherry-pick `73fff714`).
    #[arg(long, default_value = DEFAULT_EMULEQT_IMAGE)]
    pub(crate) emuleqt_image: String,
    /// Build context for the emule-qt image.
    #[arg(long, default_value = DEFAULT_EMULEQT_BUILD_CONTEXT)]
    pub(crate) emuleqt_build_context: PathBuf,
    /// The ed2k-server image.
    #[arg(long, default_value = DEFAULT_ED2KSRV_IMAGE)]
    pub(crate) ed2ksrv_image: String,
    /// Build context for the ed2k-server image.
    #[arg(long, default_value = DEFAULT_ED2KSRV_BUILD_CONTEXT)]
    pub(crate) ed2ksrv_build_context: PathBuf,
    /// The rmule-tools driver image the dialect drivers run from.
    #[arg(long, default_value = DEFAULT_RMULE_TOOLS_IMAGE)]
    pub(crate) rmule_tools_image: String,
    /// Dockerfile for the rmule-tools driver image.
    #[arg(long, default_value = DEFAULT_RMULE_TOOLS_DOCKERFILE)]
    pub(crate) rmule_tools_dockerfile: PathBuf,
    /// Build context for the rmule-tools driver image (the repo root).
    #[arg(long, default_value = ".")]
    pub(crate) rmule_tools_build_context: PathBuf,
    /// The natgw image, which bench-doctor probes the kernel with.
    #[arg(long, default_value = DEFAULT_NATGW_IMAGE)]
    pub(crate) natgw_image: String,
    /// `ipv6-kad-tags` only: arm Kad datagram obfuscation (ADR-0046) on the
    /// emule-qt leg's rmule bodies — the storer's `kad join-node --kad-crypt`
    /// and the dial-back Cores' `--peer-crypt supported` — so emule-qt can
    /// verify them through the verify-key three-way. The
    /// kno legs stay plaintext: their lifts read plain opcode bytes.
    #[arg(long)]
    pub(crate) rmule_kad_crypt: bool,
    /// Per-step readiness timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
}

fn parse_ipv6_flow(value: &str) -> std::result::Result<Ipv6Flow, String> {
    Ipv6Flow::from_name(value).map_err(|error: anyhow::Error| error.to_string())
}

/// Run one IPv6-dialect flow.
///
/// # Errors
/// If the bench cannot be built or a driver never produced a row.
pub(crate) fn ipv6_dialect(args: Ipv6DialectArgs) -> Result<()> {
    let mut contexts: Vec<(&str, &Path)> = vec![args.capture.build_context()];
    if args.flow.needs_amule_kno() {
        contexts.push(("amule-kno", &args.amule_kno_build_context));
    }
    if args.flow.needs_emuleqt() {
        contexts.push(("emuleqt", &args.emuleqt_build_context));
    }
    if args.flow.needs_legacy_amule() {
        contexts.push(args.amule.build_context());
    }
    args.bench.prepare(&contexts)?;

    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &NatResolvedConfig {
            flow: args.flow.name(),
            build_images: args.bench.build_images,
            skip_build: args.bench.skip_build,
            keep_containers: args.bench.keep_containers,
            container_runtime: args.bench.container_runtime.clone(),
            timeout_secs: args.timeout,
            images: vec![
                args.amule_kno_image.clone(),
                args.emuleqt_image.clone(),
                args.amule.amule_image.clone(),
                args.ed2ksrv_image.clone(),
                args.capture.capture_image.clone(),
                args.rmule_tools_image.clone(),
            ],
            detail: std::iter::once(args.flow.name())
                .chain(args.rmule_kad_crypt.then_some("rmule-kad-crypt"))
                .map(ToOwned::to_owned)
                .collect(),
            public_kad_used: false,
        },
    )?;
    println!("run_dir={}", run_dir.display());

    run_ipv6_dialect(Ipv6DialectOptions {
        flow: args.flow,
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        build_images: args.bench.build_images,
        amule_kno_image: &args.amule_kno_image,
        amule_kno_build_context: &args.amule_kno_build_context,
        emuleqt_image: &args.emuleqt_image,
        emuleqt_build_context: &args.emuleqt_build_context,
        amule_image: &args.amule.amule_image,
        amule_build_context: &args.amule.amule_build_context,
        ed2ksrv_image: &args.ed2ksrv_image,
        ed2ksrv_build_context: &args.ed2ksrv_build_context,
        capture_image: &args.capture.capture_image,
        capture_build_context: &args.capture.capture_build_context,
        rmule_tools_image: &args.rmule_tools_image,
        rmule_tools_dockerfile: &args.rmule_tools_dockerfile,
        rmule_tools_build_context: &args.rmule_tools_build_context,
        natgw_image: &args.natgw_image,
        rmule_kad_crypt: args.rmule_kad_crypt,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
    })
}

/// The **NAT traversal** flows (ADR-0091/ADR-0092). One subcommand with
/// a flow argument, for the same reason `portmap` and `ipv6-dialect` have one:
/// the bench is shared and only the bodies and the drive sequence differ.
#[derive(Debug, Args)]
pub(crate) struct NattArgs {
    /// Which flow to run.
    #[arg(value_parser = parse_natt_flow)]
    pub(crate) flow: NattFlow,
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) capture: CaptureArgs,
    /// kno's aMule image (Fork Pin `ab483654`).
    #[arg(long, default_value = DEFAULT_AMULE_KNO_IMAGE)]
    pub(crate) amule_kno_image: String,
    /// Build context for kno's aMule image.
    #[arg(long, default_value = DEFAULT_AMULE_KNO_BUILD_CONTEXT)]
    pub(crate) amule_kno_build_context: PathBuf,
    /// Stock aMule on the debug image, for `natt-udp-selfcheck-amule` and
    /// `natt-buddy-recruit-amule`. Built by hand (`--build-arg AMULE_DEBUG=1`);
    /// this subcommand never builds it.
    #[arg(long, default_value = DEFAULT_AMULE_DEBUG_IMAGE)]
    pub(crate) amule_image: String,
    /// Arm Kad-UDP crypt on that aMule (`AMULE_KAD_CRYPT=1`).
    #[arg(long)]
    pub(crate) kad_crypt: bool,
    /// `natt-udp-selfcheck-amule` only: the Low-ID-buddy recipe
    /// — hold aMule's UDP verdict firewalled until it holds a buddy whose
    /// hello carries a server-assigned Low ID, then release it and share.
    #[arg(long)]
    pub(crate) low_id_buddy: bool,
    /// `natt-buddy-recruit-amule` only: stand no `ed2ksrv` on the WAN, so the
    /// target recruits aMule serverless and firewalled on Kad alone, and its
    /// hello must name the Kad-firewalled id `1`.
    #[arg(long)]
    pub(crate) no_server: bool,
    /// `natt-server-punch-symmetric` only: run both peers with
    /// `natt.port_prediction = birthday` and the Kad observers that tell each
    /// its own mapping. `natt-server-punch-one-symmetric` always does.
    #[arg(long)]
    pub(crate) port_prediction: bool,
    /// The rmule-tools driver image the NAT-T drivers run from.
    #[arg(long, default_value = DEFAULT_RMULE_TOOLS_IMAGE)]
    pub(crate) rmule_tools_image: String,
    /// Dockerfile for the rmule-tools driver image.
    #[arg(long, default_value = DEFAULT_RMULE_TOOLS_DOCKERFILE)]
    pub(crate) rmule_tools_dockerfile: PathBuf,
    /// Build context for the rmule-tools driver image (the repo root).
    #[arg(long, default_value = ".")]
    pub(crate) rmule_tools_build_context: PathBuf,
    /// The natgw image — the gateway the punch flows stand their peers behind,
    /// and what bench-doctor probes the kernel with.
    #[arg(long, default_value = DEFAULT_NATGW_IMAGE)]
    pub(crate) natgw_image: String,
    /// Build context for the natgw image.
    #[arg(long, default_value = DEFAULT_NATGW_BUILD_CONTEXT)]
    pub(crate) natgw_build_context: PathBuf,
    /// The ed2k-server coordinator image.
    #[arg(long, default_value = DEFAULT_ED2KSRV_IMAGE)]
    pub(crate) ed2ksrv_image: String,
    /// Build context for the ed2k-server image (its own source tree).
    #[arg(long, default_value = DEFAULT_ED2KSRV_BUILD_CONTEXT)]
    pub(crate) ed2ksrv_build_context: PathBuf,
    /// The bench `config.toml` the coordinator runs on; its `this_ip` is
    /// rendered per run and the file is bind-mounted over the image's baked
    /// upstream config.
    #[arg(long, default_value = DEFAULT_ED2KSRV_CONFIG)]
    pub(crate) ed2ksrv_config: PathBuf,
    /// The reflector image, required in the same run as any negative verdict.
    #[arg(long, default_value = DEFAULT_NATPROBE_IMAGE)]
    pub(crate) natprobe_image: String,
    /// Build context for the reflector image.
    #[arg(long, default_value = DEFAULT_NATPROBE_BUILD_CONTEXT)]
    pub(crate) natprobe_build_context: PathBuf,
    /// Per-step readiness timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
}

fn parse_natt_flow(value: &str) -> std::result::Result<NattFlow, String> {
    NattFlow::from_name(value).map_err(|error: anyhow::Error| error.to_string())
}

/// Run one NAT-traversal flow.
///
/// # Errors
/// If the bench cannot be built or a driver never produced a row.
pub(crate) fn natt(args: NattArgs) -> Result<()> {
    let mut contexts: Vec<(&str, &Path)> = vec![args.capture.build_context()];
    if args.flow.needs_amule_kno() {
        contexts.push(("amule-kno", &args.amule_kno_build_context));
    }
    if args.flow.needs_ed2ksrv() {
        contexts.push(("ed2ksrv", &args.ed2ksrv_build_context));
    }
    args.bench.prepare(&contexts)?;
    // `natgw` and `natprobe` rebuild on every row that stands a gateway up
    // regardless of `--build-images`, so their contexts are validated
    // unconditionally too.
    if args.flow.needs_natprobe() {
        validate_build_context_dir("natgw", &args.natgw_build_context)?;
        validate_build_context_dir("natprobe", &args.natprobe_build_context)?;
    }

    let (run_dir, layout) = args.bench.create_run()?;
    write_resolved_config(
        &run_dir,
        &NatResolvedConfig {
            flow: args.flow.name(),
            build_images: args.bench.build_images,
            skip_build: args.bench.skip_build,
            keep_containers: args.bench.keep_containers,
            container_runtime: args.bench.container_runtime.clone(),
            timeout_secs: args.timeout,
            images: vec![
                if args.flow.needs_amule_debug() {
                    args.amule_image.clone()
                } else {
                    args.amule_kno_image.clone()
                },
                args.capture.capture_image.clone(),
                args.rmule_tools_image.clone(),
            ],
            detail: vec![args.flow.name().to_owned()],
            public_kad_used: false,
        },
    )?;
    println!("run_dir={}", run_dir.display());

    run_natt(NattOptions {
        flow: args.flow,
        layout: &layout,
        container_runtime: &args.bench.container_runtime,
        build_images: args.bench.build_images,
        amule_kno_image: &args.amule_kno_image,
        amule_kno_build_context: &args.amule_kno_build_context,
        amule_image: &args.amule_image,
        kad_crypt: args.kad_crypt,
        low_id_buddy: args.low_id_buddy,
        no_server: args.no_server,
        port_prediction: args.port_prediction,
        capture_image: &args.capture.capture_image,
        capture_build_context: &args.capture.capture_build_context,
        rmule_tools_image: &args.rmule_tools_image,
        rmule_tools_dockerfile: &args.rmule_tools_dockerfile,
        rmule_tools_build_context: &args.rmule_tools_build_context,
        natgw_image: &args.natgw_image,
        natgw_build_context: &args.natgw_build_context,
        ed2ksrv_image: &args.ed2ksrv_image,
        ed2ksrv_build_context: &args.ed2ksrv_build_context,
        ed2ksrv_config: &args.ed2ksrv_config,
        natprobe_image: &args.natprobe_image,
        natprobe_build_context: &args.natprobe_build_context,
        keep_containers: args.bench.keep_containers,
        timeout_secs: args.timeout,
    })
}
