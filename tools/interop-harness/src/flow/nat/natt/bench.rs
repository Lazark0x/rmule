//! The bench the NAT-traversal flows share: one fake-public WAN, the bodies the flow
//! needs, a **Capture Sidecar** on the body under observation, and one-shot
//! `rmule-tools` driver containers beside it.
//!
//! Two orderings are load-bearing, and both were learned on the IPv6-dialect bench. The **tap
//! attaches before any driver runs**, because a NAT-T exchange is over in
//! milliseconds and a sidecar still attaching writes a 24-byte pcap that reads
//! like a **Documented Absence**. And the **body settles before the first
//! frame**, because kno's aMule builds its uTP context and its listen socket
//! after the entrypoint's readiness marker, and a `ST_SYN` that lands before
//! then measures the startup rather than the transport.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::bench_doctor::{
    BenchDoctor, CAP_BR_NETFILTER, CAP_CONNTRACK, CAP_CONNTRACK_UDP_TIMEOUT, CAP_NFTABLES,
    DoctorReport, SkipReason,
};
use crate::docker::{InternalNetwork, RunContainer};
use crate::fake_public::{MAX_NODES_PER_SUBNET, fake_public_address, subnet_cidr};
use crate::flow::bench::{Bench, DEFAULT_TAP_INTERFACE};
use crate::flow::gate::wait_for_container_log;
use crate::flow::nat::claims::{Body, Claim, label};
use crate::flow::nat::natt::NattFlow;
use crate::flow::nat::natt::verdict::{NattVerdict, WireRow, write};
use crate::flow::taps::{Attachment, PerAttachmentTaps, TapRole, TapsRecord, write_taps_record};

/// Every tap records all IP traffic on the body's own attachment. A NAT-T
/// exchange is a TCP hello and a UDP `0xB2` conversation at once, so a
/// protocol-narrowed capture filter would leave half of it unrecorded; the
/// **Wire Rows** narrow afterwards, off the same whole pcap.
pub(crate) const TAP_FILTER: &str = "ip or ip6";

/// The bodies' host indices inside the WAN's `/24`. Pinned rather than
/// allocated in attachment order: a verdict names the address a body held, and
/// an address that moved between runs would make two runs uncomparable.
pub(crate) const HOST_AMULE_KNO: usize = 0;
pub(crate) const HOST_DRIVER: usize = 4;

/// kno's aMule prints this once its daemon is up.
const AMULE_KNO_READY_MARKER: &str = "rmule-amule-kno-ready";

/// How long a body is left to finish binding its sockets after its readiness
/// marker. The marker says the entrypoint launched the daemon, not that its
/// uTP context exists.
const BODY_SETTLE_SECS: u64 = 12;

/// The flow's inputs.
pub struct NattOptions<'a> {
    /// Which NAT-traversal flow to run.
    pub flow: NattFlow,
    /// The run dir.
    pub layout: &'a RunLayout,
    /// The container runtime to drive.
    pub container_runtime: &'a str,
    /// Build the project-owned images first.
    pub build_images: bool,
    /// kno's aMule image (Fork Pin `ab483654`).
    pub amule_kno_image: &'a str,
    /// Its build context.
    pub amule_kno_build_context: &'a Path,
    /// Stock aMule on the **debug** image, pre-built by hand:
    /// `--build-images` would build the release package under this tag.
    pub amule_image: &'a str,
    /// Arm Kad-UDP crypt on the aMule body (`AMULE_KAD_CRYPT=1`).
    pub kad_crypt: bool,
    /// Run `natt-server-punch-symmetric` with `natt.port_prediction = birthday`
    /// and its Kad observers, to measure that the knob leaves a
    /// both-hard pair a negative and never a port scan. The one-symmetric row
    /// always runs with it.
    pub port_prediction: bool,
    /// `natt-udp-selfcheck-amule`'s Low-ID-buddy recipe: an `ed2ksrv` gives the rmule
    /// root a Low ID, aMule's UDP verdict is held firewalled until it holds
    /// that root as its buddy, then released, then the file is shared.
    pub low_id_buddy: bool,
    /// `natt-buddy-recruit-amule` with no `ed2ksrv` on the WAN: the target is
    /// serverless and firewalled on Kad alone, so the hello aMule keeps it as
    /// a buddy for must name the Kad-firewalled id `1`.
    pub no_server: bool,
    /// The tcpdump sidecar image.
    pub capture_image: &'a str,
    /// Its build context.
    pub capture_build_context: &'a Path,
    /// The `rmule-tools` driver image, always rebuilt from the workspace.
    pub rmule_tools_image: &'a str,
    /// Its Dockerfile.
    pub rmule_tools_dockerfile: &'a Path,
    /// Its build context (the repo root).
    pub rmule_tools_build_context: &'a Path,
    /// The `natgw` image — the **NAT Gateway** the punch flows stand their
    /// peers behind, and what **Bench Doctor** probes the kernel with.
    pub natgw_image: &'a str,
    /// Its build context.
    pub natgw_build_context: &'a Path,
    /// The `ed2ksrv` coordinator image.
    pub ed2ksrv_image: &'a str,
    /// Its build context.
    pub ed2ksrv_build_context: &'a Path,
    /// The bench `config.toml` the coordinator runs on. Rendered per run — its
    /// `this_ip` must equal the container's own fake-public address — and
    /// bind-mounted over the image's baked upstream config. Authored
    /// counterparty *state* is sanctioned (ADR-0045); the binary is untouched.
    pub ed2ksrv_config: &'a Path,
    /// The `natprobe` **Reflector Probe** image, required in the same run as
    /// any negative verdict.
    pub natprobe_image: &'a str,
    /// Its build context.
    pub natprobe_build_context: &'a Path,
    /// Keep containers after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget.
    pub timeout_secs: u64,
}

/// The staged bench a flow's legs are driven against.
pub(crate) struct Stage {
    /// The run-suffixed WAN network name.
    pub(crate) network: String,
    /// Where this flow's artifacts go.
    pub(crate) leg_dir: PathBuf,
    /// The IPv4 address each host index holds.
    pub(crate) v4: Vec<String>,
    /// The bodies stood up, for the verdict.
    pub(crate) bodies: Vec<Body>,
}

impl Stage {
    /// One host's IPv4 address on the WAN.
    pub(crate) fn v4(&self, host: usize) -> &str {
        &self.v4[host]
    }
}

/// Stand the bench up, drive the flow, and write its verdict.
///
/// # Errors
/// If the bench cannot be built or a driver never produced a row.
pub(crate) fn run(options: NattOptions<'_>) -> Result<()> {
    anyhow::ensure!(
        !options.no_server || options.flow == NattFlow::BuddyRecruitAmule,
        "--no-server is a knob of natt-buddy-recruit-amule alone; {} ignores it",
        options.flow.name()
    );
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    let result = drive(&mut bench, &options);
    if result.is_err() {
        bench.collect_failure_logs(options.layout);
    }
    bench.cleanup_best_effort();
    result
}

fn drive(bench: &mut Bench, options: &NattOptions<'_>) -> Result<()> {
    let flow = options.flow;
    build_images(bench, options)?;

    let suffix = run_suffix(options.layout)?;
    // Recorded, never required: `natt-caps-utp` puts no gateway on the path,
    // so it has no capability to be short of — and a capability list in the
    // verdict is what lets a later reader tell this run's bench from the one a
    // gateway flow needed.
    let doctor: DoctorReport = BenchDoctor::new(&bench.docker, options.natgw_image, &suffix)
        .examine()
        .context("run the bench doctor")?;

    let leg_dir = options.layout.nat_dir().join(flow.name());
    fs::create_dir_all(&leg_dir).with_context(|| format!("create {}", leg_dir.display()))?;
    fs::create_dir_all(options.layout.docker_dir())?;

    let subnet_v4 = subnet_cidr(super::WAN_SUBNET_INDEX)?;
    if let Some(nat_type) = flow.nat_type() {
        // A gateway-bearing row stands its own topology up: two LANs, two
        // gateways and two long-lived driver containers, which is a different
        // shape from the single shared WAN below rather than a variation of it.
        if let Err(skip) = doctor.require(
            &[
                CAP_NFTABLES,
                CAP_CONNTRACK,
                CAP_CONNTRACK_UDP_TIMEOUT,
                CAP_BR_NETFILTER,
            ],
            "the NAT Type Proof every NAT-traversal gateway verdict cites",
        ) {
            return write_skip(options.layout, flow, &doctor, &skip, &subnet_v4);
        }
        let (driven, wire, taps) = if flow == NattFlow::UdpSelfCheckAmule {
            super::buddy::selfcheck::amule::drive(bench, options, nat_type, &suffix, &leg_dir)?
        } else if flow == NattFlow::BuddyRecruitAmule {
            super::buddy::recruit_amule::drive(bench, options, nat_type, &suffix, &leg_dir)?
        } else if matches!(
            flow,
            NattFlow::UdpSelfCheckCone | NattFlow::UdpSelfCheckRemapped
        ) {
            super::buddy::selfcheck::drive(bench, options, flow, nat_type, &suffix, &leg_dir)?
        } else if flow.is_buddy_rendezvous() {
            super::buddy::drive(bench, options, nat_type, &suffix, &leg_dir)?
        } else {
            super::punch::drive(bench, options, nat_type, &suffix, &leg_dir)?
        };
        return finish(options, &doctor, &subnet_v4, driven, taps, wire);
    }
    let network = format!("rmule-interop-nattwan-{suffix}");
    bench.create_extra_network(
        &network,
        bench
            .docker
            .create_internal_network(InternalNetwork::new(&network).subnet_v4(&subnet_v4)),
        "create the fake-public WAN",
    )?;

    let mut stage = Stage {
        network: network.clone(),
        leg_dir: leg_dir.clone(),
        v4: (0..=HOST_DRIVER)
            .map(|host| {
                Ok(fake_public_address(super::WAN_SUBNET_INDEX * MAX_NODES_PER_SUBNET + host)?.ip)
            })
            .collect::<Result<Vec<_>>>()?,
        bodies: Vec::new(),
    };

    let timeout = Duration::from_secs(options.timeout_secs);
    let observed = start_bodies(bench, options, &mut stage, &suffix, timeout)?;

    let taps = match observed.as_deref() {
        Some(container) => Some(PerAttachmentTaps::start(
            bench,
            options.capture_image,
            container,
            &format!("rmule-interop-natttap-{suffix}"),
            &leg_dir,
            &[Attachment {
                name: "wan",
                interface: DEFAULT_TAP_INTERFACE,
                role: TapRole::Evidence,
                bpf: TAP_FILTER,
            }],
            timeout,
        )?),
        None => None,
    };

    std::thread::sleep(Duration::from_secs(BODY_SETTLE_SECS));

    let mut driven = super::legs::drive(bench, options, &stage)?;
    driven.bodies = stage.bodies.clone();

    let (tap_rows, wire) = match (&taps, observed.as_deref()) {
        (Some(taps), Some(container)) => {
            let rows = taps.rows(&bench.docker, TAP_FILTER)?;
            write_taps_record(
                &leg_dir,
                &TapsRecord {
                    flow: flow.name(),
                    tapped_container: container.to_owned(),
                    filter: TAP_FILTER.to_owned(),
                    taps: rows.clone(),
                },
            )?;
            let wire = count_wire_rows(bench, taps, &driven.wire)?;
            (rows, wire)
        }
        _ => (Vec::new(), Vec::new()),
    };

    finish(options, &doctor, &subnet_v4, driven, tap_rows, wire)
}

/// Score the claims, write the verdict, and fail the run only on an `absent`
/// one. Shared by both topologies so a gateway row and a bare-WAN row are
/// labelled by the same rule.
fn finish(
    options: &NattOptions<'_>,
    doctor: &DoctorReport,
    subnet_v4: &str,
    driven: Driven,
    taps: Vec<crate::flow::taps::TapRow>,
    wire: Vec<WireRow>,
) -> Result<()> {
    let flow = options.flow;
    let claims = [driven.claims, super::legs::wire_claims(flow, &wire)].concat();
    let (verdict, detail) = label(&claims);
    write(
        options.layout.root(),
        &NattVerdict {
            flow: flow.name(),
            verdict,
            detail,
            note: driven.note,
            tunnel_rose: driven.tunnel_rose,
            skip_reason: None,
            wan_subnet_v4: subnet_v4.to_owned(),
            bodies: driven.bodies,
            taps,
            wire,
            capabilities: doctor.capabilities.clone(),
            claim: claims,
        },
    )?;
    if verdict == "FAIL" {
        bail!(
            "{} did not hold every claim the bench can drive; see {}-verdict.toml",
            flow.name(),
            flow.name()
        );
    }
    Ok(())
}

/// The verdict a flow writes when the bench lacks a capability it needs.
fn write_skip(
    layout: &RunLayout,
    flow: NattFlow,
    doctor: &DoctorReport,
    skip: &SkipReason,
    subnet_v4: &str,
) -> Result<()> {
    eprintln!("{} skipped: {}", flow.name(), skip.reason);
    write(
        layout.root(),
        &NattVerdict {
            flow: flow.name(),
            verdict: "SKIPPED",
            detail: "the bench lacks a capability this flow needs; nothing was measured."
                .to_owned(),
            note: String::new(),
            tunnel_rose: None,
            skip_reason: Some(skip.reason.clone()),
            wan_subnet_v4: subnet_v4.to_owned(),
            bodies: Vec::new(),
            taps: Vec::new(),
            wire: Vec::new(),
            capabilities: doctor.capabilities.clone(),
            claim: Vec::new(),
        },
    )
}

/// Count each declared **Wire Row** off the evidence tap's own pcap.
fn count_wire_rows(
    bench: &Bench,
    taps: &PerAttachmentTaps,
    declared: &[WireRowRequest],
) -> Result<Vec<WireRow>> {
    declared
        .iter()
        .map(|request| {
            let rows = taps.rows(&bench.docker, &request.bpf)?;
            Ok(WireRow {
                name: request.name.clone(),
                bpf: request.bpf.to_string(),
                packets: rows.iter().map(|row| row.packets).sum(),
            })
        })
        .collect()
}

/// One **Wire Row** a leg asked for: a name and what finds it on the evidence
/// tap — a BPF, or the eD2k frames on a reassembled link.
pub(crate) struct WireRowRequest {
    /// The row's stable name.
    pub(crate) name: String,
    /// What counts it.
    pub(crate) bpf: crate::flow::wire_filter::WireFilter,
}

/// What one flow's drive sequence produced.
pub(crate) struct Driven {
    /// Claims settled from the driver rows alone.
    pub(crate) claims: Vec<Claim>,
    /// Bodies the drive sequence stood up itself, beyond the ones
    /// [`start_bodies`] placed on the shared WAN.
    pub(crate) bodies: Vec<Body>,
    /// The **Wire Rows** to count off the tap once the drive is over. The
    /// claims they settle are `legs::wire_claims`', because the counting
    /// happens after the taps are read and a closure carrying that half would
    /// put one flow's scoring in two places.
    pub(crate) wire: Vec<WireRowRequest>,
    /// The standing note a reader needs to interpret the verdict at all.
    pub(crate) note: String,
    /// Whether this run raised a Tunnel, on the one row that is judged per
    /// draw (`natt-server-punch-one-symmetric`); `None` everywhere else,
    /// and when the count was never read. Its own field so the ten-run
    /// tally reads a value, not a note.
    pub(crate) tunnel_rose: Option<bool>,
}

fn build_images(bench: &Bench, options: &NattOptions<'_>) -> Result<()> {
    if options.build_images {
        if options.flow.needs_amule_kno() {
            bench
                .build_amule_kno_image(options.amule_kno_image, options.amule_kno_build_context)?;
        }
        if options.flow.needs_ed2ksrv() || options.low_id_buddy {
            crate::flow::ed2ksrv::build(
                options.ed2ksrv_image,
                options.ed2ksrv_build_context,
                options.layout.root(),
            )?;
        }
        bench.build_image(
            "capture",
            options.capture_image,
            options.capture_build_context,
        )?;
    }
    // Always rebuilt, like `rmule-tools`: each is a 30 s Debian layer plus two
    // `COPY`s, so an edited `entrypoint.sh` or `natgw-proof.sh` reaches the
    // bench without `--build-images`.
    if options.flow.needs_natprobe() {
        bench.build_image("natgw", options.natgw_image, options.natgw_build_context)?;
        bench.build_image(
            "natprobe",
            options.natprobe_image,
            options.natprobe_build_context,
        )?;
    }
    // Always rebuilt: it carries the `natt` drivers, which are workspace code.
    bench.build_rmule_tools_image(
        options.rmule_tools_image,
        options.rmule_tools_dockerfile,
        options.rmule_tools_build_context,
    )?;
    Ok(())
}

/// Start every body the flow needs and return the container the tap watches.
fn start_bodies(
    bench: &mut Bench,
    options: &NattOptions<'_>,
    stage: &mut Stage,
    suffix: &str,
    timeout: Duration,
) -> Result<Option<String>> {
    let mut observed = None;
    if options.flow.needs_amule_kno() {
        let name = format!("rmule-interop-nattkno-{suffix}");
        bench.start_extra(
            &name,
            RunContainer::new(options.amule_kno_image)
                .detach()
                .name(&name)
                .network(&stage.network)
                .ip(stage.v4(HOST_AMULE_KNO))
                .cap_add("NET_ADMIN"),
            "run kno's aMule at its Fork Pin",
        )?;
        wait_for_container_log(&bench.docker, &name, AMULE_KNO_READY_MARKER, timeout)?;
        stage.bodies.push(Body {
            name: "amule-kno".to_owned(),
            image: options.amule_kno_image.to_owned(),
            pin: "kno/amule integration/network-parity ab483654".to_owned(),
            address_v4: stage.v4(HOST_AMULE_KNO).to_owned(),
            address_v6: String::new(),
        });
        observed = Some(name);
    }
    Ok(observed)
}

/// Run one `rmule-tools` driver as a one-shot container on the WAN, retaining
/// its whole output beside the row it wrote.
///
/// A driver that exits unsuccessfully is an error: the drivers are written so
/// that a silent counterparty is a *row*, so a non-zero exit means the driver
/// itself could not run — a broken bench rather than a measurement.
pub(crate) fn run_driver(
    bench: &Bench,
    options: &NattOptions<'_>,
    stage: &Stage,
    leg: &str,
    args: &[String],
) -> Result<()> {
    let mut container = RunContainer::new(options.rmule_tools_image)
        .remove_after_exit()
        .network(&stage.network)
        .ip(stage.v4(HOST_DRIVER))
        .cap_add("NET_ADMIN")
        .volume(&stage.leg_dir, "/out");
    for arg in args {
        container = container.arg(arg.clone());
    }
    let output = bench
        .docker
        .run_container(container)
        .to_command()
        .output()
        .with_context(|| format!("run the {leg} driver"))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    let path = stage.leg_dir.join(format!("{leg}.log"));
    fs::write(&path, &text).with_context(|| format!("write {}", path.display()))?;
    println!("natt leg={leg} exit={:?}", output.status.code());
    if !output.status.success() {
        bail!(
            "the {leg} driver exited unsuccessfully: {}",
            text.lines().rev().take(6).collect::<Vec<_>>().join(" | ")
        );
    }
    Ok(())
}

/// Collect a body's own log into the leg dir and return it, so a claim can
/// quote the counterparty's own line.
pub(crate) fn body_log(bench: &Bench, stage: &Stage, container: &str, leg: &str) -> Result<String> {
    let output = bench
        .docker
        .logs(container.to_owned())
        .to_command()
        .output()
        .with_context(|| format!("docker logs {container}"))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    let path = stage.leg_dir.join(format!("{leg}.log"));
    fs::write(&path, &text).with_context(|| format!("write {}", path.display()))?;
    Ok(text)
}

/// The container name a flow's body took, derived the way `start_bodies` does.
pub(crate) fn container_name(layout: &RunLayout, role: &str) -> Result<String> {
    Ok(format!("rmule-interop-{role}-{}", run_suffix(layout)?))
}

fn run_suffix(layout: &RunLayout) -> Result<String> {
    layout
        .root()
        .file_name()
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned)
        .context("run directory has no utf-8 file name")
}

/// Join a path into a driver argument under the container's `/out` mount.
pub(crate) fn out(name: &str) -> String {
    format!("/out/{name}")
}
