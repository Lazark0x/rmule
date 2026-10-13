//! The bench every IPv6-dialect flow shares: one dual-stack fake-public WAN, the
//! bodies the flow needs, a **Capture Sidecar** on the body under observation,
//! and one-shot `rmule-tools ipv6 …` driver containers beside them.
//!
//! Two orderings are load-bearing. The **tap attaches before any driver runs**,
//! because a hello exchange is over in milliseconds and a sidecar that is still
//! attaching writes a 24-byte pcap that reads like a **Documented Absence**.
//! And the **bodies settle before the first dial**, because kno's aMule only
//! classifies its own IPv6 on an accept path, so a dial that lands before its
//! interface scan finishes measures the scan rather than the dialect.

use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::bench_doctor::{CAP_DAEMON_IPV6, DoctorReport, SkipReason};
use crate::docker::{InternalNetwork, RunContainer};
use crate::fake_public::subnet_cidr;
use crate::fake_public_v6::FakePublicV6Plan;
use crate::flow::bench::{Bench, DEFAULT_TAP_INTERFACE, run_checked};
use crate::flow::ed2ksrv::Ed2ksrvImage;
use crate::flow::gate::wait_for_container_log;
use crate::flow::nat::dialect::verdict::{Body, Claim, Ipv6Verdict, label, write};
use crate::flow::nat::dialect::{Ipv6Flow, WAN_SUBNET_INDEX, WAN_V6_NET};
use crate::flow::nat::synthetic::{SyntheticFile, write_hashed};
use crate::flow::taps::{Attachment, PerAttachmentTaps, TapRole, TapsRecord, write_taps_record};

/// Every tap records all IP traffic on the body's own attachment. A dialect
/// exchange is TCP hello and UDP reask at once, so a protocol-narrowed filter
/// would leave half of it uncaptured.
pub(crate) const TAP_FILTER: &str = "ip or ip6";

/// The bodies' host indices inside the WAN's `/24` and `/64`. Pinned rather
/// than allocated in attachment order: a verdict names the address a body held,
/// and an address that moved between runs would make two runs uncomparable.
pub(crate) const HOST_AMULE_KNO: usize = 0;
pub(crate) const HOST_EMULEQT: usize = 1;
pub(crate) const HOST_LEGACY_AMULE: usize = 2;
pub(crate) const HOST_ED2KSRV: usize = 3;
pub(crate) const HOST_DRIVER: usize = 4;
/// The second rmule body `ipv6-extsx` stands up: a requester queued on
/// emule-qt, and so the source emule-qt's answer should carry.
pub(crate) const HOST_QUEUED: usize = 5;
/// `ipv6-kad-tags`' **firewalled** rmule publisher, whose buddy row carries
/// `bi6`. It takes the queued requester's index: the two flows
/// never share a bench.
pub(crate) const HOST_KAD_FW_PUBLISHER: usize = 5;
/// `ipv6-kad-tags`' rmule publisher: a Kad node on its own address, because
/// aMule admits one Kad contact per IP (`MAX_CONTACTS_IP`).
pub(crate) const HOST_KAD_PUBLISHER: usize = 6;
/// `ipv6-extsx-kno`'s queued requester, which reaches kno over IPv4 and names
/// its IPv6 in the hello. It takes the Kad publisher's index: the WAN's `/24`
/// holds eight hosts, and the two flows never share a bench.
pub(crate) const HOST_QUEUED_DUAL_STACK: usize = 6;
/// `ipv6-kad-tags`' rmule storer, pinned at the key of the file kno shares.
pub(crate) const HOST_KAD_STORER: usize = 7;
/// `ipv6-kad-tags`' rmule downloader, which fetches kno's file off its Kad
/// row alone. It takes the legacy aMule's index: `ipv6-kad-tags` runs
/// no legacy oracle, and the firewalled publisher already holds `.7`.
pub(crate) const HOST_KAD_DOWNLOADER: usize = 2;
/// `ipv6-extsx-emit`'s third queued requester, which says it holds no part of
/// the file. It takes the Kad storer's index: the two flows never share
/// a bench.
pub(crate) const HOST_QUEUED_HOLDS_NONE: usize = 7;
/// `ipv6-kad-tags`' second rmule storer, pinned beside kno at the key of the
/// file rmule publishes, which kno searches. It takes emule-qt's index:
/// `ipv6-kad-tags`' own emule-qt stands on [`HOST_KAD_EMULEQT`].
pub(crate) const HOST_KAD_BI6_STORER: usize = 1;
/// `ipv6-extsx-emit`'s fourth requester, dual-stack with an IPv6 half no bench
/// network routes. It takes kno's index: the flow runs no kno.
pub(crate) const HOST_QUEUED_UNROUTABLE: usize = 0;
/// `ipv6-extsx-emit`'s rmule downloader, which reads the serving rmule's ExtSX
/// answer. It takes the legacy aMule's index: the flow runs no legacy
/// oracle.
pub(crate) const HOST_EXTSX_DOWNLOADER: usize = 2;
/// `ipv6-kad-tags`' emule-qt, a Kad node sharing a file of its own. A
/// ninth host: every one of the first eight is taken on that flow.
pub(crate) const HOST_KAD_EMULEQT: usize = 8;
/// `ipv6-kad-tags`' rmule storer at the key of emule-qt's file. It takes
/// the driver's index: the flow's one driver leg, kno's IPv6 hello, is over
/// before this body starts.
pub(crate) const HOST_KAD_QT_STORER: usize = HOST_DRIVER;
/// `ipv6-kad-tags`' rmule downloader of emule-qt's file. It takes the
/// Kad publisher's index: that body exited minutes before this one starts, and
/// no routing table on the bench ever admitted it (kno's bin was full).
pub(crate) const HOST_KAD_QT_DOWNLOADER: usize = HOST_KAD_PUBLISHER;
/// `ipv6-kad-tags`' dial-back Core, the second body that answers emule-qt's
/// Kad firewall check. The one host **off** the WAN's first `/24`:
/// emule-qt's routing bin admits two contacts per `/24`
/// (`KadRoutingBin.cpp:59-64`), and it needs three.
pub(crate) const HOST_KAD_QT_DIAL_BACK: usize = 9;
/// `ipv6-kad-tags`' second dial-back Core, beside the first on the
/// WAN's second `/24` (a bin admits two there too). It stands in for kno,
/// whose `HELLO_RES` declares itself UDP-firewalled (`KADMISCOPTIONS` `0x03`)
/// and so is dropped before emule-qt sends it a check
/// (`KadUDPListener.cpp:502-505`), measured on run `1790248139`.
pub(crate) const HOST_KAD_QT_DIAL_BACK_2: usize = 10;
/// How many host indices take an address on the WAN's first `/24`, `.2` up.
/// Past it, hosts continue on the next `/24` from `.2`.
const HOSTS_ON_FIRST_24: usize = 9;
/// Every host index the WAN hands out an address for.
const HOST_COUNT: usize = 11;

/// kno's aMule prints this once its daemon is up.
const AMULE_KNO_READY_MARKER: &str = "rmule-amule-kno-ready";
/// emule-qt's `direct-peer` readiness marker.
const EMULEQT_READY_MARKER: &str = "rmule-emuleqt-direct-peer-ready";
/// emule-qt's own line once it has hashed a file in its shared directory
/// (`SharedFileList.cpp:139`). A source ask for a file it has not finished
/// hashing is answered file-not-found, which would measure the hasher.
const EMULEQT_HASHED_MARKER: &str = "Hashed OK";
/// The shared file `ipv6-extsx` hands emule-qt: one part, so rmule's `0xA4`
/// bundle is exactly `58 83` and emule-qt's requester-status gate
/// (`KnownFile.cpp:771`) reads the empty status an unextended request leaves.
const EXTSX_SHARED_BYTES: u64 = 1 << 20;

/// How long a body is left to finish binding its sockets and scanning its
/// interfaces after its readiness marker. The marker says the entrypoint
/// launched the daemon, not that it has decided what its own address is.
const BODY_SETTLE_SECS: u64 = 12;

/// The flow's inputs.
pub struct Ipv6DialectOptions<'a> {
    /// Which flow to run.
    pub flow: Ipv6Flow,
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
    /// emule-qt's `emulecored` image (cherry-pick `73fff714`).
    pub emuleqt_image: &'a str,
    /// Its build context.
    pub emuleqt_build_context: &'a Path,
    /// The stock aMule 2.3.3 image — the legacy oracle.
    pub amule_image: &'a str,
    /// Its build context.
    pub amule_build_context: &'a Path,
    /// The `ed2ksrv` image.
    pub ed2ksrv_image: &'a str,
    /// Its build context.
    pub ed2ksrv_build_context: &'a Path,
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
    /// The `natgw` image, which is what **Bench Doctor** probes the kernel with.
    pub natgw_image: &'a str,
    /// Build context for the natgw image, built before the doctor runs.
    pub natgw_build_context: &'a Path,
    /// `ipv6-kad-tags`: arm Kad datagram obfuscation on the emule-qt leg's
    /// rmule bodies, for the verify-key three-way.
    pub rmule_kad_crypt: bool,
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
    /// The IPv6 address each host index holds.
    pub(crate) v6: Vec<String>,
    /// The bodies stood up, for the verdict.
    pub(crate) bodies: Vec<Body>,
    /// Whether the `ed2ksrv` counterparty image was present to stand up at all.
    /// A bench that never built it cannot measure the server's own silence, and
    /// the flow says which kind of absence it is recording.
    pub(crate) ed2ksrv_present: bool,
    /// The file the observed body shares, for the flows that need it to
    /// share one (emule-qt in `ipv6-extsx`, kno in `ipv6-kad-tags`).
    pub(crate) shared: Option<SyntheticFile>,
    /// The file rmule publishes a source for without sharing it
    /// (`ipv6-kad-tags`).
    pub(crate) published: Option<SyntheticFile>,
}

impl Stage {
    /// One host's IPv4 address on the WAN.
    pub(crate) fn v4(&self, host: usize) -> &str {
        &self.v4[host]
    }

    /// One host's IPv6 address on the WAN.
    pub(crate) fn v6(&self, host: usize) -> &str {
        &self.v6[host]
    }
}

/// Stand the bench up, drive the flow, and write its verdict.
///
/// # Errors
/// If the bench cannot be built or a driver never produced a row.
pub(crate) fn run(options: Ipv6DialectOptions<'_>) -> Result<()> {
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

fn drive(bench: &mut Bench, options: &Ipv6DialectOptions<'_>) -> Result<()> {
    let flow = options.flow;
    let suffix = run_suffix(options.layout)?;
    // The doctor decides before anything but its own image is built.
    let doctor = bench.examine_doctor(
        "natgw",
        options.natgw_image,
        options.natgw_build_context,
        &suffix,
    )?;
    if let Err(skip) = doctor.require(
        &[CAP_DAEMON_IPV6],
        "an IPv6 dialect exchange against a pinned counterparty",
    ) {
        return write_skip(options.layout, flow, &doctor, &skip);
    }
    build_images(bench, options)?;

    let leg_dir = options.layout.ipv6_dir().join(flow.name());
    fs::create_dir_all(&leg_dir).with_context(|| format!("create {}", leg_dir.display()))?;
    fs::create_dir_all(options.layout.docker_dir())?;

    let subnet_v4 = wan_subnet_v4(flow)?;
    let plan = FakePublicV6Plan::for_network(WAN_V6_NET)?;
    let network = format!("rmule-interop-v6wan-{suffix}");
    bench.create_extra_network(
        &network,
        bench.docker.create_internal_network(
            InternalNetwork::new(&network)
                .subnet_v4(&subnet_v4)
                .subnet_v6(plan.subnet()),
        ),
        "create the dual-stack fake-public WAN",
    )?;

    let mut stage = Stage {
        network: network.clone(),
        leg_dir: leg_dir.clone(),
        v4: (0..HOST_COUNT).map(wan_v4).collect::<Result<Vec<_>>>()?,
        v6: (0..HOST_COUNT)
            .map(|host| plan.address(u16::try_from(host).unwrap_or_default()))
            .collect::<Result<Vec<_>>>()?,
        bodies: Vec::new(),
        ed2ksrv_present: false,
        shared: None,
        published: None,
    };
    if flow == Ipv6Flow::ExtSx {
        let dir = leg_dir.join("shared");
        fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        stage.shared = Some(write_hashed(&dir, EXTSX_SHARED_BYTES)?);
    }

    let timeout = Duration::from_secs(options.timeout_secs);
    let observed = start_bodies(bench, options, &mut stage, &suffix, timeout)?;

    // The tap attaches to the body under observation *before* any driver runs:
    // a hello exchange is over in milliseconds. A flow whose body could not be
    // stood up taps nothing and says so with an empty tap list.
    let taps = match observed.as_deref() {
        Some(container) => Some(PerAttachmentTaps::start(
            bench,
            options.capture_image,
            container,
            &format!("rmule-interop-v6tap-{suffix}"),
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

    let (claims, note) = super::legs::drive(bench, options, &stage)?;

    let tap_rows = match (&taps, observed.as_deref()) {
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
            rows
        }
        _ => Vec::new(),
    };

    let (verdict, detail) = label(&claims);
    write(
        options.layout.root(),
        &Ipv6Verdict {
            flow: flow.name(),
            verdict,
            detail,
            note,
            skip_reason: None,
            wan_subnet_v4: subnet_v4,
            wan_subnet_v6: plan.subnet(),
            bodies: stage.bodies.clone(),
            taps: tap_rows,
            capabilities: doctor.capabilities,
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

fn build_images(bench: &Bench, options: &Ipv6DialectOptions<'_>) -> Result<()> {
    let flow = options.flow;
    if options.build_images {
        if flow.needs_amule_kno() {
            bench
                .build_amule_kno_image(options.amule_kno_image, options.amule_kno_build_context)?;
        }
        if flow.needs_emuleqt() {
            bench.build_image(
                "emuleqt",
                options.emuleqt_image,
                options.emuleqt_build_context,
            )?;
        }
        if flow.needs_legacy_amule() {
            bench.build_image("aMule", options.amule_image, options.amule_build_context)?;
        }
        if flow.needs_ed2ksrv() {
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
    // Always rebuilt: it carries the `ipv6` drivers, which are workspace code.
    bench.build_rmule_tools_image(
        options.rmule_tools_image,
        options.rmule_tools_dockerfile,
        options.rmule_tools_build_context,
    )?;
    Ok(())
}

/// Start every body the flow needs and return the container the tap watches —
/// the body whose bytes the flow's strongest claim rests on.
fn start_bodies(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &mut Stage,
    suffix: &str,
    timeout: Duration,
) -> Result<Option<String>> {
    let flow = options.flow;
    if flow == Ipv6Flow::KadTags {
        return super::kad_tags::start(bench, options, stage, suffix, timeout).map(Some);
    }
    if flow == Ipv6Flow::ExtSxKno {
        return super::ext_sx_kno::start(bench, options, stage, suffix, timeout).map(Some);
    }
    if flow == Ipv6Flow::ExtSxEmit {
        return super::ext_sx_emit::start(bench, options, stage, suffix, timeout).map(Some);
    }
    if flow == Ipv6Flow::DownloadRung0 {
        return super::download_rung0::start(bench, options, stage, suffix, timeout).map(Some);
    }
    if flow == Ipv6Flow::ExtSxCore {
        return super::ext_sx_core::start(bench, options, stage, suffix, timeout).map(Some);
    }
    if flow == Ipv6Flow::HelloSurface {
        return super::hello_surface::start(bench, options, stage, suffix, timeout);
    }
    let mut observed = None;

    if flow.needs_amule_kno() {
        let name = format!("rmule-interop-v6kno-{suffix}");
        bench.start_extra(
            &name,
            RunContainer::new(options.amule_kno_image)
                .detach()
                .name(&name)
                .network(&stage.network)
                .ip(stage.v4(HOST_AMULE_KNO))
                .ip6(stage.v6(HOST_AMULE_KNO))
                .cap_add("NET_ADMIN"),
            "run kno's aMule at its Fork Pin",
        )?;
        wait_for_container_log(&bench.docker, &name, AMULE_KNO_READY_MARKER, timeout)?;
        stage.bodies.push(Body {
            name: "amule-kno".to_owned(),
            image: options.amule_kno_image.to_owned(),
            pin: "kno/amule integration/network-parity ab483654".to_owned(),
            address_v4: stage.v4(HOST_AMULE_KNO).to_owned(),
            address_v6: stage.v6(HOST_AMULE_KNO).to_owned(),
        });
        observed = Some(name);
    }

    if flow.needs_emuleqt() {
        let name = format!("rmule-interop-v6qt-{suffix}");
        let mut container = RunContainer::new(options.emuleqt_image)
            .detach()
            .name(&name)
            .network(&stage.network)
            .ip(stage.v4(HOST_EMULEQT))
            .ip6(stage.v6(HOST_EMULEQT))
            .cap_add("NET_ADMIN")
            .env("EMULEQT_SCENARIO_MODE", "direct-peer")
            // Legal user preferences, not protocol changes: crypt on is
            // what opens the counterparty's own
            // `shouldReceiveCryptUDPPackets()` gate, without which it
            // answers every client datagram in the clear.
            .env("EMULEQT_CRYPT_SUPPORTED", "true")
            .env("EMULEQT_CRYPT_REQUESTED", "true");
        if let Some(shared) = &stage.shared {
            let dir = shared
                .path
                .parent()
                .context("the shared file has a directory")?;
            container = container.volume(dir, "/incoming");
        }
        bench.start_extra(&name, container, "run emule-qt's emulecored")?;
        wait_for_container_log(&bench.docker, &name, EMULEQT_READY_MARKER, timeout)?;
        if stage.shared.is_some() {
            wait_for_container_log(&bench.docker, &name, EMULEQT_HASHED_MARKER, timeout)?;
        }
        stage.bodies.push(Body {
            name: "emuleqt".to_owned(),
            image: options.emuleqt_image.to_owned(),
            pin: "ModderMule/emule-qt 73fff714".to_owned(),
            address_v4: stage.v4(HOST_EMULEQT).to_owned(),
            address_v6: stage.v6(HOST_EMULEQT).to_owned(),
        });
        // emule-qt is the dialect's reference body, so where it stands up it is
        // the one the tap watches.
        observed = Some(name);
    }

    if flow.needs_legacy_amule() {
        let name = format!("rmule-interop-v6legacy-{suffix}");
        bench.start_extra(
            &name,
            RunContainer::new(options.amule_image)
                .detach()
                .name(&name)
                .network(&stage.network)
                .ip(stage.v4(HOST_LEGACY_AMULE))
                .cap_add("NET_ADMIN")
                .env("AMULE_SCENARIO_MODE", "direct-peer"),
            "run the legacy stock aMule 2.3.3",
        )?;
        wait_for_container_log(
            &bench.docker,
            &name,
            "rmule-amule-direct-peer-ready",
            timeout,
        )?;
        stage.bodies.push(Body {
            name: "amule".to_owned(),
            image: options.amule_image.to_owned(),
            pin: "aMule 2.3.3, Ubuntu 24.04 package".to_owned(),
            address_v4: stage.v4(HOST_LEGACY_AMULE).to_owned(),
            address_v6: String::new(),
        });
    }

    if flow.needs_ed2ksrv() && image_present(bench, options.ed2ksrv_image) {
        stage.ed2ksrv_present = true;
        let name = format!("rmule-interop-v6srv-{suffix}");
        let ed2ksrv = Ed2ksrvImage::check(&bench.docker, options.ed2ksrv_image)?;
        bench.start_extra(
            &name,
            ed2ksrv
                .container()
                .detach()
                .name(&name)
                .network(&stage.network)
                .ip(stage.v4(HOST_ED2KSRV))
                .cap_add("NET_ADMIN"),
            "run the ed2k-server counterparty",
        )?;
        stage.bodies.push(Body {
            name: "ed2ksrv".to_owned(),
            image: options.ed2ksrv_image.to_owned(),
            pin: format!(
                "{} — no IPv6; awaiting an upstream build with IPv6",
                ed2ksrv.pin(),
            ),
            address_v4: stage.v4(HOST_ED2KSRV).to_owned(),
            address_v6: String::new(),
        });
        observed = Some(name);
    }

    Ok(observed)
}

/// The WAN's IPv4 subnet. `ipv6-kad-tags` widens it to a `/23` so one body can
/// stand on a second `/24` ([`HOST_KAD_QT_DIAL_BACK`]); every other flow keeps
/// the `/24` it was measured on. The gateway stays `.1` of the first `/24`.
///
/// # Errors
/// If the fake-public plan has no prefix at [`WAN_SUBNET_INDEX`].
fn wan_subnet_v4(flow: Ipv6Flow) -> Result<String> {
    let cidr = subnet_cidr(WAN_SUBNET_INDEX)?;
    Ok(if flow == Ipv6Flow::KadTags {
        cidr.replace("/24", "/23")
    } else {
        cidr
    })
}

/// One host index's IPv4 on the WAN: `.2` up on the first `/24`, then `.2` up
/// on the next. Pinned per index, never allocated, so a verdict's addresses
/// compare across runs.
///
/// # Errors
/// If the fake-public plan has no prefix at [`WAN_SUBNET_INDEX`].
fn wan_v4(host: usize) -> Result<String> {
    let cidr = subnet_cidr(WAN_SUBNET_INDEX)?;
    let base: Ipv4Addr = cidr
        .trim_end_matches("/24")
        .parse()
        .with_context(|| format!("the WAN prefix {cidr}"))?;
    let (block, index) = if host < HOSTS_ON_FIRST_24 {
        (0, host)
    } else {
        (1, host - HOSTS_ON_FIRST_24)
    };
    let offset = u32::try_from(block * 256 + 2 + index).context("a WAN host index")?;
    Ok(Ipv4Addr::from(u32::from(base) + offset).to_string())
}

/// Whether an image is present locally. A missing counterparty image is a
/// recorded condition, not a failure: the flow writes what it could and could
/// not measure, which is the only honest thing to do about an absent pin.
fn image_present(bench: &Bench, tag: &str) -> bool {
    bench
        .docker
        .inspect_image(tag.to_owned())
        .to_command()
        .output()
        .is_ok_and(|output| output.status.success())
}

/// Run one `rmule-tools ipv6 …` driver as a one-shot container on the WAN,
/// retaining its whole output beside the row it wrote.
///
/// A driver that exits unsuccessfully is an error: the drivers are written so
/// that a silent counterparty is a *row*, so a non-zero exit means the driver
/// itself could not run, which is a broken bench rather than a measurement.
pub(crate) fn run_driver(
    bench: &Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
    leg: &str,
    args: &[String],
) -> Result<()> {
    let mut container = RunContainer::new(options.rmule_tools_image)
        .remove_after_exit()
        .network(&stage.network)
        .ip(stage.v4(HOST_DRIVER))
        .ip6(stage.v6(HOST_DRIVER))
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
    println!("ipv6-dialect leg={leg} exit={:?}", output.status.code());
    if !output.status.success() {
        bail!(
            "the {leg} driver exited unsuccessfully: {}",
            text.lines().rev().take(6).collect::<Vec<_>>().join(" | ")
        );
    }
    Ok(())
}

/// Start one `rmule-tools ipv6 …` driver detached at `host`, owned by the bench
/// for teardown, and block until it prints `marker` — for a body that has to
/// hold its link while another driver runs. Returns the container and whether
/// the marker came: a body that never reached it is a measurement the flow
/// records, not a broken bench.
///
/// # Errors
/// If the container cannot start.
pub(crate) fn start_detached_driver(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
    role: &str,
    host: usize,
    args: &[String],
    marker: &str,
) -> Result<(String, bool)> {
    let name = container_name(options.layout, role)?;
    let mut container = RunContainer::new(options.rmule_tools_image)
        .detach()
        .name(&name)
        .network(&stage.network)
        .ip(stage.v4(host))
        .ip6(stage.v6(host))
        .cap_add("NET_ADMIN")
        .volume(&stage.leg_dir, "/out");
    for arg in args {
        container = container.arg(arg.clone());
    }
    bench.start_extra(&name, container, &format!("run the {role} driver"))?;
    let reached = wait_for_container_log(
        &bench.docker,
        &name,
        marker,
        Duration::from_secs(options.timeout_secs),
    )
    .is_ok();
    Ok((name, reached))
}

/// Block until a detached driver exits, so the row it writes on exit is there
/// to read.
///
/// # Errors
/// If `docker wait` cannot run.
pub(crate) fn wait_for_exit(bench: &Bench, container: &str) -> Result<()> {
    run_checked(
        bench.docker.wait(container.to_owned()),
        "wait for a detached driver",
    )
    .map(|_| ())
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

/// The container name a flow's body took, derived the same way `start_bodies`
/// derives it.
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

fn write_skip(
    layout: &RunLayout,
    flow: Ipv6Flow,
    doctor: &DoctorReport,
    skip: &SkipReason,
) -> Result<()> {
    eprintln!("{} skipped: {}", flow.name(), skip.reason);
    write(
        layout.root(),
        &Ipv6Verdict {
            flow: flow.name(),
            verdict: "SKIPPED",
            detail: "the bench lacks a capability this flow needs; nothing was measured."
                .to_owned(),
            note: String::new(),
            skip_reason: Some(skip.reason.clone()),
            wan_subnet_v4: wan_subnet_v4(flow)?,
            wan_subnet_v6: FakePublicV6Plan::for_network(WAN_V6_NET)?.subnet(),
            bodies: Vec::new(),
            taps: Vec::new(),
            capabilities: doctor.capabilities.clone(),
            claim: Vec::<Claim>::new(),
        },
    )
}

/// Join a path into a driver argument under the container's `/out` mount.
pub(crate) fn out(name: &str) -> String {
    format!("/out/{name}")
}

#[cfg(test)]
mod tests {
    use super::{
        HOST_KAD_EMULEQT, HOST_KAD_QT_DIAL_BACK, HOST_KAD_QT_DIAL_BACK_2, wan_subnet_v4, wan_v4,
    };
    use crate::flow::nat::dialect::Ipv6Flow;

    /// The ninth host closes the first `/24` at `.10`; the tenth opens the
    /// next `/24`, which only `ipv6-kad-tags`' `/23` holds.
    #[test]
    fn the_tenth_host_opens_the_second_24_inside_kad_tags_23() {
        assert_eq!(wan_v4(HOST_KAD_EMULEQT).unwrap(), "45.55.200.10");
        assert_eq!(wan_v4(HOST_KAD_QT_DIAL_BACK).unwrap(), "45.55.201.2");
        assert_eq!(wan_v4(HOST_KAD_QT_DIAL_BACK_2).unwrap(), "45.55.201.3");
        assert_eq!(wan_subnet_v4(Ipv6Flow::KadTags).unwrap(), "45.55.200.0/23");
        assert_eq!(wan_subnet_v4(Ipv6Flow::ExtSx).unwrap(), "45.55.200.0/24");
    }
}
