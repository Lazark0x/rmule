//! `natgw-selfproof` (ADR-0092): every **NAT Gateway** type is stood up
//! in turn and the **Reflector Probe** measures, from inside its LAN, what it
//! actually built.
//!
//! This is the flow every later NAT verdict rests on. ADR-0045 as amended makes
//! a punch failure behind a "symmetric" NAT a *fabricated row* unless the NAT
//! type was proven in the same run; proving it once, here, is what lets a NAT-traversal
//! flow cite its gateway's type instead of asserting it. The four legs run
//! sequentially on one WAN and one LAN so the whole proof costs one reflector
//! and one pair of bridges.
//!
//! Each leg writes a complete record into `nat/<nat-type>/`: the gateway's own
//! `nft list ruleset` and `conntrack -L` dumps, the dynamic set, the probe's
//! `nat-probe.toml`, both **Per-Attachment Tap** pcaps, and the `nat-type.toml`
//! that pairs claim with observation. `agrees = false` is a publishable
//! outcome — it says the bench built something other than what it claimed —
//! and the flow publishes it as `FAIL`.
//!
//! A **second** gateway of the same type stands beside the first for the
//! [`pinned_pair`] leg, with its own client, its own LAN and its own mirror of
//! that record under `nat/<nat-type>/peer/`. The reflector answers from the
//! WAN untranslated, so nothing else in this flow can see two gateways
//! colliding over the one port they both pin.

mod pinned_pair;

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::artifacts::RunLayout;
use crate::bench_doctor::{
    CAP_BR_NETFILTER, CAP_CONNTRACK, CAP_CONNTRACK_UDP_TIMEOUT, CAP_NFTABLES,
    CONNTRACK_UDP_TIMEOUT_SECS, DoctorReport, SkipReason,
};
use crate::docker::{InternalNetwork, RunContainer};
use crate::fake_public::{fake_public_address, subnet_cidr};
use crate::flow::bench::{Bench, run_checked};
use crate::flow::gate::wait_for_container_log;
use crate::flow::nat::{
    NAT_CLIENT_UDP_PORT, NAT_LAN_CLIENT, NAT_LAN_GATEWAY, NAT_LAN_SUBNET, NAT_PEER_LAN_SUBNET,
    NATPROBE_PRIMARY_PORT, NATPROBE_SECONDARY_PORT,
};
use crate::flow::taps::{
    Attachment, PerAttachmentTaps, TapRole, TapRow, TapsRecord, write_taps_record,
};
use crate::nat::{NatType, NatTypeProof, PinnedPortReach};

/// The flow's name in every artifact it writes.
const FLOW: &str = "natgw-selfproof";

/// Every tap captures all UDP, and counts it: the translation is only
/// observable if both sides of it are recorded. Nothing else crosses a gateway
/// leg, so the capture filter and the row filter are the same expression.
const TAP_FILTER: &str = "udp";

/// The flow's inputs.
pub struct NatGatewaySelfProofOptions<'a> {
    /// The run dir.
    pub layout: &'a RunLayout,
    /// The container runtime to drive.
    pub container_runtime: &'a str,
    /// Build the project-owned images first.
    pub build_images: bool,
    /// The `natgw` image and its recipe.
    pub natgw_image: &'a str,
    /// The `natgw` build context.
    pub natgw_build_context: &'a Path,
    /// The `natprobe` reflector image and its recipe.
    pub natprobe_image: &'a str,
    /// The `natprobe` build context.
    pub natprobe_build_context: &'a Path,
    /// The tcpdump sidecar image.
    pub capture_image: &'a str,
    /// The tcpdump sidecar build context.
    pub capture_build_context: &'a Path,
    /// The `rmule-tools` driver image that runs the probe from inside the LAN.
    pub rmule_tools_image: &'a str,
    /// Its Dockerfile (the build context is the repo root).
    pub rmule_tools_dockerfile: &'a Path,
    /// The repo root.
    pub rmule_tools_build_context: &'a Path,
    /// Keep containers after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget.
    pub timeout_secs: u64,
    /// The gateway types to prove, in order.
    pub nat_types: &'a [NatType],
}

/// The `[[leg]]` row for one gateway type. The type itself rides in `proof`,
/// which carries it alongside the claim it makes.
#[derive(Debug, Serialize)]
struct LegVerdict {
    #[serde(flatten)]
    proof: NatTypeProof,
    /// What two gateways of this type did toward *each other* at the pinned
    /// port, which is the arrangement a punch actually uses.
    pinned_pair: pinned_pair::PinnedPairProof,
    tap: Vec<TapRow>,
}

/// The flow's verdict.
#[derive(Debug, Serialize)]
struct SelfProofVerdict {
    #[serde(rename = "scenario")]
    flow: &'static str,
    verdict: &'static str,
    /// Present only on a skip, and then it names the missing capability and
    /// what could therefore not be measured.
    #[serde(skip_serializing_if = "Option::is_none")]
    skip_reason: Option<String>,
    wan_subnet: String,
    lan_subnet: String,
    client_udp_port: u16,
    #[serde(rename = "capability")]
    capabilities: Vec<crate::bench_doctor::Capability>,
    #[serde(rename = "leg")]
    legs: Vec<LegVerdict>,
}

/// The fields the flow reads back out of the probe's own row: the two RFC 4787
/// behaviours, and the **Pinned-Port Sink** leg beside them.
///
/// The pinned pair defaults, so a row written by an older probe parses and
/// reads as "not probed" rather than failing — and "not probed" is `false`,
/// never a quiet pass.
#[derive(Debug, Deserialize)]
struct ProbeRow {
    mapping_behaviour: String,
    filtering_behaviour: String,
    #[serde(default)]
    pinned_port: u16,
    #[serde(default)]
    pinned_port_reachable: bool,
}

/// Stand each gateway type up and measure it.
///
/// # Errors
/// If the bench cannot be built, a gateway never reports ready, or the probe
/// cannot classify (Test I unanswered). A gateway that builds the *wrong*
/// behaviour is not an error — it is an `agrees = false` row and a `FAIL`
/// verdict, because that is a real finding about the bench.
pub fn run_natgw_selfproof(options: NatGatewaySelfProofOptions<'_>) -> Result<()> {
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

fn drive(bench: &mut Bench, options: &NatGatewaySelfProofOptions<'_>) -> Result<()> {
    // The doctor decides before anything but its own image is built.
    let suffix = names(options.layout)?;
    let doctor = bench.examine_doctor(
        "natgw",
        options.natgw_image,
        options.natgw_build_context,
        &suffix,
    )?;
    if let Err(skip) = doctor.require(
        &[
            CAP_NFTABLES,
            CAP_CONNTRACK,
            CAP_CONNTRACK_UDP_TIMEOUT,
            CAP_BR_NETFILTER,
        ],
        "the NAT Type Proof for any gateway type",
    ) {
        return write_skip(options.layout, &doctor, &skip);
    }

    if options.build_images {
        bench.build_image(
            "capture",
            options.capture_image,
            options.capture_build_context,
        )?;
    }
    // Always rebuilt, like `natgw`: a 30 s Debian layer plus two `COPY`s, so an
    // edited `entrypoint.sh` reaches the bench without `--build-images`.
    bench.build_image(
        "natprobe",
        options.natprobe_image,
        options.natprobe_build_context,
    )?;
    // Always rebuilt: it carries the probe subcommand, which is workspace code.
    bench.build_rmule_tools_image(
        options.rmule_tools_image,
        options.rmule_tools_dockerfile,
        options.rmule_tools_build_context,
    )?;

    let wan_subnet = subnet_cidr(0)?;
    let addresses = Addresses {
        gateway: fake_public_address(0)?.ip,
        probe_primary: fake_public_address(1)?.ip,
        probe_secondary: fake_public_address(2)?.ip,
        peer_gateway: fake_public_address(3)?.ip,
    };

    // The three bridges are made once and outlive every leg. A per-leg bridge
    // would be tidier to read and does not work: the subnets are fixed, so the
    // second leg's `network create` is refused as an overlapping pool before
    // the first leg's has been reaped.
    let networks = Networks {
        wan: format!("rmule-interop-natwan-{suffix}"),
        lan: format!("rmule-interop-natlan-{suffix}"),
        peer_lan: format!("rmule-interop-natpeerlan-{suffix}"),
    };
    fs::create_dir_all(options.layout.docker_dir())?;
    bench.create_extra_network(
        &networks.wan,
        bench
            .docker
            .create_internal_network(InternalNetwork::new(&networks.wan).subnet_v4(&wan_subnet)),
        "create fake-public WAN",
    )?;
    bench.create_extra_network(
        &networks.lan,
        bench
            .docker
            .create_lan_bridge(&networks.lan, NAT_LAN_SUBNET),
        "create masquerade-free LAN bridge",
    )?;
    bench.create_extra_network(
        &networks.peer_lan,
        bench
            .docker
            .create_lan_bridge(&networks.peer_lan, NAT_PEER_LAN_SUBNET),
        "create the pinned pair's second LAN bridge",
    )?;

    let reflector = format!("rmule-interop-natprobe-{suffix}");
    bench.start_extra(
        &reflector,
        RunContainer::new(options.natprobe_image)
            .detach()
            .name(&reflector)
            .network(&networks.wan)
            .ip(&addresses.probe_primary)
            .cap_add("NET_ADMIN")
            .env("NATPROBE_PRIMARY_ADDR", &addresses.probe_primary)
            .env("NATPROBE_SECONDARY_ADDR", &addresses.probe_secondary)
            .env("NATPROBE_PRIMARY_PORT", NATPROBE_PRIMARY_PORT.to_string())
            .env(
                "NATPROBE_SECONDARY_PORT",
                NATPROBE_SECONDARY_PORT.to_string(),
            )
            // The Pinned-Port Sink: one more socket on the primary address, at
            // the port every gateway type pins. RFC 5780 addresses the
            // reflector's own two ports and can never see a rule keyed on this
            // one, so the sink is what makes the blind spot
            // measurable.
            .env("NATPROBE_PINNED_PORT", NAT_CLIENT_UDP_PORT.to_string()),
        "run natprobe reflector",
    )?;
    let timeout = Duration::from_secs(options.timeout_secs);
    wait_for_container_log(&bench.docker, &reflector, "rmule-natprobe-ready", timeout)?;

    let mut legs = Vec::with_capacity(options.nat_types.len());
    for nat_type in options.nat_types {
        legs.push(prove_one(
            bench, options, &suffix, &networks, &addresses, *nat_type, timeout,
        )?);
    }

    // Three axes, and each of them has been the only one a real defect showed
    // up on. The RFC 4787 pair the knob claims. The live proof that the LAN
    // still reaches the WAN on the pinned port — run `1790028867` agreed on the
    // first axis while failing this one. And the pinned pair: two
    // gateways of this type toward each other, which run `1790070327` failed
    // while passing both of the others.
    let verdict = SelfProofVerdict {
        flow: FLOW,
        verdict: label_legs(legs.iter().map(|leg| {
            leg.proof.agrees && leg.proof.pinned_port_reachable && leg.pinned_pair.as_expected
        })),
        skip_reason: None,
        wan_subnet,
        lan_subnet: NAT_LAN_SUBNET.to_owned(),
        client_udp_port: NAT_CLIENT_UDP_PORT,
        capabilities: doctor.capabilities,
        legs,
    };
    write_verdict(options.layout, &verdict)
}

/// The flow's label from each leg's three axes, `true` when all held.
///
/// A leg whose gateway built another NAT type, or cannot forward its pinned
/// port, or whose pinned pair misbehaved, is a bench every later NAT verdict
/// would cite as proven, so it is `FAIL`, never `OBSERVED`. No leg at all
/// measured nothing and reads `OBSERVED`.
fn label_legs(legs: impl IntoIterator<Item = bool>) -> &'static str {
    let mut any = false;
    for held in legs {
        if !held {
            return "FAIL";
        }
        any = true;
    }
    if any { "PASS" } else { "OBSERVED" }
}

/// The three bridges one run makes, all of them outliving every leg.
struct Networks {
    /// The fake-public WAN both gateways and the reflector attach to.
    wan: String,
    /// The gateway-under-proof's LAN.
    lan: String,
    /// The **Pinned-Pair Reach** leg's second LAN.
    peer_lan: String,
}

/// The fake-public addresses one run pins, so the two gateways and the
/// reflector cannot drift apart between legs.
struct Addresses {
    /// The gateway under proof.
    gateway: String,
    /// The reflector's two addresses, held by one container.
    probe_primary: String,
    probe_secondary: String,
    /// The **Pinned-Pair Reach** leg's second gateway, of the same type.
    peer_gateway: String,
}

/// One gateway type: start it, tap both attachments, probe it from the LAN,
/// run the pinned pair against a second gateway of the same type, take the
/// self-proof dump, count the taps, and judge.
fn prove_one(
    bench: &mut Bench,
    options: &NatGatewaySelfProofOptions<'_>,
    suffix: &str,
    networks: &Networks,
    addresses: &Addresses,
    nat_type: NatType,
    timeout: Duration,
) -> Result<LegVerdict> {
    let leg_dir = options.layout.nat_type_dir(nat_type.knob());
    fs::create_dir_all(&leg_dir).with_context(|| format!("create {}", leg_dir.display()))?;

    let gateway = format!("rmule-interop-natgw-{}-{suffix}", nat_type.knob());
    bench.start_extra(
        &gateway,
        RunContainer::new(options.natgw_image)
            .detach()
            .name(&gateway)
            .network(&networks.wan)
            .ip(&addresses.gateway)
            .cap_add("NET_ADMIN")
            .sysctl("net.ipv4.ip_forward", "1")
            .sysctl("net.ipv6.conf.all.forwarding", "1")
            .sysctl(
                "net.netfilter.nf_conntrack_udp_timeout",
                CONNTRACK_UDP_TIMEOUT_SECS.to_string(),
            )
            .volume(&leg_dir, "/proof")
            .env("NAT_TYPE", nat_type.knob())
            .env("NAT_LAN_CLIENT", NAT_LAN_CLIENT)
            .env("NAT_CLIENT_PORT", NAT_CLIENT_UDP_PORT.to_string()),
        "run NAT gateway",
    )?;
    run_checked(
        bench.docker.connect_network(
            networks.lan.clone(),
            gateway.clone(),
            Some(OsString::from(NAT_LAN_GATEWAY)),
            None,
        ),
        "attach NAT gateway to its LAN",
    )?;
    wait_for_container_log(&bench.docker, &gateway, "rmule-natgw-ready", timeout)?;

    // Per-Attachment Taps: eth0 is the WAN (the attachment `docker run` made),
    // eth1 the LAN (the one `network connect` added). The same datagram appears
    // on both, translated on one side only.
    let taps = PerAttachmentTaps::start(
        bench,
        options.capture_image,
        &gateway,
        &format!("rmule-interop-nattap-{}-{suffix}", nat_type.knob()),
        &leg_dir,
        &[
            Attachment {
                name: "wan",
                interface: "eth0",
                role: TapRole::Evidence,
                bpf: TAP_FILTER,
            },
            Attachment {
                name: "lan",
                interface: "eth1",
                role: TapRole::Corroboration,
                bpf: TAP_FILTER,
            },
        ],
        timeout,
    )?;

    run_probe(
        bench,
        options,
        &leg_dir,
        &networks.lan,
        Probe {
            reflector: (&addresses.probe_primary, &addresses.probe_secondary),
            ports: (NATPROBE_PRIMARY_PORT, NATPROBE_SECONDARY_PORT),
            pinned_port: Some(NAT_CLIENT_UDP_PORT),
            attempts: 3,
            timeout_ms: 1500,
            out: Some("/out/nat-probe.toml"),
        },
    )?;

    // The pinned pair runs *after* the reflector probe and before the dump.
    // After, because the probe's filtering tests depend on the order in which
    // the `restricted` type's dynamic set learns addresses, and the pair would
    // seed it early; before, because the pair's own mappings are the most
    // interesting thing the conntrack dump can hold.
    let pinned_pair = pinned_pair::prove(
        bench,
        options,
        &pinned_pair::PairPlan {
            leg_dir: &leg_dir,
            suffix,
            wan_network: &networks.wan,
            lan_network: &networks.lan,
            peer_lan_network: &networks.peer_lan,
            gateway_wan: &addresses.gateway,
            peer_gateway_wan: &addresses.peer_gateway,
            nat_type,
            timeout,
        },
    )?;

    // The dump is taken by exec, not by a shutdown trap: teardown is `rm -f`,
    // which is SIGKILL.
    run_checked(
        bench.docker.exec(
            gateway.clone(),
            [
                OsString::from("natgw-proof"),
                OsString::from("/proof"),
                OsString::from(nat_type.knob()),
            ],
        ),
        "take NAT gateway self-proof",
    )?;

    let tap_rows = taps.rows(&bench.docker, TAP_FILTER)?;
    write_taps_record(
        &leg_dir,
        &TapsRecord {
            flow: FLOW,
            tapped_container: gateway.clone(),
            filter: TAP_FILTER.to_owned(),
            taps: tap_rows.clone(),
        },
    )?;

    let probe_row: ProbeRow = toml::from_str(
        &fs::read_to_string(leg_dir.join("nat-probe.toml"))
            .with_context(|| format!("read {}", leg_dir.join("nat-probe.toml").display()))?,
    )
    .context("parse the reflector probe's row")?;
    let proof = NatTypeProof::new(
        nat_type,
        probe_row.mapping_behaviour,
        probe_row.filtering_behaviour,
        PinnedPortReach {
            port: probe_row.pinned_port,
            reachable: probe_row.pinned_port_reachable,
        },
    );
    let text = toml::to_string_pretty(&proof).context("serialize nat-type.toml")?;
    fs::write(leg_dir.join("nat-type.toml"), text)
        .with_context(|| format!("write {}", leg_dir.join("nat-type.toml").display()))?;
    println!(
        "natgw-selfproof leg={} claimed={}/{} observed={}/{} agrees={} pinned_port={} reachable={}",
        nat_type.knob(),
        proof.claimed_mapping,
        proof.claimed_filtering,
        proof.observed_mapping,
        proof.observed_filtering,
        proof.agrees,
        proof.pinned_port,
        proof.pinned_port_reachable,
    );

    // The leg's containers go before the next leg takes the same addresses.
    // Sidecars first: a running tcpdump holds the namespace of what it taps.
    for attachment in ["wan", "lan"] {
        bench.stop_extra(&format!(
            "rmule-interop-nattap-{}-{suffix}-{attachment}",
            nat_type.knob()
        ));
    }
    bench.stop_extra(&gateway);

    Ok(LegVerdict {
        proof,
        pinned_pair,
        tap: tap_rows,
    })
}

/// One run of the probe container: where it aims and how patiently.
struct Probe<'a> {
    reflector: (&'a str, &'a str),
    ports: (u16, u16),
    /// The gateway's pinned client port, when the reflector holds a sink there.
    pinned_port: Option<u16>,
    attempts: u32,
    timeout_ms: u64,
    /// Where the row lands inside the container, or `None` for an arming run
    /// whose output is not a measurement.
    out: Option<&'a str>,
}

/// Run `rmule-tools nat probe` from the gateway's LAN and retain its whole
/// output, whatever the exit status. The probe's stdout is kept even on a
/// failure: an unanswered Test I is the most informative thing in the run dir
/// when the bench is broken.
fn run_probe(
    bench: &Bench,
    options: &NatGatewaySelfProofOptions<'_>,
    leg_dir: &Path,
    lan_network: &str,
    probe: Probe<'_>,
) -> Result<()> {
    let mut container = RunContainer::new(options.rmule_tools_image)
        .remove_after_exit()
        .network(lan_network)
        .ip(NAT_LAN_CLIENT)
        .cap_add("NET_ADMIN")
        .volume(leg_dir, "/out")
        .env("RMULE_DEFAULT_ROUTE_VIA", NAT_LAN_GATEWAY)
        .arg("nat")
        .arg("probe")
        .arg("--reflector-primary")
        .arg(probe.reflector.0)
        .arg("--reflector-secondary")
        .arg(probe.reflector.1)
        .arg("--reflector-primary-port")
        .arg(probe.ports.0.to_string())
        .arg("--reflector-secondary-port")
        .arg(probe.ports.1.to_string())
        .arg("--local-port")
        .arg(NAT_CLIENT_UDP_PORT.to_string())
        .arg("--timeout-ms")
        .arg(probe.timeout_ms.to_string())
        .arg("--attempts")
        .arg(probe.attempts.to_string());
    if let Some(pinned) = probe.pinned_port {
        container = container.arg("--pinned-port").arg(pinned.to_string());
    }
    if let Some(out) = probe.out {
        container = container.arg("--out").arg(out);
    }

    let output = bench
        .docker
        .run_container(container)
        .to_command()
        .output()
        .context("run the reflector probe")?;
    if probe.out.is_some() {
        fs::write(leg_dir.join("probe.stdout.log"), &output.stdout)?;
        fs::write(leg_dir.join("probe.stderr.log"), &output.stderr)?;
    }
    if !output.status.success() {
        bail!(
            "reflector probe exited unsuccessfully: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn names(layout: &RunLayout) -> Result<String> {
    layout
        .root()
        .file_name()
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned)
        .context("run directory has no utf-8 file name")
}

fn write_skip(layout: &RunLayout, doctor: &DoctorReport, skip: &SkipReason) -> Result<()> {
    eprintln!("natgw-selfproof skipped: {}", skip.reason);
    write_verdict(
        layout,
        &SelfProofVerdict {
            flow: FLOW,
            verdict: "SKIPPED",
            skip_reason: Some(skip.reason.clone()),
            wan_subnet: subnet_cidr(0)?,
            lan_subnet: NAT_LAN_SUBNET.to_owned(),
            client_udp_port: NAT_CLIENT_UDP_PORT,
            capabilities: doctor.capabilities.clone(),
            legs: Vec::new(),
        },
    )
}

fn write_verdict(layout: &RunLayout, verdict: &SelfProofVerdict) -> Result<()> {
    fs::create_dir_all(layout.nat_dir())?;
    let text = toml::to_string_pretty(verdict).context("serialize natgw-selfproof verdict")?;
    let path = layout.root().join("natgw-selfproof-verdict.toml");
    println!("{text}");
    fs::write(&path, text).with_context(|| format!("write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::label_legs;

    /// A gateway that probed as another type used to read `OBSERVED`, which
    /// `natgw-selfproof`'s wrapper accepted; it is a failed self-proof.
    #[test]
    fn a_leg_that_failed_an_axis_fails_the_self_proof() {
        assert_eq!(label_legs([true, true, true, true]), "PASS");
        assert_eq!(label_legs([true, false, true, true]), "FAIL");
        assert_eq!(label_legs([]), "OBSERVED");
    }
}
