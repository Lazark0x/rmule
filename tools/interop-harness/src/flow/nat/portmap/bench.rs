//! The bench all three port-mapping flows share, and the order they drive it in.
//!
//! One `miniupnpd` **Port-Mapping Gateway** between a fake-public WAN and a
//! masquerade-free LAN, a **Reflector Probe** on the WAN, a **Per-Attachment
//! Tap** on each of the gateway's two sides, and rmule driven from inside the
//! LAN by `rmule-tools nat portmap`.
//!
//! Three orderings here are load-bearing:
//!
//! - **The NAT Type Proof is taken before any mapping exists.** A granted
//!   mapping is an unconditional DNAT of that port, which the RFC 5780
//!   filtering test would (correctly) read as endpoint-independent — so probing
//!   afterwards would measure the mapping, not the NAT.
//! - **The gateway's table is polled while the driver runs.** The driver
//!   releases on exit; a table read afterwards is empty, which is the release
//!   assertion and a false negative for everything else.
//! - **The pre-claim happens before the driver starts.** A conflict that landed
//!   after rmule's grant would be miniupnpd refusing the *second* client, which
//!   is the opposite of the flow's question.

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::bench_doctor::{
    CAP_BR_NETFILTER, CAP_CONNTRACK, CAP_CONNTRACK_UDP_TIMEOUT, CAP_DAEMON_IPV6, CAP_IP6TABLES,
    CAP_NFTABLES, CONNTRACK_UDP_TIMEOUT_SECS, DoctorReport, SkipReason,
};
use crate::docker::{InternalNetwork, RunContainer};
use crate::fake_public::{fake_public_address, subnet_cidr};
use crate::fake_public_v6::FakePublicV6Plan;
use crate::flow::bench::{Bench, run_checked};
use crate::flow::gate::wait_for_container_log;
use crate::flow::nat::portmap::gateway::{GatewayRecord, GatewayWatch, PROOF_MOUNT};
use crate::flow::nat::portmap::helper::{self, KadHelper};
use crate::flow::nat::portmap::link_local::{self, PcpSources};
use crate::flow::nat::portmap::moved;
use crate::flow::nat::portmap::row::DriverRow;
use crate::flow::nat::portmap::verdict::{self, Claim, PortMapVerdict};
use crate::flow::nat::portmap::{
    DRIVER_LAN_ADDRESS, GATEWAY_NAT_TYPE, PEER_TCP_PORT, PRECLAIM_LAN_ADDRESS, PortMapFlow,
    UDP_PORT,
};
use crate::flow::nat::{
    NAT_CLIENT_UDP_PORT, NAT_LAN_CLIENT, NAT_LAN_GATEWAY, NAT_LAN_SUBNET, NATPROBE_PRIMARY_PORT,
    NATPROBE_SECONDARY_PORT,
};
use crate::flow::taps::{Attachment, PerAttachmentTaps, TapRole, TapsRecord, write_taps_record};
use crate::nat::NatTypeProof;

/// Every tap records all IP traffic on its side, and counts it the same way.
/// A port-mapping exchange is SSDP and SOAP over TCP as well as PCP over UDP,
/// so a UDP-only filter would leave the UPnP half of the flow uncaptured.
const TAP_FILTER: &str = "ip or ip6";

/// The fake-public subnet index the port-mapping WAN takes.
///
/// **Not** index 0. miniupnpd applies its own `addr_is_reserved()` to the
/// address it would report as the external IP and that list holds the RFC 5737
/// documentation ranges, so on `203.0.113.0/24` it answers every
/// `GetExternalIPAddress` with an empty string ("private/reserved address
/// 203.0.113.2 is not suitable for external IP") and no grant is usable. Index 2
/// is `45.55.200.0/24` — the prefix ADR-0092 already names for mixed
/// topologies.
const WAN_SUBNET_INDEX: usize = 2;

/// The gateway's own WAN address: the first host on that `/24`.
const GATEWAY_WAN_HOST: usize = WAN_SUBNET_INDEX * crate::fake_public::MAX_NODES_PER_SUBNET;

/// The first fake-public host a **Kad helper** takes. `+0`, `+1` and `+2` are
/// the gateway and the reflector's two addresses, so the helpers start at `+3`.
const HELPER_WAN_HOST: usize = GATEWAY_WAN_HOST + 3;

/// The **Fake-Public v6 Plan** `/64`s: one for the WAN, one for the LAN. The LAN
/// needs its own because a PCP MAP over IPv6 is a pinhole to an address the
/// client holds, and the gateway must be reachable at a **global-scope** next
/// hop in the same `/64` — a link-local one is what `crab_nat` cannot source a
/// request from.
const WAN_V6_NET: u16 = 1;
const LAN_V6_NET: u16 = 2;

/// How often the gateway's own lease tables are read while the driver runs.
const TABLE_POLL: Duration = Duration::from_millis(900);

/// The flow's inputs.
pub struct PortMapOptions<'a> {
    /// Which of the three flows to run.
    pub flow: PortMapFlow,
    /// The run dir.
    pub layout: &'a RunLayout,
    /// The container runtime to drive.
    pub container_runtime: &'a str,
    /// Build the project-owned images first.
    pub build_images: bool,
    /// The `miniupnpd` gateway image and its recipe.
    pub miniupnpd_image: &'a str,
    /// Its build context.
    pub miniupnpd_build_context: &'a Path,
    /// The stock aMule image the **Kad helpers** run.
    pub amule_image: &'a str,
    /// Its build context.
    pub amule_build_context: &'a Path,
    /// The `natprobe` reflector image.
    pub natprobe_image: &'a str,
    /// Its build context.
    pub natprobe_build_context: &'a Path,
    /// The tcpdump sidecar image.
    pub capture_image: &'a str,
    /// Its build context.
    pub capture_build_context: &'a Path,
    /// The `rmule-tools` driver image.
    pub rmule_tools_image: &'a str,
    /// Its Dockerfile.
    pub rmule_tools_dockerfile: &'a Path,
    /// Its build context (the repo root).
    pub rmule_tools_build_context: &'a Path,
    /// Keep containers after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget.
    pub timeout_secs: u64,
}

/// Stand the bench up, drive the flow, and write its verdict.
///
/// # Errors
/// If the bench cannot be built or the driver never produced a row.
pub(crate) fn run(options: PortMapOptions<'_>) -> Result<()> {
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

#[allow(clippy::too_many_lines)]
fn drive(bench: &mut Bench, options: &PortMapOptions<'_>) -> Result<()> {
    let flow = options.flow;
    // The doctor decides before anything but its own image is built.
    let suffix = names(options.layout)?;
    let doctor = bench.examine_doctor(
        "miniupnpd",
        options.miniupnpd_image,
        options.miniupnpd_build_context,
        &suffix,
    )?;
    let mut required = vec![
        CAP_NFTABLES,
        CAP_CONNTRACK,
        CAP_CONNTRACK_UDP_TIMEOUT,
        CAP_BR_NETFILTER,
    ];
    if flow.pinhole() {
        required.push(CAP_DAEMON_IPV6);
        required.push(CAP_IP6TABLES);
    }
    if let Err(skip) = doctor.require(
        &required,
        "a port-mapping grant against a real miniupnpd gateway",
    ) {
        return write_skip(options.layout, flow, &doctor, &skip);
    }

    if options.build_images {
        if flow.kad_helpers() > 0 {
            bench.build_image("aMule", options.amule_image, options.amule_build_context)?;
        }
        bench.build_image(
            "capture",
            options.capture_image,
            options.capture_build_context,
        )?;
    }
    // Always rebuilt, like `rmule-tools`: a 30 s Debian layer plus two
    // `COPY`s, so an edited `entrypoint.sh` reaches the bench without
    // `--build-images`.
    bench.build_image(
        "natprobe",
        options.natprobe_image,
        options.natprobe_build_context,
    )?;
    // Always rebuilt: it carries `nat portmap`, which is workspace code.
    bench.build_rmule_tools_image(
        options.rmule_tools_image,
        options.rmule_tools_dockerfile,
        options.rmule_tools_build_context,
    )?;

    let leg_dir = options.layout.nat_dir().join(flow.name());
    fs::create_dir_all(&leg_dir).with_context(|| format!("create {}", leg_dir.display()))?;

    let wan_subnet = subnet_cidr(WAN_SUBNET_INDEX)?;
    let wan_plan = FakePublicV6Plan::for_network(WAN_V6_NET)?;
    let lan_plan = FakePublicV6Plan::for_network(LAN_V6_NET)?;
    let gateway_wan = fake_public_address(GATEWAY_WAN_HOST)?.ip;
    let probe_primary = fake_public_address(GATEWAY_WAN_HOST + 1)?.ip;
    let probe_secondary = fake_public_address(GATEWAY_WAN_HOST + 2)?.ip;
    let gateway_lan_v6 = lan_plan.address(0)?;
    let driver_lan_v6 = lan_plan.address(2)?;

    let wan_network = format!("rmule-interop-pmwan-{suffix}");
    let lan_network = format!("rmule-interop-pmlan-{suffix}");
    fs::create_dir_all(options.layout.docker_dir())?;
    bench.create_extra_network(
        &wan_network,
        bench.docker.create_internal_network(
            InternalNetwork::new(&wan_network)
                .subnet_v4(&wan_subnet)
                .subnet_v6(wan_plan.subnet()),
        ),
        "create fake-public WAN",
    )?;
    bench.create_extra_network(
        &lan_network,
        bench
            .docker
            .create_lan_bridge_dual(&lan_network, NAT_LAN_SUBNET, Some(lan_plan.subnet())),
        "create masquerade-free LAN bridge",
    )?;

    let timeout = Duration::from_secs(options.timeout_secs);
    let reflector = format!("rmule-interop-pmprobe-{suffix}");
    bench.start_extra(
        &reflector,
        RunContainer::new(options.natprobe_image)
            .detach()
            .name(&reflector)
            .network(&wan_network)
            .ip(&probe_primary)
            // Pinned rather than auto-allocated: Docker hands the first free
            // host in the `/64` to whoever attaches first, and the reflector
            // attaches before the gateway — an unpinned reflector takes `::2`
            // and the gateway's explicit `--ip6` then fails with "Address
            // already in use".
            .ip6(wan_plan.address(1)?)
            .cap_add("NET_ADMIN")
            .env("NATPROBE_PRIMARY_ADDR", &probe_primary)
            .env("NATPROBE_SECONDARY_ADDR", &probe_secondary)
            .env("NATPROBE_PRIMARY_PORT", NATPROBE_PRIMARY_PORT.to_string())
            .env(
                "NATPROBE_SECONDARY_PORT",
                NATPROBE_SECONDARY_PORT.to_string(),
            ),
        "run natprobe reflector",
    )?;
    wait_for_container_log(&bench.docker, &reflector, "rmule-natprobe-ready", timeout)?;

    let gateway = format!("rmule-interop-miniupnpd-{suffix}");
    bench.start_extra(
        &gateway,
        RunContainer::new(options.miniupnpd_image)
            .detach()
            .name(&gateway)
            .network(&wan_network)
            .ip(&gateway_wan)
            .ip6(wan_plan.address(0)?)
            .cap_add("NET_ADMIN")
            .sysctl("net.ipv4.ip_forward", "1")
            .sysctl("net.ipv6.conf.all.forwarding", "1")
            .sysctl(
                "net.netfilter.nf_conntrack_udp_timeout",
                CONNTRACK_UDP_TIMEOUT_SECS.to_string(),
            )
            .volume(&leg_dir, PROOF_MOUNT)
            .env("MINIUPNPD_LAN_ADDR", NAT_LAN_GATEWAY)
            .env("NAT_WAN_ADDR", &gateway_wan)
            .env("MINIUPNPD_LAN_CIDR", NAT_LAN_SUBNET)
            .env(
                "MINIUPNPD_SECURE_MODE",
                if flow.takes_the_port() { "no" } else { "yes" },
            ),
        "run miniupnpd port-mapping gateway",
    )?;
    run_checked(
        bench.docker.connect_network(
            &lan_network,
            gateway.clone(),
            Some(OsString::from(NAT_LAN_GATEWAY)),
            Some(OsString::from(&gateway_lan_v6)),
        ),
        "attach the gateway to its LAN",
    )?;
    let ready = wait_for_container_log(&bench.docker, &gateway, "rmule-miniupnpd-ready", timeout)?;
    // The gateway names its own two sides; taking them from its ready line
    // rather than assuming `eth0`/`eth1` keeps a tap from labelling the WAN
    // capture "lan" if the runtime ever hands the attachments over in the other
    // order.
    let (wan_if, lan_if) = interfaces(&ready)?;
    // The link-local variant routes the driver through the gateway's `fe80::`
    // address, the way a Router Advertisement would; the other flows keep the
    // global-scope next hop on the LAN's own `/64`.
    let next_hop_v6 = if flow == PortMapFlow::Ipv6PinholeLinkLocal {
        let link_local = link_local::gateway_link_local(bench, &gateway, &lan_if)?;
        println!("portmap gateway link-local next hop {link_local} on {lan_if}");
        V6NextHop::LinkLocal(link_local)
    } else {
        V6NextHop::Global(gateway_lan_v6.clone())
    };

    let taps = PerAttachmentTaps::start(
        bench,
        options.capture_image,
        &gateway,
        &format!("rmule-interop-pmtap-{suffix}"),
        &leg_dir,
        &[
            Attachment {
                name: "wan",
                interface: &wan_if,
                role: TapRole::Evidence,
                bpf: TAP_FILTER,
            },
            Attachment {
                name: "lan",
                interface: &lan_if,
                role: TapRole::Corroboration,
                bpf: TAP_FILTER,
            },
        ],
        timeout,
    )?;

    // The NAT Type Proof, taken while no mapping exists (see the module header).
    run_probe(
        bench,
        options,
        &leg_dir,
        &lan_network,
        &probe_primary,
        &probe_secondary,
    )?;

    for (protocol, port) in flow.preclaims() {
        preclaim(bench, options, &lan_network, protocol, *port)?;
    }

    // The Kad helpers go up before the driver and on the WAN: they must already
    // be answering when rmule's first check goes out, and the only route from
    // there to rmule's eD2k port is the redirect the gateway is about to grant.
    let helper_addresses = (0..flow.kad_helpers())
        .map(|index| helper::helper_address(HELPER_WAN_HOST, index))
        .collect::<Result<Vec<_>>>()?;
    let helpers = helper::start_helpers(
        bench,
        options.amule_image,
        &suffix,
        &wan_network,
        &leg_dir,
        &helper_addresses,
        timeout,
    )?;

    let driver = format!("rmule-interop-pmdriver-{suffix}");
    bench.start_extra(
        &driver,
        driver_container(
            options,
            &driver,
            &lan_network,
            &driver_lan_v6,
            &next_hop_v6,
            &helpers,
        ),
        "run the rmule port-mapping driver",
    )?;

    // Poll the gateway's own tables for as long as the driver runs.
    let mut watch = GatewayWatch::new();
    let driver_deadline =
        Instant::now() + Duration::from_secs(flow.window_secs() + options.timeout_secs);
    let mut port_taken = false;
    loop {
        watch.poll(&bench.docker, &gateway)?;
        if flow.takes_the_port()
            && !port_taken
            && watch.has_seen_exact(DRIVER_LAN_ADDRESS, PEER_TCP_PORT)
        {
            moved::take_the_port(bench, options.miniupnpd_image, &lan_network)?;
            port_taken = true;
        }
        if !is_running(bench, &driver)? {
            break;
        }
        if Instant::now() > driver_deadline {
            bail!(
                "the port-mapping driver was still running {}s after its own window closed",
                options.timeout_secs
            );
        }
        thread::sleep(TABLE_POLL);
    }
    run_checked(bench.docker.wait(driver.clone()), "wait for the driver")?;
    collect_logs(bench, &driver, &leg_dir.join("driver.log"))?;
    collect_logs(bench, &gateway, &leg_dir.join("gateway.log"))?;
    helper::collect_logs(bench, &helpers, &leg_dir);

    // The dump is taken by exec, not by a shutdown trap: teardown is `rm -f`,
    // which is SIGKILL.
    run_checked(
        bench.docker.exec(
            gateway.clone(),
            [
                OsString::from("miniupnpd-proof"),
                OsString::from(PROOF_MOUNT),
            ],
        ),
        "take the gateway's own proof dump",
    )?;
    let record = watch.finish(&bench.docker, &gateway)?;

    // Counted before the taps are torn down, and on the WAN side only: the LAN
    // tap holds rmule's own pre-translation bytes, which corroborate but never
    // prove (`TapRole::Evidence`).
    let kad_wire = if helpers.is_empty() {
        None
    } else {
        Some(helper::count_wire(
            &bench.docker,
            &format!("rmule-interop-pmtap-{suffix}-wan"),
            "/capture/tap-wan.pcap",
            &gateway_wan,
            PEER_TCP_PORT,
        )?)
    };
    let pcp_sources = match next_hop_v6 {
        V6NextHop::LinkLocal(next_hop) => {
            taps.lift(
                &bench.docker,
                "lan",
                link_local::PCP_REQUEST_FILTER,
                link_local::PCP_REQUEST_PCAP,
            )?;
            let known = driver_lan_v6
                .parse()
                .with_context(|| format!("driver v6 {driver_lan_v6}"))?;
            Some(PcpSources::read(
                &leg_dir.join(link_local::PCP_REQUEST_PCAP),
                known,
                next_hop,
            )?)
        }
        V6NextHop::Global(_) => None,
    };
    let tap_rows = taps.rows(&bench.docker, TAP_FILTER)?;
    write_taps_record(
        &leg_dir,
        &TapsRecord {
            flow: flow.name(),
            tapped_container: gateway.clone(),
            filter: TAP_FILTER.to_owned(),
            taps: tap_rows.clone(),
        },
    )?;

    let proof = nat_type_proof(&leg_dir)?;
    let rmule = DriverRow::read(&leg_dir.join("portmap-row.toml"))?;
    let driver_log = fs::read_to_string(leg_dir.join("driver.log")).context("read driver.log")?;
    let (label, detail, claims) = verdict::judge(
        flow,
        &proof,
        &record,
        &rmule,
        kad_wire.as_ref(),
        pcp_sources.as_ref(),
        &driver_log,
    );
    verdict::write(
        options.layout,
        &PortMapVerdict {
            flow: flow.name(),
            verdict: label,
            detail,
            skip_reason: None,
            nat_type: Some(proof),
            wan_subnet,
            lan_subnet: NAT_LAN_SUBNET.to_owned(),
            wan_subnet_v6: wan_plan.subnet(),
            lan_subnet_v6: lan_plan.subnet(),
            protocol: flow.protocol(),
            preclaimed: flow
                .preclaims()
                .iter()
                .map(|(protocol, port)| format!("{protocol}:{port}"))
                .collect(),
            taps: tap_rows,
            capabilities: doctor.capabilities,
            gateway: record,
            rmule: Some(rmule),
            kad_wire,
            pcp_sources,
            claim: claims,
        },
    )?;
    if label == "FAIL" {
        bail!(
            "{} did not hold every claim the bench can drive; see {}-verdict.toml",
            flow.name(),
            flow.name()
        );
    }
    Ok(())
}

/// The driver container: rmule on the gateway's LAN, pointed at it explicitly.
fn driver_container(
    options: &PortMapOptions<'_>,
    name: &str,
    lan_network: &str,
    driver_lan_v6: &str,
    next_hop_v6: &V6NextHop,
    helpers: &[KadHelper],
) -> RunContainer {
    let flow = options.flow;
    let mut container = RunContainer::new(options.rmule_tools_image)
        .detach()
        .name(name)
        .network(lan_network)
        .ip(DRIVER_LAN_ADDRESS)
        .ip6(driver_lan_v6)
        .cap_add("NET_ADMIN")
        .volume(options.layout.nat_dir().join(flow.name()), "/out")
        .env("RMULE_DEFAULT_ROUTE_VIA", NAT_LAN_GATEWAY)
        .env("RMULE_DEFAULT_ROUTE_VIA6", next_hop_v6.address())
        .arg("nat")
        .arg("portmap")
        .arg("--gateway")
        .arg(NAT_LAN_GATEWAY)
        .arg("--gateway-local")
        .arg(DRIVER_LAN_ADDRESS)
        .arg("--protocol")
        .arg(flow.protocol())
        .arg("--family")
        .arg(flow.families())
        .arg("--lease-secs")
        .arg(flow.lease_secs().to_string())
        .arg("--window-secs")
        .arg(flow.window_secs().to_string())
        .arg("--listen")
        .arg(format!("0.0.0.0:{PEER_TCP_PORT}"))
        .arg("--out")
        .arg("/out/portmap-row.toml");
    if flow.kad() {
        container = container
            .arg("--kad")
            .arg("--udp-port")
            .arg(UDP_PORT.to_string());
    }
    // Seeded, not discovered: the bootstrap dial loop stops on the first answer
    // (ADR-0067), so it could deliver one helper where the ≥2-ack verdict rule
    // needs two. A merged contact row is the warm-restart shape a deployment
    // reaches through its own `nodes.dat`.
    for helper in helpers {
        container = container.arg("--kad-contact").arg(helper.contact_arg());
    }
    if let V6NextHop::LinkLocal(_) = next_hop_v6 {
        container = container
            .env("RMULE_DEFAULT_ROUTE_DEV6", link_local::DRIVER_LAN_INTERFACE)
            .arg("--gateway-v6-interface")
            .arg(link_local::DRIVER_LAN_INTERFACE);
    }
    if flow.pinhole() {
        container = container
            .arg("--gateway-v6")
            .arg(next_hop_v6.address())
            .arg("--gateway-local-v6")
            .arg(driver_lan_v6)
            // The Override tier, so the v6 half of the Desired Mapping Set does
            // not ride on whatever the live interface enumeration happened to
            // find inside the container.
            .arg("--external-v6")
            .arg(driver_lan_v6);
    }
    container
}

/// The v6 next hop the driver is routed through and told to speak PCP to.
enum V6NextHop {
    /// The gateway's address on the LAN's own `/64`.
    Global(String),
    /// The gateway's `fe80::` address, scoped by the driver's LAN interface.
    LinkLocal(std::net::Ipv6Addr),
}

impl V6NextHop {
    fn address(&self) -> String {
        match self {
            Self::Global(address) => address.clone(),
            Self::LinkLocal(address) => address.to_string(),
        }
    }
}

/// Claim one external port on the gateway from a **different** LAN host, before
/// rmule asks for it.
fn preclaim(
    bench: &Bench,
    options: &PortMapOptions<'_>,
    lan_network: &str,
    protocol: &str,
    port: u16,
) -> Result<()> {
    // `upnpc` ships in the gateway image (the `miniupnpc` package), so the
    // pre-claimer is that image with its entrypoint replaced rather than a
    // fourth recipe. The LAN has no egress, so nothing can be installed here at
    // run time — the client has to be baked in.
    let script = format!(
        "ip route replace default via {NAT_LAN_GATEWAY} && \
         upnpc -e preclaim -a {PRECLAIM_LAN_ADDRESS} {port} {port} {protocol} 600"
    );
    let output = bench
        .docker
        .run_container(
            RunContainer::new(options.miniupnpd_image)
                .remove_after_exit()
                .network(lan_network)
                .ip(PRECLAIM_LAN_ADDRESS)
                .cap_add("NET_ADMIN")
                .entrypoint("sh")
                .arg("-c")
                .arg(script),
        )
        .to_command()
        .output()
        .context("run the port pre-claim")?;
    let text = String::from_utf8_lossy(&output.stdout);
    println!(
        "portmap pre-claim {protocol}:{port} -> {}",
        text.lines().last().unwrap_or("(no output)")
    );
    if !output.status.success() {
        bail!(
            "pre-claiming {protocol}:{port} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Run the **Reflector Probe** from the gateway's LAN and keep its whole output.
fn run_probe(
    bench: &Bench,
    options: &PortMapOptions<'_>,
    leg_dir: &Path,
    lan_network: &str,
    primary: &str,
    secondary: &str,
) -> Result<()> {
    let output = bench
        .docker
        .run_container(
            RunContainer::new(options.rmule_tools_image)
                .remove_after_exit()
                .network(lan_network)
                .ip(NAT_LAN_CLIENT)
                .cap_add("NET_ADMIN")
                .volume(leg_dir, "/out")
                .env("RMULE_DEFAULT_ROUTE_VIA", NAT_LAN_GATEWAY)
                .arg("nat")
                .arg("probe")
                .arg("--reflector-primary")
                .arg(primary)
                .arg("--reflector-secondary")
                .arg(secondary)
                .arg("--reflector-primary-port")
                .arg(NATPROBE_PRIMARY_PORT.to_string())
                .arg("--reflector-secondary-port")
                .arg(NATPROBE_SECONDARY_PORT.to_string())
                .arg("--local-port")
                .arg(NAT_CLIENT_UDP_PORT.to_string())
                .arg("--timeout-ms")
                .arg("1500")
                .arg("--attempts")
                .arg("3")
                .arg("--out")
                .arg("/out/nat-probe.toml"),
        )
        .to_command()
        .output()
        .context("run the reflector probe")?;
    fs::write(leg_dir.join("probe.stdout.log"), &output.stdout)?;
    fs::write(leg_dir.join("probe.stderr.log"), &output.stderr)?;
    if !output.status.success() {
        bail!(
            "reflector probe exited unsuccessfully: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Pair the gateway's claim with what the probe observed, and write the row.
fn nat_type_proof(leg_dir: &Path) -> Result<NatTypeProof> {
    #[derive(serde::Deserialize)]
    struct ProbeRow {
        mapping_behaviour: String,
        filtering_behaviour: String,
    }
    let path = leg_dir.join("nat-probe.toml");
    let row: ProbeRow = toml::from_str(
        &fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?,
    )
    .context("parse the reflector probe's row")?;
    let proof = NatTypeProof::new(
        GATEWAY_NAT_TYPE,
        row.mapping_behaviour,
        row.filtering_behaviour,
        // No Pinned-Port Sink on a miniupnpd WAN: that gateway's whole NAT is
        // the plain port-preserving SNAT `natgw-selfproof` already proved, with no rule
        // keyed on a pinned port for the leg to be wrong about.
        crate::nat::PinnedPortReach::not_probed(),
    );
    let text = toml::to_string_pretty(&proof).context("serialize nat-type.toml")?;
    fs::write(leg_dir.join("nat-type.toml"), text)?;
    println!(
        "portmap NAT Type Proof: claimed={}/{} observed={}/{} agrees={}",
        proof.claimed_mapping,
        proof.claimed_filtering,
        proof.observed_mapping,
        proof.observed_filtering,
        proof.agrees,
    );
    Ok(proof)
}

/// The two interface names the gateway printed for itself.
fn interfaces(ready_line: &str) -> Result<(String, String)> {
    let field = |key: &str| -> Option<String> {
        ready_line
            .split_whitespace()
            .find_map(|token| token.strip_prefix(key))
            .map(ToOwned::to_owned)
    };
    match (field("wan_if="), field("lan_if=")) {
        (Some(wan), Some(lan)) => Ok((wan, lan)),
        _ => bail!("the gateway's ready line named no interfaces: {ready_line}"),
    }
}

/// Whether a container is still running.
fn is_running(bench: &Bench, container: &str) -> Result<bool> {
    let output = bench
        .docker
        .inspect_state(container)
        .to_command()
        .output()
        .with_context(|| format!("docker inspect {container}"))?;
    Ok(String::from_utf8_lossy(&output.stdout).trim() == "running")
}

/// Copy a container's log into the run dir.
fn collect_logs(bench: &Bench, container: &str, path: &Path) -> Result<()> {
    let output = bench
        .docker
        .logs(container)
        .to_command()
        .output()
        .with_context(|| format!("docker logs {container}"))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    fs::write(path, text).with_context(|| format!("write {}", path.display()))
}

fn names(layout: &RunLayout) -> Result<String> {
    layout
        .root()
        .file_name()
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned)
        .context("run directory has no utf-8 file name")
}

fn write_skip(
    layout: &RunLayout,
    flow: PortMapFlow,
    doctor: &DoctorReport,
    skip: &SkipReason,
) -> Result<()> {
    eprintln!("{} skipped: {}", flow.name(), skip.reason);
    verdict::write(
        layout,
        &PortMapVerdict {
            flow: flow.name(),
            verdict: "SKIPPED",
            detail: "the bench lacks a capability this flow needs; nothing was measured."
                .to_owned(),
            skip_reason: Some(skip.reason.clone()),
            nat_type: None,
            wan_subnet: subnet_cidr(WAN_SUBNET_INDEX)?,
            lan_subnet: NAT_LAN_SUBNET.to_owned(),
            wan_subnet_v6: FakePublicV6Plan::for_network(WAN_V6_NET)?.subnet(),
            lan_subnet_v6: FakePublicV6Plan::for_network(LAN_V6_NET)?.subnet(),
            protocol: flow.protocol(),
            preclaimed: Vec::new(),
            taps: Vec::new(),
            capabilities: doctor.capabilities.clone(),
            gateway: GatewayRecord::default(),
            rmule: None,
            kad_wire: None,
            pcp_sources: None,
            claim: Vec::<Claim>::new(),
        },
    )
}
