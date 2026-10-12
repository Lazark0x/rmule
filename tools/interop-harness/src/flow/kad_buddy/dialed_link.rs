//! kad-dialed-link (flow S): a Kad firewall check that concludes through a
//! link rmule itself dialed.
//!
//! aMule acts on `OP_KAD_FWTCPCHECK_ACK` for whichever socket it arrives on
//! (`ClientTCPSocket.cpp:1950-1962`), and the helper side reuses a live socket:
//! `CClientList::RequestTCP` finds the requester's client by IP and hello port
//! (`ClientList.cpp:844-870`), `TryToConnect` calls `ConnectionEstablished()` on
//! a connected socket instead of dialing (`BaseClient.cpp:1471-1474`), and the
//! ack is then written to that socket (`ClientList.cpp:586-598`). So when rmule
//! holds a download link to a helper and also asks that helper for a TCP check,
//! the ack comes back on the link rmule dialed, and no connect-back is opened.
//!
//! Topology: a Core (`ed2k download start --serve --kad-contact …`) is handed a
//! file link naming one stock aMule helper as its only source, so it dials the
//! helper's listener. The file is large enough that the download is still
//! running when the window ends, so the link outlives the check. A second,
//! plain helper answers the TCP check the usual way, by connecting back; it
//! keeps rmule's verdict reachable whatever the first helper's ack does.
//!
//! What it judges, and from where:
//!
//!   * **The wire, from the helper's own tap.** The helper's `0xC5 0xA8` frames
//!     are sorted by the stream that carried them: a stream toward rmule's
//!     listener is a connect-back, a stream toward any other rmule port is the
//!     link rmule dialed. Passing needs the ack on the dialed link and no
//!     connect-back from that helper.
//!   * **What rmule did with it, from rmule's own trace.** The ack handed to the
//!     Kad node names the helper's listener port, not an ephemeral one, which
//!     only a link rmule dialed has. The TCP verdict is recorded beside it but
//!     does not gate: the plain helper's two connect-back acks open it alone.
//!
//! Command:
//!
//! ```bash
//! RMULE_BENCH=1 cargo test -p rmule-interop-harness --test harness \
//!   -- --ignored --test-threads=1 acceptance::kad_dialed_link
//! # or directly:
//! cargo run -p rmule-interop-harness -- kad-dialed-link --window 180
//! ```

mod verdict;

use std::fs;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::artifacts::RunLayout;
use crate::docker::{Docker, RunContainer};
use crate::flow::bench::{
    CaptureSidecar, DEFAULT_TAP_INTERFACE, KadMeshNames, KadResources, fallback_id, run_checked,
    write_id,
};
use crate::flow::gate::{wait_for_kad_log, wait_for_kad_trail};
use crate::flow::identity::{hex_lower, ipv4_string, parse_ipv4_octets};
use crate::flow::logs::{collect_amule_logfile, collect_kad_logs, collect_kad_node_logs};
use crate::flow::mesh::{
    KAD_CONTACT_VERSION, KAD_RMULE_UDP_PORT, KAD_TCP_PORT, KadCaptureOptions, KadNodeSpec,
    kad_role_env, start_kad_node,
};
use crate::flow::nat::synthetic::write_hashed;
use crate::flow::wire_filter::capture_tcp_streams;
use crate::rmule::RMULE_SERVE_TCP_PORT;

pub use self::verdict::DialedLinkVerdict;
use self::verdict::Facts;

/// rmule's pinned Kad ID.
const RMULE_KAD_ID: [u8; 16] = [0x5E; 16];
/// The helpers' Kad ID prefix, one per helper.
const HELPER_KAD_ID_PREFIX: u8 = 0x91;
/// What rmule's trace says when an ack reaches the Kad node off a peer link.
const ACK_TRACE: &str = "OP_KAD_FWTCPCHECK_ACK arrived on a peer link";
/// What rmule's trace says when its TCP verdict reaches Open.
const TCP_OPEN_TRACE: &str = "kad TCP reachability verdict changed";
/// Seconds past the TCP verdict that the run keeps tapping, so the download is
/// seen still running on the same link.
const SETTLE_SECS: u64 = 20;

/// Options for [`run_kad_dialed_link`] (flow S).
pub struct KadDialedLinkOptions<'a> {
    /// The shared Kad bench options.
    pub base: KadCaptureOptions<'a>,
    /// The image whose entrypoint is `rmule-tools`; the Core runs in it.
    pub rmule_tools_image: &'a str,
    /// The shared file's size in bytes.
    pub file_size: u64,
    /// How long rmule's TCP verdict may take to read Open once everything is up.
    pub window_secs: u64,
}

/// Run the **dialed-link Kad TCP check** leg (flow S).
pub fn run_kad_dialed_link(options: KadDialedLinkOptions<'_>) -> Result<()> {
    let base = &options.base;
    let docker = Docker::new(base.container_runtime);
    let names = KadMeshNames::from_layout(base.layout)?;
    if base.build_images {
        run_checked(
            docker.build_image(base.amule_image, base.amule_build_context),
            "build aMule image",
        )?;
        run_checked(
            docker.build_image(base.capture_image, base.capture_build_context),
            "build capture image",
        )?;
    }
    fs::create_dir_all(base.layout.docker_dir())
        .with_context(|| format!("create {}", base.layout.docker_dir().display()))?;

    // Config A: rmule on `.2`, the sharing helper on `.3`, the plain one on `.4`.
    let rmule_addr = crate::fake_public::fake_public_address(0)?;
    let subnet = rmule_addr.subnet.clone();
    let rmule_ip = parse_ipv4_octets(&rmule_addr.ip)?;
    let rmule = crate::kad_seed::KadContact {
        kad_id: RMULE_KAD_ID,
        ipv4: rmule_ip,
        udp_port: KAD_RMULE_UDP_PORT,
        tcp_port: RMULE_SERVE_TCP_PORT,
        version: KAD_CONTACT_VERSION,
    };
    let shared_dir = base.layout.kad_dir().join("shared");
    fs::create_dir_all(&shared_dir).with_context(|| format!("create {}", shared_dir.display()))?;
    let plain_dir = base.layout.kad_dir().join("helper-incoming");
    fs::create_dir_all(&plain_dir).with_context(|| format!("create {}", plain_dir.display()))?;
    let file = write_hashed(&shared_dir, options.file_size)?;

    let mut specs = Vec::with_capacity(2);
    for index in 0..2usize {
        let addr = crate::fake_public::fake_public_address(1 + index)?;
        let mut kad_id = [0x90u8; 16];
        kad_id[0] = HELPER_KAD_ID_PREFIX + u8::try_from(index).unwrap_or(0);
        specs.push(KadNodeSpec {
            // The `publisher` role is the one that shares its mounted directory.
            role: if index == 0 {
                "publisher".to_owned()
            } else {
                format!("helper-{index}")
            },
            container: if index == 0 {
                names.publisher.clone()
            } else {
                names.routing(u32::try_from(index).unwrap_or(0))
            },
            udp_port: base.kad_udp_port_base + 3 + u16::try_from(index).unwrap_or(0),
            ip: parse_ipv4_octets(&addr.ip)?,
            kad_id,
            user_hash_hex: None,
            shared_host_dir: if index == 0 {
                shared_dir.clone()
            } else {
                plain_dir.clone()
            },
            bootstrap_peers: Vec::new(),
            routing_zone_seed: true,
            seed_contacts: vec![rmule],
        });
    }
    let helper_ip = ipv4_string(specs[0].ip);
    let source_link = format!("{}|sources,{helper_ip}:{KAD_TCP_PORT}|/", file.link);
    let helper_env: Vec<String> = {
        let mut env = vec![
            "AMULE_KAD_FILTER_LAN_IPS=1".to_owned(),
            "AMULE_KAD_VERBOSE=1".to_owned(),
            "AMULE_DEBUG_PEER_CATEGORIES=1".to_owned(),
        ];
        env.extend(base.amule_env.iter().cloned());
        env
    };

    let network_id = run_checked(
        docker.create_internal_network_with_subnet(names.network_name.clone(), subnet.clone()),
        "create fake-public kad network",
    )?;
    let mut resources = KadResources::new(&docker, base.keep_containers);
    resources.own_network();

    let result = (|| -> Result<()> {
        write_id(
            &base.layout.network_id_file(),
            fallback_id(&network_id, &names.network_name),
        )?;
        let timeout = Duration::from_secs(base.timeout_secs);

        let mut nodes = Vec::with_capacity(specs.len());
        let mut taps = Vec::with_capacity(specs.len());
        for index in 0..specs.len() {
            let node_opts = KadCaptureOptions {
                build_images: false,
                routing_nodes: 0,
                amule_env: &helper_env,
                ..*base
            };
            let helper = start_kad_node(&docker, &node_opts, &specs, index, &mut resources)?;
            let capture_dir = base
                .layout
                .kad_dir()
                .join(format!("capture-{}", helper.role));
            fs::create_dir_all(&capture_dir)
                .with_context(|| format!("create {}", capture_dir.display()))?;
            let tap_name = format!("{}-{}", names.capture, helper.role);
            let tap = CaptureSidecar {
                image: base.capture_image,
                name: &tap_name,
                target_container: &helper.container,
                interface: DEFAULT_TAP_INTERFACE,
                host_dir: capture_dir,
                pcap_file: "helper.pcap",
                bpf: "tcp",
            };
            resources.start_capture(
                base.layout,
                &tap,
                &format!("kad-capture-{}-container-id.txt", helper.role),
            )?;
            taps.push((tap_name.clone(), tap.pcap_path()));
            wait_for_kad_log(
                &docker,
                base.layout,
                &helper.role,
                &helper.container,
                &format!("rmule-kad-{}-ready", kad_role_env(&helper.role)),
                timeout,
            )?;
            nodes.push(helper);
        }

        let out_dir = base.layout.kad_dir().join("rmule-out");
        fs::create_dir_all(&out_dir).with_context(|| format!("create {}", out_dir.display()))?;
        let mut container = RunContainer::new(options.rmule_tools_image)
            .detach()
            .name(&names.rmule)
            .network(&names.network_name)
            .ip(&rmule_addr.ip)
            .env("RMULE_LOG", "info,rmule_core=debug")
            .volume(&out_dir, "/out");
        for arg in [
            "ed2k",
            "download",
            "start",
            "--data-dir",
            "/out/data",
            "--server",
            "127.0.0.1:4661",
            "--file",
            &source_link,
            "--out",
            "/out/dl/output.bin",
            "--tcp-port",
            &RMULE_SERVE_TCP_PORT.to_string(),
            "--serve",
            "--udp-port",
            &KAD_RMULE_UDP_PORT.to_string(),
            "--kad-id-hex",
            &hex_lower(&RMULE_KAD_ID),
        ] {
            container = container.arg(arg);
        }
        for spec in &specs {
            container = container.arg("--kad-contact").arg(format!(
                "{}@{}:{}",
                hex_lower(&spec.kad_id),
                ipv4_string(spec.ip),
                spec.udp_port
            ));
        }
        let started = run_checked(docker.run_container(container), "run the dialing Core")?;
        resources.track_started("rmule", names.rmule.clone());
        write_id(
            &base.layout.docker_dir().join("kad-rmule-container-id.txt"),
            fallback_id(&started, &names.rmule),
        )?;
        println!(
            "kad-dialed-link: {} helper(s) up on {subnet}; waiting up to {}s for rmule's TCP \
             verdict",
            nodes.len(),
            options.window_secs
        );
        let opened = wait_for_kad_trail(
            &docker,
            base.layout,
            "rmule",
            &names.rmule,
            "after=Open",
            Duration::from_secs(options.window_secs),
        )?;
        if opened {
            std::thread::sleep(Duration::from_secs(SETTLE_SECS));
        }

        let rmule_ip_text = ipv4_string(rmule_ip);
        let dialed = read_helper_links(&docker, &taps[0], &rmule_ip_text)?;
        let plain = read_helper_links(&docker, &taps[1], &rmule_ip_text)?;
        collect_kad_node_logs(&docker, base.layout, &nodes);
        for node in &nodes {
            collect_amule_logfile(&docker, base.layout, &node.role, &node.container);
        }
        collect_kad_logs(&docker, base.layout, "rmule", &names.rmule)?;
        let trail = rmule_trail(base.layout);
        assert_dialed_link(
            base.layout,
            &Facts {
                helper_ip: &helper_ip,
                dialed,
                plain,
                trace_ack_from_listener_port: ack_traced_from_listener_port(&trail, &helper_ip),
                tcp_open: trail.contains(TCP_OPEN_TRACE) && trail.contains("after=Open"),
            },
        )
    })();

    if result.is_err() {
        resources.collect_failure_logs(base.layout);
    }
    resources.stop_capture();
    resources.cleanup_best_effort(&names);
    result
}

/// What one helper's tap says of its links with rmule.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HelperLinks {
    /// Links the helper accepted from rmule: a stream toward the helper's
    /// listener opened by the other side.
    pub(crate) dialed_by_rmule: u64,
    /// `OP_KAD_FWTCPCHECK_ACK` frames the helper wrote on those links.
    pub(crate) acks_on_dialed: u64,
    /// Links the helper opened toward rmule's listener.
    pub(crate) connect_backs: u64,
    /// `OP_KAD_FWTCPCHECK_ACK` frames the helper wrote on those links.
    pub(crate) acks_on_connect_back: u64,
}

/// Sort the helper tap's streams between the helper and rmule by who dialed.
fn read_helper_links(
    docker: &Docker,
    (tap_name, pcap): &(String, String),
    rmule_ip: &str,
) -> Result<HelperLinks> {
    let streams = capture_tcp_streams(docker, tap_name, pcap, &format!("host {rmule_ip}"))?;
    let mut links = HelperLinks::default();
    for stream in &streams {
        let acks = stream
            .ed2k_frames()
            .iter()
            .filter(|frame| frame.protocol == 0xC5 && frame.opcode == 0xA8)
            .count() as u64;
        let (from, to) = (stream.source, stream.destination);
        if from.ip().to_string() == rmule_ip {
            continue;
        }
        if from.port() == KAD_TCP_PORT && to.port() != RMULE_SERVE_TCP_PORT {
            links.dialed_by_rmule += 1;
            links.acks_on_dialed += acks;
        } else if to.port() == RMULE_SERVE_TCP_PORT {
            links.connect_backs += 1;
            links.acks_on_connect_back += acks;
        }
    }
    Ok(links)
}

/// rmule's collected stdout and stderr, one string.
fn rmule_trail(layout: &RunLayout) -> String {
    let mut trail = fs::read_to_string(layout.kad_node_stdout_log("rmule")).unwrap_or_default();
    trail.push_str(&fs::read_to_string(layout.kad_node_stderr_log("rmule")).unwrap_or_default());
    trail
}

/// Whether rmule handed an ack to its Kad node off a link whose far end was the
/// helper's listener port, which only a link rmule dialed has.
fn ack_traced_from_listener_port(trail: &str, helper_ip: &str) -> bool {
    trail.lines().any(|line| {
        line.contains(ACK_TRACE)
            && line.contains(&format!("from={helper_ip}"))
            && line.contains(&format!("port={KAD_TCP_PORT}"))
    })
}

/// Judge flow S and write its verdict file.
fn assert_dialed_link(layout: &RunLayout, facts: &Facts<'_>) -> Result<()> {
    let verdict = DialedLinkVerdict::judge(facts);
    let path = layout.kad_dir().join("kad-dialed-link-verdict.toml");
    fs::write(&path, facts.file_text(verdict))
        .with_context(|| format!("write {}", path.display()))?;
    println!(
        "kad-dialed-link verdict={} dialed_acks={} connect_backs={} tcp_open={}",
        verdict.label(),
        facts.dialed.acks_on_dialed,
        facts.dialed.connect_backs,
        facts.tcp_open
    );
    if verdict == DialedLinkVerdict::Fail {
        anyhow::bail!(
            "flow S did not stand up: rmule never dialed the sharing helper (dialed links = {})",
            facts.dialed.dialed_by_rmule
        );
    }
    Ok(())
}
