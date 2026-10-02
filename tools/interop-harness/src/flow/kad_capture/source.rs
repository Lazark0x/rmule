//! kad-source-capture: rmule publishes a source to a real aMule storer and
//! captures aMule's genuine KADEMLIA2_SEARCH_RES (0x3B) answer.

use std::fs;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::docker::{Docker, RunContainer};
use crate::flow::bench::{
    CaptureSidecar, DEFAULT_TAP_INTERFACE, KadMeshNames, KadResources, fallback_id, run_checked,
    write_id,
};
use crate::flow::gate::wait_for_kad_log;
use crate::flow::identity::{hex_lower, ipv4_string, parse_ed2k_file_hash};
use crate::flow::kad_capture::verdict::assert_kad_source_capture;
use crate::flow::logs::{collect_kad_logs, collect_kad_node_logs};
use crate::flow::mesh::{
    KAD_CONTACT_VERSION, KAD_NETWORK_SUBNET, KAD_RMULE_IP, KAD_RMULE_KAD_ID, KAD_RMULE_UDP_PORT,
    KAD_STORER_IP, KAD_TCP_PORT, KadCaptureOptions, KadNodeSpec, start_kad_node,
};

/// Options for [`run_kad_source_capture`] beyond the shared Kad capture options.
pub struct KadSourceCaptureOptions<'a> {
    /// The shared Kad bench options.
    pub base: KadCaptureOptions<'a>,
    /// The rmule stimulus-node container image (built from the repo root).
    pub rmule_image: &'a str,
    /// Dockerfile for the rmule image.
    pub rmule_dockerfile: &'a std::path::Path,
    /// Build context for the rmule image (the repo root).
    pub rmule_build_context: &'a std::path::Path,
    /// The Kad Publisher User Hash (hex). The captured source row's 16-byte ID
    /// should equal this hash word-swapped (`SourceIdMeaning`).
    pub user_hash_hex: &'a str,
    /// How long the stimulus node runs (publish retries + search + capture).
    pub stimulus_window_secs: u64,
}

/// Run the kad-source-capture interop flow (ADR-0043).
///
/// The capture ADR-0069's park was waiting for. rmule acts as **Kad Stimulus
/// Node** — publisher *and* requester — against one real aMule **storer**. The
/// old `0x3B` wall sat on aMule's *publisher* role (its `NODECOMPLETE`
/// self-lookup gate); aMule's storer path has no such gate, so rmule doing the
/// publishing dissolves the wall.
///
/// Topology and timing:
/// - One patched-aMule storer, Kad ID = the file's Kad key, seeded with the
///   rmule node's contact in a routing-zone `nodes.dat`. The all-LAN routing
///   table (plus `FilterLanIPs 0`) puts aMule in **LAN mode**, where
///   `IsFirewalledUDP` returns false — so `Process2PublishSourceRequest` does
///   not silently drop the publish (the firewall gate is pre-mitigated, no new
///   patch needed; verified against aMule `UDPFirewallTester.cpp`).
/// - The rmule stimulus node starts first (so aMule's hello to the seeded
///   contact succeeds and rmule stays in aMule's tree), bootstraps to the
///   storer, then — once a contact responds — publishes the synthetic file's
///   source (`0x44`) and searches for it (`0x34`), retrying each until aMule's
///   success-only answer arrives.
///
/// The evidence is read from rmule's own datagram tap (rmule records what
/// aMule sent it): aMule's `0x4B` publish ack and its genuine `0x3B` source
/// answer are aMule-authored bytes. rmule's `0x44`/`0x34` are stimulus context,
/// never evidence.
pub fn run_kad_source_capture(options: KadSourceCaptureOptions<'_>) -> Result<()> {
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
    run_checked(
        docker.build_image_with_dockerfile(
            options.rmule_image,
            options.rmule_dockerfile.as_os_str(),
            options.rmule_build_context.as_os_str(),
        ),
        "build rmule stimulus-node image",
    )?;

    fs::create_dir_all(base.layout.docker_dir()).with_context(|| {
        format!(
            "create docker artifact directory {}",
            base.layout.docker_dir().display()
        )
    })?;

    // The synthetic file's ED2K hash: rmule publishes and searches for it, and
    // the storer's Kad ID is derived from it so both walks converge on the
    // storer.
    let link = fs::read_to_string(base.layout.synthetic_ed2k_file())
        .with_context(|| format!("read {}", base.layout.synthetic_ed2k_file().display()))?;
    let file_hash = parse_ed2k_file_hash(link.trim())?;
    let file_size = fs::metadata(base.layout.synthetic_shared_file())
        .with_context(|| format!("stat {}", base.layout.synthetic_shared_file().display()))?
        .len();
    let storer_kad_id = crate::kad_seed::storer_kad_id_for_file_hash(file_hash);

    let hub_udp_port = base.kad_udp_port_base + 2;
    let specs = vec![KadNodeSpec {
        role: "storer".to_owned(),
        container: names.storer.clone(),
        udp_port: hub_udp_port,
        ip: KAD_STORER_IP,
        kad_id: storer_kad_id,
        user_hash_hex: None,
        shared_host_dir: base.layout.amule_dir(),
        bootstrap_peers: Vec::new(),
        // Routing-zone seed so aMule loads the rmule contact straight into its
        // queryable tree: that both makes the table all-LAN (LAN mode) and lets
        // aMule hello rmule to keep it verified.
        routing_zone_seed: true,
        seed_contacts: vec![crate::kad_seed::KadContact {
            kad_id: KAD_RMULE_KAD_ID,
            ipv4: KAD_RMULE_IP,
            udp_port: KAD_RMULE_UDP_PORT,
            tcp_port: KAD_TCP_PORT,
            version: KAD_CONTACT_VERSION,
        }],
    }];

    let network_id = run_checked(
        docker.create_network_with_subnet(names.network_name.clone(), KAD_NETWORK_SUBNET),
        "create kad docker network",
    )?;
    let mut resources = KadResources::new(&docker, base.keep_containers);
    resources.own_network();

    let result = (|| -> Result<()> {
        write_id(
            &base.layout.network_id_file(),
            fallback_id(&network_id, &names.network_name),
        )?;
        let timeout = Duration::from_secs(base.timeout_secs);

        // rmule starts first so aMule's hello to the seeded contact succeeds and
        // rmule stays in aMule's routing tree (an evicted seed would drop aMule
        // out of LAN mode). The node self-terminates at its window and finalizes
        // its capture, so the finalize happens at a deterministic instant.
        let rmule_dir = base.layout.kad_rmule_dir();
        fs::create_dir_all(&rmule_dir)
            .with_context(|| format!("create {}", rmule_dir.display()))?;
        let rmule = RunContainer::new(options.rmule_image.to_owned())
            .detach()
            .name(names.rmule.clone())
            .network(KadMeshNames::network_for(base.layout))
            .ip(ipv4_string(KAD_RMULE_IP))
            .volume(rmule_dir.clone(), "/artifacts")
            .arg("--bind")
            .arg(format!("0.0.0.0:{KAD_RMULE_UDP_PORT}"))
            .arg("--id-hex")
            .arg(hex_lower(&KAD_RMULE_KAD_ID))
            .arg("--tcp-port")
            .arg(KAD_TCP_PORT.to_string())
            .arg("--bootstrap")
            .arg(format!("{}:{hub_udp_port}", ipv4_string(KAD_STORER_IP)))
            .arg("--capture-dir")
            .arg("/artifacts/tap")
            .arg("--events-file")
            .arg("/artifacts/events.log")
            .arg("--run-secs")
            .arg(options.stimulus_window_secs.to_string())
            .arg("--user-hash-hex")
            .arg(options.user_hash_hex.to_owned())
            .arg("--publish-file-hash")
            .arg(hex_lower(&file_hash))
            .arg("--publish-file-size")
            .arg(file_size.to_string());
        let rmule_id = run_checked(docker.run_container(rmule), "run rmule stimulus node")?;
        resources.track_started("rmule", names.rmule.clone());
        write_id(
            &base.layout.docker_dir().join("kad-rmule-container-id.txt"),
            fallback_id(&rmule_id, &names.rmule),
        )?;
        wait_for_kad_log(
            &docker,
            base.layout,
            "rmule",
            &names.rmule,
            "rmule-kad-join-node-ready",
            timeout,
        )?;

        // Passive pcap on the rmule node's interface (cross-check corroboration;
        // the primary evidence is rmule's own first-class tap).
        resources.start_capture(
            base.layout,
            &CaptureSidecar {
                image: base.capture_image,
                name: &names.capture,
                target_container: &names.rmule,
                interface: DEFAULT_TAP_INTERFACE,
                host_dir: base.layout.kad_capture_dir(),
                pcap_file: "kad-source-capture.pcap",
                bpf: "udp",
            },
            "kad-source-capture-container-id.txt",
        )?;

        // The aMule storer: loads rmule from its routing-zone seed, enters LAN
        // mode (~10s after the first LAN-only routing check), and answers the
        // publish and search rmule sends.
        let storer = start_kad_node(&docker, base, &specs, 0, &mut resources)?;
        wait_for_kad_log(
            &docker,
            base.layout,
            &storer.role,
            &storer.container,
            "rmule-kad-routing-ready",
            timeout,
        )?;

        println!(
            "kad-source-capture: storer up; rmule publishing + searching for {}s",
            options.stimulus_window_secs
        );
        // "done" prints only after the node finalizes its capture, so waiting
        // for it guarantees datagrams.toml exists before the verdict.
        wait_for_kad_log(
            &docker,
            base.layout,
            "rmule",
            &names.rmule,
            "rmule-kad-join-node-done",
            Duration::from_secs(options.stimulus_window_secs + 90),
        )?;

        resources.stop_capture();
        resources.stop_role("storer");
        let nodes = vec![storer];
        collect_kad_node_logs(&docker, base.layout, &nodes);
        collect_kad_logs(&docker, base.layout, "rmule", &names.rmule)?;

        assert_kad_source_capture(
            base.layout,
            KAD_STORER_IP,
            hub_udp_port,
            options.user_hash_hex,
            storer_kad_id,
        )
    })();

    if result.is_err() {
        resources.collect_failure_logs(base.layout);
    }

    resources.cleanup_best_effort(&names);
    result
}
