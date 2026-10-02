//! kad-fake-public-source (flow F): rmule joins a STOCK-aMule
//! fake-public Kad swarm (Config A), publishes the synthetic file's source, and
//! searches it back. Unlike kad-source-capture (RFC1918 + LAN mode on the
//! patched image), the storer here runs on its normal, non-LAN-mode paths — the
//! documentation-range address already passes IsGoodIPPort, and a fresh node
//! accepts stores immediately (UDP assumed open until a firewall check proves
//! otherwise), so the round trip closes inside the stimulus window.

use std::fs;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::docker::{Docker, RunContainer};
use crate::flow::bench::{
    CaptureSidecar, DEFAULT_TAP_INTERFACE, KadMeshNames, KadResources, fallback_id, run_checked,
    write_id,
};
use crate::flow::gate::wait_for_kad_log;
use crate::flow::identity::{hex_lower, ipv4_string, parse_ed2k_file_hash, parse_ipv4_octets};
use crate::flow::kad_capture::verdict::{assert_kad_keyword_capture, assert_kad_source_capture};
use crate::flow::logs::{collect_kad_logs, collect_kad_node_logs};
use crate::flow::mesh::{
    KAD_CONTACT_VERSION, KAD_RMULE_KAD_ID, KAD_RMULE_UDP_PORT, KAD_TCP_PORT, KadCaptureOptions,
    KadNodeSpec, start_kad_node,
};

/// Options for [`run_kad_fake_public_source`] (flow F). Shares the shared Kad
/// capture options; `amule_image` here is the **stock** aMule (Config A routes
/// on unpatched aMule).
pub struct KadFakePublicSourceOptions<'a> {
    /// The shared Kad bench options.
    pub base: KadCaptureOptions<'a>,
    /// The rmule stimulus-node container image (built from the repo root).
    pub rmule_image: &'a str,
    /// Dockerfile for the rmule node image.
    pub rmule_dockerfile: &'a std::path::Path,
    /// Build context for the rmule node image (the repo root).
    pub rmule_build_context: &'a std::path::Path,
    /// The Kad Publisher User Hash (hex) rmule advertises as the source.
    pub user_hash_hex: &'a str,
    /// How long the stimulus node runs (publish retries + search + capture).
    pub stimulus_window_secs: u64,
    /// `Some(name)` runs the ADR-0062 KEYWORD legs: rmule publishes
    /// `name`'s keyword (`0x43`) then searches it back (`0x33`), and the storer is
    /// pinned to the keyword target. `None` runs the source legs (flow F).
    pub keyword: Option<&'a str>,
    /// With `keyword`: rmule sends the search while its publish walk still
    /// holds the keyword, so the search takes the target and the publish runs
    /// after it.
    pub search_during_publish: bool,
}

/// Run the fake-public Kad publish+search round trip (flow F).
///
/// One **stock** aMule storer on an internal documentation-range `/24` (Config A), its Kad ID
/// pinned to the file's Kad key (`storer_kad_id_for_file_hash`) so the publish clears the
/// tolerance zone, and seeded with the rmule node's contact so aMule holds it in its routing
/// tree. rmule (the `rmule-tools kad join-node` stimulus runner) bootstraps to the storer,
/// publishes the synthetic file's source (`0x44`), then searches it back (`0x34`). The
/// evidence is read from rmule's own tap: aMule's `0x4B` ack and its genuine `0x3B` source
/// answer — the same judge as `kad-source-capture`, keyed on the storer's fake-public IP.
pub fn run_kad_fake_public_source(options: KadFakePublicSourceOptions<'_>) -> Result<()> {
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

    let link = fs::read_to_string(base.layout.synthetic_ed2k_file())
        .with_context(|| format!("read {}", base.layout.synthetic_ed2k_file().display()))?;
    let file_hash = parse_ed2k_file_hash(link.trim())?;
    let file_size = fs::metadata(base.layout.synthetic_shared_file())
        .with_context(|| format!("stat {}", base.layout.synthetic_shared_file().display()))?
        .len();
    // The storer's Kad ID is pinned to whichever target rmule's walk converges
    // on — the keyword key (ADR-0062 keyword legs) or the file key
    // (flow F source legs) — so it is XOR-closest and clears the publish
    // tolerance zone.
    let storer_kad_id = match options.keyword {
        Some(name) => crate::kad_seed::keyword_target_kad_id(name).ok_or_else(|| {
            anyhow::anyhow!("--keyword {name:?} has no >= 3-byte token to derive a target")
        })?,
        None => crate::kad_seed::storer_kad_id_for_file_hash(file_hash),
    };

    // Fake-public plan (Config A): storer on `.2`, rmule on `.3` of one internal
    // documentation-range /24; the harness owns the address plan.
    let storer_addr = crate::fake_public::fake_public_address(0)?;
    let rmule_addr = crate::fake_public::fake_public_address(1)?;
    let subnet = storer_addr.subnet.clone();
    let storer_ip = parse_ipv4_octets(&storer_addr.ip)?;
    let rmule_ip = parse_ipv4_octets(&rmule_addr.ip)?;
    let hub_udp_port = base.kad_udp_port_base + 2;

    // Config A: FilterLanIPs=1 so the stock storer never enters LAN mode (the
    // fake-public IP already passes IsGoodIPPort). Prepended so a caller override
    // still wins if it repeats the key.
    let mut amule_env: Vec<String> = vec!["AMULE_KAD_FILTER_LAN_IPS=1".to_owned()];
    amule_env.extend(base.amule_env.iter().cloned());
    // `start_kad_node` reads only amule_image / layout / amule_env from these.
    let capture_opts = KadCaptureOptions {
        layout: base.layout,
        container_runtime: base.container_runtime,
        build_images: false,
        amule_image: base.amule_image,
        capture_image: base.capture_image,
        amule_build_context: base.amule_build_context,
        capture_build_context: base.capture_build_context,
        keep_containers: base.keep_containers,
        timeout_secs: base.timeout_secs,
        routing_nodes: 0,
        amule_env: &amule_env,
        kad_udp_port_base: base.kad_udp_port_base,
        kad_udp_port_span: base.kad_udp_port_span,
    };

    let specs = vec![KadNodeSpec {
        role: "storer".to_owned(),
        container: names.storer.clone(),
        udp_port: hub_udp_port,
        ip: storer_ip,
        kad_id: storer_kad_id,
        user_hash_hex: None,
        shared_host_dir: base.layout.amule_dir(),
        bootstrap_peers: Vec::new(),
        // Routing-zone seed so aMule loads the rmule contact straight into its
        // queryable tree and keeps helloing it — but the contact is fake-public,
        // not LAN, so the table does NOT trip LAN mode (that is the point).
        routing_zone_seed: true,
        seed_contacts: vec![crate::kad_seed::KadContact {
            kad_id: KAD_RMULE_KAD_ID,
            ipv4: rmule_ip,
            udp_port: KAD_RMULE_UDP_PORT,
            tcp_port: KAD_TCP_PORT,
            version: KAD_CONTACT_VERSION,
        }],
    }];

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

        // rmule starts first so aMule's hello to the seeded contact lands and
        // rmule stays in aMule's routing tree. It self-terminates at its window
        // and finalizes the tap at a deterministic instant.
        let rmule_dir = base.layout.kad_rmule_dir();
        fs::create_dir_all(&rmule_dir)
            .with_context(|| format!("create {}", rmule_dir.display()))?;
        let rmule = RunContainer::new(options.rmule_image.to_owned())
            .detach()
            .name(names.rmule.clone())
            .network(KadMeshNames::network_for(base.layout))
            .ip(ipv4_string(rmule_ip))
            .volume(rmule_dir.clone(), "/artifacts")
            .arg("--bind")
            .arg(format!("0.0.0.0:{KAD_RMULE_UDP_PORT}"))
            .arg("--id-hex")
            .arg(hex_lower(&KAD_RMULE_KAD_ID))
            .arg("--tcp-port")
            .arg(KAD_TCP_PORT.to_string())
            .arg("--bootstrap")
            .arg(format!("{}:{hub_udp_port}", ipv4_string(storer_ip)))
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
        // Keyword legs: the shared name whose keyword rmule publishes
        // (`0x43`) then searches back (`0x33`). The file hash + size above stay as
        // the result-row identity; the added flag flips the stimulus to keywords.
        let rmule = match options.keyword {
            Some(name) if options.search_during_publish => rmule
                .arg("--publish-keyword-name")
                .arg(name.to_owned())
                .arg("--search-during-publish"),
            Some(name) => rmule.arg("--publish-keyword-name").arg(name.to_owned()),
            None => rmule,
        };
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

        // Passive pcap on the rmule node's interface (corroboration; the tap is
        // the primary evidence).
        resources.start_capture(
            base.layout,
            &CaptureSidecar {
                image: base.capture_image,
                name: &names.capture,
                target_container: &names.rmule,
                interface: DEFAULT_TAP_INTERFACE,
                host_dir: base.layout.kad_capture_dir(),
                pcap_file: "kad-fake-public-source.pcap",
                bpf: "udp",
            },
            "kad-fake-public-capture-container-id.txt",
        )?;

        // The stock aMule storer on the fake-public /24: loads rmule from its
        // routing-zone seed and answers the publish + search.
        let storer = start_kad_node(&docker, &capture_opts, &specs, 0, &mut resources)?;
        wait_for_kad_log(
            &docker,
            base.layout,
            &storer.role,
            &storer.container,
            "rmule-kad-routing-ready",
            timeout,
        )?;

        println!(
            "kad-fake-public-source: stock storer up on {subnet}; rmule publishing + searching \
             for {}s",
            options.stimulus_window_secs
        );
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

        match options.keyword {
            Some(_) => assert_kad_keyword_capture(base.layout, storer_ip, hub_udp_port),
            None => assert_kad_source_capture(
                base.layout,
                storer_ip,
                hub_udp_port,
                options.user_hash_hex,
                storer_kad_id,
            ),
        }
    })();

    if result.is_err() {
        resources.collect_failure_logs(base.layout);
    }

    resources.cleanup_best_effort(&names);
    result
}
