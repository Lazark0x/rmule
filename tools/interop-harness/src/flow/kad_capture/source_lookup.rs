//! The Kad source-lookup capture (ADR-0043).
//!
//! Stands up the publisher / requester / storer mesh plus optional routing-node
//! density, waits the bounded publish window so the publisher's source publish
//! lands on the storer, then repeatedly triggers the requester's Kad source
//! search while a passive tcpdump records the whole exchange. The candidate
//! summary records the harness-controlled identities so a captured source row
//! can be matched against exactly one of them before promotion.

use std::fs;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::docker::Docker;
use crate::flow::bench::{
    CaptureSidecar, DEFAULT_TAP_INTERFACE, KadMeshNames, KadResources, fallback_id, run_checked,
    write_id,
};
use crate::flow::gate::wait_for_kad_log;
use crate::flow::identity::parse_ed2k_file_hash;
use crate::flow::logs::collect_kad_node_logs;
use crate::flow::mesh::{
    KAD_NETWORK_SUBNET, KAD_PUBLISHER_KAD_ID, KAD_PUBLISHER_USER_HASH_HEX,
    KAD_SEARCH_SIGNAL_GRACE_SECS, KadCandidateIdentities, KadCaptureOptions, kad_mesh_bpf,
    kad_role_env, plan_kad_nodes, start_kad_node, trigger_source_search, wait_kad_settle_window,
    write_kad_candidate_summary, write_kad_endpoints, write_kad_nodes,
};

/// The flow name every artifact this flow writes is tagged with.
const FLOW: &str = "kad-source-lookup-capture";

/// Run the source-lookup capture: stand the mesh up, sit the settle window,
/// arm the capture, trigger the requester's search, and retain the pcap plus
/// the candidate summary for manual promotion.
pub fn run_kad_source_lookup_capture(options: KadCaptureOptions<'_>) -> Result<()> {
    let docker = Docker::new(options.container_runtime);
    let names = KadMeshNames::from_layout(options.layout)?;

    if options.build_images {
        run_checked(
            docker.build_image(options.amule_image, options.amule_build_context),
            "build aMule image",
        )?;
        run_checked(
            docker.build_image(options.capture_image, options.capture_build_context),
            "build capture image",
        )?;
    }

    fs::create_dir_all(options.layout.docker_dir()).with_context(|| {
        format!(
            "create docker artifact directory {}",
            options.layout.docker_dir().display()
        )
    })?;

    // Parse the synthetic file's ED2K hash up front: the storer's Kad ID is
    // derived from it so the publish and the search converge on the storer.
    let link = fs::read_to_string(options.layout.synthetic_ed2k_file())
        .with_context(|| format!("read {}", options.layout.synthetic_ed2k_file().display()))?;
    let file_hash = parse_ed2k_file_hash(link.trim())?;
    let storer_kad_id = crate::kad_seed::storer_kad_id_for_file_hash(file_hash);
    let specs = plan_kad_nodes(&options, &names, storer_kad_id);

    let network_id = run_checked(
        docker.create_network_with_subnet(names.network_name.clone(), KAD_NETWORK_SUBNET),
        "create kad docker network",
    )?;
    let mut resources = KadResources::new(&docker, options.keep_containers);
    resources.own_network();

    let result = (|| -> Result<()> {
        write_id(
            &options.layout.network_id_file(),
            fallback_id(&network_id, &names.network_name),
        )?;

        // The storer (index 0) is the bootstrap hub: it must be listening before
        // the publisher and requester bootstrap to it, so start it first and wait
        // for its Kad socket to come up. Then start the remaining nodes — the
        // publisher seeds the private file, the requester starts empty so it must
        // resolve the source through Kad — each with a seeded identity and a
        // bootstrap `nodes.dat` naming the storer's static IP. The aMule entrypoint
        // emits the ready line for the collapsed env role
        // (publisher/requester/routing), while the label keeps the distinct
        // storer / routing-N identity for artifacts and log paths.
        let timeout = Duration::from_secs(options.timeout_secs);
        let mut nodes = Vec::with_capacity(specs.len());
        let hub = start_kad_node(&docker, &options, &specs, 0, &mut resources)?;
        wait_for_kad_log(
            &docker,
            options.layout,
            &hub.role,
            &hub.container,
            &format!("rmule-kad-{}-ready", kad_role_env(&hub.role)),
            timeout,
        )?;
        nodes.push(hub);
        for index in 1..specs.len() {
            nodes.push(start_kad_node(
                &docker,
                &options,
                &specs,
                index,
                &mut resources,
            )?);
        }
        for node in &nodes[1..] {
            wait_for_kad_log(
                &docker,
                options.layout,
                &node.role,
                &node.container,
                &format!("rmule-kad-{}-ready", kad_role_env(&node.role)),
                timeout,
            )?;
        }

        wait_kad_settle_window(options.timeout_secs);

        // Attach passive capture to the requester's network namespace, then
        // inject the Source Lookup Target so the request is recorded.
        let bpf = kad_mesh_bpf(&options);
        resources.start_capture(
            options.layout,
            &CaptureSidecar {
                image: options.capture_image,
                name: &names.capture,
                target_container: &names.requester,
                interface: DEFAULT_TAP_INTERFACE,
                host_dir: options.layout.kad_capture_dir(),
                pcap_file: "kad.pcap",
                bpf: &bpf,
            },
            "kad-capture-container-id.txt",
        )?;

        let file_hash_hex = link.trim().split('|').nth(4).unwrap_or_default();
        trigger_source_search(&docker, &names.requester, link.trim(), file_hash_hex);

        // Best-effort: the requester entrypoint emits this once the download is
        // present. The retained pcap is the real evidence, so not observing the
        // signal is non-fatal — the run still records and stops the capture.
        if let Err(error) = wait_for_kad_log(
            &docker,
            options.layout,
            "requester",
            &names.requester,
            "rmule-kad-source-search-active",
            Duration::from_secs(KAD_SEARCH_SIGNAL_GRACE_SECS),
        ) {
            eprintln!("warning: requester search-active signal not observed: {error:#}");
        }

        write_kad_endpoints(options.layout, FLOW, &nodes)?;
        write_kad_nodes(options.layout, FLOW, &nodes)?;
        write_kad_candidate_summary(
            options.layout,
            FLOW,
            options.routing_nodes,
            &KadCandidateIdentities {
                storer_kad_id,
                publisher_kad_id: KAD_PUBLISHER_KAD_ID,
                publisher_user_hash_hex: KAD_PUBLISHER_USER_HASH_HEX,
            },
        )?;

        // Stop capture before node teardown so the pcap is finalized.
        resources.stop_capture();
        collect_kad_node_logs(&docker, options.layout, &nodes);
        Ok(())
    })();

    if result.is_err() {
        resources.collect_failure_logs(options.layout);
    }

    resources.cleanup_best_effort(&names);
    result
}
