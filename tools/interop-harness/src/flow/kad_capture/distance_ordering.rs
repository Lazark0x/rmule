//! The Kad distance-ordering capture (ADR-0043).
//!
//! One aMule responder plus the four discrimination contacts from
//! `kad_distance_design`, each seeded with a chosen Kad ID and bootstrapped to
//! the responder. A stimulus `KADEMLIA2_REQ` draws the responder's
//! `KADEMLIA2_RES`, whose contact ordering is the responder's own XOR-distance
//! ranking and therefore names the winning byte-order hypothesis. The verdict is
//! read straight off the pcap, framing-agnostically.

use std::fs;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::artifacts::RunLayout;
use crate::docker::{Docker, RunContainer};
use crate::flow::bench::{
    CaptureSidecar, DEFAULT_TAP_INTERFACE, KadMeshNames, KadResources, fallback_id, run_checked,
    write_id,
};
use crate::flow::gate::wait_for_kad_log;
use crate::flow::identity::hex_lower;
use crate::flow::logs::collect_kad_node_logs;
use crate::flow::mesh::{
    KAD_NETWORK_SUBNET, KAD_STORER_IP, KadCaptureOptions, KadNode, KadNodeSpec, start_kad_node,
    wait_kad_settle_window, write_kad_endpoints, write_kad_nodes,
};

/// The flow name every artifact this flow writes is tagged with.
const FLOW: &str = "kad-distance-ordering-capture";

/// Capture the Kad distance-ordering evidence (ADR-0043).
///
/// Stands up one aMule **responder** (hub) plus the four discrimination **contact**
/// nodes from [`crate::kad_distance_design`], each seeded with a chosen Kad ID and
/// bootstrapping to the responder so the responder learns them (verified, via
/// HELLO) into its routing table. A stimulus then sends a raw `KADEMLIA2_REQ` for
/// the design target; the responder's `KADEMLIA2_RES` — captured passively —
/// returns those contacts *ranked by its own XOR distance*, which names the winning
/// byte-order hypothesis. Every returned byte is genuine aMule output; the stimulus
/// REQ is context, not evidence (a **Kad Stimulus Node**, ADR-0043).
pub fn run_kad_distance_ordering_capture(options: KadCaptureOptions<'_>) -> Result<()> {
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

    let specs = plan_kad_distance_nodes(&options, &names);

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

        let timeout = Duration::from_secs(options.timeout_secs);
        // Start the four contacts first, then the responder. The responder
        // bootstraps *to* the contacts (its seed nodes.dat names them), so it
        // actively HELLO-verifies them into a returnable state — eMule's
        // `GetClosestTo` withholds contacts it only learned passively. The
        // contacts must therefore be listening before the responder boots.
        let mut contacts = Vec::with_capacity(specs.len() - 1);
        for index in 1..specs.len() {
            contacts.push(start_kad_node(
                &docker,
                &options,
                &specs,
                index,
                &mut resources,
            )?);
        }
        for contact in &contacts {
            wait_for_kad_log(
                &docker,
                options.layout,
                &contact.role,
                &contact.container,
                "rmule-kad-routing-ready",
                timeout,
            )?;
        }
        let responder = start_kad_node(&docker, &options, &specs, 0, &mut resources)?;
        wait_for_kad_log(
            &docker,
            options.layout,
            &responder.role,
            &responder.container,
            "rmule-kad-routing-ready",
            timeout,
        )?;
        let mut nodes = vec![responder];
        nodes.extend(contacts);

        // The capture is armed before the settle window so the pcap holds the
        // responder's bootstrap/HELLO-verify of the contacts as well as the
        // stimulus; all UDP, so the `0x21`/`0x29` exchange is recorded whole.
        resources.start_capture(
            options.layout,
            &CaptureSidecar {
                image: options.capture_image,
                name: &names.capture,
                target_container: &names.storer,
                interface: DEFAULT_TAP_INTERFACE,
                host_dir: options.layout.kad_capture_dir(),
                pcap_file: "kad-distance.pcap",
                bpf: "udp",
            },
            "kad-distance-capture-container-id.txt",
        )?;

        // eMule withholds unverified contacts from a KADEMLIA2_RES, so the settle
        // window is what makes the responder's answer non-empty.
        wait_kad_settle_window(options.timeout_secs);

        send_stimulus_reqs(&docker, &options, &names, &nodes[0])?;
        // Let the last responses land before finalizing the pcap.
        thread::sleep(Duration::from_secs(3));

        write_kad_endpoints(options.layout, FLOW, &nodes)?;
        write_kad_nodes(options.layout, FLOW, &nodes)?;
        write_kad_distance_summary(options.layout, &nodes)?;

        resources.stop_capture();
        collect_kad_node_logs(&docker, options.layout, &nodes);
        report_distance_verdict(options.layout);
        Ok(())
    })();

    if result.is_err() {
        resources.collect_failure_logs(options.layout);
    }

    resources.cleanup_best_effort(&names);
    result
}

/// Plan the responder (hub) plus the four discrimination contacts. The responder's
/// Kad ID and the contacts' Kad IDs come from [`crate::kad_distance_design`]; the
/// contacts bootstrap to the responder (index 0) so it learns them by HELLO.
fn plan_kad_distance_nodes(
    options: &KadCaptureOptions<'_>,
    names: &KadMeshNames,
) -> Vec<KadNodeSpec> {
    // The responder (index 0) is seeded with the four contacts as a routing-zone
    // nodes.dat, so aMule loads them straight into its queryable routing tree and
    // can return them ranked in a KADEMLIA2_RES. (A bootstrap-edition seed would
    // only feed the bootstrap list — `CRoutingZone::ReadFile` never adds those to
    // the tree.) The contacts still run as real reachable nodes so aMule does not
    // prune them as dead before the stimulus.
    let contact_indices: Vec<usize> =
        (1..=crate::kad_distance_design::FLIP_POSITIONS.len()).collect();
    let mut specs = vec![KadNodeSpec {
        role: "storer".to_owned(),
        container: names.storer.clone(),
        udp_port: options.kad_udp_port_base + 2,
        ip: KAD_STORER_IP,
        kad_id: crate::kad_distance_design::RESPONDER_KAD_ID,
        user_hash_hex: None,
        shared_host_dir: options.layout.amule_dir(),
        bootstrap_peers: contact_indices,
        routing_zone_seed: true,
        seed_contacts: Vec::new(),
    }];
    for (i, contact) in crate::kad_distance_design::seed_contacts()
        .into_iter()
        .enumerate()
    {
        let n = (i + 1) as u16;
        specs.push(KadNodeSpec {
            role: format!("routing-{n}"),
            container: names.routing(u32::from(n)),
            udp_port: options.kad_udp_port_base + 2 + n,
            ip: [172, 30, 0, KAD_STORER_IP[3] + n as u8],
            kad_id: contact.kad_id,
            user_hash_hex: None,
            shared_host_dir: options.layout.amule_dir(),
            bootstrap_peers: vec![],
            routing_zone_seed: false,
            seed_contacts: Vec::new(),
        });
    }
    specs
}

/// Fire the stimulus `KADEMLIA2_REQ` at the responder several times over its Kad UDP
/// port. Uses the capture image's bash `/dev/udp` so no extra tool or image is
/// needed; fire-and-forget, since the passive capture records the responder's reply.
fn send_stimulus_reqs(
    docker: &Docker,
    options: &KadCaptureOptions<'_>,
    names: &KadMeshNames,
    responder: &KadNode,
) -> Result<()> {
    let hex: String = crate::kad_distance_design::stimulus_req()
        .iter()
        .map(|byte| format!("\\x{byte:02x}"))
        .collect();
    let command = format!(
        "for _ in $(seq 1 8); do printf '{hex}' > /dev/udp/{ip}/{port}; sleep 0.5; done",
        ip = responder.ip,
        port = responder.udp_port,
    );
    let container = RunContainer::new(options.capture_image.to_owned())
        .remove_after_exit()
        .name(format!("rmule-interop-kad-stimulus-{}", names.suffix))
        .network(KadMeshNames::network_for(options.layout))
        .arg("bash")
        .arg("-c")
        .arg(command);
    run_checked(
        docker.run_container(container),
        "send kad distance-ordering stimulus",
    )?;
    Ok(())
}

/// Write the design facts the promotion step needs: the target, the responder's
/// Kad ID, and each contact's on-wire Kad ID with the byte-flip position and the
/// per-hypothesis expected-closest read-out, so a human can match the captured
/// `0x29` against exactly one hypothesis.
fn write_kad_distance_summary(layout: &RunLayout, nodes: &[KadNode]) -> Result<()> {
    use crate::kad_distance_design as design;

    let mut text = String::new();
    text.push_str("# Kad distance-ordering capture design (ADR-0043)\n\n");
    text.push_str(&format!("target = {}\n", hex_lower(&design::TARGET)));
    text.push_str(&format!(
        "responder_kad_id = {}\n",
        hex_lower(&design::RESPONDER_KAD_ID)
    ));
    text.push_str(&format!(
        "stimulus_req = {}\n\n",
        design::stimulus_req()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));

    text.push_str("[contacts]\n");
    for (i, (&pos, id)) in design::FLIP_POSITIONS
        .iter()
        .zip(design::contact_ids())
        .enumerate()
    {
        let node = nodes
            .iter()
            .find(|n| n.role == format!("routing-{}", i + 1));
        let endpoint = node.map_or_else(|| "?".to_owned(), |n| format!("{}:{}", n.ip, n.udp_port));
        text.push_str(&format!(
            "contact[{i}] flip_pos={pos:>2} kad_id={} endpoint={endpoint}\n",
            hex_lower(&id),
        ));
    }

    text.push_str("\n[expected_closest_by_hypothesis]\n");
    for hypothesis in design::HYPOTHESES {
        text.push_str(&format!(
            "{:<20} -> flip_pos {} (contact kad_id {})\n",
            hypothesis.name,
            design::expected_closest_position(&hypothesis),
            hex_lower(&{
                let mut id = design::TARGET;
                id[design::expected_closest_position(&hypothesis)] ^= 0x80;
                id
            }),
        ));
    }

    let path = layout.kad_capture_dir().join("distance-design.txt");
    fs::create_dir_all(layout.kad_capture_dir())
        .with_context(|| format!("create {}", layout.kad_capture_dir().display()))?;
    fs::write(&path, text).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Scan the captured pcap for the responder's `KADEMLIA2_RES` answers to the
/// stimulus, decode them, and write a verdict naming the winning byte-order
/// hypothesis (or recording that every answer was empty — the tiny-mesh
/// verification wall). Framing-agnostic: it locates each `0x29` by the `E4 29`
/// opcode followed by the exact design target, so it needs no Ethernet/IP/UDP
/// header parsing.
fn report_distance_verdict(layout: &RunLayout) {
    use crate::kad_distance_design as design;

    let pcap_path = layout.kad_capture_dir().join("kad-distance.pcap");
    let bytes = match fs::read(&pcap_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("warning: cannot read distance pcap {pcap_path:?}: {error}");
            return;
        }
    };

    let mut signature = vec![0xE4u8, 0x29];
    signature.extend_from_slice(&design::TARGET);

    let mut empty = 0usize;
    let mut nonempty: Vec<design::DecodedRes> = Vec::new();
    let mut offset = 0usize;
    while let Some(found) = find_subslice(&bytes[offset..], &signature) {
        let start = offset + found;
        if let Some(res) = design::decode_kademlia2_res(&bytes[start..]) {
            if res.contacts.is_empty() {
                empty += 1;
            } else {
                nonempty.push(res);
            }
        }
        offset = start + 2;
    }

    let mut verdict = String::new();
    verdict.push_str("# Kad distance-ordering capture verdict (ADR-0043)\n\n");
    verdict.push_str(&format!(
        "responses: {} non-empty, {empty} empty (count=0)\n\n",
        nonempty.len()
    ));

    match nonempty.first() {
        Some(res) => {
            let closest = res.contacts[0].kad_id;
            verdict.push_str(&format!("closest_returned = {}\n", hex_lower(&closest)));
            match design::identify_hypothesis(&closest) {
                Some(name) => verdict.push_str(&format!("HYPOTHESIS CONFIRMED: {name}\n")),
                None => verdict.push_str(
                    "closest contact is not one of the seeded discrimination IDs (unexpected)\n",
                ),
            }
            verdict.push_str("\nfull ordering (closest first):\n");
            for (rank, contact) in res.contacts.iter().enumerate() {
                verdict.push_str(&format!("  {rank}: {}\n", hex_lower(&contact.kad_id)));
            }
            println!("{verdict}");
        }
        None => {
            verdict.push_str(
                "NO RANKED ANSWER: every KADEMLIA2_RES was empty. The responder \
                 retained the seeded contacts but withheld them (unverified / firewalled) \
                 — the tiny-mesh verification wall.\n",
            );
            eprintln!("{verdict}");
        }
    }

    let path = layout.kad_capture_dir().join("distance-verdict.txt");
    if let Err(error) = fs::write(&path, &verdict) {
        eprintln!("warning: cannot write distance verdict {path:?}: {error}");
    }
}

/// First index of `needle` in `haystack`, or `None`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
