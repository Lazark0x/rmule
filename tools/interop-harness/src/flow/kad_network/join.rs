//! The kad-join flow: rmule joins a private aMule mesh as a live Kad
//! citizen.
//!
//! rmule's node identity and address are fixed before anything starts, so the
//! hub's routing-zone seed can name them. Acceptance is read off the capture:
//! the hub must answer rmule's hello and then route real Kad traffic at it —
//! being *in* another node's table, not merely having sent to it.

use std::fs;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::docker::{Docker, RunContainer};
use crate::flow::bench::{
    CaptureSidecar, DEFAULT_TAP_INTERFACE, KadMeshNames, KadResources, fallback_id, run_checked,
    write_id,
};
use crate::flow::evidence::{TapRow, read_tap_rows};
use crate::flow::gate::wait_for_kad_log;
use crate::flow::identity::{hex_lower, ipv4_string};
use crate::flow::logs::{collect_kad_logs, collect_kad_node_logs};
use crate::flow::mesh::{
    KAD_CONTACT_VERSION, KAD_NETWORK_SUBNET, KAD_RMULE_IP, KAD_RMULE_KAD_ID, KAD_RMULE_UDP_PORT,
    KAD_STORER_IP, KAD_TCP_PORT, KadCaptureOptions, KadNodeSpec, start_kad_node,
};

/// Options for [`run_kad_join`] beyond the shared Kad capture options.
pub struct KadJoinOptions<'a> {
    /// The shared Kad bench options.
    pub base: KadCaptureOptions<'a>,
    /// The rmule join-node container image (built from the repo root).
    pub rmule_image: &'a str,
    /// Dockerfile for the rmule image.
    pub rmule_dockerfile: &'a std::path::Path,
    /// Build context for the rmule image (the repo root).
    pub rmule_build_context: &'a std::path::Path,
    /// How long the joined mesh runs before the verdict is read.
    pub join_window_secs: u64,
}

/// Run the kad-join interop flow (ADR-0043).
///
/// One patched-aMule hub is seeded with the rmule node's contact in its
/// routing-zone `nodes.dat`; the rmule join node (a real `rmule_net::kad`
/// process in its own container) bootstraps into the hub and answers whatever
/// aMule sends. The **bidirectional acceptance moment** is asserted from
/// rmule's datagram tap: aMule — of its own volition — sends hello/ping and
/// `KADEMLIA2_REQ` lookups *to* rmule and keeps doing so after rmule's
/// answers. rmule's bytes are stimulus; the judgement reads only
/// aMule-emitted datagrams (Kad Stimulus Node doctrine).
pub fn run_kad_join(options: KadJoinOptions<'_>) -> Result<()> {
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
    // The rmule image is always (re)built: it must track the workspace
    // sources being tested, and BuildKit layer/cargo caches keep it cheap.
    run_checked(
        docker.build_image_with_dockerfile(
            options.rmule_image,
            options.rmule_dockerfile.as_os_str(),
            options.rmule_build_context.as_os_str(),
        ),
        "build rmule join-node image",
    )?;

    fs::create_dir_all(base.layout.docker_dir()).with_context(|| {
        format!(
            "create docker artifact directory {}",
            base.layout.docker_dir().display()
        )
    })?;

    let hub_udp_port = base.kad_udp_port_base + 2;
    let specs = vec![KadNodeSpec {
        role: "hub".to_owned(),
        container: names.storer.clone(),
        udp_port: hub_udp_port,
        ip: KAD_STORER_IP,
        kad_id: [0xD1; 16],
        user_hash_hex: None,
        shared_host_dir: base.layout.amule_dir(),
        bootstrap_peers: Vec::new(),
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

        // The rmule node starts FIRST: the hub's seeded contact must already
        // be listening when aMule boots and starts helloing it.
        let rmule_dir = base.layout.kad_rmule_dir();
        fs::create_dir_all(&rmule_dir)
            .with_context(|| format!("create {}", rmule_dir.display()))?;
        // The join node observes for exactly the window, then self-terminates
        // and finalizes its capture — its lifetime is not tied to the overall
        // flow timeout, so the run stays short and the finalize happens at
        // a deterministic instant the harness waits for.
        let rmule_run_secs = options.join_window_secs;
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
            .arg(rmule_run_secs.to_string());
        let rmule_id = run_checked(docker.run_container(rmule), "run rmule join node")?;
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

        // Passive pcap on the rmule node's interface, armed before the hub
        // exists so the whole exchange is recorded.
        resources.start_capture(
            base.layout,
            &CaptureSidecar {
                image: base.capture_image,
                name: &names.capture,
                target_container: &names.rmule,
                interface: DEFAULT_TAP_INTERFACE,
                host_dir: base.layout.kad_capture_dir(),
                pcap_file: "kad-join.pcap",
                bpf: "udp",
            },
            "kad-join-capture-container-id.txt",
        )?;

        // Now the hub: it loads rmule from its routing-zone seed and begins
        // node maintenance (hello/ping) and its self-lookup (0x21) against it.
        let hub = start_kad_node(&docker, base, &specs, 0, &mut resources)?;
        wait_for_kad_log(
            &docker,
            base.layout,
            &hub.role,
            &hub.container,
            "rmule-kad-routing-ready",
            timeout,
        )?;

        // The join window: the hub keeps sending its own maintenance traffic
        // while the join node observes, self-terminates at its deadline, and
        // finalizes its capture. "done" is printed only after the finalize, so
        // waiting for it guarantees `datagrams.toml` exists before the verdict.
        println!(
            "kad-join: mesh joined; observing for {}s",
            options.join_window_secs
        );
        wait_for_kad_log(
            &docker,
            base.layout,
            "rmule",
            &names.rmule,
            "rmule-kad-join-node-done",
            Duration::from_secs(rmule_run_secs + 90),
        )?;

        resources.stop_capture();
        resources.stop_role("hub");
        let nodes = vec![hub];
        collect_kad_node_logs(&docker, base.layout, &nodes);
        collect_kad_logs(&docker, base.layout, "rmule", &names.rmule)?;

        assert_kad_join_acceptance(base.layout, hub_udp_port)
    })();

    if result.is_err() {
        resources.collect_failure_logs(base.layout);
    }

    resources.cleanup_best_effort(&names);
    result
}

/// Judge the join from rmule's datagram tap, using only aMule-emitted
/// datagrams (Kad Stimulus Node doctrine: rmule's own bytes are never
/// evidence).
///
/// The tap rows are judged in arrival order (`seq`), so "after" below means a
/// later datagram.
///
/// The bidirectional acceptance moment is a `KADEMLIA2_REQ` (`0x21`) that
/// aMule sends *to* rmule of its own volition. aMule only sends a lookup
/// request to a contact it has in its routing tree and has selected as one of
/// the closest to a search target — so a single unsolicited `0x21` proves both
/// "aMule added rmule to its routing table" and "aMule routes lookups through
/// rmule". We require, from aMule-authored bytes:
///
/// 1. rmule never sent aMule a `0x21` first — so the inbound one is genuinely
///    aMule-initiated, not a reply to us;
/// 2. aMule sent ≥1 `0x21` to rmule, and rmule answered it with a
///    `KADEMLIA2_RES` (`0x29`) — the routing exchange completed;
/// 3. aMule kept talking to rmule after that answer (any further aMule
///    datagram) — aMule did not drop rmule as a bad contact once served.
///
/// aMule completing a hello handshake with rmule (`0x19`) is recorded as
/// corroborating contact-acceptance, not required: in this topology rmule
/// initiates the hello, so aMule answers rather than initiating its own.
fn assert_kad_join_acceptance(layout: &RunLayout, hub_udp_port: u16) -> Result<()> {
    const LOOKUP_REQ: i64 = 0x21;
    const LOOKUP_RES: i64 = 0x29;
    const HELLO_RES: i64 = 0x19;

    let rows = read_tap_rows(&layout.kad_rmule_dir().join("tap"))?;
    let hub_remote = format!("{}:{hub_udp_port}", ipv4_string(KAD_STORER_IP));
    let hub_frames: Vec<&TapRow> = rows.iter().filter(|row| row.remote == hub_remote).collect();

    let rmule_sent_lookup_req = hub_frames.iter().any(|row| row.is("out", LOOKUP_REQ));
    let amule_lookup_reqs: Vec<usize> = hub_frames
        .iter()
        .filter(|row| row.is("in", LOOKUP_REQ))
        .map(|row| row.seq)
        .collect();
    let rmule_lookup_answers: Vec<usize> = hub_frames
        .iter()
        .filter(|row| row.is("out", LOOKUP_RES))
        .map(|row| row.seq)
        .collect();
    let amule_sent_hello_res = hub_frames.iter().any(|row| row.is("in", HELLO_RES));

    // The routing acceptance moment: an aMule-initiated lookup that rmule
    // answered. `answered_lookup` is the frame index of rmule's answer.
    let answered_lookup = amule_lookup_reqs.iter().find_map(|&req| {
        rmule_lookup_answers
            .iter()
            .copied()
            .find(|&answer| answer >= req)
    });
    // aMule kept interacting after being served: any aMule datagram to rmule
    // after rmule's lookup answer.
    let continued = answered_lookup
        .map(|answer| {
            hub_frames
                .iter()
                .any(|row| row.direction == "in" && row.seq > answer)
        })
        .unwrap_or(false);

    let routed = !rmule_sent_lookup_req && answered_lookup.is_some();
    let verdict_pass = routed && continued;

    let inbound_opcodes: Vec<String> = hub_frames
        .iter()
        .filter(|row| row.direction == "in")
        .map(|row| format!("0x{:02x}", row.opcode))
        .collect();
    let mut report = String::new();
    report.push_str("# kad-join acceptance verdict (ADR-0043)\n\n");
    report.push_str(&format!("hub = \"{hub_remote}\"\n"));
    report.push_str(&format!("frames_total = {}\n", rows.len()));
    report.push_str(&format!(
        "amule_initiated_lookups_0x21 = {}\n",
        amule_lookup_reqs.len()
    ));
    report.push_str(&format!(
        "rmule_answered_a_lookup = {}\n",
        answered_lookup.is_some()
    ));
    report.push_str(&format!(
        "rmule_initiated_lookup_first = {rmule_sent_lookup_req}\n"
    ));
    report.push_str(&format!(
        "amule_completed_hello_handshake = {amule_sent_hello_res}\n"
    ));
    report.push_str(&format!("amule_continued_after_answer = {continued}\n"));
    report.push_str(&format!("amule_to_rmule_opcodes = {inbound_opcodes:?}\n"));
    report.push_str(&format!(
        "verdict = \"{}\"\n",
        if verdict_pass { "PASS" } else { "FAIL" }
    ));
    let verdict_path = layout.kad_dir().join("kad-join-verdict.txt");
    fs::write(&verdict_path, &report)
        .with_context(|| format!("write {}", verdict_path.display()))?;
    println!("{report}");
    println!("verdict written to {}", verdict_path.display());

    if !verdict_pass {
        bail!(
            "kad-join acceptance not met: aMule routed a lookup through rmule = {routed}, \
             aMule continued after answer = {continued} (see {})",
            verdict_path.display()
        );
    }
    Ok(())
}
