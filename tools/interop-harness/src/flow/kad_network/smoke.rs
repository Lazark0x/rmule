//! kad-smoke: two STOCK aMule nodes reach Kad Connected on a fake-public subnet
//! — validates the Config-A topology verdict on real Docker.

use std::fs;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::docker::Docker;
use crate::flow::bench::{
    KadMeshNames, KadResources, amulecmd_command, fallback_id, run_checked, write_id,
};
use crate::flow::gate::wait_for_kad_log;
use crate::flow::identity::parse_ipv4_octets;
use crate::flow::logs::{collect_kad_node_logs, dump_kad_diagnostics};
use crate::flow::mesh::{KadCaptureOptions, KadNode, KadNodeSpec, start_kad_node};

/// Poll cadence for the amulecmd Kad-status probe: bounded retries, not a blind
/// sleep. The cold-boot → connected window is ~3–6 min, so a
/// coarse interval keeps the exec count low.
const KAD_SMOKE_POLL_INTERVAL_SECS: u64 = 5;

/// Fixed distinct Kad IDs for the two smoke nodes. Connectivity does not need a
/// pinned identity (no publish tolerance here), but `start_kad_node` always
/// seeds a `preferencesKad.dat`, so give each a stable, distinct value.
const KAD_SMOKE_SEED_ID: [u8; 16] = [0x51; 16];
const KAD_SMOKE_JOINER_ID: [u8; 16] = [0x1A; 16];

/// Options for the stock-aMule Kad smoke.
pub struct KadSmokeOptions<'a> {
    /// The run dir every artifact is written under.
    pub layout: &'a RunLayout,
    /// The Docker-compatible CLI to invoke.
    pub container_runtime: &'a str,
    /// Build the project-owned images before starting anything.
    pub build_images: bool,
    /// The **stock** aMule image (`rmule/interop-amule:local`) — Config A routes
    /// on unpatched aMule; the LAN-patched image is retired from evidence duty.
    pub amule_image: &'a str,
    /// Build context for the aMule image.
    pub amule_build_context: &'a Path,
    /// Leave the containers and network running after the run.
    pub keep_containers: bool,
    /// Per-step timeout for a node's Kad-started readiness log.
    pub timeout_secs: u64,
    /// Overall budget for a node to reach "Kad: Connected" (~3–6 min
    /// cold-boot). Failure past this is a MAJOR finding (Config A falsified).
    pub connect_deadline_secs: u64,
    /// Extra `KEY=VALUE` environment for the aMule container(s).
    pub amule_env: &'a [String],
    /// The first Kad UDP port the mesh's nodes listen on.
    pub kad_udp_port_base: u16,
}

/// The kad-smoke verdict: whether stock aMule reached Kad Connected on the
/// fake-public subnet, which node, and how long it took.
pub(crate) struct KadSmokeVerdict {
    pub(crate) connected: bool,
    pub(crate) node_role: String,
    pub(crate) status_line: String,
    pub(crate) elapsed_secs: u64,
    pub(crate) subnet: String,
}

/// Run the stock-aMule Kad smoke: two stock aMule nodes on an
/// internal fake-public `/24`, seed + joiner, and success when at least one
/// reports "Kad: Connected" via amulecmd polling. This is the empirical check
/// of the Config-A topology verdict on real Docker — a non-connect is a major
/// finding, not silently forced.
pub fn run_kad_smoke(options: KadSmokeOptions<'_>) -> Result<()> {
    let docker = Docker::new(options.container_runtime);
    let names = KadMeshNames::from_layout(options.layout)?;

    if options.build_images {
        run_checked(
            docker.build_image(options.amule_image, options.amule_build_context),
            "build aMule image",
        )?;
    }

    fs::create_dir_all(options.layout.docker_dir()).with_context(|| {
        format!(
            "create docker artifact directory {}",
            options.layout.docker_dir().display()
        )
    })?;

    // Fake-public plan: two nodes on one documentation /24 (Config A).
    let seed_addr = crate::fake_public::fake_public_address(0)?;
    let joiner_addr = crate::fake_public::fake_public_address(1)?;
    let subnet = seed_addr.subnet.clone();

    // Config A: FilterLanIPs=1 so the stock node never enters LAN mode (the
    // fake-public IPs already pass IsGoodIPPort). Prepended so a caller override
    // still wins if it repeats the key.
    let mut amule_env: Vec<String> = vec!["AMULE_KAD_FILTER_LAN_IPS=1".to_owned()];
    amule_env.extend(options.amule_env.iter().cloned());

    // `start_kad_node` reads only amule_image / layout / amule_env from these;
    // the capture fields are unused here (there is no capture sidecar).
    let capture_opts = KadCaptureOptions {
        layout: options.layout,
        container_runtime: options.container_runtime,
        build_images: false,
        amule_image: options.amule_image,
        capture_image: options.amule_image,
        amule_build_context: options.amule_build_context,
        capture_build_context: options.amule_build_context,
        keep_containers: options.keep_containers,
        timeout_secs: options.timeout_secs,
        routing_nodes: 0,
        amule_env: &amule_env,
        kad_udp_port_base: options.kad_udp_port_base,
        kad_udp_port_span: 0,
    };

    let specs = vec![
        KadNodeSpec {
            role: "seed".to_owned(),
            container: names.storer.clone(),
            udp_port: options.kad_udp_port_base + 2,
            ip: parse_ipv4_octets(&seed_addr.ip)?,
            kad_id: KAD_SMOKE_SEED_ID,
            user_hash_hex: None,
            shared_host_dir: options.layout.amule_dir(),
            // Seed: bootstraps to nobody; the joiner dials it and it learns the
            // joiner passively.
            bootstrap_peers: vec![],
            routing_zone_seed: false,
            seed_contacts: Vec::new(),
        },
        KadNodeSpec {
            role: "joiner".to_owned(),
            container: names.requester.clone(),
            udp_port: options.kad_udp_port_base + 3,
            ip: parse_ipv4_octets(&joiner_addr.ip)?,
            kad_id: KAD_SMOKE_JOINER_ID,
            user_hash_hex: None,
            shared_host_dir: options.layout.amule_dir(),
            // Bootstrap to the seed via a bootstrap-edition nodes.dat naming it.
            bootstrap_peers: vec![0],
            routing_zone_seed: false,
            seed_contacts: Vec::new(),
        },
    ];

    let network_id = run_checked(
        docker.create_internal_network_with_subnet(names.network_name.clone(), subnet.clone()),
        "create fake-public kad network",
    )?;
    let mut resources = KadResources::new(&docker, options.keep_containers);
    resources.own_network();

    let result = (|| -> Result<()> {
        write_id(
            &options.layout.network_id_file(),
            fallback_id(&network_id, &names.network_name),
        )?;
        let timeout = Duration::from_secs(options.timeout_secs);

        // The seed must be listening before the joiner bootstraps to it.
        let seed = start_kad_node(&docker, &capture_opts, &specs, 0, &mut resources)?;
        wait_for_kad_log(
            &docker,
            options.layout,
            &seed.role,
            &seed.container,
            "rmule-kad-routing-ready",
            timeout,
        )?;
        let joiner = start_kad_node(&docker, &capture_opts, &specs, 1, &mut resources)?;
        wait_for_kad_log(
            &docker,
            options.layout,
            &joiner.role,
            &joiner.container,
            "rmule-kad-routing-ready",
            timeout,
        )?;
        let nodes = vec![seed, joiner];

        println!(
            "kad-smoke: two stock aMule nodes up on {subnet}; polling amulecmd for Kad Connected \
             (budget {}s)",
            options.connect_deadline_secs
        );
        let verdict =
            wait_for_kad_connected(&docker, &nodes, options.connect_deadline_secs, &subnet)?;
        write_kad_smoke_verdict(options.layout, &verdict)?;
        collect_kad_node_logs(&docker, options.layout, &nodes);

        if !verdict.connected {
            for node in &nodes {
                if let Err(error) = dump_kad_diagnostics(&docker, options.layout, node) {
                    eprintln!(
                        "warning: failed to dump kad diagnostics for {}: {error:#}",
                        node.role
                    );
                }
            }
            bail!(
                "stock aMule did not reach 'Kad: Connected' on fake-public {subnet} within {}s — \
                 this would falsify the Config-A finding; diagnostics retained in the run dir",
                options.connect_deadline_secs
            );
        }
        Ok(())
    })();

    if result.is_err() {
        resources.collect_failure_logs(options.layout);
    }

    resources.cleanup_best_effort(&names);
    result
}

/// Poll `amulecmd Status` on each node until one reports "Kad: Connected"
/// (either `(ok)` or `(firewalled)` counts), or the deadline elapses. Bounded
/// retries at a fixed interval — never a blind sleep; a transient exec failure
/// (a node mid-restart) just skips that round.
pub(crate) fn wait_for_kad_connected(
    docker: &Docker,
    nodes: &[KadNode],
    deadline_secs: u64,
    subnet: &str,
) -> Result<KadSmokeVerdict> {
    let start = Instant::now();
    let deadline = start + Duration::from_secs(deadline_secs);
    let interval = Duration::from_secs(KAD_SMOKE_POLL_INTERVAL_SECS);
    loop {
        for node in nodes {
            let output = docker
                .exec(node.container.clone(), amulecmd_command("Status"))
                .to_command()
                .output();
            if let Ok(output) = output {
                let text = String::from_utf8_lossy(&output.stdout);
                if let Some(line) = text.lines().find(|line| line.contains("Kad: Connected")) {
                    return Ok(KadSmokeVerdict {
                        connected: true,
                        node_role: node.role.clone(),
                        status_line: line.trim().to_owned(),
                        elapsed_secs: start.elapsed().as_secs(),
                        subnet: subnet.to_owned(),
                    });
                }
            }
        }
        if Instant::now() >= deadline {
            return Ok(KadSmokeVerdict {
                connected: false,
                node_role: String::new(),
                status_line: "Kad: Not connected".to_owned(),
                elapsed_secs: start.elapsed().as_secs(),
                subnet: subnet.to_owned(),
            });
        }
        thread::sleep(interval.min(deadline.saturating_duration_since(Instant::now())));
    }
}

/// Write the kad-smoke verdict to the run dir and print it prominently.
fn write_kad_smoke_verdict(layout: &RunLayout, verdict: &KadSmokeVerdict) -> Result<()> {
    let text = format!(
        "scenario = \"kad-smoke\"\n\
         stock_amule = true\n\
         subnet = \"{}\"\n\
         kad_connected = {}\n\
         connected_node = \"{}\"\n\
         status_line = \"{}\"\n\
         elapsed_secs = {}\n",
        verdict.subnet,
        verdict.connected,
        verdict.node_role,
        verdict.status_line,
        verdict.elapsed_secs,
    );
    let path = layout.kad_dir().join("kad-smoke-verdict.txt");
    fs::create_dir_all(layout.kad_dir())
        .with_context(|| format!("create {}", layout.kad_dir().display()))?;
    fs::write(&path, &text).with_context(|| format!("write {}", path.display()))?;
    println!(
        "kad-smoke: kad_connected={} node={} ({}) after {}s on {}",
        verdict.connected,
        verdict.node_role,
        verdict.status_line,
        verdict.elapsed_secs,
        verdict.subnet,
    );
    Ok(())
}
