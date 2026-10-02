//! The private Kad mesh every Kad flow is staged on.
//!
//! A user-defined subnet lets the harness know each node's address *before* it
//! starts anything, which is what makes a seeded bootstrap `nodes.dat` (whose
//! contacts must name peer IPs) deterministic. This module plans that topology —
//! identities, static IPs, who bootstraps to whom — starts each aMule or rmule
//! node with its seeded `preferencesKad.dat` / `nodes.dat`, attaches the passive
//! capture sidecar, and records the resulting endpoint table into the run dir.

use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::artifacts::RunLayout;
use crate::docker::{Docker, RunContainer};
use crate::flow::bench::{
    KadMeshNames, KadResources, amulecmd_command, fallback_id, run_checked, write_id,
};
use crate::flow::identity::{hex_lower, ipv4_string};

pub(crate) const KAD_EC_PASSWORD: &str = "rmule";
pub(crate) const KAD_TCP_PORT: u16 = 4662;
pub(crate) const KAD_EC_PORT: u16 = 4712;
pub(crate) const KAD_CONTACT_VERSION: u8 = 8;

// `.1` is the bridge gateway, so node addresses start at `.2`; routing-N takes
// `.(KAD_ROUTING_IP_BASE + N)`.
pub(crate) const KAD_NETWORK_SUBNET: &str = "172.30.0.0/24";
pub(crate) const KAD_PUBLISHER_IP: [u8; 4] = [172, 30, 0, 2];
pub(crate) const KAD_REQUESTER_IP: [u8; 4] = [172, 30, 0, 3];
pub(crate) const KAD_STORER_IP: [u8; 4] = [172, 30, 0, 4];
pub(crate) const KAD_ROUTING_IP_BASE: u8 = 4; // routing-N gets .(BASE + N).

// Fixed, known, non-secret identities so a captured source row's 16-byte ID can
// be matched against exactly one harness-owned value (resolving
// `KadEvidence::SourceIdMeaning`). The publisher's Kad ID and User Hash are
// deliberately distinct. The storer's Kad ID is derived from the file hash at
// runtime (see `kad_seed::storer_kad_id_for_file_hash`).
pub(crate) const KAD_PUBLISHER_KAD_ID: [u8; 16] = [
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
];
pub(crate) const KAD_REQUESTER_KAD_ID: [u8; 16] = [
    0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0,
];
/// The Kad Publisher's fixed, non-secret User Hash: the captured source row's
/// 16-byte ID should equal it word-swapped (resolving `SourceIdMeaning`).
pub const KAD_PUBLISHER_USER_HASH_HEX: &str = "0badf00ddeadbeef0badf00ddeadbeef";

/// The settle window's override knob (tests set `0`); always clamped to
/// `--timeout`.
pub(crate) const KAD_SETTLE_WINDOW_ENV: &str = "RMULE_KAD_SETTLE_WINDOW_SECS";
/// The bounded wait for the counterparty's own Kad timers before the stimulus
/// fires. aMule publishes its source (`KADEMLIA2_PUBLISH_SOURCE_REQ`) only after
/// its initial `NODECOMPLETE` self-lookup completes — roughly four minutes after
/// it connects — so a requester that searches earlier finds the storer holding
/// no source; and a responder returns only contacts it has HELLO-verified, so a
/// stimulus `KADEMLIA2_REQ` fired earlier draws an empty `KADEMLIA2_RES`.
pub(crate) const KAD_DEFAULT_SETTLE_WINDOW_SECS: u64 = 240;

// The requester's Kad source search is fired by `Cancel` + re-`Add` (a bare `Add`
// of an already-present file is gated by the per-file `m_LastSearchTimeKad`). We
// repeat it so at least one fresh `0x34` lands after routing settles and after
// the publish has reached the storer.
pub(crate) const KAD_SEARCH_RETRY_ATTEMPTS: u32 = 4;
pub(crate) const KAD_SEARCH_RETRY_INTERVAL_SECS: u64 = 25;
// Best-effort grace for the entrypoint's (weak) search-active signal; the pcap is
// the real evidence, so a miss here only warns.
pub(crate) const KAD_SEARCH_SIGNAL_GRACE_SECS: u64 = 10;

/// The options every Kad flow shares: the mesh's images, bench knobs and
/// UDP port plan.
pub struct KadCaptureOptions<'a> {
    /// The run dir every artifact is written under.
    pub layout: &'a RunLayout,
    /// The Docker-compatible CLI to invoke.
    pub container_runtime: &'a str,
    /// Build the project-owned images before starting anything.
    pub build_images: bool,
    /// The aMule image.
    pub amule_image: &'a str,
    /// The tcpdump capture-sidecar image.
    pub capture_image: &'a str,
    /// Build context for the aMule image.
    pub amule_build_context: &'a Path,
    /// Build context for the capture-sidecar image.
    pub capture_build_context: &'a Path,
    /// Leave the containers and network running after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget, in seconds.
    pub timeout_secs: u64,
    /// Extra routing-role nodes for Phase 2 density (0 = Phase 1).
    pub routing_nodes: u32,
    /// Extra `KEY=VALUE` environment for the aMule container(s).
    pub amule_env: &'a [String],
    /// The first Kad UDP port the mesh's nodes listen on.
    pub kad_udp_port_base: u16,
    /// How many contiguous UDP ports above the base the capture filters on.
    pub kad_udp_port_span: u16,
}

/// A planned Kad node: its identity and address are known before it is started
/// so peers can bootstrap to it via a static-IP `nodes.dat`.
pub(crate) struct KadNodeSpec {
    pub(crate) role: String,
    pub(crate) container: String,
    pub(crate) udp_port: u16,
    pub(crate) ip: [u8; 4],
    pub(crate) kad_id: [u8; 16],
    /// Fixed User Hash (hex) for the publisher only; `None` for other roles.
    pub(crate) user_hash_hex: Option<&'static str>,
    pub(crate) shared_host_dir: std::path::PathBuf,
    /// Indices into the spec list whose contacts seed this node's `nodes.dat`.
    pub(crate) bootstrap_peers: Vec<usize>,
    /// When true, write `bootstrap_peers` as a routing-zone (version 1) `nodes.dat`
    /// that aMule loads straight into its queryable routing tree, instead of the
    /// bootstrap-edition file (which only feeds the bootstrap list). Used by the
    /// distance-ordering capture so the responder can *return* the seeded contacts.
    pub(crate) routing_zone_seed: bool,
    /// Extra contacts appended verbatim to this node's seed `nodes.dat` —
    /// participants that are not harness aMule containers (e.g. the rmule
    /// join node), so they cannot be named via `bootstrap_peers` indices.
    pub(crate) seed_contacts: Vec<crate::kad_seed::KadContact>,
}

pub(crate) struct KadNode {
    pub(crate) role: String,
    pub(crate) container: String,
    pub(crate) udp_port: u16,
    pub(crate) ip: String,
    pub(crate) kad_id: [u8; 16],
    pub(crate) user_hash_hex: Option<&'static str>,
}

/// Plan the full set of Kad nodes (identities, static IPs, bootstrap topology)
/// before any container starts. The publisher seeds the file; the requester
/// searches; the storer's Kad ID equals the file-hash target so both converge on
/// it. `--routing-nodes` adds extra routing-role nodes for Phase 2 density.
pub(crate) fn plan_kad_nodes(
    options: &KadCaptureOptions<'_>,
    names: &KadMeshNames,
    storer_kad_id: [u8; 16],
) -> Vec<KadNodeSpec> {
    // Hub topology: the storer (Kad ID = file-hash target) is the rendezvous for
    // both the publish and the search, so every other node bootstraps *to* it and
    // it bootstraps to nobody. It is index 0 and MUST be started first and be
    // listening before any other node boots: aMule sends its bootstrap exactly
    // once, so a node whose bootstrap lands on a socket that is not up yet keeps
    // an empty routing table and can neither publish nor search.
    let storer = 0usize;

    let mut specs = vec![
        KadNodeSpec {
            role: "storer".to_owned(),
            container: names.storer.clone(),
            udp_port: options.kad_udp_port_base + 2,
            ip: KAD_STORER_IP,
            kad_id: storer_kad_id,
            user_hash_hex: None,
            shared_host_dir: options.layout.amule_dir(),
            // Hub: the storer bootstraps to nobody; the others bootstrap to it.
            bootstrap_peers: vec![],
            routing_zone_seed: false,
            seed_contacts: Vec::new(),
        },
        KadNodeSpec {
            role: "publisher".to_owned(),
            container: names.publisher.clone(),
            udp_port: options.kad_udp_port_base,
            ip: KAD_PUBLISHER_IP,
            kad_id: KAD_PUBLISHER_KAD_ID,
            user_hash_hex: Some(KAD_PUBLISHER_USER_HASH_HEX),
            shared_host_dir: options.layout.synthetic_dir(),
            // Bootstrap to the storer so the source publish converges on it.
            bootstrap_peers: vec![storer],
            routing_zone_seed: false,
            seed_contacts: Vec::new(),
        },
        KadNodeSpec {
            role: "requester".to_owned(),
            container: names.requester.clone(),
            udp_port: options.kad_udp_port_base + 1,
            ip: KAD_REQUESTER_IP,
            kad_id: KAD_REQUESTER_KAD_ID,
            user_hash_hex: None,
            shared_host_dir: options.layout.amule_dir(),
            // Bootstrap to the storer so the source search converges on it.
            bootstrap_peers: vec![storer],
            routing_zone_seed: false,
            seed_contacts: Vec::new(),
        },
    ];

    for index in 1..=options.routing_nodes {
        specs.push(KadNodeSpec {
            role: format!("routing-{index}"),
            container: names.routing(index),
            udp_port: options.kad_udp_port_base + 2 + index as u16,
            ip: [172, 30, 0, KAD_ROUTING_IP_BASE + index as u8],
            kad_id: routing_kad_id(index),
            user_hash_hex: None,
            shared_host_dir: options.layout.amule_dir(),
            // Extra density nodes bootstrap to the storer.
            bootstrap_peers: vec![storer],
            routing_zone_seed: false,
            seed_contacts: Vec::new(),
        });
    }

    specs
}

/// Deterministic distinct Kad ID for routing node `index` (filler density only;
/// not a publish/search rendezvous point).
pub(crate) fn routing_kad_id(index: u32) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[0] = 0xE0;
    id[15] = index as u8;
    id
}

pub(crate) fn start_kad_node(
    docker: &Docker,
    options: &KadCaptureOptions<'_>,
    specs: &[KadNodeSpec],
    index: usize,
    resources: &mut KadResources<'_>,
) -> Result<KadNode> {
    let spec = &specs[index];
    let role = spec.role.as_str();
    let container = spec.container.clone();

    // Write this node's identity seed and bootstrap nodes.dat under the run dir,
    // then mount that directory at /seed; the entrypoint copies them into the
    // aMule config dir before amuled starts.
    let seed_dir = options.layout.kad_node_seed_dir(role);
    fs::create_dir_all(&seed_dir)
        .with_context(|| format!("create kad seed directory {}", seed_dir.display()))?;
    let prefs = crate::kad_seed::build_preferences_kad_dat(spec.kad_id);
    let prefs_path = seed_dir.join("preferencesKad.dat");
    fs::write(&prefs_path, prefs).with_context(|| format!("write {}", prefs_path.display()))?;

    let mut contacts: Vec<crate::kad_seed::KadContact> = spec
        .bootstrap_peers
        .iter()
        .map(|&peer| {
            let peer = &specs[peer];
            crate::kad_seed::KadContact {
                kad_id: peer.kad_id,
                ipv4: peer.ip,
                udp_port: peer.udp_port,
                tcp_port: KAD_TCP_PORT,
                version: KAD_CONTACT_VERSION,
            }
        })
        .collect();
    contacts.extend(spec.seed_contacts.iter().cloned());
    let nodes_dat = if spec.routing_zone_seed {
        crate::kad_seed::build_routing_zone_nodes_dat(&contacts)
    } else {
        crate::kad_seed::build_bootstrap_nodes_dat(&contacts)
    };
    let nodes_dat_path = seed_dir.join("nodes.dat");
    fs::write(&nodes_dat_path, nodes_dat)
        .with_context(|| format!("write {}", nodes_dat_path.display()))?;

    let mut node = RunContainer::new(options.amule_image.to_owned())
        .detach()
        .name(container.clone())
        .network(KadMeshNames::network_for(options.layout))
        .ip(ipv4_string(spec.ip))
        .volume(spec.shared_host_dir.clone(), "/incoming")
        .volume(seed_dir, "/seed")
        .env("AMULE_SCENARIO_MODE", "kad-node");
    // The firewalled-Kad variant installs iptables DROP rules in the
    // entrypoint, which needs NET_ADMIN. Added only when a block flag is passed,
    // so the open swarm flows (F/J/smoke) keep their minimal capability set.
    if options
        .amule_env
        .iter()
        .any(|env| env.starts_with("AMULE_KAD_BLOCK_"))
    {
        node = node.cap_add("NET_ADMIN");
    }
    node = node
        .env("AMULE_KAD_ROLE", kad_role_env(role))
        .env("AMULE_SHARED_DIR", "/incoming")
        .env("AMULE_TCP_PORT", KAD_TCP_PORT.to_string())
        .env("AMULE_UDP_PORT", spec.udp_port.to_string())
        .env("AMULE_EC_PORT", KAD_EC_PORT.to_string())
        .env("AMULE_KAD_PREFS_DAT", "/seed/preferencesKad.dat")
        .env("AMULE_KAD_NODES_DAT", "/seed/nodes.dat");
    if let Some(user_hash) = spec.user_hash_hex {
        node = node.env("AMULE_USER_HASH", user_hash);
    }
    for assignment in options.amule_env {
        node = node.env_assignment(assignment.to_owned());
    }

    let id = run_checked(docker.run_container(node), "run kad node container")?;
    resources.track_started(role, container.clone());
    write_id(
        &options
            .layout
            .docker_dir()
            .join(format!("kad-{role}-container-id.txt")),
        fallback_id(&id, &container),
    )?;

    let ip = run_checked(
        docker.container_ip(container.clone()),
        "inspect kad node ip",
    )?;

    Ok(KadNode {
        role: role.to_owned(),
        container,
        udp_port: spec.udp_port,
        ip: if ip.is_empty() {
            ipv4_string(spec.ip)
        } else {
            ip
        },
        kad_id: spec.kad_id,
        user_hash_hex: spec.user_hash_hex,
    })
}

/// Sit the settle window ([`KAD_DEFAULT_SETTLE_WINDOW_SECS`]) so the
/// counterparty's own Kad timers — the publisher's NODECOMPLETE-gated source
/// publish, the responder's HELLO-verification of its seeded contacts — have
/// run before the stimulus fires. Overridable via [`KAD_SETTLE_WINDOW_ENV`],
/// always clamped to `timeout_secs` so the overall run stays bounded.
pub(crate) fn wait_kad_settle_window(timeout_secs: u64) {
    let requested = std::env::var(KAD_SETTLE_WINDOW_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(KAD_DEFAULT_SETTLE_WINDOW_SECS);
    let window = requested.min(timeout_secs);
    if window > 0 {
        thread::sleep(Duration::from_secs(window));
    }
}

/// Fire repeated fresh Kad source searches on the requester via `Cancel` +
/// re-`Add`.
///
/// aMule searches a download's Kad sources once and then gates retries by the
/// per-file `m_LastSearchTimeKad`; a bare second `Add` of an already-present file
/// is a no-op. Dropping the file (`Cancel`) and re-`Add`ing it resets that timer,
/// so a fresh `KADEMLIA2_SEARCH_SOURCE_REQ` (`0x34`) fires. Repeating it lets at
/// least one search land after the requester's routing table holds the storer and
/// after the publisher's source publish has reached it. `Cancel` is best-effort
/// (the file is absent on the first pass); a failed `Add` warns, never aborts.
pub(crate) fn trigger_source_search(docker: &Docker, requester: &str, link: &str, hash_hex: &str) {
    for attempt in 0..KAD_SEARCH_RETRY_ATTEMPTS {
        let _ = run_checked(
            docker.exec(
                requester.to_owned(),
                amulecmd_command(&format!("Cancel {hash_hex}")),
            ),
            "cancel requester download to reset kad search timer",
        );
        thread::sleep(Duration::from_secs(2));
        if let Err(error) = run_checked(
            docker.exec(
                requester.to_owned(),
                amulecmd_command(&format!("Add {link}")),
            ),
            "inject source lookup target into requester",
        ) {
            eprintln!("warning: requester Add failed: {error:#}");
        }
        if attempt + 1 < KAD_SEARCH_RETRY_ATTEMPTS {
            thread::sleep(Duration::from_secs(KAD_SEARCH_RETRY_INTERVAL_SECS));
        }
    }
}

// The aMule entrypoint understands publisher/requester/routing roles; the
// routing-N labels collapse to the shared "routing" role.
pub(crate) fn kad_role_env(role: &str) -> &'static str {
    if role == "publisher" {
        "publisher"
    } else if role == "requester" {
        "requester"
    } else {
        "routing"
    }
}

/// The BPF a mesh capture filters on: the mesh's Kad UDP port range.
pub(crate) fn kad_mesh_bpf(options: &KadCaptureOptions<'_>) -> String {
    let base = options.kad_udp_port_base;
    let span_end = options.kad_udp_port_base + options.kad_udp_port_span;
    format!("udp and ( port {base} or portrange {base}-{span_end} )")
}

/// Record every node's endpoint under the run dir, tagged with the `flow` that
/// staged it.
pub(crate) fn write_kad_endpoints(layout: &RunLayout, flow: &str, nodes: &[KadNode]) -> Result<()> {
    let mut text = format!("scenario = \"{flow}\"\n");
    for node in nodes {
        text.push_str("\n[[nodes]]\n");
        text.push_str(&format!("role = \"{}\"\n", node.role));
        text.push_str(&format!("container = \"{}\"\n", node.container));
        text.push_str(&format!("ipv4 = \"{}\"\n", node.ip));
        text.push_str(&format!("tcp_port = {KAD_TCP_PORT}\n"));
        text.push_str(&format!("udp_port = {}\n", node.udp_port));
        text.push_str(&format!("ec_port = {KAD_EC_PORT}\n"));
    }
    let path = layout.kad_endpoint_map_file();
    fs::write(&path, text).with_context(|| format!("write {}", path.display()))
}

/// Record every node's seeded identity under the run dir, tagged with the
/// `flow` that staged it. Identities are seeded by the harness, not discovered
/// passively, so the seeded Kad ID (and the publisher's seeded User Hash) are
/// what a captured source-row identity is cross-checked against.
pub(crate) fn write_kad_nodes(layout: &RunLayout, flow: &str, nodes: &[KadNode]) -> Result<()> {
    let mut text = format!("scenario = \"{flow}\"\n");
    for node in nodes {
        text.push_str("\n[[nodes]]\n");
        text.push_str(&format!("role = \"{}\"\n", node.role));
        text.push_str(&format!("container = \"{}\"\n", node.container));
        text.push_str("kad_id_seeded = true\n");
        text.push_str(&format!("kad_id = \"{}\"\n", hex_lower(&node.kad_id)));
        if let Some(user_hash) = node.user_hash_hex {
            text.push_str(&format!("user_hash = \"{user_hash}\"\n"));
        }
    }
    let path = layout.kad_nodes_file();
    fs::write(&path, text).with_context(|| format!("write {}", path.display()))
}

/// The controlled identities recorded in the candidate summary so a human can
/// cross-check the captured `0x3B` source-row 16-byte ID before promotion.
pub(crate) struct KadCandidateIdentities {
    pub(crate) storer_kad_id: [u8; 16],
    pub(crate) publisher_kad_id: [u8; 16],
    pub(crate) publisher_user_hash_hex: &'static str,
}

pub(crate) fn write_kad_candidate_summary(
    layout: &RunLayout,
    flow: &str,
    routing_nodes: u32,
    identities: &KadCandidateIdentities,
) -> Result<()> {
    let phase2_attempted = routing_nodes > 0;
    let storer_kad_id = hex_lower(&identities.storer_kad_id);
    let publisher_kad_id = hex_lower(&identities.publisher_kad_id);
    let publisher_user_hash = identities.publisher_user_hash_hex;
    // The publisher's source row should carry exactly one of its two known
    // identities; recording both lets manual promotion resolve which (the open
    // `KadEvidence::SourceIdMeaning` question) directly from the capture.
    let text = format!(
        "scenario = \"{flow}\"\n\
         phase1_attempted = true\n\
         phase2_attempted = {phase2_attempted}\n\
         routing_node_count = {routing_nodes}\n\
         public_kad_used = false\n\
         pcap = \"capture/kad/kad.pcap\"\n\
         storer_kad_id = \"{storer_kad_id}\"\n\
         publisher_kad_id = \"{publisher_kad_id}\"\n\
         publisher_user_hash = \"{publisher_user_hash}\"\n\
         expected_source_row_identity = \"publisher_kad_id_or_user_hash\"\n\
         source_lookup_result_observed = false\n\
         routing_order_observed = false\n\
         promotion_required = true\n\
         notes = \"pcap must be inspected before fixture promotion; the 0x3B source-row id must equal exactly one of publisher_kad_id or publisher_user_hash\"\n"
    );
    let path = layout.kad_candidate_summary_file();
    fs::write(&path, text).with_context(|| format!("write {}", path.display()))
}

/// The rmule join node's planned identity and address inside the mesh. The
/// hub's routing-zone seed names them, so they are fixed before anything runs.
pub(crate) const KAD_RMULE_IP: [u8; 4] = [172, 30, 0, 9];
pub(crate) const KAD_RMULE_UDP_PORT: u16 = 4679;
pub(crate) const KAD_RMULE_KAD_ID: [u8; 16] = [0x5E; 16];
