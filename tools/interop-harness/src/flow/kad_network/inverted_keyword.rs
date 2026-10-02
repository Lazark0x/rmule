//! kad-inverted-keyword (flow J): the ROLE INVERSION of flow F. A
//! stock aMule PUBLISHES a keyword and SEARCHES it *toward rmule's keyword
//! store*, so rmule's serve side faces genuine aMule `0x43`/`0x33` request bytes
//! (ADR-0062 recipes 2+4). rmule's KadID is pinned to the
//! keyword target (`keyword_target_kad_id`) so it is the XOR-closest node,
//! clearing aMule's publish tolerance zone (SEARCHTOLERANCE = 2^24)
//! and drawing both the publish and the search onto it. rmule runs the same
//! `kad join-node` runner as flow F but WITHOUT a publish target: it only
//! bootstraps, serves inbound keyword requests from its keyword store, taps
//! every datagram, and logs each `KeywordPublishServed` / `KeywordSearchServed`
//! event — the two facts that prove it consumed aMule's real bytes and answered.

use std::fs;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};

use crate::docker::{Docker, RunContainer};
use crate::flow::bench::{
    CaptureSidecar, DEFAULT_TAP_INTERFACE, KadMeshNames, KadResources, amulecmd_command,
    fallback_id, run_checked, write_id,
};
use crate::flow::gate::wait_for_kad_log;
use crate::flow::identity::{hex_lower, ipv4_string, parse_ipv4_octets};
use crate::flow::kad_network::inverted_keyword_verdict::assert_kad_inverted_keyword;
use crate::flow::kad_network::smoke::wait_for_kad_connected;
use crate::flow::logs::{collect_kad_logs, collect_kad_node_logs};
use crate::flow::mesh::{
    KAD_CONTACT_VERSION, KAD_RMULE_UDP_PORT, KAD_TCP_PORT, KadCaptureOptions, KadNodeSpec,
    start_kad_node,
};

/// The inverted publisher aMule's fixed Kad ID. It is NOT the storer (rmule is),
/// so it needs no tolerance pin — just a stable value distinct from rmule's.
const KAD_INVERTED_PUBLISHER_ID: [u8; 16] = [0xA1; 16];

/// Grace after "Kad: Connected" before searching, so the autonomous keyword
/// publisher has a chance to fire its `0x43` (recipe 2) first.
const KAD_INVERTED_PUBLISH_WAIT_SECS: u64 = 45;

/// Spacing between the two searches and the results readback (UDP is lossy; the
/// search walk needs a moment to send its `0x33`).
const KAD_INVERTED_SEARCH_GAP_SECS: u64 = 12;

/// Options for [`run_kad_inverted_keyword`] (flow J). Shares the Kad capture
/// options; `amule_image` is the **stock** aMule (Config A routes on unpatched
/// aMule, and only stock aMule keeps its publish-tolerance zone honest).
pub struct KadInvertedKeywordOptions<'a> {
    /// The shared Kad bench options.
    pub base: KadCaptureOptions<'a>,
    /// The rmule storer-node container image (built from the repo root).
    pub rmule_image: &'a str,
    /// Dockerfile for the rmule node image.
    pub rmule_dockerfile: &'a std::path::Path,
    /// Build context for the rmule node image (the repo root).
    pub rmule_build_context: &'a std::path::Path,
    /// The keyword aMule shares (as `<keyword>.dat`) and searches for. rmule's
    /// KadID is pinned to this keyword's target.
    pub keyword: &'a str,
    /// A second ≥ 3-byte word appended to one search so aMule emits a
    /// **restrictive tree** in its `0x33` (recipe 4's tree-decode vector).
    pub filter_word: &'a str,
    /// Stock aMule helper nodes so the publisher can earn TCP-open — aMule's
    /// keyword-publish gate is `joined ∧ (TCP-open ∨ buddy)` (ADR-0062); a lone
    /// firewalled node never runs its autonomous publisher. Helpers give recipe
    /// 2 (`0x43`) a genuine chance; the search (recipe 4) needs none of them.
    pub helper_count: usize,
    /// How long the rmule storer serves (boot + connect + publish-wait + search).
    pub storer_window_secs: u64,
    /// Budget for the aMule publisher to reach "Kad: Connected" before searching.
    pub kad_connect_deadline_secs: u64,
}

/// Run the inverted-role keyword flow (flow J, ADR-0062 recipes 2+4).
///
/// One **stock** aMule publisher shares `<keyword>.dat` on an internal
/// documentation-range `/24` (Config A) and has rmule seeded into its queryable
/// routing zone; `helper_count` stock aMule nodes bootstrap to it so it can earn
/// TCP-open and run its autonomous keyword publisher. rmule (the `kad join-node`
/// binary in serve mode, KadID pinned to the keyword target) bootstraps to the
/// publisher and serves. Once the publisher is Kad-connected the harness fires an
/// `amulecmd` Kad keyword search (plain, then a restrictive two-word one). The
/// evidence is read from rmule's own tap + events log: aMule's inbound `0x33`
/// (search) — and, when the publish gate opens, `0x43` (publish) — paired with
/// rmule's `KeywordSearchServed` / `KeywordPublishServed` events.
pub fn run_kad_inverted_keyword(options: KadInvertedKeywordOptions<'_>) -> Result<()> {
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
        "build rmule storer-node image",
    )?;

    fs::create_dir_all(base.layout.docker_dir()).with_context(|| {
        format!(
            "create docker artifact directory {}",
            base.layout.docker_dir().display()
        )
    })?;

    // Pin rmule's KadID to the keyword target using rmule's OWN derivation, so a
    // fold that matches aMule routes the publish/search onto rmule (and a fold
    // that does not misroutes it away — the routing tests the parity).
    let storer_kad_id =
        crate::kad_seed::keyword_target_kad_id(options.keyword).ok_or_else(|| {
            anyhow!(
                "keyword {:?} has no >= 3-byte token to derive a Kad target from",
                options.keyword
            )
        })?;

    // Stage the publisher's shared file: a complete `<keyword>.dat` in its own
    // /incoming (aMule derives the keyword from the filename, extension stripped),
    // and an empty /incoming for the helpers (they share nothing, only route).
    let publisher_incoming = base.layout.kad_dir().join("publisher-incoming");
    let helper_incoming = base.layout.kad_dir().join("helper-incoming");
    fs::create_dir_all(&publisher_incoming)
        .with_context(|| format!("create {}", publisher_incoming.display()))?;
    fs::create_dir_all(&helper_incoming)
        .with_context(|| format!("create {}", helper_incoming.display()))?;
    let shared_name = format!("{}.dat", options.keyword);
    fs::copy(
        base.layout.synthetic_shared_file(),
        publisher_incoming.join(&shared_name),
    )
    .with_context(|| format!("stage shared file {shared_name} for the aMule publisher"))?;

    // Fake-public plan (Config A): rmule storer on `.2`, publisher on `.3`,
    // helpers on `.4`.. of one internal documentation-range /24.
    let rmule_addr = crate::fake_public::fake_public_address(0)?;
    let publisher_addr = crate::fake_public::fake_public_address(1)?;
    let subnet = rmule_addr.subnet.clone();
    let rmule_ip = parse_ipv4_octets(&rmule_addr.ip)?;
    let publisher_ip = parse_ipv4_octets(&publisher_addr.ip)?;
    let publisher_udp_port = base.kad_udp_port_base + 2;

    let mut amule_env: Vec<String> = vec!["AMULE_KAD_FILTER_LAN_IPS=1".to_owned()];
    amule_env.extend(base.amule_env.iter().cloned());
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

    // The publisher (spec 0): rmule seeded into its queryable routing zone so its
    // keyword publish/search can select rmule; it passively acquires the helpers
    // (and rmule) as they dial it. The helpers (specs 1..) each
    // bootstrap to the publisher via a bootstrap-edition seed naming it.
    let rmule_seed_contact = crate::kad_seed::KadContact {
        kad_id: storer_kad_id,
        ipv4: rmule_ip,
        udp_port: KAD_RMULE_UDP_PORT,
        tcp_port: KAD_TCP_PORT,
        version: KAD_CONTACT_VERSION,
    };
    let mut specs = vec![KadNodeSpec {
        role: "publisher".to_owned(),
        container: names.publisher.clone(),
        udp_port: publisher_udp_port,
        ip: publisher_ip,
        kad_id: KAD_INVERTED_PUBLISHER_ID,
        user_hash_hex: None,
        shared_host_dir: publisher_incoming.clone(),
        bootstrap_peers: Vec::new(),
        routing_zone_seed: true,
        seed_contacts: vec![rmule_seed_contact],
    }];
    for helper_index in 0..options.helper_count {
        let addr = crate::fake_public::fake_public_address(2 + helper_index)?;
        let mut kad_id = [0xB0u8; 16];
        kad_id[0] = 0xB1 + u8::try_from(helper_index).unwrap_or(0);
        specs.push(KadNodeSpec {
            role: format!("helper-{helper_index}"),
            container: names.routing(u32::try_from(helper_index).unwrap_or(0)),
            udp_port: base.kad_udp_port_base + 3 + u16::try_from(helper_index).unwrap_or(0),
            ip: parse_ipv4_octets(&addr.ip)?,
            kad_id,
            user_hash_hex: None,
            shared_host_dir: helper_incoming.clone(),
            // Bootstrap-edition seed naming the publisher so the helper actively
            // dials it; the publisher learns the helper passively.
            bootstrap_peers: vec![0],
            routing_zone_seed: false,
            seed_contacts: Vec::new(),
        });
    }

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

        // rmule storer starts first: pinned, serving, bootstrapping to the
        // publisher in a retry loop until the publisher comes up. No publish
        // target — it only serves inbound keyword requests.
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
            .arg(hex_lower(&storer_kad_id))
            .arg("--tcp-port")
            .arg(KAD_TCP_PORT.to_string())
            .arg("--bootstrap")
            .arg(format!(
                "{}:{publisher_udp_port}",
                ipv4_string(publisher_ip)
            ))
            .arg("--capture-dir")
            .arg("/artifacts/tap")
            .arg("--events-file")
            .arg("/artifacts/events.log")
            .arg("--run-secs")
            .arg(options.storer_window_secs.to_string());
        let rmule_id = run_checked(docker.run_container(rmule), "run rmule storer node")?;
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
                pcap_file: "kad-inverted-keyword.pcap",
                bpf: "udp",
            },
            "kad-inverted-capture-container-id.txt",
        )?;

        // The stock aMule publisher, then the helpers.
        let publisher = start_kad_node(&docker, &capture_opts, &specs, 0, &mut resources)?;
        wait_for_kad_log(
            &docker,
            base.layout,
            &publisher.role,
            &publisher.container,
            "rmule-kad-publisher-ready",
            timeout,
        )?;
        let mut nodes = vec![publisher];
        for helper_index in 0..options.helper_count {
            let helper = start_kad_node(
                &docker,
                &capture_opts,
                &specs,
                1 + helper_index,
                &mut resources,
            )?;
            wait_for_kad_log(
                &docker,
                base.layout,
                &helper.role,
                &helper.container,
                "rmule-kad-routing-ready",
                timeout,
            )?;
            nodes.push(helper);
        }

        // Poll the publisher for "Kad: Connected" before searching — its search
        // walk cannot start until Kad is joined. rmule's bootstrap (and the
        // helpers') drives it there.
        println!(
            "kad-inverted-keyword: swarm up on {subnet}; waiting for the aMule publisher to reach \
             Kad Connected (budget {}s)",
            options.kad_connect_deadline_secs
        );
        let connected = wait_for_kad_connected(
            &docker,
            std::slice::from_ref(&nodes[0]),
            options.kad_connect_deadline_secs,
            &subnet,
        )?;
        if !connected.connected {
            eprintln!(
                "warning: aMule publisher did not report 'Kad: Connected' within {}s; firing the \
                 search anyway and letting the tap decide",
                options.kad_connect_deadline_secs
            );
        }

        // Give the autonomous keyword publisher a window to fire its 0x43 (it
        // only runs once the publisher is TCP-open, which the helpers enable).
        thread::sleep(Duration::from_secs(KAD_INVERTED_PUBLISH_WAIT_SECS));

        // Fire the searches on the publisher: a plain keyword (baseline 0x33,
        // no restrictive tree) then a two-word one (restrictive-tree 0x33). Each
        // is a distinct query, so aMule's per-keyword search-repeat gate never
        // suppresses the second.
        trigger_kad_keyword_search(&docker, &nodes[0].container, options.keyword);
        thread::sleep(Duration::from_secs(KAD_INVERTED_SEARCH_GAP_SECS));
        trigger_kad_keyword_search(
            &docker,
            &nodes[0].container,
            &format!("{} {}", options.keyword, options.filter_word),
        );

        // Capture aMule's own view of the answer (proves it parsed rmule's 0x3B
        // when the store is populated); best-effort, recorded for the verdict.
        // A failed sweep warns rather than failing the flow — but it must warn,
        // because an empty view and an unrun one both read as "aMule rendered
        // nothing" in the verdict otherwise.
        thread::sleep(Duration::from_secs(KAD_INVERTED_SEARCH_GAP_SECS));
        let results_view = match docker
            .exec(nodes[0].container.clone(), amulecmd_command("Results"))
            .to_command()
            .output()
        {
            Ok(out) => String::from_utf8_lossy(&out.stdout).into_owned(),
            Err(error) => {
                eprintln!("warning: amulecmd Results sweep did not run: {error}");
                String::new()
            }
        };

        // Let the rmule window elapse so the tap finalizes (0x33/0x43 land inside
        // it). "done" prints only after the finalize, so datagrams.toml exists.
        wait_for_kad_log(
            &docker,
            base.layout,
            "rmule",
            &names.rmule,
            "rmule-kad-join-node-done",
            Duration::from_secs(options.storer_window_secs + 120),
        )?;

        resources.stop_capture();
        for node in &nodes {
            resources.stop_role(&node.role);
        }
        collect_kad_node_logs(&docker, base.layout, &nodes);
        collect_kad_logs(&docker, base.layout, "rmule", &names.rmule)?;

        assert_kad_inverted_keyword(
            base.layout,
            publisher_ip,
            publisher_udp_port,
            options.keyword,
            storer_kad_id,
            connected.connected,
            &results_view,
        )
    })();

    if result.is_err() {
        resources.collect_failure_logs(base.layout);
    }

    resources.cleanup_best_effort(&names);
    result
}

/// Fire a single aMule Kad keyword search via `amulecmd`. Fire-and-forget: a
/// failed exec warns (a transient EC hiccup) but never aborts the run — the tap
/// is the arbiter of whether a `0x33` actually flew.
fn trigger_kad_keyword_search(docker: &Docker, publisher: &str, query: &str) {
    let command = format!("search kad {query}");
    if let Err(error) = run_checked(
        docker.exec(publisher.to_owned(), amulecmd_command(&command)),
        "fire aMule Kad keyword search",
    ) {
        eprintln!("warning: aMule keyword search {query:?} failed: {error:#}");
    } else {
        println!("kad-inverted-keyword: fired aMule Kad search {query:?}");
    }
}
