//! kad-core-buddy (flow M): the CORE-PUMPED variant of flow K. Same
//! firewalled stock aMule on the same Config-A fake-public /24, but rmule's side
//! is `rmule-tools ed2k serve start --kad` — a Kad node running INSIDE the Core
//! pump that owns the serve listener — instead of `kad join-node`'s direct
//! `rmule_net::kad` driver.
//!
//! Why the swap is the whole change: a buddy exchange has two legs on two
//! surfaces. The first is Kad-UDP (`0x51` recruit → `0x5A` answer) and any
//! stimulus can carry it. The second arrives over peer-TCP — after the `0x5A`
//! aMule's `CClientList::RequestBuddy` queues the answerer as `KS_QUEUED_BUDDY`
//! and `TryToConnect`s the TCP port the `0x5A` body advertised, then keeps that
//! socket as `m_pBuddy`'s link and pings it (`OP_BUDDYPING`). A Kad-UDP-only
//! stimulus binds nothing there, so the dial lands on a closed port and every
//! held-link row (`0x9F`/`0xA0` pong, the `0x52`→`0x99` and `0x94`→`0x9A`
//! relays) stays uncapturable however correct the code is. Here the Kad node
//! advertises the serve listener's OWN port (`serve.rs::kad_enable_config`) and
//! the core-owned `BuddySlot` sits on the accept path, so the counterparty's
//! dial reaches a real listener and the link it holds is the one rmule holds.
//!
//! Convergence budget (aMule 2.3.3 source, stock timers, never patched):
//!   * `Kademlia.cpp:109` — `m_nextFindBuddy = now + MIN2S(5)` at Kad start, so
//!     the first opportunity is FIVE minutes in; `:205` re-arms it every 20.
//!   * `Prefs.h:107` — `GetFindBuddy()` is consume-once, and `ClientList.cpp:687`
//!     only reads it once BOTH self-checks read firewalled, so an unconsumed flag
//!     simply waits for the UDP verdict.
//!   * `UDPFirewallTester.cpp:60` — with no helper nodes the UDP verdict settles
//!     firewalled by the six-minute timeout, gated on the TCP verdict also being
//!     firewalled. That gate is why this leg blocks TCP and leaves UDP OPEN: the
//!     iptables TCP DROP produces the TCP verdict, and an open UDP port keeps the
//!     `0x51` reaching us and the `0x5A` reaching it.
//!   * `Kademlia.cpp:318` — anything forcing a fresh firewall check calls
//!     `SetFindBuddy(false)` and pushes the next search ≥5 min out. The first
//!     scheduled recheck is an hour away (`:106`), so the window is clean.
//!
//! Net: the buddy search fires around six to seven minutes after aMule's Kad
//! start, not the twenty the interval name suggests.
//!
//! **Measured (runs `1790075125`, `1790076028`, `1790077497`).**
//! The budget above is optimistic for this topology. With the extern-port ping
//! flood removed (`--mesh-members`, below) the observed sequence is:
//!
//!   * `0x51` recruit and rmule's `0x5A` at **≈ +10 min** after aMule's Kad
//!     start, not +6–7;
//!   * the buddy TCP dial and a full `OP_HELLO` / `OP_HELLOANSWER` exchange
//!     within a second of the `0x5A`;
//!   * `OP_BUDDYPING` — and therefore `m_nBuddyStatus = Connected`, which
//!     `CClientList::Process` sets in that same branch — at **exactly ten
//!     minutes after the hello**, i.e. ≈ +20 min.
//!
//! So a run that wants anything *past* the held link needs a window over
//! 1200 s. `--window 1500` has been run and is sufficient to reach the ping —
//! and, since the near-file placement below, the source publish that follows
//! it (runs `1790095682`, `1790097388`: `0x51`, `0x5A`, the dial, the ping,
//! and a 111-byte `0x44` to the placed member, all inside one such window).

use std::fs;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::docker::Docker;
use crate::flow::bench::{
    CaptureSidecar, DEFAULT_TAP_INTERFACE, KadMeshNames, KadResources, fallback_id, run_checked,
    write_id,
};
use crate::flow::gate::{sit_tap_window, wait_for_kad_log};
use crate::flow::identity::{hex_lower, ipv4_string, parse_ipv4_octets};
use crate::flow::kad_buddy::amule_requester::{AmuleRequesterPlan, requester_seed};
use crate::flow::kad_buddy::core_swarm::{CoreSwarmInputs, plan_core_swarm};
use crate::flow::kad_buddy::core_verdict::assert_kad_core_buddy;
use crate::flow::kad_buddy::core_wire::{
    KAD_CORE_BUDDY_STORER_ROWS, KAD_CORE_BUDDY_WIRE_ROWS, lift_publish_body,
};
use crate::flow::kad_buddy::harvest_wire_rows;
use crate::flow::kad_buddy::id_only_row::IdOnlyRowPlan;
use crate::flow::kad_buddy::third_party::{self, ThirdParty};
use crate::flow::kad_buddy::verify_keys::KAD_UDP_KEY_SEED;
use crate::flow::logs::{collect_kad_logs, collect_kad_node_logs};
use crate::flow::mesh::{
    KAD_RMULE_UDP_PORT, KAD_TCP_PORT, KadCaptureOptions, KadNodeSpec, start_kad_node,
};
use crate::rmule::CONTAINER_RUN_ROOT;

pub use crate::flow::kad_buddy::core_options::KadCoreBuddyOptions;
pub(crate) use crate::flow::kad_buddy::core_options::{
    KAD_CORE_BUDDY_AMULE_KAD_ID, KAD_CORE_BUDDY_RMULE_KAD_ID,
};

/// `docker stop --time` for the Core-pumped stimulus before its tap is read
/// Must stay ≥ `rmule-tools`'s own `serve::KAD_SHUTDOWN_GRACE`
/// (10s) so the container's SIGTERM handler — Kad node stop, ADR-0022 tap
/// finalize — has room to finish before `docker` gives up and force-kills it.
const RMULE_STOP_GRACE_SECS: u64 = 15;

/// Run the **Core-Pumped Stimulus Node** leg (flow M, ADR-0061).
pub fn run_kad_core_buddy(options: KadCoreBuddyOptions<'_>) -> Result<()> {
    let base = &options.base;
    let docker = Docker::new(base.container_runtime);
    let names = KadMeshNames::from_layout(base.layout)?;

    // The publish's own gate is topological (see `publish_source`): without a
    // contact inside `SEARCHTOLERANCE` of the file key the `0x44` is refused in
    // silence, so a run that asks for one with nowhere to put it would only
    // reproduce run `1790084715`'s empty capture.
    if options.publish_source && options.mesh_members == 0 {
        bail!(
            "--publish-source needs --mesh-members >= 1: the last member is pinned to the \
             synthetic file's Kad key, and CSearch::StorePacket (Search.cpp:456) silently \
             refuses to publish to any contact farther than SEARCHTOLERANCE from it"
        );
    }
    if options.callback_downloader && !options.publish_source {
        bail!(
            "--callback-downloader needs --publish-source: the downloader is handed only the \
             ed2k link, and the one row its Kad search can find is the one aMule publishes"
        );
    }
    if options.callback_walk && !options.callback_downloader {
        bail!("--callback-walk rides --callback-downloader's gate: pass both");
    }
    if options.amule_requester && (options.callback_downloader || !options.publish_source) {
        bail!("--amule-requester needs --publish-source and replaces --callback-downloader");
    }
    if options.omit_buddy_endpoint && !options.amule_requester {
        bail!("--omit-buddy-endpoint is a variant of --amule-requester: pass both");
    }
    if options.findsource_transfer && !options.omit_buddy_endpoint {
        bail!("--findsource-transfer carries the ID-only road: pass --omit-buddy-endpoint");
    }
    if options.requester_kad_crypt && !options.amule_requester {
        bail!("--requester-kad-crypt arms the aMule requester: pass --amule-requester");
    }
    let near_file_kad_id = if options.publish_source {
        let link = fs::read_to_string(base.layout.synthetic_ed2k_file())
            .with_context(|| format!("read {}", base.layout.synthetic_ed2k_file().display()))?;
        let file_hash = crate::flow::identity::parse_ed2k_file_hash(link.trim())?;
        Some(crate::kad_seed::storer_kad_id_for_file_hash(file_hash))
    } else {
        None
    };

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

    fs::create_dir_all(base.layout.docker_dir()).with_context(|| {
        format!(
            "create docker artifact directory {}",
            base.layout.docker_dir().display()
        )
    })?;

    // Config A: firewalled aMule on `.2`, the Core-pumped stimulus on `.3`.
    let amule_addr = crate::fake_public::fake_public_address(0)?;
    let rmule_addr = crate::fake_public::fake_public_address(1)?;
    let subnet = amule_addr.subnet.clone();
    let amule_ip = parse_ipv4_octets(&amule_addr.ip)?;
    let rmule_ip = parse_ipv4_octets(&rmule_addr.ip)?;
    let hub_udp_port = base.kad_udp_port_base + 2;

    // The helpers must stay OPEN, so the firewall env is the firewalled node's
    // alone and each side gets its own `KadCaptureOptions`.
    let helper_env: Vec<String> = {
        let mut env = vec![
            "AMULE_KAD_FILTER_LAN_IPS=1".to_owned(),
            "AMULE_KAD_VERBOSE=1".to_owned(),
        ];
        env.extend(base.amule_env.iter().cloned());
        env
    };
    let mut amule_env: Vec<String> = vec![
        "AMULE_KAD_FILTER_LAN_IPS=1".to_owned(),
        "AMULE_KAD_VERBOSE=1".to_owned(),
        // The TCP verdict's source. It is also the UDP verdict's precondition:
        // `IsFirewalledUDP` only times out into firewalled while
        // `CKademlia::IsFirewalled()` holds.
        "AMULE_KAD_BLOCK_TCP=1".to_owned(),
    ];
    // Helpers make the UDP firewall test runnable for real, and an open UDP port
    // would then come back verified-open — which withdraws the recruitment. With
    // the port dropped, both helpers' `0x62` probes are expected to fail and
    // settle the verdict firewalled before the timeout. The DROP sits behind an
    // ESTABLISHED accept, so a helper the aMule already queried over UDP (a
    // lookup's `0x21`) would get its `0x62` through — the helper-seeding bench
    // leg reads which one happened.
    let block_udp = options.block_udp_effective();
    if block_udp {
        amule_env.push("AMULE_KAD_BLOCK_UDP=1".to_owned());
    }
    if options.kad_crypt {
        amule_env.push("AMULE_KAD_CRYPT=1".to_owned());
    }
    // The third party's verdict quotes aMule's peer-TCP trail — its relay,
    // its dial-back, any packet it refuses.
    if options.third_party() {
        amule_env.push("AMULE_DEBUG_PEER_CATEGORIES=1".to_owned());
    }
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
    let helper_opts = KadCaptureOptions {
        amule_env: &helper_env,
        ..capture_opts
    };

    // Compile the stimulus BEFORE the isolated network exists: the swarm is a
    // Docker `internal` network with no DNS, and `rust-toolchain.toml` pins
    // components the base image lacks, so any in-swarm cargo invocation dies in
    // rustup's fetch. Warm cache ⇒ seconds.
    run_checked(
        options.rmule_client_container.prebuild_command(&docker)?,
        "prebuild the core-pumped stimulus binary",
    )?;

    let helper_incoming = base.layout.kad_dir().join("helper-incoming");
    fs::create_dir_all(&helper_incoming)
        .with_context(|| format!("create {}", helper_incoming.display()))?;

    // The firewalled node's routing ZONE holds rmule and the members only. The
    // direction is forced: with its UDP port dropped for unsolicited inbound,
    // nothing can dial the firewalled node — it has to reach out first, and each
    // contact's answer then rides the conntrack flow that outbound datagram
    // opened. The helpers are seeded with rmule instead (see `core_swarm`).
    let swarm = plan_core_swarm(&CoreSwarmInputs {
        rmule_ip,
        kad_udp_port_base: base.kad_udp_port_base,
        helper_count: options.helper_count,
        mesh_members: options.mesh_members,
        near_file_kad_id,
        names: &names,
        helper_incoming: &helper_incoming,
    })?;
    let member_plans = swarm.members;
    let mut specs = vec![KadNodeSpec {
        role: "storer".to_owned(),
        container: names.storer.clone(),
        udp_port: hub_udp_port,
        ip: amule_ip,
        kad_id: KAD_CORE_BUDDY_AMULE_KAD_ID,
        user_hash_hex: options
            .findsource_transfer
            .then_some(crate::flow::kad_buddy::id_only_row::FIREWALLED_USER_HASH),
        // `--publish-source` hands the counterparty the staged synthetic file
        // instead of an empty directory, which is the whole difference between
        // a node that has a buddy and a node that publishes a source through it.
        shared_host_dir: if options.publish_source
            && (!options.omit_buddy_endpoint || options.findsource_transfer)
        {
            base.layout.synthetic_dir()
        } else {
            base.layout.amule_dir()
        },
        bootstrap_peers: Vec::new(),
        routing_zone_seed: true,
        seed_contacts: swarm.storer_seed,
    }];
    specs.extend(swarm.helpers);

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

        // The Core's own per-frame tap: only under `--kad-crypt`,
        // where a keyed exchange needs a byte-level verdict rather than the
        // rmule-netns pcap the `capture_dir` tap below already gets (its rows
        // key on the plaintext `0xE4` byte, which a keyed envelope does not
        // carry). Host dir under `kad_rmule_dir()`, mounted at
        // `CONTAINER_RUN_ROOT` for every rmule container (`RmuleWorkspace`).
        let stimulus_tap_host_dir = options
            .kad_crypt
            .then(|| base.layout.kad_rmule_dir().join("tap"));
        if let Some(dir) = &stimulus_tap_host_dir {
            fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        }
        let stimulus_tap_container_path = format!("{CONTAINER_RUN_ROOT}/kad/rmule/tap");

        // The Core-pumped stimulus starts first: its serve listener must be bound
        // and its Kad node answering before the counterparty's first hello, or the
        // buddy dial that follows a `0x5A` has nothing to reach. It runs the
        // binary the prebuild produced — an `internal` network has no DNS, and a
        // cargo invocation there dies in rustup's component fetch.
        let stimulus = run_checked(
            options.rmule_client_container.stimulus_start_command(
                crate::rmule::BenchStaging {
                    docker: &docker,
                    layout: base.layout,
                    network: &names.network_name,
                },
                &names.rmule,
                crate::rmule::KadStimulusKnobs {
                    static_ip: &ipv4_string(rmule_ip),
                    kad_id_hex: &hex_lower(&KAD_CORE_BUDDY_RMULE_KAD_ID),
                    udp_port: KAD_RMULE_UDP_PORT,
                    kad_bootstrap: &format!("{}:{hub_udp_port}", ipv4_string(amule_ip)),
                    assume_open: options.assume_open,
                    // Flow M drives the buddy recruit only; the direct-callback
                    // emit is flow N's stimulus.
                    direct_callback: None,
                    direct_callback_every_secs: 0,
                    // Every crypt arming, at start or at a flip, keys on the
                    // seed the verdict opens the tap with.
                    kad_udp_key_seed: Some(KAD_UDP_KEY_SEED),
                    peer_crypt: options.kad_crypt.then_some("requested"),
                    peer_crypt_flip: options.peer_crypt_flip,
                    kad_capture_dir: stimulus_tap_host_dir
                        .is_some()
                        .then_some(stimulus_tap_container_path.as_str()),
                    user_hash_hex: None,
                    report_kad_verdicts_every_secs: 0,
                },
            )?,
            "run core-pumped stimulus node",
        )?;
        resources.track_started("rmule", names.rmule.clone());
        write_id(
            &base.layout.docker_dir().join("kad-rmule-container-id.txt"),
            fallback_id(&stimulus, &names.rmule),
        )?;
        wait_for_kad_log(
            &docker,
            base.layout,
            "rmule",
            &names.rmule,
            "serve.serving_started",
            timeout,
        )?;
        println!("kad-core-buddy: stimulus serve listener bound on {subnet}");

        // Tap rmule's OWN netns, so both surfaces land in one pcap: the Kad-UDP
        // recruit/answer and the peer-TCP buddy link the answer provokes.
        let capture_dir = base.layout.kad_dir().join("capture");
        fs::create_dir_all(&capture_dir)
            .with_context(|| format!("create {}", capture_dir.display()))?;
        let tap = CaptureSidecar {
            image: base.capture_image,
            name: &names.capture,
            target_container: &names.rmule,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: capture_dir,
            pcap_file: "core-buddy.pcap",
            bpf: "tcp or udp",
        };
        resources.start_capture(base.layout, &tap, "kad-capture-container-id.txt")?;

        // Open helpers after the stimulus and before the firewalled node: each
        // greets rmule from its seed, so rmule already names them when the
        // aMule's helper lookup asks, and with its UDP port dropped the aMule is
        // the only one that can open a flow toward them.
        let mut nodes = Vec::with_capacity(1 + options.helper_count);
        for helper_index in 0..options.helper_count {
            let helper = start_kad_node(
                &docker,
                &helper_opts,
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

        let rmule_endpoint = format!("{}:{KAD_RMULE_UDP_PORT}", ipv4_string(rmule_ip));
        // The placed members go up before the counterparty for the same reason
        // the helpers do: they must be answering before aMule's first ping, or
        // they are contacts it drops instead of contacts it spreads across.
        for (index, (address_v4, udp_port, kad_id)) in member_plans.iter().enumerate() {
            let container = names.routing(u32::try_from(100 + index).unwrap_or(100));
            let dir = base.layout.kad_dir().join(format!("member-{index}"));
            fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
            run_checked(
                docker.run_container(
                    crate::flow::kad_member::PlacedMember {
                        image: options.rmule_tools_image,
                        container: &container,
                        network: &names.network_name,
                        address_v4,
                        udp_port: *udp_port,
                        tcp_port: KAD_TCP_PORT,
                        kad_id,
                        // `join-node` requires a bootstrap peer, and rmule is
                        // the one node already up. The member's *placement* is
                        // its `--id-hex`; bootstrapping only gives it a table.
                        bootstrap: Some(&rmule_endpoint),
                        host_dir: &dir,
                        run_secs: options.window_secs + base.timeout_secs + 120,
                    }
                    .container_spec(),
                ),
                "run a placed Kad member",
            )?;
            resources.track_started(&format!("member-{index}"), container);
        }
        if options.mesh_members > 0 {
            println!(
                "kad-core-buddy: {} placed Kad member(s) up — the counterparty's \
                 extern-port probe now has more than one contact to spread across",
                options.mesh_members
            );
        }
        // The counterparty's one helper lookup fires at its own Kad
        // start, and rmule names only what its table holds by then. A stock
        // helper's pings and `0x21`s do not enroll it; its first
        // `KADEMLIA2_HELLO_REQ` does, about a minute after its start (run
        // `1790324581`). rmule's `KADEMLIA2_HELLO_RES 0x19` in the helper's own log is that
        // hello landing, so the counterparty waits for every helper's.
        let hello_answered = format!("Kad2HelloRes from {rmule_endpoint}");
        for helper in &nodes {
            wait_for_kad_log(
                &docker,
                base.layout,
                &helper.role,
                &helper.container,
                &hello_answered,
                timeout,
            )?;
        }
        if !nodes.is_empty() {
            println!("kad-core-buddy: every helper's hello answered by rmule");
        }
        if let Some(placed) = near_file_kad_id {
            println!(
                "kad-core-buddy: member-{} pinned to the synthetic file's Kad key {} \
                 (distance 0) — the only contact inside SEARCHTOLERANCE of it",
                options.mesh_members - 1,
                hex_lower(&placed)
            );
        }

        // The firewalled stock aMule: loads rmule and the members from its
        // routing-zone seed, reaches its firewalled verdicts, and (per the budget
        // above) runs its BuddySearch onto rmule.
        let amule = start_kad_node(&docker, &capture_opts, &specs, 0, &mut resources)?;
        // A second tap, on the counterparty's own netns: the publish is
        // addressed to whichever contact is closest to the FILE key, which is
        // the placed near-file member and not rmule, so the rmule tap cannot
        // see it. Started the moment the container exists, before its Kad has
        // converged on anything.
        let storer_capture_name = format!("{}-storer", names.capture);
        let storer_capture_dir = base.layout.kad_dir().join("capture-storer");
        fs::create_dir_all(&storer_capture_dir)
            .with_context(|| format!("create {}", storer_capture_dir.display()))?;
        let storer_tap = CaptureSidecar {
            image: base.capture_image,
            name: &storer_capture_name,
            target_container: &names.storer,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: storer_capture_dir,
            pcap_file: "storer-egress.pcap",
            // The callback leg reads aMule's dial-back off its own netns too.
            bpf: if options.third_party() {
                "tcp or udp"
            } else {
                "udp"
            },
        };
        if options.publish_source {
            resources.start_capture(
                base.layout,
                &storer_tap,
                "kad-capture-storer-container-id.txt",
            )?;
        }
        wait_for_kad_log(
            &docker,
            base.layout,
            &amule.role,
            &amule.container,
            "rmule-kad-routing-ready",
            timeout,
        )?;
        nodes.insert(0, amule);
        println!(
            "kad-core-buddy: firewalled aMule up on {subnet} (tcp_block=true udp_block={block_udp} \
             helpers={}); tapping {}s for the buddy convergence",
            options.helper_count, options.window_secs
        );

        // The third party starts only once aMule's row is
        // stored: earlier, a High-ID Core is the fresh UDP helper that opens
        // aMule's UDP verdict and ends its buddy search before it begins.
        let walker_v4 = crate::fake_public::fake_public_address(
            3 + options.helper_count + options.mesh_members,
        )?
        .ip;
        let party = if options.third_party() {
            Some(ThirdParty {
                docker: &docker,
                layout: base.layout,
                names: &names,
                rmule_tools_image: options.rmule_tools_image,
                capture_image: base.capture_image,
                downloader_v4: crate::fake_public::fake_public_address(
                    2 + options.helper_count + options.mesh_members,
                )?
                .ip,
                walker_v4: walker_v4.clone(),
                storer_events: base
                    .layout
                    .kad_dir()
                    .join(format!("member-{}", options.mesh_members - 1))
                    .join("events.log"),
                window: Duration::from_secs(options.window_secs),
                seed: crate::flow::kad_buddy::callback::seed(
                    (
                        &hex_lower(&KAD_CORE_BUDDY_RMULE_KAD_ID),
                        &ipv4_string(rmule_ip),
                        KAD_RMULE_UDP_PORT,
                    ),
                    &member_plans,
                ),
                amule_kad: format!("{}:{hub_udp_port}", ipv4_string(amule_ip)),
                amule_ip: ipv4_string(amule_ip),
                rmule_ip: ipv4_string(rmule_ip),
                // `~stimulusKadID` is aMule's own ID: the walk converges on
                // aMule and the relayed check names the stimulus.
                walk_buddy_id: options.callback_walk.then_some(KAD_CORE_BUDDY_AMULE_KAD_ID),
                amule_requester: options.amule_requester.then(|| AmuleRequesterPlan {
                    base: helper_opts,
                    seed: requester_seed(&specs[0]),
                    storer_ip: member_plans[options.mesh_members - 1].0.clone(),
                    firewalled_ip: ipv4_string(amule_ip),
                    kad_crypt: options.requester_kad_crypt,
                    findsource_transfer: options.findsource_transfer,
                }),
                id_only_row: options.omit_buddy_endpoint.then(|| IdOnlyRowPlan {
                    image: options.rmule_tools_image,
                    address_v4: walker_v4.clone(),
                    storer_kad: {
                        let (ip, port, _) = &member_plans[options.mesh_members - 1];
                        format!("{ip}:{port}")
                    },
                    buddy_id: KAD_CORE_BUDDY_RMULE_KAD_ID,
                    after_firewalled_row: options.findsource_transfer,
                }),
            })
        } else {
            None
        };
        let legs = match &party {
            Some(party) => Some(third_party::drive(party, &mut resources)?),
            None => {
                sit_tap_window("kad-core-buddy", Duration::from_secs(options.window_secs));
                None
            }
        };

        // Harvest before teardown: the pcap rows first (the sidecar still holds
        // the file), then both sides' own logs.
        let mut rows = harvest_wire_rows(
            &docker,
            &names.capture,
            &tap.pcap_path(),
            KAD_CORE_BUDDY_WIRE_ROWS,
            &ipv4_string(amule_ip),
            "kad-core-buddy",
        )?;
        // The body, not just the count: a fixture is bytes. Lifted from the
        // counterparty's own pcap by the same BPF the row counted with, while
        // the sidecar still holds the file.
        let body = if options.publish_source {
            rows.extend(harvest_wire_rows(
                &docker,
                &storer_capture_name,
                &storer_tap.pcap_path(),
                KAD_CORE_BUDDY_STORER_ROWS,
                &ipv4_string(amule_ip),
                "kad-core-buddy",
            )?);
            lift_publish_body(
                &docker,
                &storer_capture_name,
                &storer_tap.pcap_path(),
                &ipv4_string(amule_ip),
                &storer_tap.host_dir,
            )?
        } else {
            None
        };
        // aMule's own verbose log, before teardown: the only trail that says
        // which publish gate refused.
        crate::flow::logs::collect_amule_logfile(&docker, base.layout, "storer", &names.storer);
        collect_kad_node_logs(&docker, base.layout, &nodes);
        collect_kad_logs(&docker, base.layout, "rmule", &names.rmule)?;
        let third = match (&legs, &party) {
            (Some(legs), Some(party)) => legs.judge(
                party,
                (&names.capture, &tap.pcap_path(), &tap.host_dir),
                (
                    &storer_capture_name,
                    &storer_tap.pcap_path(),
                    &storer_tap.host_dir,
                ),
            ),
            _ => Ok(()),
        };

        // A clean stop (SIGTERM, not `docker kill`'s immediate
        // SIGKILL) before the tap read below — the container's own SIGTERM
        // handler needs the room to stop the Kad node and finalize its
        // ADR-0022 tap, or `assert_kad_core_buddy`'s per-frame check still
        // reads `kad_tap_status = "unfinalized"`.
        run_checked(
            docker.stop_container(&names.rmule, RMULE_STOP_GRACE_SECS),
            "stop the core-pumped stimulus cleanly before reading its tap",
        )?;
        assert_kad_core_buddy(
            base.layout,
            &rows,
            &options,
            body.as_deref(),
            near_file_kad_id.map(|id| hex_lower(&id)).as_deref(),
            amule_ip,
            hub_udp_port,
        )?;
        third
    })();

    if result.is_err() {
        resources.collect_failure_logs(base.layout);
    }

    resources.stop_capture();
    resources.cleanup_best_effort(&names);
    result
}
