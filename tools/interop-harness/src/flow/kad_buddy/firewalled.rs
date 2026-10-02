//! kad-firewalled-buddy (flow K): the FIREWALLED-COUNTERPARTY leg for
//! the ADR-0061 buddy / direct-callback route tree. A stock
//! aMule Kad node is stood up on the fake-public /24 with its Kad TCP (and, for
//! the buddy variant, UDP) port DROPped by the entrypoint's iptables rule, so it
//! self-reports firewalled — the recruitment precondition. rmule (`kad join-node`
//! in JOIN mode) is pinned to `~aMuleKadID` so a FindBuddy walk (which targets
//! `~ourKadID`) converges on it, and its datagram tap records every frame the
//! firewalled aMule sends toward it. The verdict scans the tap for the buddy /
//! callback opcodes (`0x51`/`0x52`/`0x5A` Kademlia, `0x94`/`0x95` client-UDP).
//!
//! Documented reality (the ADR-0045 attempt trail): a *complete* buddy/callback
//! exchange is not unattended-safe here. rmule-core DOES wire the whole
//! ADR-0061 open-node side — the recruit fills the shared buddy slot, the
//! accepted buddy's inbound peer-TCP connection is HELD (aMule's
//! `buddy->GetSocket()`), and the `0x52`→`0x99` / `0x94`→`0x9A` relays and the
//! `0x9F`→`0xA0` pong all ride that held link (deterministically proven at the
//! FakePeer tier). What remains for a LIVE serve capture: (a) this flow's rmule
//! counterparty is `kad join-node` — `rmule_net::kad` driven directly, no Core
//! pump — so the core buddy slot is not in its path; a core-pump-reachable
//! stimulus (full `Core` with `EnableKad` + the serve listener the buddy dials)
//! is the named follow-up; and (b) the topology's scale: aMule's
//! `FIND_BUDDY_INTERVAL` is 20 min and its firewall self-check needs open peers
//! to run the connect-back (a lone rmule stimulus answers no reachability
//! probe), so the firewalled aMule only ever *emits* `0x51` inside a
//! multi-open-peer swarm. This leg therefore proves the firewall plumbing +
//! captures whatever the firewalled aMule genuinely emits toward rmule inside
//! the bounded window, and records the buddy-opcode capture as an observation
//! (never fabricated).

use std::fs;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::docker::{Docker, RunContainer};
use crate::flow::bench::{KadMeshNames, KadResources, fallback_id, run_checked, write_id};
use crate::flow::gate::wait_for_kad_log;
use crate::flow::identity::{hex_lower, ipv4_string, parse_ipv4_octets};
use crate::flow::kad_buddy::firewalled_verdict::{
    assert_kad_buddy_recruit, assert_kad_firewall_selfcheck, assert_kad_firewalled_buddy,
};
use crate::flow::kad_buddy::verify_keys::assert_kad_verify_keys;
use crate::flow::logs::{collect_kad_logs, collect_kad_node_logs};
use crate::flow::mesh::{
    KAD_CONTACT_VERSION, KAD_RMULE_UDP_PORT, KAD_TCP_PORT, KadCaptureOptions, KadNodeSpec,
    start_kad_node,
};

/// How long rmule holds its bootstrap dial in the verify-key leg.
/// aMule's `CRoutingZone::OnSmallTimer` runs once a minute and needs two passes
/// before it hellos a freshly loaded contact (the first pass only stamps its
/// expiry), so the quiet window must clear two minutes with margin.
const KAD_VERIFY_KEY_BOOTSTRAP_DELAY_SECS: u64 = 200;

/// The firewalled aMule's fixed Kad ID for flow K. rmule's ID is its bitwise
/// inverse, so aMule's FindBuddy target (`~ownID`) lands exactly on rmule.
pub(crate) const KAD_FW_AMULE_KAD_ID: [u8; 16] = [0x55; 16];
/// `~0x55 == 0xAA`: rmule sits at distance 0 from the FindBuddy target.
pub(crate) const KAD_FW_RMULE_KAD_ID: [u8; 16] = [0xAA; 16];

/// Client-UDP + Kademlia buddy/callback opcodes the flow-K verdict scans for
/// (the tap records the byte after the protocol byte as `opcode`).
pub(crate) const KAD_BUDDY_CALLBACK_OPCODES: &[(i64, &str)] = &[
    (0x51, "KADEMLIA_FINDBUDDY_REQ"),
    (0x5A, "KADEMLIA_FINDBUDDY_RES"),
    (0x52, "KADEMLIA_CALLBACK_REQ"),
    (0x95, "OP_DIRECTCALLBACKREQ"),
    (0x94, "OP_REASKCALLBACKUDP"),
];

/// Options for [`run_kad_firewalled_buddy`] (flow K).
pub struct KadFirewalledBuddyOptions<'a> {
    /// The shared Kad bench options.
    pub base: KadCaptureOptions<'a>,
    /// The rmule Kad node image, built from the repo root.
    pub rmule_image: &'a str,
    /// Dockerfile for the rmule node image.
    pub rmule_dockerfile: &'a std::path::Path,
    /// Build context for the rmule node image (the repo root).
    pub rmule_build_context: &'a std::path::Path,
    /// Drop the firewalled aMule's Kad TCP port (direct-callback branch).
    pub block_tcp: bool,
    /// Also drop its Kad UDP port (TCP+UDP-firewalled buddy recruitment).
    pub block_udp: bool,
    /// How long rmule taps before finalizing (bounded; buddy timer is 20 min).
    pub window_secs: u64,
    /// Arm aMule Kad-UDP obfuscation (ADR-0046): the aMule node then
    /// encrypts its outgoing Kad datagrams toward rmule (a v6+ contact), which
    /// rmule's always-on dual-path receive decrypts. Off keeps the plain-`0xE4`
    /// evidence every other Kad flow relies on.
    pub kad_crypt: bool,
    /// Requester-capture mode (ADR-0058): the aMule is left NON-
    /// firewalled and rmule's own firewall self-check is armed
    /// (`--firewall-self-check`), so rmule emits its `0x53`/`0x50` check toward
    /// the open aMule and captures the aMule's `0x58` reply. Switches the
    /// verdict to `assert_kad_firewall_selfcheck`.
    pub requester_capture: bool,
    /// Buddy-recruit-capture mode (ADR-0061): the aMule is left NON-
    /// firewalled (an open, candidate buddy) and rmule's own buddy recruiter is
    /// armed (`--recruit-buddy`), so rmule emits its `0x51 KADEMLIA_FINDBUDDY_REQ`
    /// toward the open aMule and captures any `0x5A` answer. Switches the verdict
    /// to `assert_kad_buddy_recruit`.
    pub recruit_buddy: bool,
    /// Verify-key-capture mode (ADR-0064): the aMule is left NON-
    /// firewalled and **rmule's** Kad datagram crypt + verify keys are armed
    /// (`--kad-crypt --public-ip <rmule's fake-public address>`), so rmule's
    /// `HELLO_RES` answers aMule's `HELLO_REQ` with the misc-options ACK-request
    /// bit *and* a valid sender key in the crypt trailer — both halves of
    /// `Process2HelloResponse`'s emit condition. Switches the verdict to
    /// `assert_kad_verify_keys`.
    pub verify_keys: bool,
}

/// Run the firewalled-counterparty leg (flow K, ADR-0061–s3).
pub fn run_kad_firewalled_buddy(options: KadFirewalledBuddyOptions<'_>) -> Result<()> {
    let base = &options.base;
    // The verify-key leg holds rmule's bootstrap dial silent for the delay below,
    // so a window that does not outlast it captures nothing and the run would
    // fail claiming the topology never came up. Name the misconfiguration here.
    if options.verify_keys && options.window_secs <= KAD_VERIFY_KEY_BOOTSTRAP_DELAY_SECS {
        bail!(
            "--verify-keys holds rmule's bootstrap dial {KAD_VERIFY_KEY_BOOTSTRAP_DELAY_SECS}s, \
             so --window {} never reaches an emit (needs > {KAD_VERIFY_KEY_BOOTSTRAP_DELAY_SECS})",
            options.window_secs
        );
    }
    let docker = Docker::new(base.container_runtime);
    let names = KadMeshNames::from_layout(base.layout)?;

    if base.build_images {
        run_checked(
            docker.build_image(base.amule_image, base.amule_build_context),
            "build aMule image",
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

    // Fake-public plan (Config A): firewalled aMule on `.2`, rmule on `.3`.
    let amule_addr = crate::fake_public::fake_public_address(0)?;
    let rmule_addr = crate::fake_public::fake_public_address(1)?;
    let subnet = amule_addr.subnet.clone();
    let amule_ip = parse_ipv4_octets(&amule_addr.ip)?;
    let rmule_ip = parse_ipv4_octets(&rmule_addr.ip)?;
    let hub_udp_port = base.kad_udp_port_base + 2;

    let mut amule_env: Vec<String> = vec![
        "AMULE_KAD_FILTER_LAN_IPS=1".to_owned(),
        "AMULE_KAD_VERBOSE=1".to_owned(),
    ];
    if options.block_tcp {
        amule_env.push("AMULE_KAD_BLOCK_TCP=1".to_owned());
    }
    if options.block_udp {
        amule_env.push("AMULE_KAD_BLOCK_UDP=1".to_owned());
    }
    if options.kad_crypt {
        amule_env.push("AMULE_KAD_CRYPT=1".to_owned());
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

    let specs = vec![KadNodeSpec {
        role: "storer".to_owned(),
        container: names.storer.clone(),
        udp_port: hub_udp_port,
        ip: amule_ip,
        kad_id: KAD_FW_AMULE_KAD_ID,
        user_hash_hex: None,
        shared_host_dir: base.layout.amule_dir(),
        bootstrap_peers: Vec::new(),
        routing_zone_seed: true,
        seed_contacts: vec![crate::kad_seed::KadContact {
            kad_id: KAD_FW_RMULE_KAD_ID,
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

        // rmule starts first so it is already listening when the firewalled aMule
        // hellos its seeded contact; JOIN mode = no publish target.
        let rmule_dir = base.layout.kad_rmule_dir();
        fs::create_dir_all(&rmule_dir)
            .with_context(|| format!("create {}", rmule_dir.display()))?;
        let mut rmule = RunContainer::new(options.rmule_image.to_owned())
            .detach()
            .name(names.rmule.clone())
            .network(KadMeshNames::network_for(base.layout))
            .ip(ipv4_string(rmule_ip))
            .volume(rmule_dir.clone(), "/artifacts")
            .arg("--bind")
            .arg(format!("0.0.0.0:{KAD_RMULE_UDP_PORT}"))
            .arg("--id-hex")
            .arg(hex_lower(&KAD_FW_RMULE_KAD_ID))
            .arg("--tcp-port")
            .arg(KAD_TCP_PORT.to_string())
            .arg("--bootstrap")
            .arg(format!("{}:{hub_udp_port}", ipv4_string(amule_ip)))
            .arg("--capture-dir")
            .arg("/artifacts/tap")
            .arg("--events-file")
            .arg("/artifacts/events.log")
            .arg("--run-secs")
            .arg(options.window_secs.to_string());
        if options.requester_capture {
            // Arm rmule's own ADR-0058 self-check: it then piggybacks `0x53`/
            // `0x50` on the hello exchange with the open aMule.
            rmule = rmule.arg("--firewall-self-check");
        }
        if options.recruit_buddy {
            // Arm rmule's own ADR-0061 buddy recruiter: once the open aMule
            // responds, rmule emits its `0x51` toward it.
            rmule = rmule.arg("--recruit-buddy");
        }
        if options.verify_keys {
            // Arm rmule's Kad datagram crypt AND the verify-key layer.
            // Both are needed: the sender key aMule demands before it
            // will answer `0x22` lives inside the crypt trailer. `--public-ip`
            // is passed explicitly — it is the container's own fake-public
            // address from the harness address plan, never a derived guess.
            rmule = rmule
                .arg("--kad-crypt")
                .arg("--public-ip")
                .arg(ipv4_string(rmule_ip))
                // …and stay silent long enough for the aMule to hello US. rmule
                // is already in its routing zone (the seed), and aMule's own
                // maintenance hello is the ONLY way into `Process2HelloResponse`
                // — but it only fires while the contact is the oldest one still
                // due for a check, so any rmule dial first would refresh the
                // entry an hour out and close the window.
                .arg("--bootstrap-delay-secs")
                .arg(KAD_VERIFY_KEY_BOOTSTRAP_DELAY_SECS.to_string());
        }
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

        // The firewalled stock aMule: loads rmule from its routing-zone seed and
        // (once Kad-connected) hellos + firewall-self-checks against it.
        let amule = start_kad_node(&docker, &capture_opts, &specs, 0, &mut resources)?;
        wait_for_kad_log(
            &docker,
            base.layout,
            &amule.role,
            &amule.container,
            "rmule-kad-routing-ready",
            timeout,
        )?;

        if options.requester_capture {
            println!(
                "kad-firewall-selfcheck: open aMule up on {subnet}; rmule (self-check armed) \
                 tapping for {}s",
                options.window_secs
            );
        } else if options.recruit_buddy {
            println!(
                "kad-buddy-recruit: open aMule up on {subnet}; rmule (buddy recruiter armed) \
                 emitting 0x51, tapping for {}s",
                options.window_secs
            );
        } else {
            println!(
                "kad-firewalled-buddy: firewalled aMule up on {subnet} (tcp_block={} udp_block={}); \
                 rmule tapping for {}s",
                options.block_tcp, options.block_udp, options.window_secs
            );
        }
        wait_for_kad_log(
            &docker,
            base.layout,
            "rmule",
            &names.rmule,
            "rmule-kad-join-node-done",
            Duration::from_secs(options.window_secs + 90),
        )?;

        // Collect the aMule log *before* stopping the node — `stop_role` removes
        // the container (docker rm -f), and the verdict reads the firewall marker
        // from that log.
        let nodes = vec![amule];
        collect_kad_node_logs(&docker, base.layout, &nodes);
        collect_kad_logs(&docker, base.layout, "rmule", &names.rmule)?;
        resources.stop_role("storer");

        if options.requester_capture {
            assert_kad_firewall_selfcheck(base.layout, amule_ip, hub_udp_port)
        } else if options.recruit_buddy {
            assert_kad_buddy_recruit(base.layout, amule_ip, hub_udp_port)
        } else if options.verify_keys {
            assert_kad_verify_keys(base.layout, amule_ip, hub_udp_port, rmule_ip)
        } else {
            assert_kad_firewalled_buddy(base.layout, amule_ip, hub_udp_port, &options)
        }
    })();

    if result.is_err() {
        resources.collect_failure_logs(base.layout);
    }

    resources.cleanup_best_effort(&names);
    result
}
