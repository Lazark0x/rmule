//! kad-direct-callback (flow N): the DIRECT `0x95` leg. Same
//! Core-Pumped Stimulus Node and the same Config-A fake-public /24 as flow M,
//! and the same firewall shape the aMule image already names the direct-callback
//! branch — `AMULE_KAD_BLOCK_TCP` alone, TCP-firewalled and UDP-OPEN. What
//! changes is who speaks first: rmule emits `OP_DIRECTCALLBACKREQ` (`0x95`) at
//! the counterparty on a cadence, and the counterparty's REACTION is the
//! evidence.
//!
//! Why it lands where it lands. aMule handles `0x95` in
//! `CClientUDPSocket::ProcessPacket` (`ClientUDPSocket.cpp:277`), not in the Kad
//! listener — but its Kad UDP port and its client UDP port are the SAME socket,
//! demuxed on the leading protocol byte (`OnPacketReceived`, `:92-104`), so a
//! `0xC5` peer-protocol frame sent to the Kad port reaches the eMule handler.
//! That is exactly where aMule addresses its own direct callback
//! (`BaseClient.cpp:1520`, `SendPacket(..., GetKadPort(), ...)`), and it is what
//! `callback.rs` records as route 2's destination.
//!
//! The counterparty's gate is two facts and a rate limit, all cheap here:
//!   * `CKademlia::IsRunning()` — true from `Connect Kad`, no convergence needed.
//!   * `CKademlia::IsFirewalled()` — `CPrefs::GetFirewalled()` is `m_firewalled <
//!     2` (`Prefs.cpp:161`) and the counter only rises on connect-back acks, so a
//!     node whose TCP port is DROPped reads firewalled from START. Unlike the
//!     buddy leg there is NO five-minute arm and no six-minute UDP timeout to
//!     wait out — which is the point of the short window below.
//!   * `CClientList::AllowCallbackRequest` (`ClientList.cpp:1115`) honours one
//!     request per source IP per THREE minutes, so re-emitting costs nothing.
//!
//! It then builds a `CUpDownClient` from the datagram's source IP and the body's
//! TCP port and calls `TryToConnect` (`:310`) — a plain dial, because the source
//! IP reads HighID. That dial onto the serve listener, and the `OP_HELLO` it
//! speaks there, are the counterparty bytes this flow exists to draw.
//!
//! Window budget. Flow M's run saw rmule ban the counterparty's IP for a genuine
//! `KADEMLIA2_PING` flood at roughly six minutes in (the two-node extern-port
//! probe, `CPrefs::SetExternKadPort` never reaching EXTERNAL_PORT_ASKIPS = 3),
//! and a banned IP's inbound connection is refused on both sides. This leg needs
//! no convergence at all, so the default window sits well inside that — the
//! callback is emitted within the first cadence tick and the dial answers in
//! seconds.

use std::fs;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::docker::Docker;
use crate::flow::bench::{
    CaptureSidecar, DEFAULT_TAP_INTERFACE, KadMeshNames, KadResources, fallback_id, run_checked,
    write_id,
};
use crate::flow::evidence::read_verdict_log;
use crate::flow::gate::{sit_tap_window, wait_for_kad_log};
use crate::flow::identity::{hex_lower, ipv4_string, parse_ipv4_octets};
use crate::flow::kad_buddy::{BuddyWireRow, harvest_wire_rows};
use crate::flow::logs::{collect_kad_logs, collect_kad_node_logs};
use crate::flow::mesh::{
    KAD_CONTACT_VERSION, KAD_RMULE_UDP_PORT, KadCaptureOptions, KadNodeSpec, start_kad_node,
};
use crate::flow::wire_filter::{OP_EDONKEYPROT, WireFilter};
use crate::rmule::{RMULE_SERVE_TCP_PORT, RmuleServeContainer};

/// The firewalled aMule's pinned Kad ID for flow N. Distance does not matter
/// here (no search converges on anyone), but pinning both IDs keeps the seeded
/// `nodes.dat` deterministic and the two flows' logs comparable.
const KAD_DIRECT_CALLBACK_AMULE_KAD_ID: [u8; 16] = [0x33; 16];
/// rmule's pinned Kad ID for flow N.
const KAD_DIRECT_CALLBACK_RMULE_KAD_ID: [u8; 16] = [0xCC; 16];

/// Options for [`run_kad_direct_callback`] (flow N).
pub struct KadDirectCallbackOptions<'a> {
    /// The shared Kad bench options.
    pub base: KadCaptureOptions<'a>,
    /// The rust image the stimulus container runs the prebuilt `rmule-tools` in.
    pub rmule_client_container: &'a RmuleServeContainer,
    /// How long the tap runs once both sides are up.
    pub window_secs: u64,
    /// How often rmule re-issues the callback. aMule honours one per source IP
    /// per three minutes, so this only buys robustness against a stimulus that
    /// starts before the counterparty's Kad does.
    pub emit_every_secs: u64,
    /// Pass `--kad-assume-open` to the stimulus. On by default: route 1 of the
    /// chooser drops a LowID→LowID pair, so a stimulus whose own TCP verdict has
    /// not converged would never reach route 2. rmule's own posture only — the
    /// counterparty's bytes stay genuine (ADR-0045).
    pub assume_open: bool,
    /// Also drop the counterparty's Kad UDP port. Off by default and normally
    /// wrong here: a dropped UDP port swallows the `0x95` itself. Exposed so a
    /// run can record what a UDP-firewalled counterparty does (nothing, which is
    /// the honest control).
    pub block_udp: bool,
}

/// The wire rows flow N harvests. `{a}` is the counterparty's IP; the peer-TCP
/// row reads eD2k frames off the reassembled link, as flow M's do.
const KAD_DIRECT_CALLBACK_WIRE_ROWS: &[BuddyWireRow] = &[
    BuddyWireRow {
        key: "rmule_directcallbackreq_0x95_rmule_tap",
        label: "OP_DIRECTCALLBACKREQ out (rmule stimulus)",
        filter: WireFilter::packets_static(
            "udp and dst host {a} and udp[8] = 0xc5 and udp[9] = 0x95",
        ),
    },
    BuddyWireRow {
        key: "amule_callback_tcp_syn_rmule_tap",
        label: "counterparty dial onto the serve listener (the direct-callback answer)",
        filter: WireFilter::packets_static(
            "tcp and src host {a} and dst port {p} and tcp[tcpflags] & tcp-syn != 0",
        ),
    },
    BuddyWireRow {
        key: "amule_hello_0xe3_0x01_rmule_tap",
        label: "OP_HELLO on the dialed-back link",
        filter: WireFilter::ed2k_static("src host {a}", &[OP_EDONKEYPROT], 0x01),
    },
    BuddyWireRow {
        key: "amule_directcallbackreq_0x95_in_rmule_tap",
        label: "OP_DIRECTCALLBACKREQ in (the REVERSE leg — counterparty-authored)",
        filter: WireFilter::packets_static(
            "udp and src host {a} and udp[8] = 0xc5 and udp[9] = 0x95",
        ),
    },
    BuddyWireRow {
        key: "amule_kad_datagrams_in_rmule_tap",
        label: "any Kad datagram from the counterparty (liveness)",
        filter: WireFilter::packets_static("udp and src host {a} and udp[8] = 0xe4"),
    },
    BuddyWireRow {
        key: "amule_peer_udp_in_rmule_tap",
        label: "any peer-protocol datagram from the counterparty",
        filter: WireFilter::packets_static("udp and src host {a} and udp[8] = 0xc5"),
    },
];

/// Run the **direct `0x95` callback** leg (flow N, ADR-0061 route 2).
pub fn run_kad_direct_callback(options: KadDirectCallbackOptions<'_>) -> Result<()> {
    let base = &options.base;
    // The tap is only created once the stimulus reports its listener bound, so
    // the t=0 emit is untapped by construction and at least one FURTHER tick has
    // to land inside the window. Otherwise the run bails claiming rmule's
    // callback never reached the wire, when it simply was never recorded.
    if options.emit_every_secs >= options.window_secs {
        bail!(
            "--emit-every {} must be under --window {}: the pcap starts after the serve \
             listener comes up, so the t=0 callback is untapped and a later tick is required",
            options.emit_every_secs,
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

    let mut amule_env: Vec<String> = vec![
        "AMULE_KAD_FILTER_LAN_IPS=1".to_owned(),
        "AMULE_KAD_VERBOSE=1".to_owned(),
        // The whole precondition: a DROPped TCP port keeps `m_firewalled` at
        // zero, so `CKademlia::IsFirewalled()` reads true and the `0x95` handler
        // accepts. UDP stays open so the datagram can arrive at all.
        "AMULE_KAD_BLOCK_TCP=1".to_owned(),
    ];
    if options.block_udp {
        amule_env.push("AMULE_KAD_BLOCK_UDP=1".to_owned());
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

    // Compile before the isolated network exists (a Config-A `internal` network
    // has no DNS, and `rust-toolchain.toml` pins components the base image lacks,
    // so an in-swarm cargo dies in rustup's fetch).
    run_checked(
        options.rmule_client_container.prebuild_command(&docker)?,
        "prebuild the core-pumped stimulus binary",
    )?;

    let seed_contacts = vec![crate::kad_seed::KadContact {
        kad_id: KAD_DIRECT_CALLBACK_RMULE_KAD_ID,
        ipv4: rmule_ip,
        udp_port: KAD_RMULE_UDP_PORT,
        tcp_port: RMULE_SERVE_TCP_PORT,
        version: KAD_CONTACT_VERSION,
    }];
    let specs = vec![KadNodeSpec {
        role: "storer".to_owned(),
        container: names.storer.clone(),
        udp_port: hub_udp_port,
        ip: amule_ip,
        kad_id: KAD_DIRECT_CALLBACK_AMULE_KAD_ID,
        user_hash_hex: None,
        shared_host_dir: base.layout.amule_dir(),
        bootstrap_peers: Vec::new(),
        routing_zone_seed: true,
        seed_contacts,
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

        // The stimulus starts first: its serve listener must be bound before any
        // callback goes out, or the dial the callback invites has nothing to
        // land on.
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
                    kad_id_hex: &hex_lower(&KAD_DIRECT_CALLBACK_RMULE_KAD_ID),
                    udp_port: KAD_RMULE_UDP_PORT,
                    kad_bootstrap: &format!("{}:{hub_udp_port}", ipv4_string(amule_ip)),
                    assume_open: options.assume_open,
                    direct_callback: Some(&format!("{}:{hub_udp_port}", ipv4_string(amule_ip))),
                    direct_callback_every_secs: options.emit_every_secs,
                    kad_udp_key_seed: None,
                    peer_crypt: None,
                    kad_capture_dir: None,
                    user_hash_hex: None,
                    peer_crypt_flip: &[],
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
        println!("kad-direct-callback: stimulus serve listener bound on {subnet}");

        // Tap rmule's own netns: the outbound `0x95` and the inbound peer-TCP
        // dial it provokes land in one pcap.
        let capture_dir = base.layout.kad_dir().join("capture");
        fs::create_dir_all(&capture_dir)
            .with_context(|| format!("create {}", capture_dir.display()))?;
        let tap = CaptureSidecar {
            image: base.capture_image,
            name: &names.capture,
            target_container: &names.rmule,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: capture_dir,
            pcap_file: "direct-callback.pcap",
            bpf: "tcp or udp",
        };
        resources.start_capture(base.layout, &tap, "kad-capture-container-id.txt")?;

        let amule = start_kad_node(&docker, &capture_opts, &specs, 0, &mut resources)?;
        wait_for_kad_log(
            &docker,
            base.layout,
            &amule.role,
            &amule.container,
            "rmule-kad-routing-ready",
            timeout,
        )?;
        let nodes = vec![amule];
        println!(
            "kad-direct-callback: firewalled aMule up on {subnet} (tcp_block=true \
             udp_block={}); tapping {}s while rmule emits 0x95 every {}s",
            options.block_udp, options.window_secs, options.emit_every_secs
        );

        sit_tap_window(
            "kad-direct-callback",
            Duration::from_secs(options.window_secs),
        );

        let rows = harvest_wire_rows(
            &docker,
            &names.capture,
            &tap.pcap_path(),
            KAD_DIRECT_CALLBACK_WIRE_ROWS,
            &ipv4_string(amule_ip),
            "kad-direct-callback",
        )?;
        collect_kad_node_logs(&docker, base.layout, &nodes);
        collect_kad_logs(&docker, base.layout, "rmule", &names.rmule)?;
        assert_kad_direct_callback(base.layout, &rows, &options)
    })();

    if result.is_err() {
        resources.collect_failure_logs(base.layout);
    }

    resources.stop_capture();
    resources.cleanup_best_effort(&names);
    result
}

/// Judge flow N from the pcap rows plus both sides' logs.
///
/// PASS is the counterparty **reacting** to our `0x95`: a TCP dial onto the
/// serve listener the callback body named. rmule's own `0x95` is stimulus and
/// can never be the verdict (ADR-0045). OBSERVED covers the honest partial —
/// the topology stood up, the callback went out, and the counterparty stayed
/// silent; that is a documented absence with the counterparty's own gates
/// beside it, not a failure.
fn assert_kad_direct_callback(
    layout: &RunLayout,
    rows: &[(&'static BuddyWireRow, u64)],
    options: &KadDirectCallbackOptions<'_>,
) -> Result<()> {
    let count = |key: &str| -> u64 {
        rows.iter()
            .find(|(row, _)| row.key == key)
            .map_or(0, |(_, count)| *count)
    };

    let amule_log = read_verdict_log(&layout.kad_node_stdout_log("storer"))?;
    let tcp_fw = amule_log.contains("rmule-amule-kad-tcp-firewall-installed");
    let rmule_log = read_verdict_log(&layout.kad_node_stdout_log("rmule"))?;
    let rmule_err = read_verdict_log(&layout.kad_node_stderr_log("rmule"))?;
    let rmule_trail = format!("{rmule_log}{rmule_err}");
    let serving = rmule_trail.contains("serve.serving_started");
    // rmule's own disposition trail: which branch of the ADR-0061 chooser ran.
    let route_chosen = rmule_trail.contains("direct UDP callback emitted");
    let route_unenactable = rmule_trail.contains("chosen but not enactable");
    let routed_low_to_low = rmule_trail.contains("route=dropped reason=low_to_low");

    let callback_out = count("rmule_directcallbackreq_0x95_rmule_tap");
    let dial_in = count("amule_callback_tcp_syn_rmule_tap");
    let hello_in = count("amule_hello_0xe3_0x01_rmule_tap");
    let reverse_in = count("amule_directcallbackreq_0x95_in_rmule_tap");
    let kad_in = count("amule_kad_datagrams_in_rmule_tap");

    let verdict = if dial_in > 0 {
        "PASS"
    } else if serving && tcp_fw && callback_out > 0 {
        "OBSERVED"
    } else {
        "FAIL"
    };

    let mut verdict_toml =
        String::from("# Flow N — direct 0x95 callback leg (ADR-0061 route 2).\n");
    verdict_toml.push_str(&format!("verdict = \"{verdict}\"\n"));
    verdict_toml.push_str(&format!("emit_every_secs = {}\n", options.emit_every_secs));
    verdict_toml.push_str(&format!("block_udp = {}\n", options.block_udp));
    verdict_toml.push_str(&format!(
        "assume_open_requested = {}\n",
        options.assume_open
    ));
    verdict_toml.push_str(&format!("amule_tcp_firewall_installed = {tcp_fw}\n"));
    verdict_toml.push_str(&format!("rmule_serving_started = {serving}\n"));
    verdict_toml.push_str(&format!("rmule_route_2_emitted = {route_chosen}\n"));
    verdict_toml.push_str(&format!(
        "rmule_route_2_unenactable = {route_unenactable}\n"
    ));
    verdict_toml.push_str(&format!("rmule_routed_low_to_low = {routed_low_to_low}\n"));
    verdict_toml.push_str(
        "\n# Wire rows, counted off the rmule-netns pcap; every key carries the\n\
         # _rmule_tap suffix (tools/interop-harness/CONTEXT.md, Capture Sidecar).\n",
    );
    for (row, count) in rows {
        verdict_toml.push_str(&format!("{} = {count} # {}\n", row.key, row.label));
    }
    verdict_toml.push_str(
        "\n# PASS = the counterparty DIALED the serve listener our 0x95 body named.\n\
         # That dial (and the OP_HELLO on it) is counterparty evidence; rmule's own\n\
         # 0x95 is stimulus and is never the verdict (ADR-0045).\n\
         # OBSERVED = the topology stood up and the callback went out, but the\n\
         # counterparty did not dial. Its gates are cheap and few\n\
         # (ClientUDPSocket.cpp:277): Kad running, CKademlia::IsFirewalled(), and\n\
         # one honoured request per source IP per three minutes\n\
         # (CClientList::AllowCallbackRequest) -- so a silent run is a documented\n\
         # absence to be read against those, never fabricated into a pass.\n\
         # amule_directcallbackreq_0x95_in_rmule_tap is the REVERSE leg: aMule only emits a\n\
         # 0x95 when it wants to reach a LowID peer that advertised direct-callback\n\
         # support (BaseClient.cpp:1500), which this topology does not drive.\n",
    );
    let verdict_path = layout.kad_dir().join("kad-direct-callback-verdict.toml");
    fs::write(&verdict_path, &verdict_toml)
        .with_context(|| format!("write {}", verdict_path.display()))?;
    println!(
        "kad-direct-callback verdict={verdict} 0x95_out={callback_out} dial_in={dial_in} \
         hello_in={hello_in} reverse_0x95_in={reverse_in} kad_in={kad_in}"
    );

    if verdict == "FAIL" {
        bail!(
            "flow N did not stand up: amule_tcp_firewall_installed={tcp_fw}, \
             rmule_serving_started={serving}, \
             rmule_directcallbackreq_0x95_rmule_tap={callback_out} \
             (expected the firewall installed, the serve listener bound, and rmule's \
             callback on the wire)"
        );
    }
    Ok(())
}
