//! kad-required-check (flow R): rmule's own ADR-0058
//! firewall self-checks under `--peer-crypt required`, against stock aMule
//! helpers, with `--peer-crypt requested` as the control.
//!
//! A Core-Pumped Stimulus Node (`ed2k serve start --kad --peer-crypt …`)
//! runs its **live** self-checks — no `--kad-assume-open` — against at least
//! two OPEN stock aMule Kad nodes on fake-public addresses, each running
//! aMule's own obfuscation defaults (supported and requested) and seeded with
//! rmule. rmule's User Hash is sixteen distinct bytes: the tool's default
//! (`0x42` ×16) reads the same in either word order and would hide a word-order fault.
//!
//! What it judges, and from where:
//!
//!   * **rmule's verdicts, from rmule's diagnostics.** The stimulus prints
//!     `rmule-kad-verdicts tcp=… udp=…` from its `DiagnosticsSnapshot` whenever
//!     they change.
//!   * **Which dial-backs were obfuscated, from each helper's capture.** A tap
//!     on every helper's netns counts, toward rmule's serve port, the helper's
//!     TCP connect-back segments by the connection that carried them: a
//!     reassembled stream opening with `0xE3`/`0xC5`/`0xD4` is plain and every
//!     segment of it counts plain, anything else obfuscated. rmule's own debug
//!     line per inbound connection (`inbound peer connection: …`) classifies
//!     each opener too.
//!
//! **What it proves: the TCP check.** Under both policies every helper dials
//! back **obfuscated**, keyed on the user hash the `0x53` carries, and Kad TCP
//! reads Open within seconds (runs `1790703278`, `1790703530`, `1790704014`).
//! The verdict is `PASS` when both verdicts read open, `TCP_OPEN` when TCP did
//! and UDP did not, `OBSERVED` when a helper dialed back and TCP stayed short;
//! only TCP is gated. The UDP verdict is recorded beside it and reads
//! Unverified here: the UDP check engages only a helper absent from rmule's
//! routing zone (aMule `QueryNextClient`), and in a swarm of two to four nodes
//! every helper is already a contact. The UDP check under `Required` is proven
//! live, by hand (Kad UDP Open 0.66 s after the connect, 2026-09-29), not
//! here.
//!
//! Command:
//!
//! ```bash
//! RMULE_BENCH=1 cargo test -p rmule-interop-harness --test harness \
//!   -- --ignored --test-threads=1 acceptance::kad_required
//! # or directly:
//! cargo run -p rmule-interop-harness -- kad-required-check --helpers 2 --window 900
//! ```

mod verdict;

use std::fs;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::docker::Docker;
use crate::flow::bench::{
    CaptureSidecar, DEFAULT_TAP_INTERFACE, KadMeshNames, KadResources, fallback_id, run_checked,
    write_id,
};
use crate::flow::evidence::{count_pcap_rows, read_verdict_log};
use crate::flow::gate::wait_for_kad_log;
use crate::flow::identity::{hex_lower, ipv4_string, parse_ipv4_octets};
use crate::flow::logs::{collect_amule_logfile, collect_kad_logs, collect_kad_node_logs};
use crate::flow::mesh::{
    KAD_CONTACT_VERSION, KAD_RMULE_UDP_PORT, KAD_TCP_PORT, KadCaptureOptions, KadNodeSpec,
    start_kad_node,
};
use crate::flow::wire_filter::capture_tcp_streams;
use crate::rmule::{RMULE_SERVE_TCP_PORT, RmuleServeContainer};

pub use self::verdict::RequiredCheckVerdict;
use self::verdict::{BOTH_OPEN, TCP_OPEN_LINE};

/// rmule's pinned Kad ID for flow R.
const KAD_REQUIRED_RMULE_KAD_ID: [u8; 16] = [0x5E; 16];
/// rmule's User Hash for flow R: sixteen distinct bytes, so a hash field
/// framed in the wrong word order reaches a helper as another hash — the
/// tool's default (`0x42` ×16) reads the same in either order and hid exactly
/// that.
const KAD_REQUIRED_RMULE_USER_HASH: &str = "00112233445566778899AABBCCDDEEFF";
/// The helpers' Kad ID prefix, one per helper.
const KAD_REQUIRED_HELPER_KAD_ID_PREFIX: u8 = 0x91;
/// How often the stimulus reads its own verdicts.
const VERDICT_REPORT_SECS: u64 = 10;
/// How long the UDP verdict may take to follow once TCP reads open.
const UDP_GRACE_SECS: u64 = 60;

/// Options for [`run_kad_required_check`] (flow R).
pub struct KadRequiredCheckOptions<'a> {
    /// The shared Kad bench options.
    pub base: KadCaptureOptions<'a>,
    /// The rust image the stimulus container runs the prebuilt `rmule-tools` in.
    pub rmule_client_container: &'a RmuleServeContainer,
    /// Open stock aMule helpers; at least two, since each verdict needs two.
    pub helper_count: usize,
    /// How long rmule's verdicts may take to read open once every helper is up.
    pub window_secs: u64,
    /// rmule's `--peer-crypt` policy: `required`, or `requested` as the control.
    pub peer_crypt: &'a str,
}

/// One helper's dial-back counts off its own tap.
struct HelperRows {
    role: String,
    connect_back_syn: u64,
    connect_back_plain: u64,
    connect_back_obfuscated: u64,
    check_link_syn: u64,
    check_link_plain: u64,
    check_link_obfuscated: u64,
}

/// One direction's first-dial SYNs.
fn syn_filter(direction: &str) -> String {
    format!("tcp and {direction} and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0")
}

/// One direction's payload segments, split by the stream that carried them:
/// `(plain, obfuscated)`. A stream is plain when its first delivered byte is an
/// eD2k protocol byte; every segment of it counts plain, the continuation of a
/// split frame included.
fn payload_segments(docker: &Docker, tap: &str, pcap: &str, direction: &str) -> Result<(u64, u64)> {
    let streams = capture_tcp_streams(docker, tap, pcap, direction)?;
    Ok(streams.iter().fold((0, 0), |(plain, obfuscated), stream| {
        if stream.opens_plain() {
            (plain + stream.segments, obfuscated)
        } else {
            (plain, obfuscated + stream.segments)
        }
    }))
}

/// Run the **Kad under Required** leg (flow R).
pub fn run_kad_required_check(options: KadRequiredCheckOptions<'_>) -> Result<()> {
    let base = &options.base;
    if options.helper_count < 2 {
        bail!(
            "--helpers must be at least 2: the TCP verdict needs connect-backs from two \
             distinct helpers and the UDP verdict two helpers' answers"
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
    fs::create_dir_all(base.layout.docker_dir())
        .with_context(|| format!("create {}", base.layout.docker_dir().display()))?;

    // Config A: rmule on `.2`, the helpers from `.3` on, all OPEN.
    let rmule_addr = crate::fake_public::fake_public_address(0)?;
    let subnet = rmule_addr.subnet.clone();
    let rmule_ip = parse_ipv4_octets(&rmule_addr.ip)?;
    let rmule = crate::kad_seed::KadContact {
        kad_id: KAD_REQUIRED_RMULE_KAD_ID,
        ipv4: rmule_ip,
        udp_port: KAD_RMULE_UDP_PORT,
        tcp_port: RMULE_SERVE_TCP_PORT,
        version: KAD_CONTACT_VERSION,
    };
    let helper_incoming = base.layout.kad_dir().join("helper-incoming");
    fs::create_dir_all(&helper_incoming)
        .with_context(|| format!("create {}", helper_incoming.display()))?;
    let mut specs = Vec::with_capacity(options.helper_count);
    for index in 0..options.helper_count {
        let addr = crate::fake_public::fake_public_address(1 + index)?;
        let mut kad_id = [0x90u8; 16];
        kad_id[0] = KAD_REQUIRED_HELPER_KAD_ID_PREFIX + u8::try_from(index).unwrap_or(0);
        specs.push(KadNodeSpec {
            role: format!("helper-{index}"),
            container: names.routing(u32::try_from(index).unwrap_or(0)),
            udp_port: base.kad_udp_port_base + 3 + u16::try_from(index).unwrap_or(0),
            ip: parse_ipv4_octets(&addr.ip)?,
            kad_id,
            user_hash_hex: None,
            shared_host_dir: helper_incoming.clone(),
            bootstrap_peers: Vec::new(),
            routing_zone_seed: true,
            // Each helper greets rmule from its seed, so rmule holds every
            // helper by the time its checks pick them.
            seed_contacts: vec![rmule],
        });
    }
    let helper_env: Vec<String> = {
        let mut env = vec![
            // aMule's own obfuscation defaults (`Preferences.cpp`: supported
            // and requested on, required off). The Kad image otherwise turns
            // obfuscation off, and a helper with it off refuses a `0x53` whose
            // connect options require it ("CryptLayer-Settings incompatible"),
            // which no helper on the live network does.
            "AMULE_KAD_CRYPT=1".to_owned(),
            "AMULE_KAD_FILTER_LAN_IPS=1".to_owned(),
            "AMULE_KAD_VERBOSE=1".to_owned(),
            "AMULE_DEBUG_PEER_CATEGORIES=1".to_owned(),
        ];
        env.extend(base.amule_env.iter().cloned());
        env
    };
    let helper_opts = KadCaptureOptions {
        build_images: false,
        routing_nodes: 0,
        amule_env: &helper_env,
        ..*base
    };

    run_checked(
        options.rmule_client_container.prebuild_command(&docker)?,
        "prebuild the core-pumped stimulus binary",
    )?;
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
        let first_helper = &specs[0];
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
                    kad_id_hex: &hex_lower(&KAD_REQUIRED_RMULE_KAD_ID),
                    udp_port: KAD_RMULE_UDP_PORT,
                    kad_bootstrap: &format!(
                        "{}:{}",
                        ipv4_string(first_helper.ip),
                        first_helper.udp_port
                    ),
                    // The whole point: the live self-checks, not a declaration.
                    assume_open: false,
                    direct_callback: None,
                    direct_callback_every_secs: 0,
                    kad_udp_key_seed: None,
                    peer_crypt: Some(options.peer_crypt),
                    kad_capture_dir: None,
                    user_hash_hex: Some(KAD_REQUIRED_RMULE_USER_HASH),
                    peer_crypt_flip: &[],
                    report_kad_verdicts_every_secs: VERDICT_REPORT_SECS,
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

        let mut nodes = Vec::with_capacity(specs.len());
        let mut taps = Vec::with_capacity(specs.len());
        for index in 0..specs.len() {
            let helper = start_kad_node(&docker, &helper_opts, &specs, index, &mut resources)?;
            let capture_dir = base
                .layout
                .kad_dir()
                .join(format!("capture-{}", helper.role));
            fs::create_dir_all(&capture_dir)
                .with_context(|| format!("create {}", capture_dir.display()))?;
            let tap_name = format!("{}-{}", names.capture, helper.role);
            let tap = CaptureSidecar {
                image: base.capture_image,
                name: &tap_name,
                target_container: &helper.container,
                interface: DEFAULT_TAP_INTERFACE,
                host_dir: capture_dir,
                pcap_file: "helper.pcap",
                bpf: "tcp",
            };
            resources.start_capture(
                base.layout,
                &tap,
                &format!("kad-capture-{}-container-id.txt", helper.role),
            )?;
            taps.push((tap_name.clone(), tap.pcap_path()));
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
        println!(
            "kad-required-check: {} open helper(s) up on {subnet}; waiting up to {}s for \
             rmule's verdicts under {}",
            nodes.len(),
            options.window_secs,
            options.peer_crypt
        );
        let tcp_open = wait_for_kad_log(
            &docker,
            base.layout,
            "rmule",
            &names.rmule,
            TCP_OPEN_LINE,
            Duration::from_secs(options.window_secs),
        )
        .is_ok();
        // Both verdicts are read from rmule's last diagnostics line below; the
        // grace only gives UDP its chance to follow TCP.
        if tcp_open {
            let _ = wait_for_kad_log(
                &docker,
                base.layout,
                "rmule",
                &names.rmule,
                BOTH_OPEN,
                Duration::from_secs(UDP_GRACE_SECS),
            );
        }

        let rmule_ip_text = ipv4_string(rmule_ip);
        let mut rows = Vec::with_capacity(nodes.len());
        for (node, (tap_name, pcap)) in nodes.iter().zip(&taps) {
            let to_rmule = format!("dst host {rmule_ip_text} and dst port {RMULE_SERVE_TCP_PORT}");
            let from_rmule = format!("src host {rmule_ip_text} and dst port {KAD_TCP_PORT}");
            let syns =
                |direction: &str| count_pcap_rows(&docker, tap_name, pcap, syn_filter(direction));
            let (connect_back_plain, connect_back_obfuscated) =
                payload_segments(&docker, tap_name, pcap, &to_rmule)?;
            let (check_link_plain, check_link_obfuscated) =
                payload_segments(&docker, tap_name, pcap, &from_rmule)?;
            rows.push(HelperRows {
                role: node.role.clone(),
                connect_back_syn: syns(&to_rmule)?,
                connect_back_plain,
                connect_back_obfuscated,
                check_link_syn: syns(&from_rmule)?,
                check_link_plain,
                check_link_obfuscated,
            });
        }
        collect_kad_node_logs(&docker, base.layout, &nodes);
        // Each helper's own reasoning (a `logKad*`/`logLocalClient` trail on
        // the debug image, `--amule-image rmule/interop-amule-debug:local`):
        // whether it queued, dialed, obfuscated and acked.
        for node in &nodes {
            collect_amule_logfile(&docker, base.layout, &node.role, &node.container);
        }
        collect_kad_logs(&docker, base.layout, "rmule", &names.rmule)?;
        assert_kad_required_check(base.layout, options.peer_crypt, &rows)
    })();

    if result.is_err() {
        resources.collect_failure_logs(base.layout);
    }
    resources.stop_capture();
    resources.cleanup_best_effort(&names);
    result
}

/// Judge flow R: rmule's own verdicts from its diagnostics lines, and what each
/// helper's tap saw of the dial-backs.
///
/// PASS: both verdicts read open. TCP_OPEN: TCP did, UDP stayed short (the
/// UDP check found no helper outside rmule's routing zone). OBSERVED: the
/// topology stood up (rmule serving, a helper dialed back) and TCP stayed
/// short of open — a documented absence with the dial-back counts beside it.
/// FAIL: the topology never stood up.
fn assert_kad_required_check(
    layout: &RunLayout,
    peer_crypt: &str,
    rows: &[HelperRows],
) -> Result<()> {
    let rmule_log = read_verdict_log(&layout.kad_node_stdout_log("rmule"))?;
    let serving = rmule_log.contains("serve.serving_started");
    let last_verdicts = rmule_log
        .lines()
        .rfind(|line| line.starts_with("rmule-kad-verdicts "))
        .unwrap_or("rmule-kad-verdicts none")
        .to_owned();
    let dialed_back = rows.iter().any(|row| row.connect_back_syn > 0);
    let verdict = RequiredCheckVerdict::judge(&last_verdicts, serving, dialed_back);

    let mut toml = String::from(
        "# Flow R — Kad self-checks under --peer-crypt required, or requested as\n\
         # the control. rmule's verdicts come from its own diagnostics\n\
         # (rmule-kad-verdicts lines); the dial-back counts from each helper's tap,\n\
         # each segment classified by its reassembled stream's first byte\n\
         # (0xE3/0xC5/0xD4 plain, anything else obfuscated).\n",
    );
    toml.push_str(&verdict.file_line());
    toml.push_str(&format!("peer_crypt = \"{peer_crypt}\"\n"));
    toml.push_str(&format!("rmule_serving_started = {serving}\n"));
    toml.push_str(&format!("rmule_last_verdicts = \"{last_verdicts}\"\n"));
    for row in rows {
        toml.push_str(&format!("\n[{}]\n", row.role));
        toml.push_str(&format!("connect_back_syn = {}\n", row.connect_back_syn));
        toml.push_str(&format!(
            "connect_back_plain_segments = {}\n",
            row.connect_back_plain
        ));
        toml.push_str(&format!(
            "connect_back_obfuscated_segments = {}\n",
            row.connect_back_obfuscated
        ));
        toml.push_str(&format!("udp_check_link_syn = {}\n", row.check_link_syn));
        toml.push_str(&format!(
            "udp_check_link_plain_segments = {}\n",
            row.check_link_plain
        ));
        toml.push_str(&format!(
            "udp_check_link_obfuscated_segments = {}\n",
            row.check_link_obfuscated
        ));
    }
    let path = layout.kad_dir().join("kad-required-check-verdict.toml");
    fs::write(&path, &toml).with_context(|| format!("write {}", path.display()))?;
    println!(
        "kad-required-check peer_crypt={peer_crypt} verdict={} {last_verdicts}",
        verdict.label()
    );
    if verdict == RequiredCheckVerdict::Fail {
        bail!(
            "flow R did not stand up: rmule_serving_started={serving}, no helper dialed \
             rmule's listener"
        );
    }
    Ok(())
}
