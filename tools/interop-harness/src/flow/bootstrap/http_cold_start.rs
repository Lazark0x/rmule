//! http-bootstrap-cold-start (flow H): the full cold start driven by
//! the `rmule-tools ed2k bootstrap-fetch` runner (leg 1). A fresh rmule (no
//! state) fetches server.met + nodes.dat over HTTP from a local fixture, connects
//! to the fetched eD2k server, and Kad-joins from the fetched contact. Topology
//! reuses flow G's known-green swarm (eserver + Kad-running aMule + rmule seed
//! that brings the aMule to "Kad: Connected"), adds an alpine `httpd` fixture, and
//! runs the bootstrap-fetch runner.
//!
//! Served-file note: the served server.met/nodes.dat are harness-built to the
//! LIVE bench addresses (the eserver's and the aMule's fake-public IPs), in
//! aMule's own on-disk formats. They are format-faithful but topology-matched, not
//! the committed aMule-AUTHORED goldens — those carry the harvest bench's fixed
//! addresses (172.18.0.2 / 45.55.x) and cannot connect a fresh bench. The
//! aMule-authored bytes are proven separately by the server_met_golden /
//! nodes_dat_golden decode tests (legs 2 + 3); this flow proves the runner's live
//! fetch -> decode -> connect -> join pipeline against real counterparties.

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::docker::RunContainer;
use crate::flow::bench::{
    Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, ED2K_SERVER_PORT, run_checked,
};
use crate::flow::bootstrap::ed2k_kad_handoff::{
    HANDOFF_AMULE_KAD_UDP_PORT, HANDOFF_SEED_KAD_ID, HANDOFF_SEED_UDP_PORT,
};
use crate::flow::evidence::count_pcap_rows;
use crate::flow::gate::wait_for_amule_kad_connected;
use crate::flow::identity::{hex_lower, parse_ipv4_octets};
use crate::flow::logs::retain_artifact;
use crate::flow::mesh::{KAD_CONTACT_VERSION, KAD_TCP_PORT};
use crate::rmule::RmuleClientContainer;

/// The fixture httpd listens here; the runner fetches `http://<ip>/server.met`.
const COLD_START_FIXTURE_HTTP_PORT: u16 = 80;

/// Options for [`run_http_bootstrap_cold_start`] (flow H).
pub struct HttpBootstrapColdStartOptions<'a> {
    /// The run dir every artifact is written under.
    pub layout: &'a RunLayout,
    /// The Docker-compatible CLI to invoke.
    pub container_runtime: &'a str,
    /// Build the project-owned images before starting anything.
    pub build_images: bool,
    /// The eserver image.
    pub server_image: &'a str,
    /// The aMule image.
    pub amule_image: &'a str,
    /// The rmule Kad-seed image (`rmule-tools kad join-node`), built from the repo root.
    pub seed_image: &'a str,
    /// The HTTP fixture image (`alpine:3` — busybox `httpd` serves the goldens).
    pub fixture_image: &'a str,
    /// Packet-capture sidecar image (tcpdump on the join-target aMule's netns:
    /// the counterparty's Kad bootstrap answers are counted off this pcap).
    pub capture_image: &'a str,
    /// Build context for the eserver image.
    pub server_build_context: &'a Path,
    /// Build context for the aMule image.
    pub amule_build_context: &'a Path,
    /// Dockerfile for the Kad-seed image.
    pub seed_dockerfile: &'a Path,
    /// Build context for the Kad-seed image (the repo root).
    pub seed_build_context: &'a Path,
    /// Build context for the capture-sidecar image.
    pub capture_build_context: &'a Path,
    /// The rust image + workspace rmule runs as a client in.
    pub rmule_client_container: &'a RmuleClientContainer,
    /// Leave the containers and network running after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget, in seconds.
    pub timeout_secs: u64,
    /// Budget for the aMule to reach "Kad: Connected", in seconds.
    pub kad_connect_deadline_secs: u64,
    /// Seconds the runner waits to reach Kad contact after the join dial.
    pub join_window_secs: u64,
    /// Extra environment for the join-target aMule (`KEY=VALUE`).
    pub amule_env: &'a [String],
}

/// Build a minimal one-server `server.met` naming `ip:port` (aMule's on-disk
/// layout: `[u8 0xE0][u32 count][ip 4 octets][u16 port LE][u32 tagcount 0]`).
fn cold_start_server_met(ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut out = vec![0xE0];
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&ip);
    out.extend_from_slice(&port.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}

/// Drive the full HTTP-bootstrap cold start end to end (flow H).
pub fn run_http_bootstrap_cold_start(options: HttpBootstrapColdStartOptions<'_>) -> Result<()> {
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    let seed_name = format!("{}-kadseed", bench.names.amule_container_name);
    let fixture_name = format!("{}-httpfixture", bench.names.amule_container_name);
    let tap_name = format!("{}-coldtap", bench.names.amule_container_name);

    if options.build_images {
        bench.build_image("server", options.server_image, options.server_build_context)?;
        bench.build_image("aMule", options.amule_image, options.amule_build_context)?;
        run_checked(
            bench.docker.build_image_with_dockerfile(
                options.seed_image,
                options.seed_dockerfile.as_os_str(),
                options.seed_build_context.as_os_str(),
            ),
            "build rmule Kad-seed image",
        )?;
        bench.build_image(
            "capture",
            options.capture_image,
            options.capture_build_context,
        )?;
    }
    fs::create_dir_all(options.layout.synthetic_dir()).context("create synthetic dir")?;

    let server_addr = crate::fake_public::fake_public_address(0)?;
    let amule_addr = crate::fake_public::fake_public_address(1)?;
    let seed_addr = crate::fake_public::fake_public_address(2)?;
    let fixture_addr = crate::fake_public::fake_public_address(3)?;
    // The runner's static address: pinned so the pcap rows can name the join
    // exchange (aMule → runner) apart from the seed's own traffic.
    let runner_addr = crate::fake_public::fake_public_address(4)?;
    let subnet = server_addr.subnet.clone();
    let amule_ip = amule_addr.ip.clone();
    let timeout = Duration::from_secs(options.timeout_secs);

    // Assemble the fixture payload against the LIVE bench addresses.
    let www_dir = options.layout.docker_dir().join("http-fixture-www");
    fs::create_dir_all(&www_dir).with_context(|| format!("create {}", www_dir.display()))?;
    let server_octets = parse_ipv4_octets(&server_addr.ip)?;
    fs::write(
        www_dir.join("server.met"),
        cold_start_server_met(server_octets, ED2K_SERVER_PORT),
    )
    .context("write fixture server.met")?;
    let amule_octets = parse_ipv4_octets(&amule_ip)?;
    let contact = crate::kad_seed::KadContact {
        kad_id: [0x5E; 16],
        ipv4: amule_octets,
        udp_port: HANDOFF_AMULE_KAD_UDP_PORT,
        tcp_port: KAD_TCP_PORT,
        version: KAD_CONTACT_VERSION,
    };
    fs::write(
        www_dir.join("nodes.dat"),
        crate::kad_seed::build_routing_zone_nodes_dat(&[contact]),
    )
    .context("write fixture nodes.dat")?;

    // Prebuild the runner on the default network (the flow-M sequencing): a
    // warm cache turns the in-flow `cargo run` into seconds, so the capture
    // window starts near the runner's actual wire activity.
    run_checked(
        options
            .rmule_client_container
            .prebuild_command(&bench.docker)?,
        "prebuild the bootstrap-fetch runner",
    )?;

    let result = (|| -> Result<()> {
        bench.create_network(options.layout, Some(&subnet))?;

        // 1. eserver, on its static address.
        let server = RunContainer::new(options.server_image.to_owned())
            .detach()
            .name(bench.names.server_container_name.clone())
            .network(bench.names.network_name.clone())
            .ip(server_addr.ip.clone());
        bench.start_server_container(options.layout, server)?;

        // 2. aMule: server-connected AND Kad-running (the join target).
        let amule = bench
            .amule_role_container(options.amule_image)
            .ip(amule_ip.clone())
            .volume(options.layout.synthetic_dir(), "/incoming")
            .env("AMULE_SCENARIO_MODE", "ed2k-server-kad")
            .env("AMULE_KAD_FILTER_LAN_IPS", "1")
            .env("AMULE_SHARED_DIR", "/incoming")
            .env_assignments(options.amule_env);
        bench.start_amule(
            options.layout,
            amule,
            "rmule-amule-server-kad-ready",
            timeout,
        )?;

        // Passive tap on the join-target aMule's netns (the flow-M shape): the
        // counterparty's answers to the runner's Kad bootstrap — the ADR-0045
        // evidence the verdict counts — land in this pcap. Started before the
        // seed so it observes the whole window.
        let capture_dir = options.layout.docker_dir().join("cold-start-capture");
        fs::create_dir_all(&capture_dir)
            .with_context(|| format!("create {}", capture_dir.display()))?;
        let amule_name = bench.names.amule_container_name.clone();
        let tap = CaptureSidecar {
            image: options.capture_image,
            name: &tap_name,
            target_container: &amule_name,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: capture_dir,
            pcap_file: "cold-start.pcap",
            bpf: "tcp or udp",
        };
        bench.start_extra(&tap_name, tap.container(), "run cold-start tcpdump sidecar")?;

        // 3. Kad seed brings the aMule to "Kad: Connected" so it answers bootstraps.
        let seed_dir = options.layout.docker_dir().join("kad-seed");
        fs::create_dir_all(&seed_dir).with_context(|| format!("create {}", seed_dir.display()))?;
        let seed = RunContainer::new(options.seed_image.to_owned())
            .detach()
            .name(seed_name.clone())
            .network(bench.names.network_name.clone())
            .ip(seed_addr.ip.clone())
            .volume(seed_dir.clone(), "/artifacts")
            .arg("--bind")
            .arg(format!("0.0.0.0:{HANDOFF_SEED_UDP_PORT}"))
            .arg("--id-hex")
            .arg(hex_lower(&HANDOFF_SEED_KAD_ID))
            .arg("--tcp-port")
            .arg(KAD_TCP_PORT.to_string())
            .arg("--bootstrap")
            .arg(format!("{amule_ip}:{HANDOFF_AMULE_KAD_UDP_PORT}"))
            .arg("--capture-dir")
            .arg("/artifacts/tap")
            .arg("--events-file")
            .arg("/artifacts/events.log")
            .arg("--run-secs")
            .arg((options.join_window_secs + options.kad_connect_deadline_secs + 120).to_string());
        bench.start_extra(&seed_name, seed, "run rmule Kad seed")?;

        if !wait_for_amule_kad_connected(
            &bench.docker,
            &bench.names.amule_container_name,
            options.kad_connect_deadline_secs,
        )? {
            bail!(
                "flow H: join-target aMule did not reach 'Kad: Connected' within {}s, so it would \
                 not answer the runner's bootstrap dial",
                options.kad_connect_deadline_secs
            );
        }

        // 4. HTTP fixture: busybox httpd serves the payload on the docker net.
        // Alpine's base busybox omits the httpd applet; busybox-extras supplies
        // it. The network is not --internal, so apk reaches the mirror. httpd -f
        // keeps it in the foreground.
        let fixture = RunContainer::new(options.fixture_image.to_owned())
            .detach()
            .name(fixture_name.clone())
            .network(bench.names.network_name.clone())
            .ip(fixture_addr.ip.clone())
            .volume(www_dir.clone(), "/www")
            .arg("sh")
            .arg("-c")
            .arg(format!(
                "apk add --no-cache busybox-extras >/dev/null 2>&1 && \
                 httpd -f -v -p {COLD_START_FIXTURE_HTTP_PORT} -h /www"
            ));
        bench.start_extra(&fixture_name, fixture, "run http fixture")?;
        // Poll the fixture from inside its own container (the fake-public IP is
        // not host-routable): busybox wget succeeds once apk finishes + httpd
        // binds and can serve server.met.
        let fixture_deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let ok = bench
                .docker
                .exec(
                    fixture_name.clone(),
                    [
                        OsString::from("wget"),
                        OsString::from("-q"),
                        OsString::from("-O"),
                        OsString::from("/dev/null"),
                        OsString::from(format!(
                            "http://127.0.0.1:{COLD_START_FIXTURE_HTTP_PORT}/server.met"
                        )),
                    ],
                )
                .to_command()
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if ok {
                break;
            }
            if Instant::now() >= fixture_deadline {
                bail!("flow H: http fixture did not start serving server.met within 90s");
            }
            thread::sleep(Duration::from_secs(2));
        }

        // 5. The bootstrap-fetch runner: the production ADR-0067 Join Sequence
        // caller — fetch both over HTTP, join both networks, verify each leg.
        let base = format!("http://{}:{COLD_START_FIXTURE_HTTP_PORT}", fixture_addr.ip);
        let output = options
            .rmule_client_container
            .bootstrap_fetch_command(
                bench.staging(options.layout),
                &runner_addr.ip,
                &format!("{base}/server.met"),
                &format!("{base}/nodes.dat"),
                options.join_window_secs,
            )?
            .to_command()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("run bootstrap-fetch runner")?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        retain_artifact(
            &options.layout.root().join("cold-start-stdout.log"),
            stdout.as_bytes(),
        );
        retain_artifact(
            &options.layout.root().join("cold-start-stderr.log"),
            stderr.as_bytes(),
        );

        // The counterparty half off the pcap: aMule's `0x09` BOOTSTRAP_RES
        // answers addressed to the runner (the seed's exchange is excluded by
        // the dst filter). Zero with a green runner would mean the join fact
        // came from somewhere other than the counterparty — fail loudly.
        let bootstrap_res = count_pcap_rows(
            &bench.docker,
            &tap_name,
            &tap.pcap_path(),
            format!(
                "udp and src host {} and dst host {} and udp[8] = 0xe4 and udp[9] = 0x09",
                amule_ip, runner_addr.ip
            ),
        )?;

        let join_sequence = stdout.contains("bootstrap-fetch join_sequence first_run=installed");
        let logged_in = stdout.contains("bootstrap-fetch server_login");
        let joined = output.status.success() && stdout.contains("bootstrap-fetch result=joined");
        let pass = join_sequence && logged_in && joined && bootstrap_res >= 1;
        let verdict = format!(
            "scenario = \"http-bootstrap-cold-start\"\njoin_sequence = {join_sequence}\n\
             server_login = {logged_in}\nkad_joined = {joined}\n\
             kad_bootstrap_res_answers = {bootstrap_res}\nverdict = {}\n",
            if pass { "\"PASS\"" } else { "\"FAIL\"" },
        );
        fs::write(
            options
                .layout
                .root()
                .join("http-bootstrap-cold-start-verdict.toml"),
            &verdict,
        )
        .context("write cold-start verdict")?;
        println!("{verdict}");

        if !pass {
            bail!(
                "flow H: cold start did not complete (join_sequence={join_sequence}, \
                 server_login={logged_in}, joined={joined}, bootstrap_res={bootstrap_res}).\n\
                 --- runner stdout ---\n{stdout}\n--- runner stderr ---\n{stderr}"
            );
        }
        Ok(())
    })();

    bench.cleanup_best_effort();
    result
}
