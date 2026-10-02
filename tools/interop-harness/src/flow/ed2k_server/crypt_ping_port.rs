//! The crypt-ping-port leg: which port stock Lugdunum answers rmule's
//! obfuscated status ping from, and whether rmule reads the answer.
//!
//! rmule's Status Ping Sweep sends the crypt ping (a raw challenge plus
//! padding) to the server's obfuscation port, TCP+12, once its own public
//! address is known — at first contact when the login already named it — and
//! again at every 20 min refresh. The server keys its encrypted `0x97` on the
//! challenge; aMule and eMule take that answer from TCP+4, the obfuscation
//! port or TCP+12. A tap in Lugdunum's namespace
//! (`udp and portrange 4661-4680`) records the answer's source port; that
//! rmule *read* it is shown by what it does next: no plain `0x96` fallback
//! inside the 20 s grace, and the `0xA2` description request that follows an
//! answered status. The bench network is a documentation range rmule counts as
//! public (`198.51.100.0/24`), so the login's High ID names the address.

use std::fs;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::docker::RunContainer;
use crate::flow::bench::{
    Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, ED2K_SERVER_PORT, run_checked,
};
use crate::flow::pcap::{records, udp_payloads, udp4_ports};

const SUBNET: &str = "198.51.100.0/24";
/// Past the first-contact ping (5 s after start) and its 20 s grace.
const WATCH_SECS: u64 = 45;
const SHARE_BYTES: usize = 700_001;
const PCAP: &str = "lugdunum-udp.pcap";

/// Options for the crypt-ping-port leg.
pub struct CryptPingPortOptions<'a> {
    /// The run dir every artifact is written under.
    pub layout: &'a RunLayout,
    /// The Docker-compatible CLI to invoke.
    pub container_runtime: &'a str,
    /// Leave the containers and network running after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget, in seconds.
    pub timeout_secs: u64,
    /// The Lugdunum eserver image.
    pub server_image: &'a str,
    /// Extra `KEY=VALUE` environment for the eserver container.
    pub server_env: &'a [String],
    /// The `rmule-tools` image, built from the tip under test.
    pub rmule_tools_image: &'a str,
    /// The tcpdump capture-sidecar image.
    pub capture_image: &'a str,
}

/// Run the leg and write `crypt-ping-port/verdict.txt`.
pub fn run_crypt_ping_port(options: CryptPingPortOptions<'_>) -> Result<()> {
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    let timeout = Duration::from_secs(options.timeout_secs);
    let root = options.layout.root().join("crypt-ping-port");
    fs::create_dir_all(&root).with_context(|| format!("create {}", root.display()))?;
    let share: Vec<u8> = (0..SHARE_BYTES)
        .map(|index| (index.wrapping_mul(197) ^ (index >> 9)) as u8)
        .collect();
    fs::write(root.join("crypt-ping.bin"), share).context("write the shared file")?;

    let result = (|| -> Result<String> {
        bench.create_network(options.layout, Some(SUBNET))?;
        bench.start_eserver_in_network(
            options.layout,
            options.server_image,
            options.server_env,
            timeout,
        )?;
        let server = bench.names.server_container_name.clone();
        let tap = format!("{server}-tap");
        let sidecar = CaptureSidecar {
            image: options.capture_image,
            name: &tap,
            target_container: &server,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: root.clone(),
            pcap_file: PCAP,
            bpf: "udp and portrange 4661-4680",
        };
        bench.start_extra(&tap, sidecar.container(), "run the server tap")?;
        std::thread::sleep(Duration::from_secs(2));

        let rmule = format!("{server}-crypt-rmule");
        // By address: the sweep walks past a DNS-named row (it has no
        // `Ipv4Endpoint` to key a challenge on), so a container name would
        // never be pinged at all.
        let server_ip = run_checked(bench.docker.container_ip(server.clone()), "server address")?;
        let endpoint = format!("{server_ip}:{ED2K_SERVER_PORT}");
        let serve = [
            "ed2k",
            "serve",
            "start",
            "--file",
            "/w/crypt-ping.bin",
            "--server",
            &endpoint,
            "--peer-crypt",
            "requested",
            "--listen",
            "0.0.0.0:4662",
            "--tcp-port",
            "4662",
            "--user-hash",
            "3D8E17A52C094B6F81E05A7C9B24D6F3",
            "--nickname",
            "crypt-ping-port",
            "--max-seconds",
            &WATCH_SECS.to_string(),
        ];
        let container = serve.into_iter().fold(
            RunContainer::new(options.rmule_tools_image.to_owned())
                .detach()
                .name(&rmule)
                .network(bench.names.network_name.clone())
                .env("RMULE_LOG", "info")
                .volume(&root, "/w"),
            RunContainer::arg,
        );
        bench.start_extra(&rmule, container, "run the serving rmule")?;
        // The driver exits on its own `--max-seconds`.
        run_checked(
            bench.docker.wait(rmule.clone()),
            "wait for the serving rmule",
        )?;
        let logs = run_checked(bench.docker.logs(rmule.clone()), "rmule logs")?;
        fs::write(root.join("rmule.log"), format!("{logs}\n")).context("write rmule.log")?;
        bench.stop_extra(&rmule);
        bench.stop_extra(&tap);
        if !logs.contains("server connected") {
            bail!("rmule never logged in to Lugdunum");
        }
        verdict(&root.join(PCAP))
    })();

    if result.is_err() {
        bench.collect_failure_logs(options.layout);
    }
    bench.cleanup_best_effort();
    let verdict = result?;
    fs::write(root.join("verdict.txt"), format!("{verdict}\n")).context("write verdict")?;
    println!("{verdict}");
    Ok(())
}

/// Read the tap: the crypt ping (to TCP+12), the answer to its source port,
/// and what rmule sent the server afterwards.
fn verdict(pcap: &std::path::Path) -> Result<String> {
    let obfuscation_port = ED2K_SERVER_PORT + 12;
    let ports = udp4_ports(pcap)?;
    let payloads = udp_payloads(pcap)?;
    let times: Vec<f64> = records(pcap)?.iter().map(|record| record.at).collect();
    let datagrams: Vec<_> = ports.into_iter().zip(payloads).zip(times).collect();
    let Some(ping_at) = datagrams
        .iter()
        .position(|((ports, _), _)| ports.1 == obfuscation_port)
    else {
        bail!("rmule sent no crypt ping to TCP+12 (port {obfuscation_port})");
    };
    let (((ping_source, _), ping), sent_at) = &datagrams[ping_at];
    let answer = datagrams[ping_at + 1..]
        .iter()
        .find(|((ports, _), _)| ports.1 == *ping_source);
    let answer_port = answer.map(|((ports, _), _)| ports.0);
    let after = |opcode: u8| {
        datagrams[ping_at + 1..]
            .iter()
            .any(|((ports, payload), at)| {
                ports.0 == *ping_source
                    && payload.first() == Some(&0xE3)
                    && payload.get(1) == Some(&opcode)
                    && at - sent_at <= 25.0
            })
    };
    let fallback = after(0x96);
    let described = after(0xA2);
    let outcome = if answer_port.is_some() && !fallback {
        "ANSWERED-AND-READ"
    } else if answer_port.is_some() {
        "ANSWERED-NOT-READ"
    } else {
        "UNANSWERED"
    };
    Ok(format!(
        "verdict={outcome} ping_bytes={} answer_from_port={} plain_fallback_within_25s={fallback} \
         description_request={described}",
        ping.len(),
        answer_port.map_or_else(|| "none".to_owned(), |port| port.to_string()),
    ))
}
