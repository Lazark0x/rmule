//! The sweep-follows-list leg: a server listed mid-run is reached by the
//! next search's Global Search Sweep.
//!
//! The swept list is the managed list as it stands, less the connected
//! server (ADR-0051, ADR-0052). rmule logs in to Lugdunum, searches once with
//! nothing else listed, then lists ed2k-server (`ed2k search --also-server`)
//! and searches again. A tap in ed2k-server's namespace on its UDP port
//! (TCP+4) records every global search datagram rmule sends it; ed2k-server
//! was never listed before the second search, so one such datagram is the
//! sweep following the list.

use std::fs;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::flow::bench::{
    Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, ED2K_SERVER_PORT, run_checked,
};
use crate::flow::ed2k_server::SEARCH_QUERY;
use crate::flow::ed2k_server::rmule_tools::run_to_exit;
use crate::flow::ed2k_server::search_wire::server_tap::global_searches;
use crate::flow::ed2k_server::search_wire::{ED2KSRV_IP, SUBNET, start_ed2ksrv};

/// rmule's static address on the bench network.
const RMULE_IP: &str = "203.0.113.70";
const PCAP: &str = "ed2ksrv-udp.pcap";

/// Options for the sweep-follows-list leg.
pub struct SweepFollowsListOptions<'a> {
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
    /// The ed2k-server image, refused unless its commit label matches the pin.
    pub ed2ksrv_image: &'a str,
    /// The ed2k-server bench config; its `this_ip` is rendered per run.
    pub ed2ksrv_config: &'a std::path::Path,
    /// The `rmule-tools` image, built from the tip under test.
    pub rmule_tools_image: &'a str,
    /// The tcpdump capture-sidecar image.
    pub capture_image: &'a str,
}

/// Run the leg and write `sweep-follows-list/verdict.txt`.
pub fn run_sweep_follows_list(options: SweepFollowsListOptions<'_>) -> Result<()> {
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    let timeout = Duration::from_secs(options.timeout_secs);
    let root = options.layout.root().join("sweep-follows-list");
    fs::create_dir_all(&root).with_context(|| format!("create {}", root.display()))?;

    let result = (|| -> Result<String> {
        bench.create_network(options.layout, Some(SUBNET))?;
        bench.start_eserver_in_network(
            options.layout,
            options.server_image,
            options.server_env,
            timeout,
        )?;
        // By address: the sweeps walk past a row named by host name.
        let server = bench.names.server_container_name.clone();
        let lugdunum_ip = run_checked(bench.docker.container_ip(server), "server address")?;
        let ed2ksrv = start_ed2ksrv(
            &mut bench,
            options.ed2ksrv_image,
            options.ed2ksrv_config,
            &root,
            timeout,
        )?;
        let tap = format!("{ed2ksrv}-tap");
        let sidecar = CaptureSidecar {
            image: options.capture_image,
            name: &tap,
            target_container: &ed2ksrv,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: root.clone(),
            pcap_file: PCAP,
            bpf: "udp",
        };
        bench.start_extra(&tap, sidecar.container(), "run the ed2k-server tap")?;
        std::thread::sleep(Duration::from_secs(2));

        let lugdunum = format!("{}:{ED2K_SERVER_PORT}", lugdunum_ip.trim());
        let added = format!("{ED2KSRV_IP}:4661");
        let rmule = format!("{}-sweep-rmule", bench.names.server_container_name);
        let logs = run_to_exit(
            &mut bench,
            options.rmule_tools_image,
            &rmule,
            RMULE_IP,
            &root,
            &[
                "ed2k",
                "search",
                "--server",
                &lugdunum,
                "--query",
                SEARCH_QUERY,
                "--also-server",
                &added,
                "--quiet-timeout-secs",
                "10",
                "--user-hash",
                "5A17C3E90B2D4F6881E4A7C09D3B5E21",
                "--nickname",
                "sweep-follows-list",
            ],
        )?;
        bench.stop_extra(&rmule);
        bench.stop_extra(&tap);
        if !logs.contains("search_also_server") {
            bail!("rmule never reached the second search");
        }
        let searches = global_searches(&root.join(PCAP), RMULE_IP.parse()?)?;
        let verdict = if searches.is_empty() {
            "NOT-SWEPT"
        } else {
            "SWEPT"
        };
        let opcodes: Vec<String> = searches
            .iter()
            .map(|(_, opcode)| format!("{opcode:#04x}"))
            .collect();
        Ok(format!(
            "verdict={verdict} global_search_datagrams={} opcodes=[{}] completed_searches={}",
            searches.len(),
            opcodes.join(","),
            logs.matches("search_completed").count(),
        ))
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
