//! The server-cycle acceptance flow (flow A).
//!
//! One eserver plus one aMule sharing the synthetic file; rmule then runs the
//! five server-facing legs — login/IDCHANGE, UDP status ping, global search,
//! get-sources, transfer — and each leg is asserted from the counterparty's
//! observable reaction. The per-leg verdict is written to the run dir.

use std::fs;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::flow::bench::{Bench, Eserver};
use crate::flow::ed2k_server::SEARCH_QUERY;
use crate::flow::ed2k_server::bench_smoke::BenchSmokeSummary;
use crate::flow::evidence::verify_bytes;
use crate::rmule::{
    RmuleClientContainer, run_rmule_download_in_container, run_rmule_search_in_container,
};

/// Options for the server-cycle acceptance flow (flow A). One
/// eserver plus one aMule sharing the synthetic file; rmule then runs the four
/// server-facing legs against them. Shares the container shape with
/// [`super::ServerSkeletonOptions`] but drives a fixed probe → search →
/// get-sources → download sequence and asserts each leg.
pub struct ServerCycleOptions<'a> {
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
    /// Build context for the eserver image.
    pub server_build_context: &'a Path,
    /// Build context for the aMule image.
    pub amule_build_context: &'a Path,
    /// Leave the containers and network running after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget, in seconds.
    pub timeout_secs: u64,
    /// Host TCP port the eserver's port is published on (the readiness probe target).
    pub server_host_port: u16,
    /// Extra `KEY=VALUE` environment for the eserver container.
    pub server_env: &'a [String],
    /// Extra `KEY=VALUE` environment for the aMule container(s).
    pub amule_env: &'a [String],
    /// Log substring that marks the aMule container ready.
    pub amule_ready_log_pattern: &'a str,
    /// The rust image + workspace rmule runs as a client in.
    pub rmule_client_container: &'a RmuleClientContainer,
}

/// Run the server-cycle flow (flow A): rmule exercises the full
/// server-facing lifecycle against a live eserver with one aMule sharing the
/// synthetic file. Every leg is asserted from the counterparty's observable
/// reaction:
///
/// 1. **Login + IDCHANGE** — the probe completes a High-ID login and reads the
///    `SRV_TCPFLG` word from `OP_IDCHANGE` (a non-`none` `tcp_flags` proves the
///    login was accepted and the flags word parsed).
/// 2. **UDP status ping** — the probe's plain `0x96` status ping (TCP+4, the
///    Lugdunum offset quirk) draws a `0x97`, so a non-`none` `udp_flags` proves
///    it answered.
/// 3. **Global search** — rmule's `0x98` search finds the aMule-shared file.
/// 4. **Get-sources** — the download's server get-sources returns ≥1 usable
///    High-ID source (aMule).
/// 5. **Transfer** — the download byte-completes against the synthetic file.
pub fn run_server_cycle(options: ServerCycleOptions<'_>) -> Result<()> {
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    if options.build_images {
        bench.build_image("server", options.server_image, options.server_build_context)?;
        bench.build_image("aMule", options.amule_image, options.amule_build_context)?;
    }
    let timeout = Duration::from_secs(options.timeout_secs);

    let result = (|| -> Result<()> {
        bench.create_network(options.layout, None)?;
        bench.start_eserver(
            options.layout,
            &Eserver {
                image: options.server_image,
                host_port: options.server_host_port,
                env: options.server_env,
                timeout,
            },
        )?;
        let amule = bench
            .amule_role_container(options.amule_image)
            .volume(options.layout.synthetic_dir(), "/incoming")
            .env("AMULE_SHARED_DIR", "/incoming")
            .env_assignments(options.amule_env);
        bench.start_amule(
            options.layout,
            amule,
            options.amule_ready_log_pattern,
            timeout,
        )?;

        let server_endpoint = bench.names.server_endpoint();

        // --- Leg 1+2: login/IDCHANGE + UDP status ping (the probe) ---
        fs::create_dir_all(options.layout.probe_dir()).with_context(|| {
            format!("create probe dir {}", options.layout.probe_dir().display())
        })?;
        let probe = options.rmule_client_container.probe_command(
            bench.staging(options.layout),
            &server_endpoint,
            crate::rmule::ProbeAsks::default(),
        );
        let probe_output = probe
            .to_command()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("run server-cycle probe container")?;
        fs::write(options.layout.probe_stdout_log(), &probe_output.stdout)
            .with_context(|| format!("write {}", options.layout.probe_stdout_log().display()))?;
        fs::write(options.layout.probe_stderr_log(), &probe_output.stderr)
            .with_context(|| format!("write {}", options.layout.probe_stderr_log().display()))?;
        if !probe_output.status.success() {
            bail!(
                "server-cycle probe exited unsuccessfully: {}",
                String::from_utf8_lossy(&probe_output.stderr)
            );
        }
        let probe_stdout = String::from_utf8_lossy(&probe_output.stdout);
        let summary = BenchSmokeSummary::from_probe_stdout(&probe_stdout);
        let login_ok = summary.tcp_flags != "none";
        let status_ping_answered = summary.udp_flags != "none";
        if !login_ok {
            bail!(
                "server-cycle leg 1 failed: no SRV_TCPFLG from OP_IDCHANGE (login not accepted / \
                 flags not parsed); probe report:\n{probe_stdout}"
            );
        }
        if !status_ping_answered {
            bail!(
                "server-cycle leg 2 failed: UDP status ping (TCP+4) drew no 0x97; probe \
                 report:\n{probe_stdout}"
            );
        }

        // --- Leg 3: global search finds the aMule-shared file ---
        let search = run_rmule_search_in_container(
            bench.staging(options.layout),
            options.rmule_client_container,
            &server_endpoint,
            SEARCH_QUERY,
        )?;

        // --- Leg 4+5: get-sources (>=1 source) + byte-complete download ---
        let download = run_rmule_download_in_container(
            bench.staging(options.layout),
            options.rmule_client_container,
            &server_endpoint,
            false,
        )?;
        let get_sources_ok = download.usable_high_id.is_some();
        verify_bytes(options.layout, &options.layout.rmule_output_file(), "rmule")?;

        let verdict = ServerCycleVerdict {
            login_accepted: login_ok,
            tcp_flags: summary.tcp_flags.clone(),
            compression_advert: summary.compression_advert.clone(),
            status_ping_answered,
            udp_flags: summary.udp_flags.clone(),
            search_found: search.completed && search.matched,
            usable_high_id: download.usable_high_id,
            download_completed: download.completed,
        };
        write_server_cycle_verdict(options.layout, &verdict)?;
        if !verdict.search_found {
            bail!("server-cycle leg 3 failed: global search did not find the shared file");
        }
        if !get_sources_ok {
            bail!("server-cycle leg 4 failed: get-sources returned no usable High-ID source");
        }
        Ok(())
    })();

    if result.is_err() {
        bench.collect_failure_logs(options.layout);
    }
    bench.cleanup_best_effort();
    result
}

/// The per-leg server-cycle verdict, written to the run dir and printed.
struct ServerCycleVerdict {
    login_accepted: bool,
    tcp_flags: String,
    compression_advert: String,
    status_ping_answered: bool,
    udp_flags: String,
    search_found: bool,
    usable_high_id: Option<u64>,
    download_completed: bool,
}

fn write_server_cycle_verdict(layout: &RunLayout, verdict: &ServerCycleVerdict) -> Result<()> {
    let all_pass = verdict.login_accepted
        && verdict.status_ping_answered
        && verdict.search_found
        && verdict.usable_high_id.is_some()
        && verdict.download_completed;
    let text = format!(
        "scenario = \"server-cycle\"\n\
         login_accepted = {}\n\
         idchange_tcp_flags = \"{}\"\n\
         compression_advert = \"{}\"\n\
         status_ping_answered = {}\n\
         status_udp_flags = \"{}\"\n\
         global_search_found = {}\n\
         get_sources_usable_high_id = {}\n\
         download_completed = {}\n\
         verdict = \"{}\"\n",
        verdict.login_accepted,
        verdict.tcp_flags,
        verdict.compression_advert,
        verdict.status_ping_answered,
        verdict.udp_flags,
        verdict.search_found,
        verdict
            .usable_high_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "none".to_owned()),
        verdict.download_completed,
        if all_pass { "PASS" } else { "FAIL" },
    );
    let path = layout.root().join("server-cycle-verdict.toml");
    fs::write(&path, &text).with_context(|| format!("write {}", path.display()))?;
    println!("{text}");
    println!("server-cycle verdict written to {}", path.display());
    Ok(())
}
