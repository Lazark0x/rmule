//! The direct-connect SUI flow (ADR-0041).
//!
//! One aMule container in `direct-peer` mode — no eD2k server, no Kad — with its
//! peer port published to the host, and host-run rmule-tools dialing it directly
//! with `--secure-ident`. The run succeeds only if a Secure User Identification
//! exchange completes; the full-mode capture retains the SUI opcodes in both
//! directions for the golden vectors.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use anyhow::Result;

use crate::artifacts::RunLayout;
use crate::docker::RunContainer;
use crate::flow::bench::{AMULE_PEER_TCP_PORT, Bench};
use crate::readiness::wait_for_tcp_ready;
use crate::rmule::{RmuleToolsCommand, run_rmule_sui_capture};

/// Options for the direct-connect SUI flow (ADR-0041): one aMule
/// container in `direct-peer` mode (no eD2k server, no Kad), its peer port
/// published to the host, and host-run rmule-tools dialing it directly with
/// `--secure-ident`.
pub struct DirectSuiOptions<'a> {
    /// The run dir every artifact is written under.
    pub layout: &'a RunLayout,
    /// The Docker-compatible CLI to invoke.
    pub container_runtime: &'a str,
    /// Build the project-owned images before starting anything.
    pub build_images: bool,
    /// The aMule image.
    pub amule_image: &'a str,
    /// Build context for the aMule image.
    pub amule_build_context: &'a Path,
    /// Leave the containers and network running after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget, in seconds.
    pub timeout_secs: u64,
    /// Host TCP port published to the aMule container's peer port (4662).
    pub amule_host_port: u16,
    /// Extra `KEY=VALUE` environment for the aMule container(s).
    pub amule_env: &'a [String],
    /// Log substring that marks the aMule container ready.
    pub amule_ready_log_pattern: &'a str,
    /// The host-run rmule-tools that dials the published peer port.
    pub rmule_tools_command: &'a RmuleToolsCommand,
    /// Obfuscation policy for the rmule→aMule dial, or `None` for the
    /// plaintext SUI flow. The aMule's User Hash is learned at run time (it
    /// ignores a pinned one), so only the policy is threaded here.
    pub obfuscation: Option<String>,
}

/// rmule dials a real aMule peer directly — no server in the loop (both sides
/// are High-ID on the harness LAN, so the broken Low-ID image, ADR-0040, is
/// irrelevant) — and the run succeeds only if a Secure User Identification
/// exchange completes. Full-mode capture artifacts (the SUI opcodes both
/// directions) are retained as the golden-vector source.
pub fn run_amule_direct_sui(options: DirectSuiOptions<'_>) -> Result<()> {
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    if options.build_images {
        bench.build_image("aMule", options.amule_image, options.amule_build_context)?;
    }
    let timeout = Duration::from_secs(options.timeout_secs);

    let result = (|| -> Result<()> {
        bench.create_network(options.layout, None)?;

        let amule = RunContainer::new(options.amule_image.to_owned())
            .detach()
            .name(bench.names.amule_container_name.clone())
            .network(bench.names.network_name.clone())
            .volume(options.layout.synthetic_dir(), "/incoming")
            .publish(
                options.amule_host_port.to_string(),
                format!("{AMULE_PEER_TCP_PORT}/tcp"),
            )
            .env("AMULE_SCENARIO_MODE", "direct-peer")
            .env("AMULE_SHARED_DIR", "/incoming")
            .env_assignments(options.amule_env);
        bench.start_amule(
            options.layout,
            amule,
            options.amule_ready_log_pattern,
            timeout,
        )?;

        let peer_endpoint = format!("127.0.0.1:{}", options.amule_host_port);
        wait_for_tcp_ready(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), options.amule_host_port),
            timeout,
        )?;

        run_rmule_sui_capture(
            options.layout,
            options.rmule_tools_command,
            &peer_endpoint,
            // Bound the exchange + optional one-part pull well under the flow
            // timeout so a stalled peer still yields artifacts.
            options.timeout_secs.min(60),
            options.obfuscation.as_deref(),
        )
    })();

    if result.is_err() {
        bench.collect_failure_logs(options.layout);
    }
    bench.cleanup_best_effort();
    result
}
