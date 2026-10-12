//! The server-skeleton flow: one eserver, one aMule, one rmule action.
//!
//! The harness's oldest shape — build images, start the eserver, start an aMule
//! that shares the synthetic file, then run exactly one `RmuleClientAction`
//! (download, search, SUI capture, or the Low-ID callback-capability
//! observation) against them and assert its observable outcome.

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::flow::bench::{Bench, ED2K_SERVER_PORT, Eserver, run_checked};
use crate::flow::ed2k_server::SEARCH_QUERY;
use crate::flow::evidence::verify_bytes;
use crate::rmule::{
    CallbackCapabilityReport, RmuleClientContainer, RmuleServeContainer, RmuleToolsCommand,
    run_rmule_callback_capability_in_container, run_rmule_download,
    run_rmule_download_in_container, run_rmule_search, run_rmule_search_in_container,
};

/// Bounded runtime for the Low-ID callback capability observation.
/// rmule reaches a High ID within a few seconds of login; the bound only has to
/// outlast that plus a status cycle, since the run can never byte-complete
/// against the Lugdunum eserver (ADR-0040). Kept short so the exempt flow stays
/// well under the bench suite budget.
const CALLBACK_CAPABILITY_BOUND_SECS: u64 = 120;

/// The one rmule action a skeleton run drives against the eserver + aMule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RmuleClientAction {
    /// Download the synthetic file and byte-verify it.
    Download,
    /// Global-search the synthetic file's name.
    Search,
    /// Low-ID callback compatibility tier (ADR-0040 exemption): run a
    /// bounded `download start --serve` and assert rmule reaches callback
    /// capability (High ID + bound listener) against the real eserver while a
    /// real Low-ID aMule shares the file. Byte-completion is impossible here
    /// (the eserver surfaces no Low-ID source) and lives in the in-process tier.
    CallbackCapability,
}

/// Options for the server-skeleton flow.
pub struct ServerSkeletonOptions<'a> {
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
    /// A host-run rmule-tools (the test hook); `None` runs rmule inside the
    /// bench network.
    pub rmule_tools_command: Option<&'a RmuleToolsCommand>,
    /// The rust image + workspace rmule runs as a client in.
    pub rmule_client_container: &'a RmuleClientContainer,
    /// The rust image + workspace rmule serves from.
    pub rmule_serve_container: &'a RmuleServeContainer,
    /// The one rmule action this run drives.
    pub rmule_client_action: RmuleClientAction,
    /// Force the aMule sharer to Low-ID (ADR-0039): adds `AMULE_FORCE_LOW_ID=1`
    /// and `NET_ADMIN` so its entrypoint firewalls inbound TCP and the server
    /// assigns it a Low ID, so rmule can only reach it via a callback.
    pub amule_low_id: bool,
    /// Run the rmule download with `--serve` so it binds the inbound listener
    /// (High-ID + callback-capable) and can adopt the called-back Low-ID source.
    pub rmule_serve: bool,
    /// The serving rmule's `--peer-crypt` policy, for the flows that start one.
    pub rmule_peer_crypt: Option<&'a str>,
    /// `--peer-crypt-flip <secs>:<policy>` for the serving rmule, one per
    /// entry: its policy changes mid-run, live (ADR-0046) — the next accept,
    /// datagram and server crypt-ping after each change meet the new one.
    /// Read only by `rmule-serves-amule-downloads`.
    pub rmule_peer_crypt_flip: &'a [String],
}

/// Run the skeleton: eserver + aMule sharer, then the one
/// [`RmuleClientAction`].
pub fn run_server_skeleton(options: ServerSkeletonOptions<'_>) -> Result<()> {
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

        let mut amule = bench
            .amule_role_container(options.amule_image)
            .volume(options.layout.synthetic_dir(), "/incoming")
            .env("AMULE_SHARED_DIR", "/incoming");
        if options.amule_low_id {
            // Firewall inbound TCP (NET_ADMIN) so the server cannot reach this
            // aMule back and assigns it a Low ID (ADR-0039).
            amule = amule.env("AMULE_FORCE_LOW_ID", "1").cap_add("NET_ADMIN");
        }
        bench.start_amule(
            options.layout,
            amule.env_assignments(options.amule_env),
            options.amule_ready_log_pattern,
            timeout,
        )?;

        let names = &bench.names;
        match options.rmule_client_action {
            RmuleClientAction::Download => {
                if let Some(command) = options.rmule_tools_command {
                    run_rmule_download(
                        options.layout,
                        command,
                        &format!("127.0.0.1:{}", options.server_host_port),
                        options.rmule_serve,
                    )?;
                } else {
                    // The Low-ID callback correlation key is the source's
                    // (connected_server, client_id), so rmule must reach the
                    // server by IP: a hostname makes rmule encode its own
                    // connected_server as 0.0.0.0:0, which never matches the
                    // called-back peer's reported server (ADR-0039). The plain
                    // download does not correlate, so the container name is fine.
                    let server_endpoint = if options.rmule_serve {
                        let ip = run_checked(
                            bench
                                .docker
                                .container_ip(names.server_container_name.clone()),
                            "inspect server container ip",
                        )?;
                        format!("{}:{ED2K_SERVER_PORT}", ip.trim())
                    } else {
                        names.server_endpoint()
                    };
                    run_rmule_download_in_container(
                        bench.staging(options.layout),
                        options.rmule_client_container,
                        &server_endpoint,
                        options.rmule_serve,
                    )?;
                }
                verify_bytes(options.layout, &options.layout.rmule_output_file(), "rmule")
            }
            RmuleClientAction::CallbackCapability => {
                // Low-ID callback compatibility tier (the ADR-0040 exemption).
                // Reach the server by IP so rmule's connected_server encodes
                // concretely (the callback correlation key, ADR-0039), run a
                // bounded `download start --serve`, and assert rmule reached
                // callback capability. The Lugdunum eserver never surfaces the
                // Low-ID aMule as a source, so no byte-completion is possible —
                // that adoption path is proven in the in-process correctness tier.
                let ip = run_checked(
                    bench
                        .docker
                        .container_ip(names.server_container_name.clone()),
                    "inspect server container ip",
                )?;
                let server_endpoint = format!("{}:{ED2K_SERVER_PORT}", ip.trim());
                let report = run_rmule_callback_capability_in_container(
                    bench.staging(options.layout),
                    options.rmule_client_container,
                    &server_endpoint,
                    CALLBACK_CAPABILITY_BOUND_SECS,
                )?;
                write_callback_capability_verdict(options.layout, &report)?;
                if !report.callback_capable {
                    bail!(
                        "flow D: rmule did not reach callback capability \
                         (listener_bound={}, reachability_probe={})",
                        report.listener_bound,
                        report.reachability_probe,
                    );
                }
                Ok(())
            }
            RmuleClientAction::Search => {
                if let Some(command) = options.rmule_tools_command {
                    run_rmule_search(
                        options.layout,
                        command,
                        &format!("127.0.0.1:{}", options.server_host_port),
                        SEARCH_QUERY,
                    )?;
                } else {
                    run_rmule_search_in_container(
                        bench.staging(options.layout),
                        options.rmule_client_container,
                        &names.server_endpoint(),
                        SEARCH_QUERY,
                    )?;
                }
                Ok(())
            }
        }
    })();

    if result.is_err() {
        bench.collect_failure_logs(options.layout);
    }
    bench.cleanup_best_effort();
    result
}

/// Record the Low-ID callback compatibility-tier observation (the
/// ADR-0040 exemption). PASS = rmule reached callback capability (High ID +
/// bound listener) against the real eserver while a real Low-ID aMule shared the
/// file — the ADR-0039 precondition for adopting a called-back peer. The eserver
/// surfacing no Low-ID source (`server_sources = 0`) is the documented Lugdunum
/// limitation, not a rmule fault; the byte-completing adoption path is proven in
/// the in-process correctness tier (`callback_loopback`, ADR-0040).
fn write_callback_capability_verdict(
    layout: &RunLayout,
    report: &CallbackCapabilityReport,
) -> Result<()> {
    let text = format!(
        "scenario = \"amule-low-id-callback\"\n\
         listener_bound = {}\n\
         reachability_probe = {}\n\
         callback_capable = {}\n\
         download_completed = {}\n\
         exemption = \"ADR-0040: the Lugdunum eserver surfaces no Low-ID source (no OP_FOUNDSOURCES), so no callback is relayed and no byte-completion is possible; the adopt path is proven in the in-process correctness tier (callback_loopback)\"\n\
         verdict = \"{}\"\n",
        report.listener_bound,
        report.reachability_probe,
        report.callback_capable,
        report.download_completed,
        if report.callback_capable {
            "CALLBACK_CAPABLE"
        } else {
            "FAIL"
        },
    );
    let path = layout.root().join("amule-low-id-callback-verdict.toml");
    fs::write(&path, &text).with_context(|| format!("write {}", path.display()))?;
    println!("{text}");
    println!(
        "amule-low-id-callback verdict written to {}",
        path.display()
    );
    Ok(())
}
