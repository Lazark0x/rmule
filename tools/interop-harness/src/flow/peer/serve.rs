//! The reverse flow: rmule serves, a real aMule downloads.
//!
//! rmule logs into the eserver, announces the synthetic file and binds its
//! upload listener; the aMule is handed a link naming rmule as the source and
//! must byte-complete the transfer from it. The assertion is the aMule's own
//! output file matching the synthetic bytes.

use std::fs;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::flow::bench::{Bench, Eserver, fallback_id, run_checked, write_id};
use crate::flow::ed2k_server::skeleton::ServerSkeletonOptions;
use crate::flow::evidence::verify_bytes;
use crate::flow::identity::ed2k_link_with_source;
use crate::flow::logs::collect_rmule_logs;
use crate::rmule::{RMULE_SERVE_TCP_PORT, ServeKnobs};

/// The serve body's `--identity-dir`, under the mounted workspace's
/// git-ignored `.scratch/` so it outlives the run: every run of this flow
/// proves its pinned User Hash with the one SUI key kept there,
/// as an aMule that remembers the hash in `clients.met` requires.
const SERVE_IDENTITY_DIR: &str = "/workspace/.scratch/interop-identity";

/// Run the reverse flow: rmule serves the synthetic file, the aMule downloads
/// it from a link naming rmule as the source, and the aMule's output must
/// byte-match the synthetic file.
pub fn run_rmule_serves_amule_downloads(options: ServerSkeletonOptions<'_>) -> Result<()> {
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

        let rmule_container_id = bench.start_rmule_serve(
            options.layout,
            options.rmule_serve_container,
            ServeKnobs {
                identity_dir: Some(SERVE_IDENTITY_DIR),
                peer_crypt: options.rmule_peer_crypt,
                ..ServeKnobs::default()
            },
            timeout,
        )?;
        let names = &bench.names;
        write_id(
            &options.layout.docker_dir().join("rmule-container-id.txt"),
            fallback_id(&rmule_container_id, &names.rmule_container_name),
        )?;

        let ed2k_link = fs::read_to_string(options.layout.synthetic_ed2k_file())
            .with_context(|| format!("read {}", options.layout.synthetic_ed2k_file().display()))?;
        let rmule_container_ip = run_checked(
            bench
                .docker
                .container_ip(names.rmule_container_name.clone()),
            "inspect rmule container ip",
        )?;
        let ed2k_link = ed2k_link_with_source(
            ed2k_link.trim(),
            rmule_container_ip.trim(),
            RMULE_SERVE_TCP_PORT,
        );
        let expected_size = fs::metadata(options.layout.synthetic_shared_file())
            .with_context(|| format!("stat {}", options.layout.synthetic_shared_file().display()))?
            .len();
        let amule = bench
            .amule_role_container(options.amule_image)
            .volume(options.layout.amule_dir(), "/incoming")
            .env("AMULE_SHARED_DIR", "/incoming")
            .env("AMULE_DOWNLOAD_LINK", ed2k_link)
            .env("AMULE_EXPECTED_FILE_NAME", "shared.bin")
            .env("AMULE_EXPECTED_SIZE", expected_size.to_string())
            // Reverse-download evidence: unlock aMule's verbose debug logfile
            // so its source-handling decision for the rmule link source lands
            // in the archived logs.
            .env("AMULE_VERBOSE", "1")
            .env_assignments(options.amule_env);
        bench.start_amule(
            options.layout,
            amule,
            "rmule-amule-download-complete",
            timeout,
        )?;
        verify_bytes(options.layout, &options.layout.amule_output_file(), "aMule")?;
        if options.rmule_peer_crypt == Some("required") {
            let log = collect_rmule_logs(
                &bench.docker,
                options.layout,
                &bench.names.rmule_container_name,
            )?;
            require_high_id_login(&log)?;
        }
        Ok(())
    })();

    if result.is_err() {
        bench.collect_failure_logs(options.layout);
    }
    bench.cleanup_best_effort();
    result
}

/// Under `Required`, the eserver's High-ID port test dials plain and must be
/// admitted as a Test Connection (ADR-0046): the serving rmule's
/// last `server connected` line must carry a High ID (`>= 2^24`).
fn require_high_id_login(log: &str) -> Result<()> {
    let client_id = log
        .lines()
        .rev()
        .filter(|line| line.contains("server connected"))
        .filter_map(|line| line.split("client_id=").nth(1))
        .find_map(|rest| rest.split_whitespace().next()?.parse::<u32>().ok())
        .context("the serving rmule never logged `server connected`")?;
    anyhow::ensure!(
        client_id >= 1 << 24,
        "under --peer-crypt required the login landed Low ID {client_id}: \
         the eserver's plain port test was refused"
    );
    Ok(())
}
