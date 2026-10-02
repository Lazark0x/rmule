//! packed-source-exchange (flow I): the ADR-0043
//! multi-registrant leg. ≥12 fabricated High-ID identities register one hash on
//! the live eserver; a downloading aMule learns and *establishes* them via
//! get-sources; rmule then dials that aMule and asks it for sources inside the
//! 0xA4 bundle. aMule packs the answer above its own 354-byte threshold, which
//! at the v4 geometry (19 + 29n) lands at 12 sources — one 0xD4 frame that is
//! simultaneously the inbound-inflate and 0x84-v4
//! capture.

use std::fs;
use std::path::Path;
use std::process::Stdio;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};

use crate::artifacts::RunLayout;
use crate::flow::bench::{AMULE_PEER_TCP_PORT, Bench, Eserver, run_checked};
use crate::flow::gate::wait_for_container_log;
use crate::flow::logs::{collect_amule_logs, retain_artifact};
use crate::rmule::{Registrant, RmuleClientContainer};

/// A user-defined subnet so each registrant gets a **distinct static IP**:
/// Lugdunum assigns High-ID per source IP and Low-IDs (then drops, ADR-0040)
/// extra clients sharing one IP, so N same-IP identities surface 0 sources —
/// the sources must come from N distinct-IP containers. `.11`.. are the
/// registrants; the server/aMule/capture take dynamic `.2`..`.10`.
const PACKED_SX_SUBNET: &str = "172.31.0.0/16";
const REGISTRANT_IP_PREFIX: &str = "172.31.0.";
const REGISTRANT_IP_FIRST_OCTET4: u16 = 11;
/// aMule download rate cap (KB/s) while it holds the staged sources: fast enough
/// that aMule actively transfers from (and so *establishes* + exchanges) each
/// source, slow enough that it settles well short of completion.
///
/// A cap alone is **not** sufficient to keep the file incomplete. aMule's
/// download limiter is a lagging feedback controller keyed off the measured
/// rate, so its opening burst runs at LAN speed regardless — at this cap it
/// still pulled 20 MiB in ~10 s and 200 MiB in ~62 s before converging.
/// Keeping the aMule a *partfile* at dial time is the file size's job;
/// this cap only stops it drifting to completion afterwards.
const AMULE_DOWNLOAD_THROTTLE_KBPS: u32 = 64;

/// Options for [`run_packed_source_exchange`] (flow I).
pub struct PackedSourceExchangeOptions<'a> {
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
    /// The rust image running the rmule-tools registrant + capture containers.
    pub rmule_client_container: &'a RmuleClientContainer,
    /// How many fabricated source identities to register.
    pub registrant_count: u16,
    /// Source-exchange nibble rmule advertises on the capture dial. `3` (aMule's
    /// own default) is what makes aMule's packed `0x82` reply land at v3 geometry
    /// and reconcile on decode; `0` leaves the honest v1 advert.
    pub sx_nibble: u8,
    /// How long the capture dial holds the connection to receive the answer.
    pub capture_window_secs: u64,
}

/// Parse `run_dir=`-style `key=value` facts out of a stdout line prefixed with
/// `marker`, returning the substring value of `key` on the line, if present.
fn parse_fact(text: &str, marker: &str, key: &str) -> Option<String> {
    let line = text.lines().find(|line| line.contains(marker))?;
    line.split_whitespace()
        .find_map(|token| token.strip_prefix(&format!("{key}=")))
        .map(|value| value.to_owned())
}

/// Run flow I: stage the registrants, let the aMule learn them, dial it for
/// sources and judge the packed answer.
pub fn run_packed_source_exchange(options: PackedSourceExchangeOptions<'_>) -> Result<()> {
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

    // aMule downloads the hash, so it must NOT already hold the file — give it an
    // empty incoming dir (the synthetic file is the registrants' offer only).
    let amule_incoming = options.layout.root().join("amule-incoming");
    fs::create_dir_all(&amule_incoming)
        .with_context(|| format!("create aMule incoming {}", amule_incoming.display()))?;
    let sx_dir = options.layout.rmule_dir().join("sx");
    fs::create_dir_all(&sx_dir).with_context(|| format!("create {}", sx_dir.display()))?;

    let ed2k_link = fs::read_to_string(options.layout.synthetic_ed2k_file())
        .with_context(|| {
            format!(
                "read synthetic ed2k link {}",
                options.layout.synthetic_ed2k_file().display()
            )
        })?
        .trim()
        .to_owned();

    let mut registrant_names: Vec<String> = Vec::new();

    let result = (|| -> Result<PackedSxVerdict> {
        bench.create_network(options.layout, Some(PACKED_SX_SUBNET))?;
        bench.start_eserver(
            options.layout,
            &Eserver {
                image: options.server_image,
                host_port: options.server_host_port,
                env: options.server_env,
                timeout,
            },
        )?;
        let server_endpoint = bench.names.server_endpoint();

        // --- registrants: N fabricated identities, each on its OWN static IP
        // (one container per source), so every one earns a distinct High ID. ---
        for index in 0..options.registrant_count {
            let name = format!("{}-reg{index}", bench.names.rmule_container_name);
            let ip = format!(
                "{REGISTRANT_IP_PREFIX}{}",
                REGISTRANT_IP_FIRST_OCTET4 + index
            );
            let registrant = options.rmule_client_container.register_sources_command(
                bench.staging(options.layout),
                &Registrant {
                    name: &name,
                    ip: &ip,
                    server_endpoint: &server_endpoint,
                    index,
                },
            )?;
            run_checked(registrant, "run registrant container")?;
            bench.track(&name);
            registrant_names.push(name);
            // Stagger launches so the registrants' High-ID logins do not all hit
            // the single-threaded eserver at once (it drops concurrent logins).
            thread::sleep(Duration::from_millis(1500));
        }
        // Wait for each (the first absorbs the cold rmule-tools build; the rest
        // reuse the warm shared target), tallying how many reached High-ID.
        let mut registrants_live = 0u32;
        let mut all_logs = String::new();
        for name in &registrant_names {
            let logs = wait_for_container_log(
                &bench.docker,
                name,
                "rmule-registrants-ready",
                Duration::from_secs(options.timeout_secs),
            )?;
            if logs.contains("announced file_count=") {
                registrants_live += 1;
            }
            all_logs.push_str(&format!("===== {name} =====\n"));
            all_logs.push_str(&logs);
        }
        retain_artifact(
            &options.layout.root().join("registrants.log"),
            all_logs.as_bytes(),
        );
        println!("registrants high_id count = {registrants_live}");

        // --- aMule downloads the hash (learns the registrants), then holds ---
        let amule = bench
            .amule_role_container(options.amule_image)
            .volume(&amule_incoming, "/incoming")
            .env("AMULE_SHARED_DIR", "/incoming")
            .env("AMULE_DOWNLOAD_LINK", ed2k_link.as_str())
            .env("AMULE_DOWNLOAD_NO_WAIT", "1")
            // Long enough for aMule to connect to and establish every staged
            // source (source connects are paced a few/sec), short enough that
            // the dial still finds a partfile: aMule's MaxDownload throttle is
            // a lagging feedback controller, so its opening burst runs at LAN
            // speed before converging.
            .env("AMULE_DOWNLOAD_SETTLE", "25")
            .env("AMULE_EXPECTED_FILE_NAME", "shared.bin")
            // Throttle aMule's download hard: it must establish the ≥12 served
            // sources (which happens on connect) but never complete and drop
            // them, so the capture window sees a mid-download partfile with a
            // full source list. Establishment does not need received data.
            .env(
                "AMULE_MAX_DOWNLOAD",
                AMULE_DOWNLOAD_THROTTLE_KBPS.to_string(),
            )
            .env("AMULE_VERBOSE", "1")
            .env_assignments(options.amule_env);
        bench.start_amule(
            options.layout,
            amule,
            "rmule-amule-download-sources-ready",
            timeout,
        )?;
        let amule_ip = run_checked(
            bench
                .docker
                .container_ip(bench.names.amule_container_name.clone()),
            "resolve aMule container ip",
        )?;

        // --- capture: rmule dials aMule and asks it for sources ---
        let peer_endpoint = format!("{amule_ip}:{AMULE_PEER_TCP_PORT}");
        let capture_output = options
            .rmule_client_container
            .source_exchange_capture_command(
                bench.staging(options.layout),
                &peer_endpoint,
                &ed2k_link,
                options.sx_nibble,
                options.capture_window_secs,
            )?
            .to_command()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("run source-exchange capture container")?;
        retain_artifact(&sx_dir.join("capture.stdout.log"), &capture_output.stdout);
        retain_artifact(&sx_dir.join("capture.stderr.log"), &capture_output.stderr);
        let capture_stdout = String::from_utf8_lossy(&capture_output.stdout).into_owned();
        if !capture_output.status.success() {
            bail!(
                "source-exchange capture exited unsuccessfully:\n{}\n{capture_stdout}",
                String::from_utf8_lossy(&capture_output.stderr)
            );
        }

        let found = parse_fact(&capture_stdout, "sx_capture:", "found").as_deref() == Some("true");
        let packed =
            parse_fact(&capture_stdout, "sx_capture:", "packed").as_deref() == Some("true");
        let source_count = parse_fact(&capture_stdout, "sx_capture:", "source_count")
            .unwrap_or_else(|| "unknown".to_owned());
        let frame_bytes = parse_fact(&capture_stdout, "sx_capture:", "frame_bytes")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);

        Ok(PackedSxVerdict {
            registrants_requested: options.registrant_count,
            registrants_live,
            sx_nibble: options.sx_nibble,
            answer_found: found,
            answer_packed: packed,
            answer_frame_bytes: frame_bytes,
            source_count,
        })
    })();

    // Collect logs for diagnosis whether or not the run reached a verdict.
    if bench.amule_started
        && let Err(error) = collect_amule_logs(
            &bench.docker,
            options.layout,
            &bench.names.amule_container_name,
        )
    {
        eprintln!("warning: aMule log collection: {error:#}");
    }

    let outcome = match &result {
        Ok(verdict) => {
            write_packed_sx_verdict(options.layout, verdict)?;
            // PASS = a packed answer was captured. Anything less is a failure,
            // never an exemption: this recipe has no documented counterparty
            // limitation (ADR-0045), so an unpacked or absent answer is a
            // regression on rmule's side of the exchange.
            if verdict.answer_packed {
                Ok(())
            } else if verdict.answer_found {
                bail!(
                    "packed-source-exchange: aMule answered with only {} sources \
                     ({} bytes) — the >354-byte pack threshold needs >=12 rows at \
                     the v4 geometry. {}/{} registrants staged; see registrants.log",
                    verdict.source_count,
                    verdict.answer_frame_bytes,
                    verdict.registrants_live,
                    verdict.registrants_requested,
                )
            } else {
                bail!(
                    "packed-source-exchange: aMule sent no OP_ANSWERSOURCES(2) at \
                     all ({}/{} registrants staged) — check that the aMule still \
                     held a partfile with established sources at dial time; see \
                     registrants.log and logs/amule",
                    verdict.registrants_live,
                    verdict.registrants_requested,
                )
            }
        }
        Err(error) => {
            bench.collect_failure_logs(options.layout);
            Err(anyhow!("packed-source-exchange failed: {error:#}"))
        }
    };

    bench.cleanup_best_effort();
    outcome
}

struct PackedSxVerdict {
    registrants_requested: u16,
    registrants_live: u32,
    sx_nibble: u8,
    answer_found: bool,
    answer_packed: bool,
    answer_frame_bytes: u64,
    source_count: String,
}

fn write_packed_sx_verdict(layout: &RunLayout, verdict: &PackedSxVerdict) -> Result<()> {
    let verdict_label = if verdict.answer_packed {
        "PASS"
    } else {
        "FAIL"
    };
    let text = format!(
        "scenario = \"packed-source-exchange\"\n\
         registrants_requested = {}\n\
         registrants_live = {}\n\
         sx_nibble = {}\n\
         answer_found = {}\n\
         answer_packed = {}\n\
         answer_frame_bytes = {}\n\
         answer_source_count = \"{}\"\n\
         requirements = \"aMule packs an OP_ANSWERSOURCES(2) whose plain body exceeds 354 bytes. At the v4 SX2 geometry the body is 19 + 29*n, so n >= 12 sources must be in the answer. CPartFile::CreateSrcInfoPacket only counts a source that is High-ID (every registrant now earns High-ID; as Low-ID ones Lugdunum never surfaced them) AND is DS_DOWNLOADING or DS_ONQUEUE with a known part status - so the aMule must still be mid-download, which is why the synthetic file is sized so it cannot complete inside the window. The ask must ride the 0xA4 bundle: aMule's standalone OP_REQUESTSOURCES2 handler throws size != 16 on its own 19-byte wire shape and drops the connection.\"\n\
         verdict = \"{}\"\n",
        verdict.registrants_requested,
        verdict.registrants_live,
        verdict.sx_nibble,
        verdict.answer_found,
        verdict.answer_packed,
        verdict.answer_frame_bytes,
        verdict.source_count,
        verdict_label,
    );
    let path = layout.root().join("packed-source-exchange-verdict.toml");
    fs::write(&path, &text).with_context(|| format!("write {}", path.display()))?;
    println!("{text}");
    println!(
        "packed-source-exchange verdict written to {}",
        path.display()
    );
    Ok(())
}
