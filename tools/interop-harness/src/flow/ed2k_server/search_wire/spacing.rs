//! The search-spacing leg: how far apart Lugdunum wants one link's searches.
//!
//! Lugdunum's binary is closed, so its spacing rule is known only by
//! measurement, and one sweep says little: a link it closes bans the address
//! for the rest of the server's life, and the rule may count more than the
//! last gap. So the leg repeats **sweeps**, each from an address of its own,
//! and names each by its **shape**:
//!
//! - `alone`: a fresh login, then four searches `gap` apart.
//! - `after-reconnect`: the link history of the search-wire leg's spacing sweep —
//!   a search, a drop and re-login with a second search 1500 ms after the first
//!   and a third 3 s on; again with 300 ms; then four searches 2000 ms apart,
//!   and four `gap` apart.
//! - `search-wire`: the search-wire probe's whole sequence before its spacing
//!   sweep — the tokenisation probes 3 s apart, the Related-Files Searches, the
//!   more-results walk — then `after-reconnect`. The sharer then also holds the
//!   search-wire leg's sharer-0 files.
//!
//! Sweeps run in **rounds**, each on a fresh Lugdunum with one aMule sharer that
//! holds every burst word's file, the conditions interleaved in every round, so
//! no condition rides one server instance or one stretch of time. A sweep's
//! outcome comes from the probe's report; the gaps the server saw, and which
//! side closed the link, from the tap. Reports under `search-spacing/lugdunum/`:
//! `sweeps.txt` (one line per sweep) and `summary.txt` (one line per condition).

use std::fmt::Write as _;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use super::{
    IP_PREFIX, MORE_WORD, POPULAR, PROBE_QUERIES, RARE, SUBNET, burst_words, server_tap,
    stage_shares, wait_for_offers, write_file,
};
use crate::artifacts::RunLayout;
use crate::docker::RunContainer;
use crate::flow::bench::{Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, ESERVER_ENTRYPOINT_LOG};
use crate::flow::gate::wait_for_container_log;
use crate::flow::logs::retain_artifact;
use crate::rmule::RmuleClientContainer;

/// Lugdunum's address on the bench, fixed so every round's sharer and probes
/// reach it by address.
const SERVER_OCTET: u8 = 10;
const SERVER_PORT: u16 = 4661;
const SHARER_OCTET: u8 = 20;
/// The first sweep address of a round; each sweep takes the next.
const FIRST_SWEEP_OCTET: u8 = 30;
/// The reconnect gaps of the `after-reconnect` shape.
const RECONNECT_GAPS_MS: &str = "1500,300";
/// The spacing that precedes the measured one in the `after-reconnect` shape.
const LEAD_SPACING_MS: u64 = 2000;

/// Options for the search-spacing leg.
pub struct SearchSpacingOptions<'a> {
    /// The run dir every artifact is written under.
    pub layout: &'a RunLayout,
    /// The Docker-compatible CLI to invoke.
    pub container_runtime: &'a str,
    /// Build the project-owned images before starting anything.
    pub build_images: bool,
    /// The Lugdunum eserver image.
    pub server_image: &'a str,
    /// Build context for the eserver image.
    pub server_build_context: &'a Path,
    /// Extra `KEY=VALUE` environment for the eserver container.
    pub server_env: &'a [String],
    /// The aMule image the sharer runs.
    pub amule_image: &'a str,
    /// Build context for the aMule image.
    pub amule_build_context: &'a Path,
    /// Extra `KEY=VALUE` environment for the sharer.
    pub amule_env: &'a [String],
    /// Log substring that marks the sharer ready.
    pub amule_ready_log_pattern: &'a str,
    /// Leave the containers and network running after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget, in seconds.
    pub timeout_secs: u64,
    /// The rust image + workspace the probe runs in.
    pub rmule_client_container: &'a RmuleClientContainer,
    /// The tcpdump image tapping the server.
    pub capture_image: &'a str,
    /// Gaps swept in the `alone` shape, milliseconds.
    pub alone_gaps_ms: &'a [u64],
    /// Gaps swept in the `after-reconnect` shape, milliseconds.
    pub after_reconnect_gaps_ms: &'a [u64],
    /// Gaps swept in the `search-wire` shape, milliseconds.
    pub search_wire_gaps_ms: &'a [u64],
    /// Sweeps per condition, over all rounds.
    pub sweeps: usize,
    /// How many fresh servers the sweeps are spread over.
    pub rounds: usize,
}

#[derive(Clone, Copy)]
enum Shape {
    Alone,
    AfterReconnect,
    SearchWire,
}

impl Shape {
    fn label(self) -> &'static str {
        match self {
            Self::Alone => "alone",
            Self::AfterReconnect => "after-reconnect",
            Self::SearchWire => "search-wire",
        }
    }
}

#[derive(Clone, Copy)]
struct Condition {
    shape: Shape,
    gap_ms: u64,
}

/// One sweep's outcome.
struct Sweep {
    round: usize,
    condition: Condition,
    address: Ipv4Addr,
    /// The probe's report line for the measured spacing.
    report: String,
    lost: bool,
    /// Answers that came back without a row.
    empty: usize,
}

/// Run the sweeps against Lugdunum.
pub fn run_search_spacing(options: SearchSpacingOptions<'_>) -> Result<()> {
    if options.rounds == 0 || options.sweeps == 0 {
        bail!("the leg needs at least one round and one sweep");
    }
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    if options.build_images {
        bench.build_image("server", options.server_image, options.server_build_context)?;
        bench.build_image("aMule", options.amule_image, options.amule_build_context)?;
    }
    let root = options.layout.root().join("search-spacing");
    let leg_dir = root.join("lugdunum");
    fs::create_dir_all(&leg_dir).with_context(|| format!("create {}", leg_dir.display()))?;
    let share = if options.search_wire_gaps_ms.is_empty() {
        let share = root.join("share");
        fs::create_dir_all(&share).with_context(|| format!("create {}", share.display()))?;
        for word in burst_words() {
            write_file(&share, &format!("wire-{word}.bin"), &word)?;
        }
        share
    } else {
        stage_shares(&root, true)?.swap_remove(0)
    };

    let conditions: Vec<Condition> = options
        .alone_gaps_ms
        .iter()
        .map(|&gap_ms| Condition {
            shape: Shape::Alone,
            gap_ms,
        })
        .chain(
            options
                .after_reconnect_gaps_ms
                .iter()
                .map(|&gap_ms| Condition {
                    shape: Shape::AfterReconnect,
                    gap_ms,
                }),
        )
        .chain(options.search_wire_gaps_ms.iter().map(|&gap_ms| Condition {
            shape: Shape::SearchWire,
            gap_ms,
        }))
        .collect();
    let per_round = options.sweeps.div_ceil(options.rounds);
    if per_round * conditions.len() > usize::from(u8::MAX - FIRST_SWEEP_OCTET) {
        bail!(
            "a round of {per_round} sweeps per condition needs more addresses than the subnet holds"
        );
    }

    let result = (|| -> Result<Vec<Sweep>> {
        bench.create_network(options.layout, Some(SUBNET))?;
        let mut sweeps = Vec::new();
        for round in 0..options.rounds {
            let wanted = options
                .sweeps
                .saturating_sub(round * per_round)
                .min(per_round);
            if wanted == 0 {
                break;
            }
            sweeps.extend(run_round(
                &mut bench,
                &options,
                &leg_dir,
                &share,
                round,
                wanted,
                &conditions,
            )?);
        }
        Ok(sweeps)
    })();
    if result.is_err() {
        bench.collect_failure_logs(options.layout);
    }
    bench.cleanup_best_effort();
    let sweeps = result?;
    write_reports(&leg_dir, &conditions, &sweeps)
}

fn run_round(
    bench: &mut Bench,
    options: &SearchSpacingOptions<'_>,
    leg_dir: &Path,
    share: &Path,
    round: usize,
    per_condition: usize,
    conditions: &[Condition],
) -> Result<Vec<Sweep>> {
    let timeout = Duration::from_secs(options.timeout_secs);
    let server = format!("{}-r{round}", bench.names.server_container_name);
    let server_ip = format!("{IP_PREFIX}{SERVER_OCTET}");
    bench.start_extra(
        &server,
        RunContainer::new(options.server_image)
            .detach()
            .name(&server)
            .network(bench.names.network_name.clone())
            .ip(&server_ip)
            .env_assignments(options.server_env),
        "run the eserver",
    )?;
    wait_for_container_log(&bench.docker, &server, ESERVER_ENTRYPOINT_LOG, timeout)?;
    let tap = format!("{server}-tap");
    let pcap_file = format!("round-{round}.pcap");
    let sidecar = CaptureSidecar {
        image: options.capture_image,
        name: &tap,
        target_container: &server,
        interface: DEFAULT_TAP_INTERFACE,
        host_dir: leg_dir.to_path_buf(),
        pcap_file: &pcap_file,
        bpf: "tcp port 4661",
    };
    bench.start_extra(&tap, sidecar.container(), "run the server tap")?;
    let sharer = format!("{server}-sharer");
    let sharer_ip = format!("{IP_PREFIX}{SHARER_OCTET}");
    let pcap = leg_dir.join(&pcap_file);

    let outcome = (|| -> Result<Vec<Sweep>> {
        bench.start_extra(
            &sharer,
            RunContainer::new(options.amule_image)
                .detach()
                .name(&sharer)
                .network(bench.names.network_name.clone())
                .ip(&sharer_ip)
                .env("ED2K_SERVER_HOST", server_ip.as_str())
                .env("ED2K_SERVER_PORT", SERVER_PORT.to_string())
                .volume(share, "/incoming")
                .env("AMULE_SHARED_DIR", "/incoming")
                .env("AMULE_CRYPT_SUPPORTED", "0")
                .env("AMULE_CRYPT_REQUESTED", "0")
                .env_assignments(options.amule_env),
            "run the sharer",
        )?;
        let logs = wait_for_container_log(
            &bench.docker,
            &sharer,
            options.amule_ready_log_pattern,
            timeout,
        )?;
        retain_artifact(
            &leg_dir.join(format!("round-{round}-sharer.log")),
            logs.as_bytes(),
        );
        wait_for_offers(&pcap, sharer_ip.parse()?, share, timeout)?;

        let mut sweeps = Vec::new();
        let mut octet = FIRST_SWEEP_OCTET;
        for index in 0..per_condition {
            for &condition in conditions {
                let address: Ipv4Addr = format!("{IP_PREFIX}{octet}").parse()?;
                octet += 1;
                let out = format!(
                    "search-spacing/lugdunum/round-{round}/{}-{}ms-{index}",
                    condition.shape.label(),
                    condition.gap_ms
                );
                let sweep = run_sweep(bench, options, &server_ip, address, &out, condition)?;
                println!(
                    "search-spacing round {round} {} {} ms from {address}: {}",
                    condition.shape.label(),
                    condition.gap_ms,
                    if sweep.1 {
                        "lost the link"
                    } else {
                        "kept the link"
                    }
                );
                sweeps.push(Sweep {
                    round,
                    condition,
                    address,
                    report: sweep.0,
                    lost: sweep.1,
                    empty: sweep.2,
                });
            }
        }
        Ok(sweeps)
    })();
    if let Ok(output) = bench.docker.logs(server.clone()).to_command().output() {
        let mut log = output.stdout;
        log.extend_from_slice(&output.stderr);
        retain_artifact(&leg_dir.join(format!("round-{round}-server.log")), &log);
    }
    bench.stop_extra(&sharer);
    bench.stop_extra(&tap);
    bench.stop_extra(&server);
    outcome
}

/// One probe run from `address`: the report line for the measured spacing,
/// whether the link was lost under it, and how many of its answers were empty.
fn run_sweep(
    bench: &Bench,
    options: &SearchSpacingOptions<'_>,
    server_ip: &str,
    address: Ipv4Addr,
    out: &str,
    condition: Condition,
) -> Result<(String, bool, usize)> {
    let words: Vec<String> = burst_words().into_iter().take(6).collect();
    let mut args = vec![
        "--bursts".to_owned(),
        "--burst-words".to_owned(),
        words.join(","),
        "--udp-burst".to_owned(),
        "0".to_owned(),
        "--answer-wait".to_owned(),
        "6".to_owned(),
        "--low-id".to_owned(),
        "--spacings-ms".to_owned(),
    ];
    match condition.shape {
        Shape::Alone => args.push(condition.gap_ms.to_string()),
        Shape::AfterReconnect | Shape::SearchWire => {
            args.push(format!("{LEAD_SPACING_MS},{}", condition.gap_ms));
            args.push("--reconnect-gaps-ms".to_owned());
            args.push(RECONNECT_GAPS_MS.to_owned());
        }
    }
    if let Shape::SearchWire = condition.shape {
        for probe in PROBE_QUERIES {
            args.push("--probe-query".to_owned());
            args.push(probe.to_owned());
        }
        for word in [POPULAR, RARE] {
            args.push("--related-via".to_owned());
            args.push(word.to_owned());
        }
        args.push("--more-query".to_owned());
        args.push(MORE_WORD.to_owned());
    }
    let output = options
        .rmule_client_container
        .search_wire_command(
            bench.staging(options.layout),
            &format!("{server_ip}:{SERVER_PORT}"),
            &address.to_string(),
            out,
            &args,
        )?
        .to_command()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("run the probe from {address}"))?;
    let dir: PathBuf = options.layout.root().join(out);
    retain_artifact(&dir.join("stdout.log"), &output.stdout);
    retain_artifact(&dir.join("stderr.log"), &output.stderr);
    if !output.status.success() {
        bail!("the probe from {address} exited {}", output.status);
    }
    let report = fs::read_to_string(dir.join("search-wire.txt"))
        .with_context(|| format!("read the report of the probe from {address}"))?;
    let head = format!("spacing[{}ms]", condition.gap_ms);
    let summary = report
        .lines()
        .find(|line| line.starts_with(&format!("{head}: sent=")))
        .with_context(|| format!("the probe from {address} reported no {head} line"))?
        .to_owned();
    let lost = report
        .lines()
        .any(|line| line.contains(": sent=") && !line.ends_with("disconnected=no"));
    let empty = report
        .lines()
        .filter(|line| line.starts_with(&format!("{head} answer[")))
        .filter(|line| line.contains("rows=0 "))
        .count();
    Ok((summary, lost, empty))
}

/// The search gaps the server saw on a sweep's last link, and whether the
/// server closed it.
fn server_side(links: &[server_tap::Link], address: Ipv4Addr) -> (Vec<u64>, &'static str) {
    let Some(link) = links.iter().rfind(|link| *link.client.ip() == address) else {
        return (Vec::new(), "no-link");
    };
    let tail = link.searches.len().saturating_sub(4);
    let gaps = link.searches[tail..]
        .windows(2)
        .map(|pair| ((pair[1] - pair[0]) * 1000.0).round() as u64)
        .collect();
    let closed = match link.closed_by_server {
        Some(true) => "server",
        Some(false) => "client",
        None => "open",
    };
    (gaps, closed)
}

fn write_reports(leg_dir: &Path, conditions: &[Condition], sweeps: &[Sweep]) -> Result<()> {
    let mut lines = String::new();
    let mut rounds: Vec<usize> = sweeps.iter().map(|sweep| sweep.round).collect();
    rounds.dedup();
    for round in rounds {
        let links = server_tap::links(&leg_dir.join(format!("round-{round}.pcap")), SERVER_PORT)?;
        for sweep in sweeps.iter().filter(|sweep| sweep.round == round) {
            let (gaps, closed) = server_side(&links, sweep.address);
            let gaps: Vec<String> = gaps.iter().map(u64::to_string).collect();
            let _ = writeln!(
                lines,
                "round={round} shape={} gap_ms={} address={} outcome={} empty_answers={} \
                 server_gaps_ms={} last_link_closed_by={closed} | {}",
                sweep.condition.shape.label(),
                sweep.condition.gap_ms,
                sweep.address,
                if sweep.lost { "lost" } else { "kept" },
                sweep.empty,
                gaps.join(","),
                sweep.report
            );
        }
    }
    fs::write(leg_dir.join("sweeps.txt"), &lines)
        .with_context(|| format!("write {}", leg_dir.join("sweeps.txt").display()))?;

    let mut summary = String::new();
    for condition in conditions {
        let of: Vec<&Sweep> = sweeps
            .iter()
            .filter(|sweep| {
                sweep.condition.gap_ms == condition.gap_ms
                    && sweep.condition.shape.label() == condition.shape.label()
            })
            .collect();
        let _ = writeln!(
            summary,
            "shape={} gap_ms={} sweeps={} lost={} with_empty_answers={}",
            condition.shape.label(),
            condition.gap_ms,
            of.len(),
            of.iter().filter(|sweep| sweep.lost).count(),
            of.iter().filter(|sweep| sweep.empty > 0).count()
        );
    }
    print!("{summary}");
    fs::write(leg_dir.join("summary.txt"), summary)
        .with_context(|| format!("write {}", leg_dir.join("summary.txt").display()))
}
