//! The search-wire leg: what Lugdunum and ed2k-server do with
//! searches sent together, how each reads a query's words, and how each answers
//! a Related-Files Search.
//!
//! Per server, five aMule **sharers** join the bench: sharer 0 shares one file
//! per burst word, the tokenisation probes' files, the popular file and the
//! rare file; sharers 1–4 share the popular file only, so it has five sources
//! and the rare one has one. rmule's `search-wire` probe then runs twice — as a
//! High-ID requester and as a Low-ID one — sending bursts of 3, 10 and 30
//! back-to-back `OP_SEARCHREQUEST`s with disjoint queries, the tokenisation
//! probes, a Related-Files Search for each file, and a `0x98` burst. Sharer 1
//! runs the same two-word search through `amulecmd`, the joined one-term form
//! aMule sends, for comparison with rmule's AND-ed words. Everything lands under `search-wire/` in the run dir, the tap's frames as the timeline
//! `decoded.txt`; no verdict is drawn here — the reports are the evidence the
//! rulings are made from.

pub(crate) mod server_tap;
mod spacing;

pub use self::spacing::{SearchSpacingOptions, run_search_spacing};

use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::docker::RunContainer;
use crate::flow::bench::{Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, amulecmd_command};
use crate::flow::ed2ksrv::ED2KSRV;
use crate::flow::gate::wait_for_container_log;
use crate::flow::logs::retain_artifact;
use crate::rmule::RmuleClientContainer;

/// The bench network: the fake-public documentation range the ed2k-server
/// config is written for, which aMule accepts (it refuses 192.0.2/24 and
/// 198.18/15).
pub(crate) const SUBNET: &str = "203.0.113.0/24";
const IP_PREFIX: &str = "203.0.113.";
/// ed2k-server's static address, its config's `this_ip`; far above the
/// addresses Docker hands out first.
pub(crate) const ED2KSRV_IP: &str = "203.0.113.200";
/// How many sharers hold the popular file.
const SHARERS: u8 = 5;
/// The burst sizes, largest last.
const BURSTS: [usize; 3] = [3, 10, 30];
/// How many `0x98` go out back to back: above ed2k-server's bot-detector
/// floor of 30 queries in its 60 s window (`bot_detector.rs:19-29`).
const UDP_BURST: usize = 40;
/// The word every more-results file carries.
const MORE_WORD: &str = "morepage";
/// How many files carry it: past ed2k-server's 200-row cap (`search.rs:19`,
/// so its answer should still say no more — derived) and past the one-page
/// sizes eMule's comment gives for other servers, 201 and 300
/// (`Opcodes.h:61`); Lugdunum's page size is not known.
const MORE_FILES: usize = 450;
/// The two-word search both clients send, rmule as AND-ed words, aMule joined.
const TWO_WORDS: &str = "ubuntu desktop";
/// Three words, all in one shared name.
const THREE_WORDS: &str = "ubuntu desktop wire";
/// The queries aMule itself sends through `amulecmd`, each joined into one
/// term by its parser, beside rmule's split form of the same text.
const AMULE_QUERIES: [&str; 7] = [
    TWO_WORDS,
    THREE_WORDS,
    "\"ubuntu desktop\"",
    "betaga",
    "alphabetagamma",
    "desktop OR server",
    "ubuntu NOT server",
];

/// Options for the search-wire leg.
pub struct SearchWireOptions<'a> {
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
    /// The ed2k-server image.
    pub ed2ksrv_image: &'a str,
    /// Build context for the ed2k-server image.
    pub ed2ksrv_build_context: &'a Path,
    /// The ed2k-server bench config; its `this_ip` is rendered per run.
    pub ed2ksrv_config: &'a Path,
    /// The aMule image the sharers run.
    pub amule_image: &'a str,
    /// Build context for the aMule image.
    pub amule_build_context: &'a Path,
    /// Extra `KEY=VALUE` environment for every sharer.
    pub amule_env: &'a [String],
    /// Log substring that marks a sharer ready.
    pub amule_ready_log_pattern: &'a str,
    /// Leave the containers and network running after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget, in seconds.
    pub timeout_secs: u64,
    /// The rust image + workspace the probe runs in.
    pub rmule_client_container: &'a RmuleClientContainer,
    /// The tcpdump image tapping each server.
    pub capture_image: &'a str,
    /// The servers to run against, in order.
    pub servers: &'a [SearchWireServer],
    /// Share several hundred files under one word and have each probe walk
    /// `OP_QUERY_MORE_RESULT` over them.
    pub more_results: bool,
    /// The reconnect leg's gaps, milliseconds; empty skips the leg.
    pub reconnect_gaps_ms: &'a [u64],
}

/// A server the leg runs against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchWireServer {
    /// The Lugdunum eserver.
    Lugdunum,
    /// ed2k-server.
    Ed2kServer,
}

/// One server the leg runs against.
struct Leg {
    /// Its label under `search-wire/`.
    label: &'static str,
    /// The address the sharers resolve it by.
    host: String,
    /// `host:port` for the probe.
    endpoint: String,
    /// The server's container, whose traffic the leg taps.
    container: String,
    /// The fourth octet the leg's sharers and probes count up from.
    first_octet: u8,
}

/// Run the search-wire leg against Lugdunum, then ed2k-server.
pub fn run_search_wire(options: SearchWireOptions<'_>) -> Result<()> {
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    if options.build_images {
        bench.build_image("server", options.server_image, options.server_build_context)?;
        bench.build_image("aMule", options.amule_image, options.amule_build_context)?;
        crate::flow::ed2ksrv::build(
            options.ed2ksrv_image,
            options.ed2ksrv_build_context,
            options.layout.root(),
        )?;
    }
    let timeout = Duration::from_secs(options.timeout_secs);
    let root = options.layout.root().join("search-wire");
    let shares = stage_shares(&root, options.more_results)?;

    let result = (|| -> Result<()> {
        bench.create_network(options.layout, Some(SUBNET))?;
        for server in options.servers {
            match server {
                SearchWireServer::Lugdunum => {
                    bench.start_eserver_in_network(
                        options.layout,
                        options.server_image,
                        options.server_env,
                        timeout,
                    )?;
                    let leg = Leg {
                        label: "lugdunum",
                        host: bench.names.server_container_name.clone(),
                        endpoint: bench.names.server_endpoint(),
                        container: bench.names.server_container_name.clone(),
                        first_octet: 20,
                    };
                    run_leg(&mut bench, &options, &leg, &shares, &root, timeout)?;
                }
                SearchWireServer::Ed2kServer => {
                    let ed2ksrv = start_ed2ksrv(
                        &mut bench,
                        options.ed2ksrv_image,
                        options.ed2ksrv_config,
                        &root,
                        timeout,
                    )?;
                    let leg = Leg {
                        label: "ed2k-server",
                        host: ED2KSRV_IP.to_owned(),
                        endpoint: format!("{ED2KSRV_IP}:4661"),
                        container: ed2ksrv.clone(),
                        first_octet: 40,
                    };
                    let outcome = run_leg(&mut bench, &options, &leg, &shares, &root, timeout);
                    bench.stop_extra(&ed2ksrv);
                    outcome?;
                }
            }
        }
        Ok(())
    })();

    if result.is_err() {
        bench.collect_failure_logs(options.layout);
    }
    bench.cleanup_best_effort();
    result
}

/// The words each burst query carries: one per file, none inside another.
fn burst_words() -> Vec<String> {
    (1..=BURSTS[BURSTS.len() - 1])
        .map(|index| format!("kw{index:02}x"))
        .collect()
}

/// The tokenisation probes, each sent alone, and the file names that answer
/// them: a substring that is no whole word, accents both ways, each separator,
/// and the two-word search as AND-ed words and as a quoted run.
const PROBE_FILES: [&str; 13] = [
    "tokenprobe-alphabetagamma.bin",
    "Café Crème tokenprobe.bin",
    "resume tokenprobe.bin",
    "sepdash-dashword.bin",
    "sepunder_underword.bin",
    "sepdot.dotword.bin",
    "sepspace spaceword.bin",
    "sepparen(parenword).bin",
    "sepbracket[bracketword].bin",
    "sepcomma,commaword.bin",
    "sepplus+plusword.bin",
    "ubuntu-desktop-wire.bin",
    "ubuntu-server-wire.bin",
];
const PROBE_QUERIES: [&str; 20] = [
    "betaga",
    "alphabet",
    "gamma",
    "alphabetagamma",
    "cafe",
    "café",
    "résumé",
    "dashword",
    "underword",
    "dotword",
    "spaceword",
    "parenword",
    "bracketword",
    "commaword",
    "plusword",
    TWO_WORDS,
    THREE_WORDS,
    "\"sepspace spaceword\"",
    "\"spaceword sepspace\"",
    "\"ubuntu desktop\"",
];
/// Spacings between four successive searches, widest first.
const SPACINGS_MS: [u64; 8] = [2000, 1000, 900, 800, 700, 600, 500, 0];
/// The file with five sources and the one with one, found by these words.
const POPULAR: &str = "relatedpopular";
const RARE: &str = "relatedrare";
const COMPANION: &str = "relatedcompanion";

/// Write each sharer's directory: sharer 0 holds every file, the others the
/// popular one. Contents differ per file, so every name is its own hash; the
/// popular file's bytes are the same in every directory, so it is one hash
/// with five sources.
fn stage_shares(root: &Path, more_results: bool) -> Result<Vec<PathBuf>> {
    let mut shares = Vec::new();
    for sharer in 0..SHARERS {
        let dir = root.join(format!("share-{sharer}"));
        fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        write_file(&dir, &format!("{POPULAR}-wire.bin"), POPULAR)?;
        if sharer > 0 {
            // A file held beside the popular one by its other sources: what a
            // Related-Files Search is for.
            write_file(&dir, &format!("{COMPANION}-{sharer}-wire.bin"), COMPANION)?;
        }
        if sharer == 0 {
            write_file(&dir, &format!("{RARE}-wire.bin"), RARE)?;
            for word in burst_words() {
                write_file(&dir, &format!("wire-{word}.bin"), &word)?;
            }
            for name in PROBE_FILES {
                write_file(&dir, name, name)?;
            }
            if more_results {
                for index in 1..=MORE_FILES {
                    let name = format!("{MORE_WORD}-{index:04}.bin");
                    write_file(&dir, &name, &name)?;
                }
            }
        }
        shares.push(dir);
    }
    Ok(shares)
}

/// A small file whose bytes are `seed` repeated — distinct per seed.
fn write_file(dir: &Path, name: &str, seed: &str) -> Result<()> {
    let body = seed.repeat(4096 / seed.len().max(1) + 1);
    let path = dir.join(name);
    fs::write(&path, body).with_context(|| format!("write {}", path.display()))
}

/// Stand ed2k-server up at its static address, its config's `this_ip`
/// rendered to it (ADR-0045: authored counterparty state, the binary untouched),
/// once its image passes the pin check; the pin lands in `ed2ksrv-pin.txt`.
/// The bench network must be [`SUBNET`].
pub(crate) fn start_ed2ksrv(
    bench: &mut Bench,
    image: &str,
    config: &Path,
    root: &Path,
    timeout: Duration,
) -> Result<String> {
    let config =
        fs::read_to_string(config).with_context(|| format!("read {}", config.display()))?;
    let rendered: Vec<String> = config
        .lines()
        .map(|line| {
            if line.starts_with("this_ip") {
                format!("this_ip = \"{ED2KSRV_IP}\"")
            } else {
                line.to_owned()
            }
        })
        .collect();
    let config_path = root.join("ed2ksrv-config.toml");
    fs::write(&config_path, rendered.join("\n"))
        .with_context(|| format!("write {}", config_path.display()))?;
    let name = format!("{}-ed2ksrv", bench.names.server_container_name);
    let ed2ksrv = ED2KSRV.check(&bench.docker, image)?;
    bench.start_extra(
        &name,
        ed2ksrv
            .container()
            .detach()
            .name(&name)
            .network(bench.names.network_name.clone())
            .ip(ED2KSRV_IP)
            .volume(&config_path, "/etc/ed2k-server/config.toml"),
        "run ed2k-server",
    )?;
    wait_for_container_log(&bench.docker, &name, "TCP listener ready", timeout)?;
    // The reports carry no verdict, so the pin they rest on is named beside them.
    let pin_path = root.join("ed2ksrv-pin.txt");
    fs::write(&pin_path, format!("{}\n", ed2ksrv.pin()))
        .with_context(|| format!("write {}", pin_path.display()))?;
    Ok(name)
}

/// One server's run: its sharers, the two probes, the aMule comparison, then
/// the sharers go.
fn run_leg(
    bench: &mut Bench,
    options: &SearchWireOptions<'_>,
    leg: &Leg,
    shares: &[PathBuf],
    root: &Path,
    timeout: Duration,
) -> Result<()> {
    let leg_dir = root.join(leg.label);
    fs::create_dir_all(&leg_dir).with_context(|| format!("create {}", leg_dir.display()))?;
    let mut sharers = Vec::new();
    // Tap the server: aMule's joined frames, rmule's split ones and every
    // answer, in one pcap.
    let tap = format!("{}-tap", leg.container);
    let sidecar = CaptureSidecar {
        image: options.capture_image,
        name: &tap,
        target_container: &leg.container,
        interface: DEFAULT_TAP_INTERFACE,
        host_dir: leg_dir.clone(),
        pcap_file: "server.pcap",
        bpf: "tcp port 4661 or udp",
    };
    bench.start_extra(&tap, sidecar.container(), "run the server tap")?;
    let outcome = (|| -> Result<()> {
        // One at a time: the eserver drops logins that arrive together.
        for (index, share) in (0_u8..).zip(shares) {
            let name = format!(
                "{}-{}-sharer{index}",
                bench.names.amule_container_name, leg.label
            );
            let ip = format!("{IP_PREFIX}{}", leg.first_octet + index);
            bench.start_extra(
                &name,
                RunContainer::new(options.amule_image)
                    .detach()
                    .name(&name)
                    .network(bench.names.network_name.clone())
                    .ip(&ip)
                    .env("ED2K_SERVER_HOST", leg.host.as_str())
                    .env("ED2K_SERVER_PORT", "4661")
                    .volume(share, "/incoming")
                    .env("AMULE_SHARED_DIR", "/incoming")
                    // Plain frames to the server, so the tap reads them.
                    .env("AMULE_CRYPT_SUPPORTED", "0")
                    .env("AMULE_CRYPT_REQUESTED", "0")
                    .env_assignments(options.amule_env),
                "run a sharer",
            )?;
            sharers.push(name.clone());
            let logs = wait_for_container_log(
                &bench.docker,
                &name,
                options.amule_ready_log_pattern,
                timeout,
            )?;
            retain_artifact(&leg_dir.join(format!("{name}.log")), logs.as_bytes());
        }
        let first_sharer: Ipv4Addr = format!("{IP_PREFIX}{}", leg.first_octet)
            .parse()
            .context("sharer 0's address")?;
        wait_for_offers(
            "search-wire",
            &leg_dir.join("server.pcap"),
            first_sharer,
            &shares[0],
            timeout,
        )?;

        for (requester, low_id, octet) in [("high-id", false, 8), ("low-id", true, 9)] {
            let mut args = vec![
                "--bursts".to_owned(),
                BURSTS.map(|size| size.to_string()).join(","),
                "--burst-words".to_owned(),
                burst_words().join(","),
                "--udp-burst".to_owned(),
                // One ban per leg is enough evidence; the second requester
                // would only meet it.
                if low_id {
                    "0".to_owned()
                } else {
                    UDP_BURST.to_string()
                },
                // Both servers answer in milliseconds; a shorter wait keeps a
                // leg inside one polling window.
                "--answer-wait".to_owned(),
                "6".to_owned(),
                "--related-via".to_owned(),
                POPULAR.to_owned(),
                "--related-via".to_owned(),
                RARE.to_owned(),
            ];
            for probe in PROBE_QUERIES {
                args.push("--probe-query".to_owned());
                args.push(probe.to_owned());
            }
            args.push("--spacings-ms".to_owned());
            args.push(SPACINGS_MS.map(|ms| ms.to_string()).join(","));
            if !options.reconnect_gaps_ms.is_empty() {
                args.push("--reconnect-gaps-ms".to_owned());
                let gaps: Vec<String> = options
                    .reconnect_gaps_ms
                    .iter()
                    .map(u64::to_string)
                    .collect();
                args.push(gaps.join(","));
            }
            if low_id {
                args.push("--low-id".to_owned());
            }
            if options.more_results {
                args.push("--more-query".to_owned());
                args.push(MORE_WORD.to_owned());
            }
            let output = options
                .rmule_client_container
                .search_wire_command(
                    bench.staging(options.layout),
                    &leg.endpoint,
                    &format!("{IP_PREFIX}{}", leg.first_octet + octet),
                    &format!("search-wire/{}/{requester}", leg.label),
                    &args,
                )?
                .to_command()
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .with_context(|| format!("run the {requester} search-wire probe"))?;
            retain_artifact(
                &leg_dir.join(format!("{requester}.stdout.log")),
                &output.stdout,
            );
            retain_artifact(
                &leg_dir.join(format!("{requester}.stderr.log")),
                &output.stderr,
            );
            println!(
                "search-wire {} {requester}: probe exit {}",
                leg.label, output.status
            );
        }

        // aMule's own joined form of the same texts, captured by the tap.
        if let Some(sharer) = sharers.get(1) {
            let mut transcript = Vec::new();
            for query in AMULE_QUERIES {
                for command in [format!("Search local {query}"), "Results".to_owned()] {
                    let output = bench
                        .docker
                        .exec(sharer.clone(), amulecmd_command(&command))
                        .to_command()
                        .output()
                        .with_context(|| format!("amulecmd {command}"))?;
                    transcript.extend_from_slice(format!("===== {command} =====\n").as_bytes());
                    transcript.extend_from_slice(&output.stdout);
                    transcript.extend_from_slice(&output.stderr);
                    // Let the server answer before the results are read.
                    thread::sleep(Duration::from_secs(6));
                }
            }
            retain_artifact(&leg_dir.join("amule-queries.log"), &transcript);
        }
        Ok(())
    })();
    // The server's own log of the run: its flood and ban lines, if any.
    if let Ok(output) = bench
        .docker
        .logs(leg.container.clone())
        .to_command()
        .output()
    {
        let mut log = output.stdout;
        log.extend_from_slice(&output.stderr);
        retain_artifact(&leg_dir.join("server.log"), &log);
    }
    for name in &sharers {
        bench.stop_extra(name);
    }
    bench.stop_extra(&tap);
    outcome?;
    server_tap::write_timeline(&leg_dir.join("server.pcap"), &leg_dir.join("decoded.txt"))
}

/// Hold until the tap shows `sharer` has offered the server every file in
/// `share`: aMule offers at most 200 a minute, so a large share reaches the
/// server over minutes, and a search sent before then is answered short.
/// `flow` prefixes the progress line.
pub(crate) fn wait_for_offers(
    flow: &str,
    pcap: &Path,
    sharer: Ipv4Addr,
    share: &Path,
    timeout: Duration,
) -> Result<()> {
    let held = fs::read_dir(share)
        .with_context(|| format!("list {}", share.display()))?
        .count() as u64;
    let deadline = Instant::now() + timeout;
    loop {
        let offered = server_tap::offered_files(pcap, sharer)?;
        if offered >= held {
            println!("{flow}: sharer {sharer} offered {offered} of {held} files");
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "sharer {sharer} offered {offered} of its {held} files within {} s",
                timeout.as_secs()
            );
        }
        thread::sleep(Duration::from_secs(2));
    }
}
