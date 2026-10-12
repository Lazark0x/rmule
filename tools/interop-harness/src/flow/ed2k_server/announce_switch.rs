//! The announce-switch leg: what a live server does with a client's offered
//! files when the client offers again, offers an empty list, and hangs up.
//!
//! rmule re-announces its whole share set to every server it switches to and,
//! under the Announce Policy (ADR-0099), may withhold it from a server that
//! grants related search. Whether a server drops a client's offers when the
//! link closes, and whether an empty `OP_OFFERFILES` retracts them, decides
//! what withholding can promise mid-session; neither is written anywhere a
//! reading can settle. Per server, `offer_probe.py` runs two links from two
//! addresses (Lugdunum drops a second concurrent login from one address): a
//! publisher that offers two files, then a second overlapping set, then an
//! empty list, then all three, then hangs up; and a searcher that asks one
//! keyword search after each step. The probe's frames are Stimulus; the
//! servers' `OP_SEARCHRESULT` payloads, retained as hex in each
//! `searcher.jsonl`, are the evidence. Each server's `offer-set-summary` line
//! lands in `announce-switch/verdict.txt`, followed, when asked, by rmule's
//! own legs (`rmule_legs`): what rmule offers each server across a switch,
//! plain and withholding. The same probe also runs in `markers` mode against
//! each server: it offers one whole file and one part-file the way aMule marks
//! them, and the searcher's `marker-summary` line records the ID, port and
//! counters each result row carries for either; the legs' summary lines carry
//! the ID and port every entry of rmule's own offers wore.

mod rmule_legs;

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::docker::RunContainer;
use crate::flow::bench::{Bench, run_checked};
use crate::flow::ed2k_server::search_wire::{ED2KSRV_IP, SUBNET, start_ed2ksrv};

/// The probe both roles run, written into the run dir and mounted.
const OFFER_PROBE: &str = include_str!("announce_switch/offer_probe.py");
/// The marker line the searcher closes with.
const SUMMARY_MARKER: &str = "offer-set-summary";
/// The marker line the `markers`-mode searcher closes with.
const MARKER_SUMMARY: &str = "marker-summary";
/// Each probe run's publisher and searcher addresses, the ones their
/// listeners bind: by server (Lugdunum, then ed2k-server), then by mode (the
/// offer set, then `markers`). A pair per run, so one left standing under
/// `--keep-containers` holds no address a later run takes.
const PROBE_ADDRESSES: [[(&str, &str); 2]; 2] = [
    [
        ("203.0.113.80", "203.0.113.81"),
        ("203.0.113.82", "203.0.113.83"),
    ],
    [
        ("203.0.113.84", "203.0.113.85"),
        ("203.0.113.86", "203.0.113.87"),
    ],
];

/// Options for the announce-switch leg.
pub struct AnnounceSwitchOptions<'a> {
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
    pub ed2ksrv_config: &'a Path,
    /// An image carrying `python3`, the probe's interpreter.
    pub probe_image: &'a str,
    /// Run the offer-set probes (skipped when only rmule's legs are wanted).
    pub probes: bool,
    /// Run the `markers` probe: one whole file and one part-file offered the
    /// way aMule marks them.
    pub markers: bool,
    /// The `rmule-tools` image, when rmule's own legs run after the probes.
    pub rmule_tools_image: Option<&'a str>,
    /// The tcpdump capture-sidecar image rmule's legs tap the servers with.
    pub capture_image: &'a str,
}

/// Run the offer-set probe against Lugdunum, then ed2k-server, then rmule's
/// legs against both when asked.
pub fn run_announce_switch(options: AnnounceSwitchOptions<'_>) -> Result<()> {
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    let timeout = Duration::from_secs(options.timeout_secs);
    let root = options.layout.root().join("announce-switch");
    fs::create_dir_all(&root).with_context(|| format!("create {}", root.display()))?;
    fs::write(root.join("offer_probe.py"), OFFER_PROBE).context("write offer_probe.py")?;

    let result = (|| -> Result<Vec<String>> {
        bench.create_network(options.layout, Some(SUBNET))?;
        bench.start_eserver_in_network(
            options.layout,
            options.server_image,
            options.server_env,
            timeout,
        )?;
        let endpoint = bench.names.server_endpoint();
        let mut lines = Vec::new();
        for markers in probe_modes(&options) {
            lines.push(probe_server(
                &mut bench,
                options.probe_image,
                &root,
                "lugdunum",
                &endpoint,
                markers,
                PROBE_ADDRESSES[0][usize::from(markers)],
            )?);
        }

        let ed2ksrv = start_ed2ksrv(
            &mut bench,
            options.ed2ksrv_image,
            options.ed2ksrv_config,
            &root,
            timeout,
        )?;
        let outcome = (|| -> Result<()> {
            for markers in probe_modes(&options) {
                lines.push(probe_server(
                    &mut bench,
                    options.probe_image,
                    &root,
                    "ed2k-server",
                    &format!("{ED2KSRV_IP}:4661"),
                    markers,
                    PROBE_ADDRESSES[1][usize::from(markers)],
                )?);
            }
            if let Some(image) = options.rmule_tools_image {
                let server = bench.names.server_container_name.clone();
                let address =
                    run_checked(bench.docker.container_ip(server.clone()), "server address")?;
                let servers = rmule_legs::Servers {
                    lugdunum: (&server, address.trim().parse()?),
                    ed2ksrv: &ed2ksrv,
                };
                lines.extend(rmule_legs::run(
                    &mut bench,
                    image,
                    options.capture_image,
                    &root,
                    &servers,
                )?);
            }
            Ok(())
        })();
        bench.stop_extra(&ed2ksrv);
        outcome.map(|()| lines)
    })();

    if result.is_err() {
        bench.collect_failure_logs(options.layout);
    }
    bench.cleanup_best_effort();
    let summaries = result?;
    let verdict = root.join("verdict.txt");
    fs::write(&verdict, summaries.join("\n") + "\n")
        .with_context(|| format!("write {}", verdict.display()))?;
    for line in &summaries {
        println!("{line}");
    }
    Ok(())
}

/// The probe runs wanted: the offer-set probe (`false`), the markers probe
/// (`true`), or both.
fn probe_modes(options: &AnnounceSwitchOptions<'_>) -> Vec<bool> {
    [(false, options.probes), (true, options.markers)]
        .into_iter()
        .filter_map(|(markers, wanted)| wanted.then_some(markers))
        .collect()
}

/// One server's probe: the publisher detached, the searcher in the
/// foreground, each at its own of `addresses` (publisher, searcher); both logs
/// retained under `root/<label>/` (`root/<label>-markers/` for the `markers`
/// run). Returns the searcher's summary line prefixed with the server's label.
fn probe_server(
    bench: &mut Bench,
    image: &str,
    root: &Path,
    label: &str,
    endpoint: &str,
    markers: bool,
    (publisher_ip, searcher_ip): (&str, &str),
) -> Result<String> {
    let (dir_name, summary_marker) = if markers {
        (format!("{label}-markers"), MARKER_SUMMARY)
    } else {
        (label.to_owned(), SUMMARY_MARKER)
    };
    let dir = root.join(&dir_name);
    let sync = dir.join("sync");
    fs::create_dir_all(&sync).with_context(|| format!("create {}", sync.display()))?;
    let prefix = bench.names.server_container_name.clone();
    let network = bench.names.network_name.clone();
    let role = |role: &str, address: &str| {
        let run = RunContainer::new(image.to_owned())
            .name(format!("{prefix}-{dir_name}-{role}"))
            .network(network.clone())
            .ip(address)
            .volume(root, "/w")
            .entrypoint("python3")
            .arg("/w/offer_probe.py")
            .arg(role)
            .arg(endpoint)
            .arg(format!("/w/{dir_name}/sync"))
            .arg(address);
        if markers { run.arg("markers") } else { run }
    };
    let publisher = format!("{prefix}-{dir_name}-publisher");
    bench.start_extra(
        &publisher,
        role("publisher", publisher_ip).detach(),
        "run offer publisher",
    )?;
    let searched = run_checked(
        bench
            .docker
            .run_container(role("searcher", searcher_ip).remove_after_exit()),
        "run offer searcher",
    );
    let published = run_checked(bench.docker.logs(publisher.clone()), "offer publisher logs");
    bench.stop_extra(&publisher);
    if let Ok(log) = &published {
        fs::write(dir.join("publisher.jsonl"), format!("{log}\n")).context("write publisher")?;
    }
    let searched = searched?;
    fs::write(dir.join("searcher.jsonl"), format!("{searched}\n")).context("write searcher")?;
    let Some(summary) = searched
        .lines()
        .find(|line| line.starts_with(summary_marker))
    else {
        bail!("{label}: the searcher printed no {summary_marker} line");
    };
    if markers {
        // A file the server leaves out is a finding the summary records; a
        // search that answered nothing at all is a failed run.
        if summary.contains(" found=none") || summary.contains(" found=0 ") {
            bail!("{label}: the server listed neither marked file: {summary}");
        }
    } else if !summary.contains("baseline_found=2") {
        bail!("{label}: the two offered files were not found at baseline: {summary}");
    }
    Ok(format!("server={label} {summary}"))
}
