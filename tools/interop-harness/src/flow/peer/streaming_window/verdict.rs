//! The streaming-window verdict: the claims ADR-0112 §1, §4 and §6 make,
//! scored from the tap on rmule's namespace and rmule's own log, and the §5
//! measurement — the verified prefix over time.
//!
//! The wire settles what each seed advertised and what rmule asked of it; the
//! log settles the order of rmule's decisions; [`super::replay`] lays one over
//! the other. A claim the topology cannot drive is not made: the count-`0`
//! form needs a complete seed, the phantom form a file an exact multiple of the
//! part size, the 43-minute wait a part no seed holds.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result};
use rmule_primitives::{ED2K_PART_SIZE, part_count};
use serde::{Deserialize, Serialize};

use super::ROOT_DIR;
use super::pace::{self, Pace};
use super::prefix::{Measurement, measure, traced_verifies};
use super::replay::{Pick, Replay, Topology, parse_log, replay};
use super::wire::{StatusForm, Wire, read};
use crate::flow::identity::ParseHex16;
use crate::flow::nat::claims::{Claim, Evidence, label};

/// The flow's name, as its verdict file states it.
pub(crate) const FLOW: &str = "peer-streaming-window";
/// The topology file the flow writes and the scorer reads.
pub(crate) const TOPOLOGY_FILE: &str = "topology.toml";
/// The tap on rmule's namespace.
pub(crate) const RMULE_PCAP: &str = "rmule-tap.pcap";
/// rmule's own download id: one download per run.
const DOWNLOAD_ID: u64 = 1;
/// Twice aMule's `FILEREASKTIME` (1,300 s): the TCP full ask a source that
/// holds nothing we need waits for (ADR-0112 §6, ADR-0057).
const NO_NEEDED_PARTS_REASK_SECS: f64 = 2_600.0;
/// Slack under that instant for clock and scheduling jitter.
const REASK_SLACK_SECS: f64 = 20.0;

/// What the flow staged, written before rmule starts so a re-score needs
/// nothing else.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct TopologyFile {
    /// The stream file's size.
    pub(crate) file_size: u64,
    /// Its ED2K hash, hex.
    pub(crate) file_hash: String,
    /// `--streaming-window`.
    pub(crate) window_parts: u32,
    /// `--max-connections`; a run from before the Connection Budget wrote
    /// its per-download worker cap here, which one download read the same.
    #[serde(alias = "peer_concurrency")]
    pub(crate) max_connections: usize,
    /// rmule's address on the tap.
    pub(crate) rmule_ip: Ipv4Addr,
    /// Every seed, in start order.
    pub(crate) seeds: Vec<SeedRow>,
    /// The seeds hold every part between them, so the download can finish.
    pub(crate) expect_complete: bool,
    /// rmule's container, for a hand collection of a kept run.
    pub(crate) rmule_container: String,
    /// The tap's container.
    pub(crate) tap_container: String,
    /// `--seed-netem-delay-ms`; absent from a run before it existed.
    #[serde(default)]
    pub(crate) seed_netem_delay_ms: Option<u32>,
}

/// One seed in [`TopologyFile`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SeedRow {
    /// `a`, `b`, …
    pub(crate) role: String,
    /// Its address on the bench network.
    pub(crate) ip: Ipv4Addr,
    /// What it holds, as `--seed` spells it.
    pub(crate) holding: String,
    /// Its container.
    pub(crate) container: String,
    /// Its upload cap, KiB/s.
    pub(crate) max_upload_kib: u32,
}

#[derive(Serialize)]
struct Verdict<'a> {
    #[serde(rename = "scenario")]
    flow: &'static str,
    verdict: &'static str,
    detail: String,
    file_size: u64,
    part_count: u32,
    window_parts: u32,
    max_connections: usize,
    seeds: Vec<String>,
    /// Seeds rmule sent a part request to: fewer than the seeds is a run
    /// that lost one, and is not its topology's measurement.
    seeds_asked: usize,
    statuses: Vec<String>,
    first_requests: Vec<String>,
    measurement: Measurement,
    /// The download's last verify over `pace.ideal_s`: 1.0 is every link at
    /// its cap to the last byte.
    tail_over_ideal: Option<f64>,
    seed_netem_delay_ms: Option<u32>,
    pace: Pace,
    claim: &'a [Claim],
}

/// Score the run dir a finished (or kept, then collected) flow left, write
/// `peer-streaming-window-verdict.toml` and `prefix-series.tsv`, and return
/// the label.
///
/// # Errors
/// If an artifact cannot be read or the verdict cannot be written.
pub fn score_run_dir(run_dir: &Path) -> Result<&'static str> {
    let root = run_dir.join(ROOT_DIR);
    let topology_path = root.join(TOPOLOGY_FILE);
    let topology: TopologyFile = toml::from_str(
        &fs::read_to_string(&topology_path)
            .with_context(|| format!("read {}", topology_path.display()))?,
    )
    .with_context(|| format!("parse {}", topology_path.display()))?;
    let file_hash = topology
        .file_hash
        .parse_hex16()
        .context("topology file_hash is not 32 hex digits")?;
    let seeds: Vec<Ipv4Addr> = topology.seeds.iter().map(|seed| seed.ip).collect();
    let wire = read(
        &root.join(RMULE_PCAP),
        topology.rmule_ip,
        &seeds,
        &file_hash,
        topology.file_size,
    )?;
    let log_path = run_dir.join("rmule/stdout.log");
    let log =
        fs::read_to_string(&log_path).with_context(|| format!("read {}", log_path.display()))?;
    let events = parse_log(&log, DOWNLOAD_ID);

    let advertised = advertised(&wire);
    let first_status_at = first_status_at(&wire);
    let run = replay(
        &events,
        &Topology {
            size: topology.file_size,
            window_parts: topology.window_parts,
            advertised: &advertised,
            first_status_at: &first_status_at,
        },
    );
    let claims = claims(&topology, &wire, &advertised, &run);
    let (verdict, detail) = label(&claims);
    let trace = fs::read_to_string(run_dir.join("rmule/stderr.log")).unwrap_or_default();
    let (measurement, series) = measure(
        &run,
        &traced_verifies(&trace, DOWNLOAD_ID),
        topology.file_size,
    );
    let mut pace = pace::read(
        &root.join(RMULE_PCAP),
        topology.rmule_ip,
        &topology
            .seeds
            .iter()
            .map(|seed| (seed.role.clone(), seed.ip))
            .collect::<Vec<_>>(),
        &file_hash,
    )?;
    let caps: u64 = topology
        .seeds
        .iter()
        .map(|seed| u64::from(seed.max_upload_kib) * 1_024)
        .sum();
    pace.ideal_s = (caps > 0).then(|| topology.file_size as f64 / caps as f64);
    let tail_over_ideal = measurement
        .last_part_verified_s
        .zip(pace.ideal_s)
        .map(|(last, ideal)| last / ideal);
    let series_path = root.join("prefix-series.tsv");
    fs::write(&series_path, series).with_context(|| format!("write {}", series_path.display()))?;

    let role_of = |ip: Ipv4Addr| {
        topology
            .seeds
            .iter()
            .find(|seed| seed.ip == ip)
            .map_or_else(|| ip.to_string(), |seed| seed.role.clone())
    };
    let text = toml::to_string_pretty(&Verdict {
        flow: FLOW,
        verdict,
        detail,
        file_size: topology.file_size,
        part_count: part_count(topology.file_size),
        window_parts: topology.window_parts,
        max_connections: topology.max_connections,
        seeds: topology
            .seeds
            .iter()
            .map(|seed| {
                format!(
                    "{} {} {} KiB/s holding {}",
                    seed.role, seed.ip, seed.max_upload_kib, seed.holding
                )
            })
            .collect(),
        seeds_asked: wire
            .requests
            .iter()
            .map(|request| request.seed)
            .collect::<BTreeSet<_>>()
            .len(),
        statuses: wire
            .statuses
            .iter()
            .map(|status| {
                format!(
                    "{} at {:.3}: count {} {:?} advertising {}",
                    role_of(status.seed),
                    status.at,
                    status.count,
                    status.form,
                    list(&status.held)
                )
            })
            .collect(),
        first_requests: first_requests(&wire)
            .iter()
            .map(|(seed, parts)| format!("{} first asked for {}", role_of(*seed), list(parts)))
            .collect(),
        measurement,
        tail_over_ideal,
        seed_netem_delay_ms: topology.seed_netem_delay_ms,
        pace,
        claim: &claims,
    })
    .context("serialize the streaming-window verdict")?;
    let path = run_dir.join(format!("{FLOW}-verdict.toml"));
    fs::write(&path, &text).with_context(|| format!("write {}", path.display()))?;
    println!("peer_streaming_window verdict={verdict}");
    Ok(verdict)
}

/// Each seed's advertised parts: the union of the statuses it sent.
fn advertised(wire: &Wire) -> BTreeMap<Ipv4Addr, BTreeSet<u32>> {
    let mut advertised: BTreeMap<Ipv4Addr, BTreeSet<u32>> = BTreeMap::new();
    for status in &wire.statuses {
        advertised
            .entry(status.seed)
            .or_default()
            .extend(&status.held);
    }
    advertised
}

fn first_status_at(wire: &Wire) -> BTreeMap<Ipv4Addr, f64> {
    let mut first = BTreeMap::new();
    for status in &wire.statuses {
        first.entry(status.seed).or_insert(status.at);
    }
    first
}

fn first_requests(wire: &Wire) -> BTreeMap<Ipv4Addr, BTreeSet<u32>> {
    let mut first = BTreeMap::new();
    for request in &wire.requests {
        first
            .entry(request.seed)
            .or_insert_with(|| request.parts.clone());
    }
    first
}

fn claims(
    topology: &TopologyFile,
    wire: &Wire,
    advertised: &BTreeMap<Ipv4Addr, BTreeSet<u32>>,
    run: &Replay,
) -> Vec<Claim> {
    let parts = part_count(topology.file_size);
    let mut claims = vec![
        advertised_only(wire, advertised),
        first_ask(wire, run),
        window_ascends(run),
        rank_minimum(run),
    ];
    if topology.seeds.iter().any(|seed| seed.holding == "complete") {
        claims.push(status_form(
            "a-complete-seeds-count-0-status-decodes",
            wire,
            advertised,
            |form| form == StatusForm::Complete,
        ));
    }
    if topology.file_size.is_multiple_of(ED2K_PART_SIZE)
        && topology.seeds.iter().any(|seed| seed.holding != "complete")
    {
        claims.push(status_form(
            "an-exact-multiples-phantom-count-status-decodes",
            wire,
            advertised,
            |form| form == StatusForm::Counted { phantom: true },
        ));
    }
    claims.push(no_needed_parts_only_when_nothing_held(run));
    if topology.expect_complete {
        claims.push(Claim::about(
            "the-download-completed",
            run.completed,
            Evidence::Captured,
            format!(
                "download.completed {}; the last tick reads {}",
                if run.completed {
                    "logged"
                } else {
                    "never logged"
                },
                run.ticks.last().map_or("nothing", |(_, map)| map.as_str())
            ),
        ));
    } else {
        claims.push(retired_seed_waits(wire, run, parts));
    }
    claims
}

/// Claim 1, ADR-0112 §4: every request names only parts the seed's own status
/// advertised before it.
fn advertised_only(wire: &Wire, advertised: &BTreeMap<Ipv4Addr, BTreeSet<u32>>) -> Claim {
    let mut violations = Vec::new();
    for request in &wire.requests {
        let before: BTreeSet<u32> = wire
            .statuses
            .iter()
            .filter(|status| status.seed == request.seed && status.at <= request.at)
            .flat_map(|status| status.held.iter().copied())
            .collect();
        let outside: Vec<u32> = request.parts.difference(&before).copied().collect();
        if !outside.is_empty() {
            violations.push(format!(
                "{} at {:.3} asked for {outside:?}, advertised {}",
                request.seed,
                request.at,
                list(&before)
            ));
        }
    }
    let note = format!(
        "{} requests to {} seeds ({} advertised); {} named an unadvertised part{}{}",
        wire.requests.len(),
        wire.requests
            .iter()
            .map(|request| request.seed)
            .collect::<BTreeSet<_>>()
            .len(),
        advertised.len(),
        violations.len(),
        violations
            .first()
            .map_or_else(String::new, |first| format!(", first: {first}")),
        unread_note(wire)
    );
    Claim::about(
        "every-request-names-a-part-the-seed-advertised",
        !wire.requests.is_empty() && violations.is_empty() && wire.unread_links == 0,
        Evidence::Captured,
        note,
    )
}

/// Claim 2, ADR-0112 §4: each seed's first part is the rank's — very rare
/// when it holds one, else a band part — and the wire's first request agrees.
fn first_ask(wire: &Wire, run: &Replay) -> Claim {
    let first_on_wire = first_requests(wire);
    let firsts: Vec<_> = run
        .decisions
        .iter()
        .filter(|decision| decision.first_for_peer)
        .collect();
    let mut notes = Vec::new();
    let mut held = !firsts.is_empty();
    for decision in &firsts {
        let (Pick::Fresh(part) | Pick::Raced(part)) = decision.actual else {
            continue;
        };
        // A seed that never granted a slot was never asked on the wire.
        let agrees = first_on_wire
            .get(&decision.peer)
            .is_none_or(|parts| parts.contains(&part));
        held &= decision.matched() && agrees;
        notes.push(format!(
            "{} part {part} ({}{}{}){}",
            decision.peer,
            if decision.very_rare {
                "very rare"
            } else if decision.band {
                "band"
            } else {
                "neither very rare nor band"
            },
            if decision.matched() {
                ""
            } else {
                ", not the rank's"
            },
            if decision.ambiguous() {
                ", reading ambiguous"
            } else {
                ""
            },
            if agrees {
                ""
            } else {
                ", not the wire's first ask"
            }
        ));
    }
    Claim::about(
        "each-seed-is-first-asked-for-a-very-rare-part-else-a-band-part",
        held,
        Evidence::Captured,
        if notes.is_empty() {
            "no part was assigned".to_owned()
        } else {
            notes.join("; ")
        },
    )
}

/// Claim 3, ADR-0112 §4–5: every part handed out inside the window is the
/// rank's, so the window is taken in ascending order.
fn window_ascends(run: &Replay) -> Claim {
    let inside: Vec<_> = run
        .decisions
        .iter()
        .filter(|decision| decision.in_window && matches!(decision.actual, Pick::Fresh(_)))
        .collect();
    let missed: Vec<String> = inside
        .iter()
        .filter(|decision| !decision.matched())
        .map(|decision| describe(decision))
        .collect();
    Claim::about(
        "inside-the-window-requests-ascend",
        !inside.is_empty() && missed.is_empty(),
        Evidence::Captured,
        format!(
            "{} parts handed out inside the window, {} not the rank's{}",
            inside.len(),
            missed.len(),
            missed
                .first()
                .map_or_else(String::new, |first| format!(", first: {first}"))
        ),
    )
}

/// Every assignment against the whole rank, beside claims 2 and 3.
fn rank_minimum(run: &Replay) -> Claim {
    let missed: Vec<String> = run
        .decisions
        .iter()
        .filter(|decision| !decision.matched())
        .map(describe)
        .collect();
    let ambiguous = run
        .decisions
        .iter()
        .filter(|decision| decision.ambiguous())
        .count();
    Claim::about(
        "every-part-handed-out-is-the-rank-minimum",
        !run.decisions.is_empty() && missed.is_empty() && run.unjudged == 0,
        Evidence::Captured,
        format!(
            "{} assignments replayed, {} not the rank's, {ambiguous} on an ambiguous reading, {} to a peer with no status on the tap; {} of {} ticks disagree with the replayed part map{}",
            run.decisions.len(),
            missed.len(),
            run.unjudged,
            run.tick_mismatches,
            run.ticks.len(),
            missed
                .first()
                .map_or_else(String::new, |first| format!("; first: {first}"))
        ),
    )
}

/// Claim 4: a seed sent the form, and rmule took parts from it within what
/// that status advertised.
fn status_form(
    name: &str,
    wire: &Wire,
    advertised: &BTreeMap<Ipv4Addr, BTreeSet<u32>>,
    form: impl Fn(StatusForm) -> bool,
) -> Claim {
    let senders: BTreeSet<Ipv4Addr> = wire
        .statuses
        .iter()
        .filter(|status| form(status.form))
        .map(|status| status.seed)
        .collect();
    let mut notes = Vec::new();
    let mut held = !senders.is_empty();
    for seed in &senders {
        let asked: BTreeSet<u32> = wire
            .requests
            .iter()
            .filter(|request| request.seed == *seed)
            .flat_map(|request| request.parts.iter().copied())
            .collect();
        let within = advertised
            .get(seed)
            .is_some_and(|parts| asked.is_subset(parts));
        held &= !asked.is_empty() && within;
        notes.push(format!(
            "{seed} sent it; rmule asked it for {}",
            list(&asked)
        ));
    }
    Claim::about(
        name,
        held,
        Evidence::Captured,
        if notes.is_empty() {
            "no seed sent this form".to_owned()
        } else {
            notes.join("; ")
        },
    )
}

/// Claim 5, ADR-0112 §6: no `NoNeededParts` while the seed still advertised
/// a part the file lacked.
fn no_needed_parts_only_when_nothing_held(run: &Replay) -> Claim {
    let early: Vec<String> = run
        .retirements
        .iter()
        .filter(|retirement| !retirement.lacked.is_empty())
        .map(|retirement| {
            format!(
                "{} still held {}",
                retirement.peer,
                list(&retirement.lacked)
            )
        })
        .collect();
    Claim::absence(
        "no-needed-parts-only-once-a-seed-holds-nothing-we-lack",
        i64::try_from(early.len()).unwrap_or(i64::MAX),
        format!(
            "{} NoNeededParts retirements, {} while the seed held a part the file lacked{}",
            run.retirements.len(),
            early.len(),
            early
                .first()
                .map_or_else(String::new, |first| format!(": {first}"))
        ),
    )
}

/// Claim 5's wait, ADR-0112 §6: a seed retired `NoNeededParts` is not dialed
/// again before twice `FILEREASKTIME`.
fn retired_seed_waits(wire: &Wire, run: &Replay, parts: u32) -> Claim {
    let name = "a-retired-seed-is-not-dialed-again-inside-twice-filereasktime";
    let mut first_retired: BTreeMap<Ipv4Addr, (f64, f64)> = BTreeMap::new();
    for retirement in &run.retirements {
        let (Some(not_before), Some(not_after)) = (retirement.not_before, retirement.not_after)
        else {
            continue;
        };
        first_retired
            .entry(retirement.peer)
            .or_insert((not_before, not_after));
    }
    if first_retired.is_empty() {
        return Claim::about(
            name,
            false,
            Evidence::DocumentedAbsence,
            format!(
                "no seed was retired NoNeededParts between two ticks; the file has {parts} parts"
            ),
        );
    }
    let mut notes = Vec::new();
    let mut redials = 0_i64;
    let mut covered = true;
    for (seed, (not_before, not_after)) in &first_retired {
        let until = not_before + NO_NEEDED_PARTS_REASK_SECS - REASK_SLACK_SECS;
        covered &= wire.last_at >= until;
        let inside = wire
            .dials
            .iter()
            .filter(|dial| dial.seed == *seed && dial.at > *not_after && dial.at < until)
            .count();
        let full_ask = wire
            .dials
            .iter()
            .find(|dial| dial.seed == *seed && dial.at >= until)
            .map(|dial| dial.at - not_before);
        let pings = wire
            .datagrams
            .iter()
            .filter(|datagram| {
                datagram.seed == *seed && datagram.at > *not_after && datagram.at < until
            })
            .count();
        redials += i64::try_from(inside + pings).unwrap_or(i64::MAX);
        notes.push(format!(
            "{seed} retired between {not_before:.1} and {not_after:.1}: {inside} dials and {pings} UDP datagrams before +{until_s:.0} s; next dial {}, re-asked over TCP {}",
            full_ask.map_or_else(|| "none on the tap".to_owned(), |after| format!("+{after:.0} s")),
            run.reasked_over_tcp.contains(seed),
            until_s = NO_NEEDED_PARTS_REASK_SECS - REASK_SLACK_SECS,
        ));
    }
    if !covered {
        return Claim::blocked(
            name,
            format!(
                "the tap ends at {:.1}, short of twice FILEREASKTIME after a retirement: {}",
                wire.last_at,
                notes.join("; ")
            ),
        );
    }
    Claim::absence(name, redials, notes.join("; "))
}

fn describe(decision: &super::replay::Decision) -> String {
    format!(
        "{} handed {:?}, the rank names {:?}",
        decision.peer, decision.actual, decision.expected
    )
}

fn unread_note(wire: &Wire) -> String {
    if wire.unread_links == 0 {
        String::new()
    } else {
        format!(
            "; {} seed links opened obfuscated and were not read",
            wire.unread_links
        )
    }
}

fn list(parts: &BTreeSet<u32>) -> String {
    let parts: Vec<String> = parts.iter().map(u32::to_string).collect();
    format!("{{{}}}", parts.join(","))
}

#[cfg(test)]
mod tests;
