//! The partial-share flow's verdict, scored from the run dir alone: the tap
//! on rmule's namespace ([`super::wire`]), rmule's own stamped trail
//! ([`super::marks`]), the topology the flow wrote and the files it staged.
//!
//! Each claim holds rmule to one section of ADR-0113 (and the completion
//! move to ADR-0115) and is `PASS`, `FAIL`, `OBSERVED` (a fact recorded with
//! no rule to break) or `NOT-RUN` (the run's knobs never drew the frames it
//! reads, said with the reason). The run passes when no claim fails.

mod answers;
mod known_source;
mod offers;
mod uploads;

use std::fmt;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result};
use rmule_primitives::ed2k_status_part_count;
use serde::{Deserialize, Serialize};

use super::marks::Trail;
use super::wire::{self, Hash, Wire};
use crate::flow::ed2k_server::search_wire::server_tap::{OfferedRow, granted_flags, offered_rows};

/// The flow's directory under the run dir.
pub(crate) const ROOT_DIR: &str = "partial-share";
/// The topology the flow writes under [`ROOT_DIR`].
pub(crate) const TOPOLOGY_FILE: &str = "topology.toml";
/// The tap on rmule's namespace, under [`ROOT_DIR`].
pub(crate) const RMULE_PCAP: &str = "rmule-tap.pcap";
/// The verdict, beside the run dir's other verdicts.
const VERDICT_FILE: &str = "partial-share-verdict.toml";

/// What the flow staged and did, as the verdict reads it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct TopologyFile {
    pub(crate) file_name: String,
    pub(crate) file_size: u64,
    pub(crate) file_hash: String,
    pub(crate) part_hashes: Vec<String>,
    /// The whole file rmule shares beside the download; `0` for none.
    pub(crate) whole_size: u64,
    pub(crate) whole_hash: Option<String>,
    pub(crate) rmule_ip: Ipv4Addr,
    pub(crate) rmule_container: String,
    pub(crate) tap_container: String,
    pub(crate) seeds: Vec<Body>,
    pub(crate) downloaders: Vec<Body>,
    pub(crate) stimuli: Vec<Stimulus>,
    pub(crate) actions: Vec<Action>,
    pub(crate) knobs: Knobs,
}

/// One stock aMule body of the run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Body {
    /// `seed-a`, `prober`, `downloader`, `queued`.
    pub(crate) role: String,
    pub(crate) ip: Ipv4Addr,
    pub(crate) container: String,
    /// The parts a seed holds, or a downloader's cap.
    pub(crate) detail: String,
}

/// One `rmule-tools peer transfer capture` run against rmule.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Stimulus {
    /// [`PRE_PART`], [`STRADDLE`] or [`DURING_CHECK`].
    pub(crate) purpose: String,
    pub(crate) container: String,
    pub(crate) ip: Ipv4Addr,
    /// Seconds since the epoch.
    pub(crate) started_at: f64,
    pub(crate) ended_at: f64,
    /// The ranges it asked for, in order.
    pub(crate) ranges: Vec<(u64, u64)>,
}

/// The stimulus asking before rmule holds a part.
pub(crate) const PRE_PART: &str = "pre-part";
/// The stimulus straddling a verified part's edge.
pub(crate) const STRADDLE: &str = "straddle";
/// The stimulus asking right after the restart, while the Offer Check may
/// still run.
pub(crate) const DURING_CHECK: &str = "during-check";

/// One harness step, stamped.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Action {
    pub(crate) at: f64,
    pub(crate) what: String,
}

/// The run's knobs, as the claims need them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Knobs {
    pub(crate) prober: bool,
    pub(crate) queued: bool,
    pub(crate) pause: bool,
    pub(crate) restart: bool,
    pub(crate) straddle: bool,
    /// Whether rmule's dials to the downloaders went through.
    #[serde(default)]
    pub(crate) dial_downloaders: bool,
    /// The server rmule logged in to: `lugdunum` or `ed2k-server`.
    #[serde(default)]
    pub(crate) rmule_server: String,
    pub(crate) downloader_image: String,
}

/// A claim's outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum Verdict {
    #[serde(rename = "PASS")]
    Pass,
    #[serde(rename = "FAIL")]
    Fail,
    #[serde(rename = "OBSERVED")]
    Observed,
    #[serde(rename = "NOT-RUN")]
    NotRun,
}

/// One claim, judged.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Claim {
    pub(crate) name: &'static str,
    pub(crate) verdict: Verdict,
    pub(crate) detail: String,
}

impl Claim {
    pub(crate) fn new(name: &'static str, verdict: Verdict, detail: impl Into<String>) -> Self {
        Self {
            name,
            verdict,
            detail: detail.into(),
        }
    }

    /// `PASS` when `failures` is empty, else `FAIL` naming them.
    pub(crate) fn judged(name: &'static str, failures: &[String], passed: String) -> Self {
        match failures {
            [] => Self::new(name, Verdict::Pass, passed),
            _ => Self::new(name, Verdict::Fail, failures.join("; ")),
        }
    }
}

#[derive(Serialize)]
struct VerdictFile<'a> {
    verdict: &'static str,
    file_hash: &'a str,
    unread_links: usize,
    claims: &'a [Claim],
}

/// Everything one run's claims read.
pub(crate) struct Run<'a> {
    pub(crate) topology: &'a TopologyFile,
    pub(crate) wire: &'a Wire,
    pub(crate) trail: &'a Trail,
    pub(crate) offers: &'a [(f64, Vec<OfferedRow>)],
    /// The server flags word of rmule's last `OP_IDCHANGE`.
    pub(crate) flags: Option<u32>,
    pub(crate) stream: &'a [u8],
    pub(crate) whole: Option<&'a [u8]>,
    pub(crate) stream_hash: Hash,
    pub(crate) whole_hash: Option<Hash>,
    pub(crate) part_hashes: Vec<Hash>,
    /// The status count rmule must write for the stream file.
    pub(crate) count: u16,
}

impl Run<'_> {
    /// Every stock aMule downloader's address.
    pub(crate) fn downloaders(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.topology.downloaders.iter().map(|body| body.ip)
    }

    /// The downloader playing `role`.
    pub(crate) fn downloader(&self, role: &str) -> Option<&Body> {
        self.topology
            .downloaders
            .iter()
            .find(|body| body.role == role)
    }

    /// The stimulus run for `purpose`.
    pub(crate) fn stimulus(&self, purpose: &str) -> Option<&Stimulus> {
        self.topology
            .stimuli
            .iter()
            .find(|stimulus| stimulus.purpose == purpose)
    }

    /// When rmule's first leg first printed a part verified.
    pub(crate) fn first_verified(&self) -> Option<f64> {
        self.trail.first_verified_at(1)
    }

    /// When the download completed, in either leg.
    pub(crate) fn completed_at(&self) -> Option<f64> {
        self.trail.first_at("download.completed")
    }

    /// When rmule's second leg began.
    pub(crate) fn reopened_at(&self) -> Option<f64> {
        self.trail.first_at(super::marks::REOPENED)
    }

    /// When the second leg offered the download again.
    pub(crate) fn reoffered_at(&self) -> Option<f64> {
        self.trail.first_at("download reoffered")
    }

    /// The leg a capture time falls in.
    pub(crate) fn leg_at(&self, at: f64) -> u8 {
        match self.reopened_at() {
            Some(reopened) if at >= reopened => 2,
            _ => 1,
        }
    }
}

/// Score the run dir `run_dir` and write its verdict file; the overall
/// verdict.
///
/// # Errors
/// If a file the score reads is missing or unreadable.
pub fn score_run_dir(run_dir: &Path) -> Result<String> {
    let root = run_dir.join(ROOT_DIR);
    let topology: TopologyFile = read_toml(&root.join(TOPOLOGY_FILE))?;
    let pcap = root.join(RMULE_PCAP);
    let mut peers: Vec<Ipv4Addr> = topology.downloaders.iter().map(|body| body.ip).collect();
    peers.extend(topology.stimuli.iter().map(|stimulus| stimulus.ip));
    let wire = wire::read(&pcap, topology.rmule_ip, &peers)?;
    let stdout_path = run_dir.join("rmule").join("stdout.log");
    let stdout = fs::read_to_string(&stdout_path)
        .with_context(|| format!("read {}", stdout_path.display()))?;
    let trail = Trail::new(&stdout);
    let offers = offered_rows(&pcap, topology.rmule_ip)?;
    let flags = granted_flags(&pcap, topology.rmule_ip)?;
    let stream_path = run_dir.join("synthetic").join(&topology.file_name);
    let stream =
        fs::read(&stream_path).with_context(|| format!("read {}", stream_path.display()))?;
    let whole = match &topology.whole_hash {
        Some(_) => {
            let path = root
                .join(super::legs::SHARE_DIR)
                .join(super::WHOLE_FILE_NAME);
            Some(fs::read(&path).with_context(|| format!("read {}", path.display()))?)
        }
        None => None,
    };
    let run = Run {
        topology: &topology,
        wire: &wire,
        trail: &trail,
        offers: &offers,
        flags,
        stream: &stream,
        whole: whole.as_deref(),
        stream_hash: hash_hex(&topology.file_hash)?,
        whole_hash: topology.whole_hash.as_deref().map(hash_hex).transpose()?,
        part_hashes: topology
            .part_hashes
            .iter()
            .map(|hex| hash_hex(hex))
            .collect::<Result<_>>()?,
        count: u16::try_from(ed2k_status_part_count(topology.file_size))
            .context("the stream file's part count")?,
    };
    let claims = claims(&run);
    let verdict = if claims.iter().any(|claim| claim.verdict == Verdict::Fail) {
        "FAIL"
    } else {
        "PASS"
    };
    let file = VerdictFile {
        verdict,
        file_hash: &topology.file_hash,
        unread_links: wire.unread_links,
        claims: &claims,
    };
    let path = run_dir.join(VERDICT_FILE);
    fs::write(
        &path,
        toml::to_string_pretty(&file).context("serialize the verdict")?,
    )
    .with_context(|| format!("write {}", path.display()))?;
    for claim in &claims {
        println!(
            "partial_share claim={} verdict={}",
            claim.name, claim.verdict
        );
    }
    Ok(verdict.to_owned())
}

/// Every claim, in ADR order.
pub(crate) fn claims(run: &Run<'_>) -> Vec<Claim> {
    vec![
        answers::pre_part_probe(run),
        answers::pre_part_slot_ask(run),
        answers::status_is_the_verified_range(run),
        answers::amule_keeps_rmule(run),
        answers::hash_set(run),
        uploads::verified_bytes_only(run),
        uploads::straddle(run),
        offers::sentinels(run),
        known_source::reask_ack(run),
        uploads::completion(run),
        known_source::source_exchange(run),
        uploads::pause(run),
        offers::restart(run),
        answers::complete_form(run),
    ]
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Observed => "OBSERVED",
            Self::NotRun => "NOT-RUN",
        })
    }
}

fn read_toml<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    toml::from_str(&fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?)
        .with_context(|| format!("parse {}", path.display()))
}

/// A 32-digit hex hash.
pub(crate) fn hash_hex(hex: &str) -> Result<Hash> {
    anyhow::ensure!(hex.len() == 32, "{hex} is not a 16-byte hash");
    let mut hash = [0u8; 16];
    for (index, byte) in hash.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .with_context(|| format!("{hex} is not hex"))?;
    }
    Ok(hash)
}

/// The address a source record's ID names, read either way round: a High
/// ID is the address's octets little-endian, the hybrid form big-endian.
pub(crate) fn id_addresses(id: u32) -> [Ipv4Addr; 2] {
    [
        Ipv4Addr::from(id.to_le_bytes()),
        Ipv4Addr::from(id.to_be_bytes()),
    ]
}

#[cfg(test)]
mod tests;
