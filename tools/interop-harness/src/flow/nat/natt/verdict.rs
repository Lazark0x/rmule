//! The verdict a NAT-traversal flow writes.
//!
//! It is the IPv6-dialect file plus the two things a transport row needs that a tag
//! row did not: the **Wire Rows** counted off the evidence tap — a NAT-T claim
//! is a statement about datagrams of a named frame type, and counting them
//! individually is what lets a verdict be written as precisely from a zero as
//! from a one — and a slot for the **NAT Type Proof** a gateway-bearing flow
//! attaches.
//!
//! The claim vocabulary is the shared one ([`crate::flow::nat::claims`]), so a
//! NAT-traversal `OBSERVED` means exactly what an IPv6-dialect one means.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::flow::nat::claims::{Body, Claim};
use crate::flow::taps::TapRow;

/// One named frame count taken off the evidence tap's own pcap.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct WireRow {
    /// The row's stable name, which a claim cites.
    pub(crate) name: String,
    /// The BPF expression that counted it, so the number can be re-taken from
    /// the retained pcap by hand.
    pub(crate) bpf: String,
    /// Packets matching — a measurement, and a zero here is a **Documented
    /// Absence** rather than a silent skip.
    pub(crate) packets: u64,
}

/// The flow's verdict file.
#[derive(Debug, Serialize)]
pub(crate) struct NattVerdict {
    #[serde(rename = "scenario")]
    pub(crate) flow: &'static str,
    /// `PASS`, `OBSERVED`, `SKIPPED` or `FAIL`.
    pub(crate) verdict: &'static str,
    /// What the label means for this run.
    pub(crate) detail: String,
    /// The standing note a reader needs to interpret the row at all — a
    /// correction this run measured against ADR-0092's own table, or the pin
    /// behind a **Documented Absence**.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) note: String,
    /// Whether the run raised a Tunnel, on the per-draw prediction row only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) tunnel_rose: Option<bool>,
    /// Present only on a skip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) skip_reason: Option<String>,
    /// The WAN the bodies stood on.
    pub(crate) wan_subnet_v4: String,
    /// The bodies stood up, with their pins.
    #[serde(rename = "body")]
    pub(crate) bodies: Vec<Body>,
    /// The **Per-Attachment Taps**.
    #[serde(rename = "tap")]
    pub(crate) taps: Vec<TapRow>,
    /// The **Wire Rows** counted off the evidence tap.
    #[serde(rename = "wire")]
    pub(crate) wire: Vec<WireRow>,
    /// The bench capabilities the doctor measured.
    #[serde(rename = "capability")]
    pub(crate) capabilities: Vec<crate::bench_doctor::Capability>,
    /// The per-claim results.
    pub(crate) claim: Vec<Claim>,
}

/// The count a named **Wire Row** reached, or `-1` when the row was never
/// taken — which only happens when no tap could attach, and is never read as a
/// zero.
pub(crate) fn packets(wire: &[WireRow], name: &str) -> i64 {
    wire.iter()
        .find(|row| row.name == name)
        .map_or(-1, |row| i64::try_from(row.packets).unwrap_or(i64::MAX))
}

/// Write the verdict into the run dir and print it.
///
/// # Errors
/// If it cannot be serialised or written.
pub(crate) fn write(run_root: &Path, verdict: &NattVerdict) -> Result<()> {
    let text = toml::to_string_pretty(verdict).context("serialize the NAT-T verdict")?;
    let path = run_root.join(format!("{}-verdict.toml", verdict.flow));
    println!("{text}");
    fs::write(&path, text).with_context(|| format!("write {}", path.display()))
}
