//! The verdict an IPv6-dialect flow writes.
//!
//! The claim vocabulary it is written in — [`Claim`], [`Evidence`], [`label`]
//! and the [`DriverRow`] reader — is shared with every other NAT and IPv6 family
//! and lives in [`crate::flow::nat::claims`]; what is specific to the IPv6 dialect is the
//! file's shape: the dual-stack WAN it names, the bodies and their pins, and
//! the **Per-Attachment Taps**.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

pub(crate) use crate::flow::nat::claims::{Body, Claim, DriverRow, Evidence, label};
use crate::flow::taps::TapRow;

/// The flow's verdict file.
#[derive(Debug, Serialize)]
pub(crate) struct Ipv6Verdict {
    #[serde(rename = "scenario")]
    pub(crate) flow: &'static str,
    /// `PASS`, `OBSERVED`, `SKIPPED` or `FAIL`.
    pub(crate) verdict: &'static str,
    /// What the label means for this run.
    pub(crate) detail: String,
    /// The standing note a reader needs to interpret the row at all — the
    /// missing pin behind a **Documented Absence**, or a correction this run
    /// measured against ADR-0092's own table.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) note: String,
    /// Present only on a skip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) skip_reason: Option<String>,
    /// The WAN's IPv4 half.
    pub(crate) wan_subnet_v4: String,
    /// The WAN's **Fake-Public v6 Plan** `/64`.
    pub(crate) wan_subnet_v6: String,
    /// The bodies stood up, with their pins.
    #[serde(rename = "body")]
    pub(crate) bodies: Vec<Body>,
    /// The **Per-Attachment Taps**.
    #[serde(rename = "tap")]
    pub(crate) taps: Vec<TapRow>,
    /// The bench capabilities the doctor measured.
    #[serde(rename = "capability")]
    pub(crate) capabilities: Vec<crate::bench_doctor::Capability>,
    /// The per-claim results.
    pub(crate) claim: Vec<Claim>,
}

/// Write the verdict into the run dir and print it.
///
/// # Errors
/// If it cannot be serialised or written.
pub(crate) fn write(run_root: &Path, verdict: &Ipv6Verdict) -> Result<()> {
    let text = toml::to_string_pretty(verdict).context("serialize the IPv6 dialect verdict")?;
    let path = run_root.join(format!("{}-verdict.toml", verdict.flow));
    println!("{text}");
    fs::write(&path, text).with_context(|| format!("write {}", path.display()))
}
