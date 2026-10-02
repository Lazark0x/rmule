//! rmule's own row, as `rmule-tools nat portmap` wrote it.
//!
//! Read back into types so a verdict can state *which* row was `Degraded` and
//! *which* address the store adopted rather than grepping a file. Everything
//! here is **Stimulus** (ADR-0045): it says what rmule believed, and it is
//! judged only against what the gateway itself recorded.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// The whole row.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct DriverRow {
    /// emule-qt's protocol mask the run raced (1 PCP, 2 NAT-PMP, 4 UPnP).
    pub(crate) protocols_mask: u8,
    /// The lifetime rmule asked the gateway for.
    pub(crate) lease_secs: u64,
    /// How long the driver watched.
    pub(crate) window_secs: u64,
    /// Whether the run was configured to withdraw its mappings on exit.
    pub(crate) release_on_exit: bool,
    /// Whether a Kad node ran inside the Core.
    pub(crate) kad_enabled: bool,
    /// How many **desired** mappings the set held when the row was written.
    pub(crate) desired_mappings: usize,
    /// Whether every row's granted external port equalled its internal one —
    /// the sentence that decides a High-ID (ADR-0086's grading rule).
    pub(crate) every_row_exact: bool,
    /// Renewals rmule counted across every row.
    pub(crate) total_renewals: u64,
    /// The Kad TCP firewall verdict as it last read.
    pub(crate) kad_firewall: String,
    /// Whether the verdict was ever seen in `checking` — the only externally
    /// visible sign that a recheck started.
    pub(crate) kad_recheck_observed: bool,
    /// When the verdict first read `open`, in seconds into the window, or
    /// `-1.0` — never. The *timing* is what ties the flip to the grant: a flip
    /// that predated the mapping would say nothing about it.
    pub(crate) kad_first_open_secs: f64,
    /// How many contacts the Kad routing table held when the row was written.
    pub(crate) kad_contacts: usize,
    /// One row per desired mapping.
    #[serde(default, rename = "mapping")]
    pub(crate) mappings: Vec<DriverMapping>,
    /// One row per learned address.
    #[serde(default, rename = "address")]
    pub(crate) addresses: Vec<DriverAddress>,
}

/// One **Port Mapping** row.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct DriverMapping {
    /// `tcp` or `udp` (ADR-0057: one UDP socket, one role).
    pub(crate) role: String,
    /// `v4` or `v6`.
    pub(crate) family: String,
    /// The port the socket bound.
    pub(crate) internal_port: u16,
    /// `not-mapped`, `probing`, `mapped`, `degraded` or `failed`.
    pub(crate) status: String,
    /// The protocol that granted it, or empty.
    pub(crate) method: String,
    /// The granted endpoint rendered, or empty.
    pub(crate) external: String,
    /// The granted external port, or `0`.
    pub(crate) external_port: u16,
    /// Whether the granted port equals the internal one.
    pub(crate) exact: bool,
    /// The clamped lifetime the gateway returned.
    pub(crate) lease_secs: u64,
    /// Renewals rmule counted on this row.
    pub(crate) renewals: u32,
    /// Whether the row ever read `mapped`.
    pub(crate) ever_mapped: bool,
    /// Whether the row ever read `degraded`.
    pub(crate) ever_degraded: bool,
    /// The last failure rendered, or empty.
    pub(crate) last_error: String,
    /// When the gateway first granted this row, in seconds into the window, or
    /// `-1.0` — never granted.
    pub(crate) first_granted_secs: f64,
}

/// One **Address Learning** row.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct DriverAddress {
    /// `v4` or `v6`.
    pub(crate) family: String,
    /// `tcp` or `udp` (ADR-0057: one UDP socket, one role).
    pub(crate) role: String,
    /// `known`, `stale` or `unknown`.
    pub(crate) verdict: String,
    /// The tier holding a fresh verdict, or empty.
    pub(crate) tier: String,
    /// The endpoint rendered, or empty.
    pub(crate) endpoint: String,
}

impl DriverRow {
    /// Read the row the driver container wrote into the run dir.
    ///
    /// # Errors
    /// If the file is absent or does not parse — either means the driver did not
    /// finish, which is a broken run rather than an absence to record.
    pub(crate) fn read(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read the driver row {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parse the driver row {}", path.display()))
    }

    /// The row for one `(role, family)`.
    pub(crate) fn mapping(&self, role: &str, family: &str) -> Option<&DriverMapping> {
        self.mappings
            .iter()
            .find(|mapping| mapping.role == role && mapping.family == family)
    }

    /// The learned address for one `(role, family)`.
    pub(crate) fn address(&self, role: &str, family: &str) -> Option<&DriverAddress> {
        self.addresses
            .iter()
            .find(|address| address.role == role && address.family == family)
    }

    /// Every row in `family`.
    pub(crate) fn family_rows(&self, family: &str) -> Vec<&DriverMapping> {
        self.mappings
            .iter()
            .filter(|mapping| mapping.family == family)
            .collect()
    }
}
