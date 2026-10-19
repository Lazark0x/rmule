//! The gateway's own record of what it granted — the evidence half of every
//! port-mapping flow.
//!
//! miniupnpd keeps two lease tables and one log, and all three are written by
//! the daemon rather than by the harness:
//!
//! - `upnp.leases` (`lease_file`) — one line per IPv4 redirect,
//!   `proto:eport:iaddr:iport:expiry:description`.
//! - `upnp6.leases` (`lease_file6`) — the IPv6 **pinhole** table. A PCP MAP over
//!   IPv6 opens a firewall hole rather than a redirect, so it never appears in
//!   the first file and a pinhole flow that read only that one would record a
//!   documented absence that was really a misread.
//! - the daemon's `-d` log — one line per SOAP action and per PCP request, which
//!   is where a **renewal** is visible as the gateway's own second
//!   `AddPortMapping` for a port it already holds.
//!
//! The tables are *polled* while the driver runs, because they are transient by
//! construction: the driver releases on exit, so a table read afterwards is
//! empty — which is itself the release assertion, and would be a false negative
//! for everything else.

use std::collections::BTreeMap;
use std::ffi::OsString;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::docker::Docker;

/// Where the gateway's tables live inside its container (the harness mounts the
/// leg directory there).
pub(crate) const PROOF_MOUNT: &str = "/proof";

/// One row of a miniupnpd lease table, as the daemon wrote it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct LeaseRow {
    /// `TCP` or `UDP`.
    pub(crate) protocol: String,
    /// The external port the gateway chose.
    pub(crate) external_port: u16,
    /// The internal address it forwards to.
    pub(crate) internal_address: String,
    /// The internal port.
    pub(crate) internal_port: u16,
    /// The description the client asked for (`rmule`, or `preclaim`).
    pub(crate) description: String,
    /// The line verbatim, so a verdict can quote the gateway rather than
    /// paraphrase it.
    pub(crate) line: String,
    /// How many times this row's expiry moved forward while the flow watched —
    /// the gateway's own count of renewals it granted.
    pub(crate) renewals: u32,
    /// Which family's table it came from.
    pub(crate) family: &'static str,
}

impl LeaseRow {
    /// The key a renewal is tracked against: one mapping is one
    /// `(family, protocol, external port, internal address)`.
    fn key(&self) -> (String, String, u16, String) {
        (
            self.family.to_owned(),
            self.protocol.clone(),
            self.external_port,
            self.internal_address.clone(),
        )
    }
}

/// Everything the gateway said about itself across one flow.
#[derive(Debug, Default, Serialize)]
pub(crate) struct GatewayRecord {
    /// Every lease row seen at any poll, with its renewal count.
    #[serde(rename = "lease")]
    pub(crate) leases: Vec<LeaseRow>,
    /// The IPv4 table exactly as it read at the fullest poll.
    pub(crate) table_v4: String,
    /// The IPv6 pinhole table at the fullest poll.
    pub(crate) table_v6: String,
    /// The IPv4 table after the driver exited — empty is the release proof.
    /// `None` when it could not be read, which is no proof either way.
    pub(crate) table_v4_after: Option<String>,
    /// The IPv6 table after the driver exited, `None` when unread.
    pub(crate) table_v6_after: Option<String>,
    /// `AddPortMapping` SOAP actions the daemon logged.
    pub(crate) add_port_mapping: u64,
    /// `AddAnyPortMapping` SOAP actions — the IGD2 fallback a conflict forces.
    pub(crate) add_any_port_mapping: u64,
    /// `DeletePortMapping` SOAP actions — the release pass.
    pub(crate) delete_port_mapping: u64,
    /// `PCP MAP: added mapping …` lines.
    pub(crate) pcp_added: u64,
    /// `… mapping removed` lines, PCP's and NAT-PMP's.
    pub(crate) pcp_removed: u64,
    /// `NAT-PMP port mapping request : …` lines with a lifetime: every
    /// NAT-PMP MAP and renewal, the zero-lifetime releases left out.
    pub(crate) natpmp_requests: u64,
    /// Lines naming a conflict the gateway refused.
    pub(crate) conflicts: u64,
    /// The daemon's own version banner, kept verbatim: it is what says this
    /// gateway was built `--ipv6 --igd2` with PCP at all.
    pub(crate) build: Vec<String>,
    /// How many times the tables were polled.
    pub(crate) polls: u64,
}

impl GatewayRecord {
    /// Whether the gateway itself holds a mapping forwarding `internal_port` to
    /// `internal_address` on the **same** external port.
    pub(crate) fn holds_exact(&self, internal_address: &str, internal_port: u16) -> bool {
        self.leases.iter().any(|lease| {
            lease.internal_address == internal_address
                && lease.internal_port == internal_port
                && lease.external_port == internal_port
        })
    }

    /// The external port the gateway granted for `internal_port` at
    /// `internal_address`, when it granted one.
    pub(crate) fn external_for(&self, internal_address: &str, internal_port: u16) -> Option<u16> {
        self.leases
            .iter()
            .find(|lease| {
                lease.internal_address == internal_address && lease.internal_port == internal_port
            })
            .map(|lease| lease.external_port)
    }

    /// The largest number of renewals the gateway recorded for any one row.
    pub(crate) fn max_renewals(&self) -> u32 {
        self.leases
            .iter()
            .map(|lease| lease.renewals)
            .max()
            .unwrap_or(0)
    }

    /// Whether both tables are empty after the driver exited — the
    /// `release_on_exit` assertion — or `None` when either could not be read.
    pub(crate) fn released(&self) -> Option<bool> {
        Some(empty(self.table_v4_after.as_deref()?) && empty(self.table_v6_after.as_deref()?))
    }

    /// The rows the IPv4 table still held after the driver exited, or `None`
    /// when it could not be read.
    pub(crate) fn rows_v4_after(&self) -> Option<Vec<LeaseRow>> {
        Some(
            self.table_v4_after
                .as_deref()?
                .lines()
                .filter_map(|line| parse_lease(line, "v4"))
                .collect(),
        )
    }
}

/// Polls the gateway's tables while a flow runs and folds them into one record.
#[derive(Debug, Default)]
pub(crate) struct GatewayWatch {
    seen: BTreeMap<(String, String, u16, String), LeaseRow>,
    best_v4: String,
    best_v6: String,
    polls: u64,
}

impl GatewayWatch {
    /// A watch with nothing seen yet.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Whether any poll so far saw `internal_address:internal_port` forwarded
    /// from the same external port.
    pub(crate) fn has_seen_exact(&self, internal_address: &str, internal_port: u16) -> bool {
        self.seen.values().any(|lease| {
            lease.internal_address == internal_address
                && lease.internal_port == internal_port
                && lease.external_port == internal_port
        })
    }

    /// Read both tables once and fold them in.
    ///
    /// # Errors
    /// Never on an absent table — a gateway that has granted nothing has no
    /// file, which is a legitimate reading. Only a runtime failure propagates.
    pub(crate) fn poll(&mut self, docker: &Docker, container: &str) -> Result<()> {
        self.polls += 1;
        // A poll that fails to read is only a poll that saw less; the
        // post-exit read in `finish` is the one that must not guess.
        let v4 = read_table(docker, container, "upnp.leases").unwrap_or_default();
        let v6 = read_table(docker, container, "upnp6.leases").unwrap_or_default();
        self.fold(&v4, "v4");
        self.fold(&v6, "v6");
        if v4.lines().count() > self.best_v4.lines().count() {
            self.best_v4 = v4;
        }
        if v6.lines().count() > self.best_v6.lines().count() {
            self.best_v6 = v6;
        }
        Ok(())
    }

    fn fold(&mut self, table: &str, family: &'static str) {
        for line in table.lines() {
            let Some(row) = parse_lease(line, family) else {
                continue;
            };
            let key = row.key();
            match self.seen.get_mut(&key) {
                // The expiry is the only field that moves, and it moves exactly
                // when the gateway granted the mapping again.
                Some(existing) if existing.line != row.line => {
                    existing.renewals += 1;
                    existing.line = row.line;
                }
                Some(_) => {}
                None => {
                    self.seen.insert(key, row);
                }
            }
        }
    }

    /// Finish: read the post-exit tables and scrape the daemon's log.
    ///
    /// # Errors
    /// If the daemon's log cannot be read — an unreadable counterparty log is a
    /// broken run, not an absence.
    pub(crate) fn finish(self, docker: &Docker, container: &str) -> Result<GatewayRecord> {
        let after_v4 = read_table(docker, container, "upnp.leases");
        let after_v6 = read_table(docker, container, "upnp6.leases");
        let logs = docker
            .logs(container)
            .to_command()
            .output()
            .with_context(|| format!("docker logs {container}"))?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&logs.stdout),
            String::from_utf8_lossy(&logs.stderr)
        );
        let count = |needle: &str| -> u64 {
            u64::try_from(text.matches(needle).count()).unwrap_or(u64::MAX)
        };
        Ok(GatewayRecord {
            leases: self.seen.into_values().collect(),
            table_v4: self.best_v4,
            table_v6: self.best_v6,
            table_v4_after: after_v4,
            table_v6_after: after_v6,
            add_port_mapping: count("#AddPortMapping"),
            add_any_port_mapping: count("#AddAnyPortMapping"),
            delete_port_mapping: count("#DeletePortMapping"),
            pcp_added: count("PCP MAP: added mapping"),
            pcp_removed: count("mapping removed"),
            natpmp_requests: count("NAT-PMP port mapping request")
                .saturating_sub(count(" lifetime=0s")),
            conflicts: count("ConflictInMappingEntry")
                + count("conflict")
                + count("already redirected"),
            build: text
                .lines()
                .filter(|line| line.starts_with("rmule-miniupnpd-version"))
                .map(ToOwned::to_owned)
                .collect(),
            polls: self.polls,
        })
    }
}

/// Whether a table read holds no row.
fn empty(table: &str) -> bool {
    table.trim().is_empty()
}

/// `docker exec <gw> cat /proof/<file>`: the table, empty for an absent file
/// (a gateway that holds no lease writes none), and `None` for any other
/// failure — a container that could not be read is not an emptied table.
fn read_table(docker: &Docker, container: &str, file: &str) -> Option<String> {
    let output = docker
        .exec(
            container.to_owned(),
            [
                OsString::from("cat"),
                OsString::from(format!("{PROOF_MOUNT}/{file}")),
            ],
        )
        .to_command()
        .output();
    let output = output.ok()?;
    if output.status.success() {
        return Some(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    String::from_utf8_lossy(&output.stderr)
        .contains("No such file or directory")
        .then(String::new)
}

/// One line of either lease table, in miniupnpd's own two formats.
///
/// The two are **not** the same shape, which is the whole reason this is a
/// function rather than a split:
///
/// - IPv4 (`lease_file`) is colon-separated with an external port:
///   `TCP:4662:10.77.0.4:4662:1789580273:rmule`.
/// - IPv6 (`lease_file6`) is **semicolon**-separated and carries **no** external
///   port, because a pinhole is not a translation — the hole is opened on the
///   port the client already holds:
///   `TCP;3fff:ed2:2::4;4662;;0;1;1789580738;PCP MAP c46a…`. A colon split would
///   also shred the address, which itself contains colons.
fn parse_lease(line: &str, family: &'static str) -> Option<LeaseRow> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    if line.contains(';') {
        return parse_pinhole(line, family);
    }
    let mut fields = line.splitn(6, ':');
    let protocol = fields.next()?.to_owned();
    let external_port = fields.next()?.parse().ok()?;
    let internal_address = fields.next()?.to_owned();
    let internal_port = fields.next()?.parse().ok()?;
    let _expiry = fields.next()?;
    let description = fields.next().unwrap_or_default().to_owned();
    Some(LeaseRow {
        protocol,
        external_port,
        internal_address,
        internal_port,
        description,
        line: line.to_owned(),
        renewals: 0,
        family,
    })
}

/// `proto;iaddr;iport;rem_host;rem_port;proto_no;expiry;description`.
fn parse_pinhole(line: &str, family: &'static str) -> Option<LeaseRow> {
    let fields: Vec<&str> = line.split(';').collect();
    let protocol = (*fields.first()?).to_owned();
    let internal_address = (*fields.get(1)?).to_owned();
    let internal_port: u16 = fields.get(2)?.parse().ok()?;
    let description = fields.get(7).copied().unwrap_or_default().to_owned();
    Some(LeaseRow {
        protocol,
        // A pinhole has no translated port; naming the held port here is what
        // lets one `holds_exact` read both tables.
        external_port: internal_port,
        internal_address,
        internal_port,
        description,
        line: line.to_owned(),
        renewals: 0,
        family,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The v6 table is semicolon-separated with the address in field two and no
    /// external port at all, so the v4 reader applied to it would name `3fff` as
    /// an address and fail to find a port.
    #[test]
    fn each_table_parses_in_its_own_format() {
        let v4 = parse_lease("TCP:4662:10.77.0.4:4662:1789580273:rmule", "v4").expect("v4 row");
        assert_eq!(v4.external_port, 4662);
        assert_eq!(v4.internal_address, "10.77.0.4");
        assert_eq!(v4.description, "rmule");

        let v6 = parse_lease(
            "TCP;3fff:ed2:2::4;4662;;0;1;1789580738;PCP MAP c46a8d2d7e337493722dcfea",
            "v6",
        )
        .expect("v6 row");
        assert_eq!(v6.internal_address, "3fff:ed2:2::4");
        assert_eq!(v6.internal_port, 4662);
        assert_eq!(v6.external_port, 4662, "a pinhole holds its own port");
        assert_eq!(v6.description, "PCP MAP c46a8d2d7e337493722dcfea");
    }

    /// A second reading of the same mapping with a later expiry is the
    /// gateway's own statement that it granted the mapping again.
    #[test]
    fn a_moved_expiry_counts_one_renewal() {
        let mut watch = GatewayWatch::new();
        watch.fold("UDP:4672:10.77.0.4:4672:100:rmule", "v4");
        watch.fold("UDP:4672:10.77.0.4:4672:100:rmule", "v4");
        watch.fold("UDP:4672:10.77.0.4:4672:112:rmule", "v4");
        let rows: Vec<_> = watch.seen.values().collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].renewals, 1);
    }
}
