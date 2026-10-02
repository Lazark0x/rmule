//! What the driver watched, and the TOML row it renders.
//!
//! Everything here is rmule's own state, so it is **Stimulus** (ADR-0045) and
//! judged nothing on its own. Its job is to be *foldable against* the gateway's
//! own table: one row per desired mapping, naming the external port rmule was
//! granted and the status it graded that grant, plus the **Address Learning**
//! verdict that decides whether the endpoint is ever advertised.
//!
//! Two facts are recorded as *edges* rather than levels, because a level
//! sampled at 500 ms would miss both:
//!
//! - **A renewal** is `next_renewal` moving forward on a granted row. The
//!   gateway's own second `AddPortMapping` (or PCP MAP) for the same port is
//!   the evidence; this is the rmule-side count to line it up against.
//! - **A Kad recheck** is the firewall verdict passing through `Checking`. A
//!   fresh node is not in a recheck and the self-paced cadence is hourly, so a
//!   `Checking` inside a minute-long window can only be the externally
//!   triggered one a fresh `Exact` grant fires (ADR-0086's amendment to
//!   ADR-0058).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::{Duration, Instant};

use rmule_core::diagnostics::{DiagnosticsSnapshot, KadFirewallVerdict};
use rmule_core::port_mapping::{DesiredMapping, MappingStatus};
use rmule_core::{ConfidenceTier, CoreEvent, EndpointVerdict, SocketRole};
use rmule_net::portmap::{Gateway, MappingProtocol};
use rmule_primitives::AddressFamily;

use super::NatPortMapArgs;

/// How many core events are kept verbatim in the row. Bounded because a Kad
/// node in a swarm emits thousands; the first handful is what says the session
/// started and the last handful what it was doing when the window closed.
const KEPT_EVENTS: usize = 40;

/// One desired mapping, as it read across the whole run.
#[derive(Debug)]
struct Row {
    status: MappingStatus,
    method: Option<MappingProtocol>,
    external: Option<String>,
    external_port: Option<u16>,
    lease_secs: Option<u64>,
    last_error: Option<String>,
    /// `next_renewal` as last seen, and how many times it moved forward.
    next_renewal: Option<Instant>,
    renewals: u32,
    ever_mapped: bool,
    ever_degraded: bool,
    first_granted_at: Option<Duration>,
}

/// One **Address Learning** row as it last read.
#[derive(Debug)]
struct AddressRow {
    verdict: &'static str,
    tier: Option<ConfidenceTier>,
    endpoint: Option<String>,
    hint: Option<String>,
}

/// The whole watch, foldable into one TOML row.
#[derive(Debug)]
pub(crate) struct Observations {
    protocols_mask: u8,
    lease_secs: u64,
    window_secs: u64,
    release_on_exit: bool,
    listen: String,
    kad_enabled: bool,
    udp_port: u16,
    gateways: Vec<String>,
    rows: BTreeMap<DesiredMapping, Row>,
    addresses: BTreeMap<(AddressFamily, SocketRole), AddressRow>,
    kad_firewall: Option<KadFirewallVerdict>,
    kad_checking_seen: bool,
    kad_first_open: Option<Duration>,
    kad_contacts: usize,
    kad_contact_responded: bool,
    samples: u64,
    last_at: Duration,
    events: Vec<String>,
    events_seen: u64,
}

impl Observations {
    /// A fresh watch over the run the arguments describe.
    pub(crate) fn new(args: &NatPortMapArgs, protocols_mask: u8, gateways: &[Gateway]) -> Self {
        Self {
            protocols_mask,
            lease_secs: args.lease_secs,
            window_secs: args.window_secs,
            release_on_exit: args.release_on_exit,
            listen: args.listen.to_string(),
            kad_enabled: args.kad,
            udp_port: args.udp_port,
            gateways: gateways
                .iter()
                .map(|gateway| {
                    format!(
                        "{} via {} (scope {:?})",
                        gateway.address, gateway.local_address, gateway.scope_id
                    )
                })
                .collect(),
            rows: BTreeMap::new(),
            addresses: BTreeMap::new(),
            kad_firewall: None,
            kad_checking_seen: false,
            kad_first_open: None,
            kad_contacts: 0,
            kad_contact_responded: false,
            samples: 0,
            last_at: Duration::ZERO,
            events: Vec::new(),
            events_seen: 0,
        }
    }

    /// Fold one diagnostics sample.
    pub(crate) fn observe(&mut self, snapshot: &DiagnosticsSnapshot, at: Duration) {
        self.samples += 1;
        self.last_at = at;
        for mapping in &snapshot.mappings {
            self.fold_mapping(mapping, at);
        }
        for address in &snapshot.addresses {
            self.addresses
                .insert((address.family, address.role), address_row(address));
        }
        let Some(kad) = snapshot.kad else {
            return;
        };
        self.kad_contacts = kad.contacts;
        self.kad_contact_responded = kad.contact_responded;
        if kad.firewall == KadFirewallVerdict::Checking {
            self.kad_checking_seen = true;
        }
        if kad.firewall == KadFirewallVerdict::Open && self.kad_first_open.is_none() {
            self.kad_first_open = Some(at);
        }
        if self.kad_firewall != Some(kad.firewall) {
            println!(
                "rmule-portmap-kad-firewall at={:.1}s verdict={} contacts={}",
                at.as_secs_f64(),
                firewall_token(kad.firewall),
                kad.contacts,
            );
        }
        self.kad_firewall = Some(kad.firewall);
    }

    /// Keep a bounded trail of core events; every one is also printed, so the
    /// container log holds the full stream and the row holds a readable slice.
    pub(crate) fn note_event(&mut self, event: &CoreEvent, at: Duration) {
        self.events_seen += 1;
        let line = format!("{:.1}s {event}", at.as_secs_f64());
        println!("rmule-portmap-event {line}");
        if self.events.len() < KEPT_EVENTS {
            self.events.push(line);
        }
    }

    fn fold_mapping(
        &mut self,
        diagnostics: &rmule_core::port_mapping::MappingDiagnostics,
        at: Duration,
    ) {
        let key = diagnostics.mapping;
        let external_port = diagnostics
            .external
            .map(rmule_primitives::PeerEndpoint::port);
        let entry = self.rows.entry(key).or_insert_with(|| Row {
            status: diagnostics.status,
            method: None,
            external: None,
            external_port: None,
            lease_secs: None,
            last_error: None,
            next_renewal: None,
            renewals: 0,
            ever_mapped: false,
            ever_degraded: false,
            first_granted_at: None,
        });
        if entry.status != diagnostics.status
            || (external_port.is_some() && entry.external_port != external_port)
        {
            println!(
                "rmule-portmap-row at={:.1}s mapping={key} status={} method={} external={}",
                at.as_secs_f64(),
                status_token(diagnostics.status),
                diagnostics
                    .method
                    .map_or("-", MappingProtocol::persisted_name),
                diagnostics
                    .external
                    .map_or_else(|| "-".to_owned(), |endpoint| endpoint.to_string()),
            );
        }
        entry.status = diagnostics.status;
        entry.method = diagnostics.method;
        entry.external = diagnostics.external.map(|endpoint| endpoint.to_string());
        entry.external_port = external_port;
        entry.lease_secs = diagnostics.lease.map(|lease| lease.as_secs());
        if let Some(error) = diagnostics.last_error.clone() {
            entry.last_error = Some(error.to_string());
        }
        match diagnostics.status {
            MappingStatus::Mapped => entry.ever_mapped = true,
            MappingStatus::Degraded => entry.ever_degraded = true,
            _ => {}
        }
        if diagnostics.external.is_some() && entry.first_granted_at.is_none() {
            entry.first_granted_at = Some(at);
        }
        if let Some(renewal) = diagnostics.next_renewal {
            match entry.next_renewal {
                Some(previous) if renewal > previous => {
                    entry.renewals += 1;
                    println!(
                        "rmule-portmap-renewal at={:.1}s mapping={key} renewal={}",
                        at.as_secs_f64(),
                        entry.renewals,
                    );
                }
                _ => {}
            }
            entry.next_renewal = Some(renewal);
        }
    }

    /// Render the row.
    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# rmule-tools nat portmap — rmule's own Port Mapping state (ADR-0086).\n");
        out.push_str("# Stimulus, never evidence (ADR-0045): the gateway's own table and log\n");
        out.push_str("# beside this file are what a port-mapping flow judges on.\n");
        let _ = writeln!(out, "protocols_mask = {}", self.protocols_mask);
        let _ = writeln!(out, "lease_secs = {}", self.lease_secs);
        let _ = writeln!(out, "window_secs = {}", self.window_secs);
        let _ = writeln!(out, "release_on_exit = {}", self.release_on_exit);
        let _ = writeln!(out, "listen = \"{}\"", escape(&self.listen));
        let _ = writeln!(out, "kad_enabled = {}", self.kad_enabled);
        let _ = writeln!(out, "udp_port = {}", self.udp_port);
        let _ = writeln!(out, "samples = {}", self.samples);
        let _ = writeln!(out, "events_seen = {}", self.events_seen);
        let _ = writeln!(out, "watched_secs = {:.1}", self.last_at.as_secs_f64());
        let _ = writeln!(
            out,
            "gateways = [{}]",
            self.gateways
                .iter()
                .map(|gateway| format!("\"{}\"", escape(gateway)))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let _ = writeln!(out, "desired_mappings = {}", self.rows.len());
        let _ = writeln!(
            out,
            "every_row_exact = {}",
            !self.rows.is_empty() && self.rows.iter().all(|(key, row)| row.is_exact(key))
        );
        let _ = writeln!(
            out,
            "total_renewals = {}",
            self.rows
                .values()
                .map(|row| u64::from(row.renewals))
                .sum::<u64>()
        );
        let _ = writeln!(
            out,
            "kad_firewall = \"{}\"",
            self.kad_firewall.map_or("unknown", firewall_token)
        );
        let _ = writeln!(out, "kad_recheck_observed = {}", self.kad_checking_seen);
        let _ = writeln!(
            out,
            "kad_first_open_secs = {}",
            self.kad_first_open.map_or_else(
                || "-1.0".to_owned(),
                |at| format!("{:.1}", at.as_secs_f64())
            )
        );
        let _ = writeln!(out, "kad_contacts = {}", self.kad_contacts);
        let _ = writeln!(
            out,
            "kad_contact_responded = {}",
            self.kad_contact_responded
        );

        for (key, row) in &self.rows {
            out.push_str("\n[[mapping]]\n");
            let _ = writeln!(out, "role = \"{}\"", role_token(key.role));
            let _ = writeln!(out, "family = \"{}\"", family_token(key.family));
            let _ = writeln!(out, "internal_port = {}", key.internal_port);
            let _ = writeln!(out, "status = \"{}\"", status_token(row.status));
            let _ = writeln!(
                out,
                "method = \"{}\"",
                row.method.map_or("", MappingProtocol::persisted_name)
            );
            let _ = writeln!(
                out,
                "external = \"{}\"",
                escape(row.external.as_deref().unwrap_or_default())
            );
            let _ = writeln!(
                out,
                "external_port = {}",
                row.external_port.map_or(0, u16::from)
            );
            let _ = writeln!(out, "exact = {}", row.is_exact(key));
            let _ = writeln!(out, "lease_secs = {}", row.lease_secs.unwrap_or(0));
            let _ = writeln!(out, "renewals = {}", row.renewals);
            let _ = writeln!(out, "ever_mapped = {}", row.ever_mapped);
            let _ = writeln!(out, "ever_degraded = {}", row.ever_degraded);
            let _ = writeln!(
                out,
                "first_granted_secs = {}",
                row.first_granted_at.map_or_else(
                    || "-1.0".to_owned(),
                    |at| format!("{:.1}", at.as_secs_f64())
                )
            );
            let _ = writeln!(
                out,
                "last_error = \"{}\"",
                escape(row.last_error.as_deref().unwrap_or_default())
            );
        }

        for ((family, role), address) in &self.addresses {
            out.push_str("\n[[address]]\n");
            let _ = writeln!(out, "family = \"{}\"", family_token(*family));
            let _ = writeln!(out, "role = \"{}\"", role_token(*role));
            let _ = writeln!(out, "verdict = \"{}\"", address.verdict);
            let _ = writeln!(out, "tier = \"{}\"", address.tier.map_or("", tier_token));
            let _ = writeln!(
                out,
                "endpoint = \"{}\"",
                escape(address.endpoint.as_deref().unwrap_or_default())
            );
            let _ = writeln!(
                out,
                "hint = \"{}\"",
                escape(address.hint.as_deref().unwrap_or_default())
            );
        }

        out.push_str("\nevent = [\n");
        for event in &self.events {
            let _ = writeln!(out, "  \"{}\",", escape(event));
        }
        out.push_str("]\n");
        out
    }
}

impl Row {
    /// Whether the granted external port is the internal one — the sentence
    /// that decides a High-ID (ADR-0086's grading rule).
    fn is_exact(&self, key: &DesiredMapping) -> bool {
        self.external_port == Some(key.internal_port)
    }
}

fn address_row(address: &rmule_core::diagnostics::AddressDiagnostics) -> AddressRow {
    let (verdict, endpoint) = match address.verdict {
        EndpointVerdict::Known { endpoint, .. } => ("known", Some(endpoint.to_string())),
        EndpointVerdict::Stale { endpoint, .. } => ("stale", Some(endpoint.to_string())),
        EndpointVerdict::Unknown => ("unknown", None),
    };
    AddressRow {
        verdict,
        tier: address.verdict.tier(),
        endpoint,
        hint: address.hint.map(|hint| format!("{hint:?}")),
    }
}

/// Stable row spellings. The harness parses these, so they are a read contract
/// and change only deliberately.
fn status_token(status: MappingStatus) -> &'static str {
    match status {
        MappingStatus::NotMapped => "not-mapped",
        MappingStatus::Probing => "probing",
        MappingStatus::Mapped => "mapped",
        MappingStatus::Degraded => "degraded",
        MappingStatus::Failed => "failed",
    }
}

fn role_token(role: SocketRole) -> &'static str {
    match role {
        SocketRole::Tcp => "tcp",
        SocketRole::Udp => "udp",
    }
}

fn family_token(family: AddressFamily) -> &'static str {
    match family {
        AddressFamily::V4 => "v4",
        AddressFamily::V6 => "v6",
    }
}

fn firewall_token(verdict: KadFirewallVerdict) -> &'static str {
    match verdict {
        KadFirewallVerdict::Open => "open",
        KadFirewallVerdict::Checking => "checking",
        KadFirewallVerdict::Firewalled => "firewalled",
    }
}

fn tier_token(tier: ConfidenceTier) -> &'static str {
    match tier {
        ConfidenceTier::Override => "override",
        ConfidenceTier::Server => "server",
        ConfidenceTier::KadCheck => "kad-check",
        ConfidenceTier::PeerVote => "peer-vote",
        ConfidenceTier::MappingGrant => "mapping-grant",
        ConfidenceTier::LowIdReport => "low-id-report",
        ConfidenceTier::Interface => "interface",
    }
}

/// TOML basic-string escaping for the two characters a rendered value can
/// carry: everything written here is an address, an opcode name or a rendered
/// error, so quote and backslash are the whole alphabet to worry about.
fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
