//! Core's reachability facts are levels on the diagnostics snapshot, not
//! events, so the [`ReachTrail`] turns each *change* of one into records: a
//! run's log then says when a mapping was granted, which address was learned
//! and what verdict Kad reached, in order with the events around them. Every
//! field here is ours (an own address, a port, a verdict), so a level's records
//! are the same at both levels.

use rmule_core::diagnostics::{
    AddressDiagnostics, BuddyState, DiagnosticsSnapshot, KadFirewallVerdict, KadUdpVerdict,
};
use rmule_core::port_mapping::MappingDiagnostics;
use rmule_core::{EndpointVerdict, NatHint, OwnMapping};

use super::codes;
use super::record::Record;

/// The reachability levels as last written, so a data tick that moved none of
/// them writes nothing.
#[derive(Default)]
pub struct ReachTrail {
    last: [Option<Vec<Record>>; 5],
}

impl ReachTrail {
    /// The records of every reachability level `snapshot` holds that differs
    /// from the one last returned; a level with nothing to say is one record
    /// saying so.
    pub fn observe(&mut self, snapshot: &DiagnosticsSnapshot) -> Vec<Record> {
        let levels = [
            server(snapshot),
            mappings(snapshot),
            addresses(snapshot),
            kad(snapshot),
            natt(snapshot),
        ];
        let mut changed = Vec::new();
        for (last, records) in self.last.iter_mut().zip(levels) {
            if last.as_ref() != Some(&records) {
                changed.extend(records.iter().cloned());
                *last = Some(records);
            }
        }
        changed
    }
}

fn server(snapshot: &DiagnosticsSnapshot) -> Vec<Record> {
    let record = Record::new("reach.server");
    vec![match &snapshot.connected_server {
        Some(server) => record.server_endpoint("server", server),
        None => record.code("server", "none"),
    }]
}

fn mappings(snapshot: &DiagnosticsSnapshot) -> Vec<Record> {
    if snapshot.mappings.is_empty() {
        return vec![Record::new("reach.port_mapping").code("mapping", "none")];
    }
    snapshot.mappings.iter().map(mapping).collect()
}

fn mapping(row: &MappingDiagnostics) -> Record {
    let record = Record::new("reach.port_mapping")
        .code("role", codes::role(row.mapping.role))
        .code("family", codes::family(row.mapping.family))
        .port("internal_port", row.mapping.internal_port)
        .code("status", codes::mapping_status(row.status));
    let record = match row.mapping.pinhole {
        Some(pinhole) => record.own_address("pinhole", &pinhole),
        None => record,
    };
    let record = match row.method {
        Some(method) => record.code("method", codes::protocol(method)),
        None => record.code("method", "none"),
    };
    let record = match &row.external {
        Some(external) => record.own_address("external", external),
        None => record.code("external", "none"),
    };
    let record = match row.lease {
        Some(lease) => record.count("lease_secs", lease.as_secs()),
        None => record.code("lease_secs", "none"),
    };
    match &row.last_error {
        Some(error) => codes::mapping_error(record, error),
        None => record.code("error", "none"),
    }
}

fn addresses(snapshot: &DiagnosticsSnapshot) -> Vec<Record> {
    if snapshot.addresses.is_empty() {
        return vec![Record::new("reach.address").code("address", "none")];
    }
    snapshot.addresses.iter().map(address).collect()
}

fn address(row: &AddressDiagnostics) -> Record {
    let record = Record::new("reach.address")
        .code("family", codes::family(row.family))
        .code("role", codes::role(row.role));
    let record = match &row.verdict {
        EndpointVerdict::Known { endpoint, tier } => record
            .code("verdict", "known")
            .own_address("endpoint", endpoint)
            .code("tier", codes::tier(*tier)),
        EndpointVerdict::Stale { endpoint, .. } => record
            .code("verdict", "stale")
            .own_address("endpoint", endpoint),
        EndpointVerdict::Unknown => record.code("verdict", "unknown"),
    };
    match &row.hint {
        None => record.code("hint", "none"),
        Some(NatHint::Disagreement {
            adopted_tier,
            adopted,
            dissenting_tier,
            dissenting,
        }) => record
            .code("hint", "disagreement")
            .code("adopted_tier", codes::tier(*adopted_tier))
            .own_address("adopted", adopted)
            .code("dissenting_tier", codes::tier(*dissenting_tier))
            .own_address("dissenting", dissenting),
        Some(NatHint::DoubleNat { granted }) => record
            .code("hint", "double_nat")
            .own_address("granted", granted),
        Some(NatHint::CarrierGradeNat { granted }) => record
            .code("hint", "carrier_grade_nat")
            .own_address("granted", granted),
        Some(NatHint::Hairpin { reflected, tier }) => record
            .code("hint", "hairpin")
            .own_address("reflected", reflected)
            .code("tier", codes::tier(*tier)),
    }
}

fn kad(snapshot: &DiagnosticsSnapshot) -> Vec<Record> {
    let record = Record::new("reach.kad");
    vec![match &snapshot.kad {
        None => record.code("kad", "none"),
        Some(kad) => {
            let record = record.code(
                "firewall",
                match kad.firewall {
                    KadFirewallVerdict::Open => "open",
                    KadFirewallVerdict::Checking => "checking",
                    KadFirewallVerdict::Firewalled => "firewalled",
                },
            );
            let record = match kad.udp {
                KadUdpVerdict::Open { port } => record.code("udp", "open").port("udp_port", port),
                KadUdpVerdict::Firewalled => record.code("udp", "firewalled"),
                KadUdpVerdict::Unverified => record.code("udp", "unverified"),
            };
            // The own buddy's state, never its address: a firewalled node's
            // inbound path is whether a buddy link is held.
            record.code(
                "buddy",
                match snapshot.session.buddy_state {
                    BuddyState::None => "none",
                    BuddyState::Walking => "walking",
                    BuddyState::Recruited => "recruited",
                    BuddyState::Held => "held",
                },
            )
        }
    }]
}

fn natt(snapshot: &DiagnosticsSnapshot) -> Vec<Record> {
    let record = Record::new("reach.natt_own_mapping");
    vec![match snapshot.natt_own_mapping {
        None => record.code("mapping", "none"),
        Some(OwnMapping::EndpointDependent) => record.code("mapping", "endpoint_dependent"),
        Some(OwnMapping::EndpointIndependent) => record.code("mapping", "endpoint_independent"),
        Some(OwnMapping::Unknown) => record.code("mapping", "unknown"),
    }]
}
