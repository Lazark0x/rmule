//! The records of the reachability levels: what each says when it moves, and
//! the one record a level with nothing to say writes.

use rmule_peer::natt::OwnMapping;
use rmule_primitives::ServerEndpoint;

use crate::address_learning::{EndpointVerdict, NatHint};
use crate::diagnostics::{AddressDiagnostics, BuddyState, KadFirewallVerdict, KadUdpVerdict};
use crate::port_mapping::MappingDiagnostics;
use crate::run_log::{Record, codes};

use super::KadVerdicts;

pub(super) fn server(connected: Option<&ServerEndpoint>) -> Record {
    let record = Record::new("reach.server");
    match connected {
        Some(server) => record.server_endpoint("server", server),
        None => record.code("server", "none"),
    }
}

pub(super) fn mappings(rows: &[MappingDiagnostics]) -> Vec<Record> {
    if rows.is_empty() {
        return vec![Record::new("reach.port_mapping").code("mapping", "none")];
    }
    rows.iter().map(mapping).collect()
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

pub(super) fn addresses(rows: &[AddressDiagnostics]) -> Vec<Record> {
    if rows.is_empty() {
        return vec![Record::new("reach.address").code("address", "none")];
    }
    rows.iter().map(address).collect()
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
    hint(record, row.hint.as_ref())
}

fn hint(record: Record, hint: Option<&NatHint>) -> Record {
    match hint {
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
            .code("reflected_tier", codes::tier(*tier)),
    }
}

pub(super) fn kad(verdicts: KadVerdicts, buddy: BuddyState) -> Record {
    let record = Record::new("reach.kad");
    let Some((firewall, udp)) = verdicts else {
        return record.code("kad", "none");
    };
    let record = record.code(
        "firewall",
        match firewall {
            KadFirewallVerdict::Open => "open",
            KadFirewallVerdict::Checking => "checking",
            KadFirewallVerdict::Firewalled => "firewalled",
        },
    );
    let record = match udp {
        KadUdpVerdict::Open { port } => record.code("udp", "open").port("udp_port", port),
        KadUdpVerdict::Firewalled => record.code("udp", "firewalled"),
        KadUdpVerdict::Unverified => record.code("udp", "unverified"),
    };
    // The own buddy's state, never its address: a firewalled node's inbound
    // path is whether a buddy link is held.
    record.code(
        "buddy",
        match buddy {
            BuddyState::None => "none",
            BuddyState::Walking => "walking",
            BuddyState::Recruited => "recruited",
            BuddyState::Held => "held",
        },
    )
}

pub(super) fn natt(mapping: Option<OwnMapping>) -> Record {
    let record = Record::new("reach.natt_own_mapping");
    match mapping {
        None => record.code("mapping", "none"),
        Some(OwnMapping::EndpointDependent) => record.code("mapping", "endpoint_dependent"),
        Some(OwnMapping::EndpointIndependent) => record.code("mapping", "endpoint_independent"),
        Some(OwnMapping::Unknown) => record.code("mapping", "unknown"),
    }
}
