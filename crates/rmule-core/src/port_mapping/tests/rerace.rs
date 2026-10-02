//! The re-race (ADR-0086, "the mapper keeps looking for Exact"): a winner
//! short of Exact is not terminal and not remembered, the other protocols are
//! raced again while it keeps its leases, and only a strictly better standing
//! replaces it.

use std::time::Instant;

use rmule_net::portmap::{MappingError, MappingProtocol};
use rmule_primitives::AddressFamily;

use crate::address_learning::SocketRole;
use crate::port_mapping::mapper::rerace::RERACE_INTERVAL;
use crate::port_mapping::{DesiredMapping, GrantAnswer, MappingCommand, MappingStatus, PortMapper};

use super::{answer_maps, bound_v4_store, drain, granted, mapper, probe_absent, probed};

/// Every probe in `commands`, in order.
fn probes_in(commands: &[MappingCommand]) -> Vec<MappingProtocol> {
    commands
        .iter()
        .filter_map(|command| match command {
            MappingCommand::Probe { protocol } => Some(*protocol),
            _ => None,
        })
        .collect()
}

/// A grant that shifts the TCP port and keeps the UDP one: `Mismatched`, a
/// silent LowID.
fn shifted_tcp(mapping: DesiredMapping) -> Result<GrantAnswer, MappingError> {
    let shift = if mapping.role == SocketRole::Tcp {
        1000
    } else {
        0
    };
    granted(mapping.internal_port + shift)
}

/// A mapper whose only answering protocol, UPnP, won with a shifted TCP port.
fn mismatched_upnp_install(t0: Instant) -> PortMapper {
    let mut mapper = mapper(bound_v4_store());
    mapper.start(t0);
    let _ = drain(&mut mapper);
    probe_absent(MappingProtocol::Pcp, t0, &mut mapper);
    probe_absent(MappingProtocol::NatPmp, t0, &mut mapper);
    probed(MappingProtocol::Upnp, &[AddressFamily::V4], t0, &mut mapper);
    answer_maps(&mut mapper, t0, shifted_tcp);
    let _ = drain(&mut mapper);
    mapper
}

#[test]
fn a_mismatched_winner_is_re_raced_and_an_exact_challenger_replaces_it() {
    let t0 = Instant::now();
    let mut mapper = mismatched_upnp_install(t0);
    assert_eq!(
        mapper.learned_method(),
        None,
        "a Mismatched winner is not remembered to be probed alone"
    );

    let rerace = t0 + RERACE_INTERVAL;
    assert!(mapper.next_wake().is_some_and(|wake| wake <= rerace));
    mapper.tick(rerace);
    assert_eq!(
        probes_in(&drain(&mut mapper)),
        vec![MappingProtocol::Pcp, MappingProtocol::NatPmp],
        "the other protocols are asked again; the incumbent is not re-trialled"
    );

    // The router's PCP server has come up and grants the exact ports.
    probed(
        MappingProtocol::Pcp,
        &[AddressFamily::V4],
        rerace,
        &mut mapper,
    );
    probe_absent(MappingProtocol::NatPmp, rerace, &mut mapper);
    answer_maps(&mut mapper, rerace, |mapping| {
        granted(mapping.internal_port)
    });
    let concluded = drain(&mut mapper);
    let released: Vec<_> = concluded
        .iter()
        .filter_map(|command| match command {
            MappingCommand::Release { protocol, .. } => Some(*protocol),
            _ => None,
        })
        .collect();
    assert_eq!(released, vec![MappingProtocol::Upnp; 2]);
    assert!(concluded.contains(&MappingCommand::RecheckReachability));
    assert!(mapper.diagnostics().iter().all(|row| {
        row.method == Some(MappingProtocol::Pcp) && row.status == MappingStatus::Mapped
    }));
    assert_eq!(mapper.learned_method(), Some(MappingProtocol::Pcp));
}

#[test]
fn a_learned_method_that_grants_mismatched_lets_the_others_try_at_once() {
    // The persisted method opens a short round alone. A short round that
    // wins short of Exact asked nobody else, so the others are raced at once
    // rather than never.
    let t0 = Instant::now();
    let mut mapper = mapper(bound_v4_store()).with_learned_method(Some(MappingProtocol::Upnp));
    mapper.start(t0);
    assert_eq!(probes_in(&drain(&mut mapper)), vec![MappingProtocol::Upnp]);
    probed(MappingProtocol::Upnp, &[AddressFamily::V4], t0, &mut mapper);
    answer_maps(&mut mapper, t0, shifted_tcp);
    let _ = drain(&mut mapper);

    assert_eq!(mapper.next_wake(), Some(t0));
    mapper.tick(t0);
    assert_eq!(
        probes_in(&drain(&mut mapper)),
        vec![MappingProtocol::Pcp, MappingProtocol::NatPmp]
    );
}

#[test]
fn a_rerace_that_finds_nothing_better_keeps_the_incumbent_and_tries_again_later() {
    let t0 = Instant::now();
    let mut mapper = mismatched_upnp_install(t0);
    let rerace = t0 + RERACE_INTERVAL;
    mapper.tick(rerace);
    let _ = drain(&mut mapper);

    // NAT-PMP answers, and grants no better than the incumbent.
    probe_absent(MappingProtocol::Pcp, rerace, &mut mapper);
    probed(
        MappingProtocol::NatPmp,
        &[AddressFamily::V4],
        rerace,
        &mut mapper,
    );
    answer_maps(&mut mapper, rerace, shifted_tcp);
    let concluded = drain(&mut mapper);
    assert!(
        concluded.iter().all(|command| matches!(
            command,
            MappingCommand::Release {
                protocol: MappingProtocol::NatPmp,
                ..
            }
        )),
        "only the challenger's grants go back: {concluded:?}"
    );
    assert_eq!(concluded.len(), 2);
    assert!(
        mapper
            .diagnostics()
            .iter()
            .all(|row| row.method == Some(MappingProtocol::Upnp))
    );
    assert!(
        mapper
            .next_wake()
            .is_some_and(|wake| wake <= rerace + RERACE_INTERVAL),
        "the next re-race is scheduled"
    );
    // The incumbent's leases are still renewed on their own ladder.
    let renew = mapper
        .diagnostics()
        .iter()
        .filter_map(|row| row.next_renewal)
        .min()
        .expect("the incumbent holds its leases");
    mapper.tick(renew);
    assert!(drain(&mut mapper).iter().any(|command| matches!(
        command,
        MappingCommand::Map {
            protocol: MappingProtocol::Upnp,
            ..
        }
    )));
}
