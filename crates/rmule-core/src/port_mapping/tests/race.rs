//! The race and the grade (ADR-0086): what is mapped, the two graces, late
//! adoption, the four grades, `Exact` ending the race, the losers' mappings
//! going back, and the learned method turning the next race into one probe.

use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

use rmule_net::family::FamilyBinds;
use rmule_net::portmap::{MappedTransport, MappingProtocol};
use rmule_primitives::AddressFamily;

use crate::address_learning::{
    AddressObservation, ObservationSource, SharedAddressLearning, SocketRole,
};
use crate::port_mapping::desired::DesiredMappingSet;
use crate::port_mapping::{
    MappingCommand, MappingGrade, MappingStatus, PortMapper, PortMappingConfig,
};

use super::{
    TCP_PORT, UDP_PORT, answer_maps, bound_v4_store, drain, external, granted, mapper,
    probe_absent, probed, refused, verdict_port,
};

/// Every probe the mapper queued, in order.
fn probes(mapper: &mut PortMapper) -> Vec<MappingProtocol> {
    drain(mapper)
        .into_iter()
        .filter_map(|command| match command {
            MappingCommand::Probe { protocol } => Some(protocol),
            _ => None,
        })
        .collect()
}

#[test]
fn the_desired_set_is_derived_from_what_bound_and_never_names_the_server_socket() {
    // The configured selection says what was *attempted*; the bind table says
    // what came up. And the server-UDP socket is not a Socket Role at all —
    // every datagram it receives answers one we sent, so our own outbound
    // packet already opens the binding.
    let store = bound_v4_store();
    let desired = DesiredMappingSet::derive(&store);
    let rows: Vec<_> = desired
        .mappings()
        .iter()
        .map(|mapping| (mapping.role, mapping.family, mapping.internal_port))
        .collect();
    assert_eq!(
        rows,
        vec![
            (SocketRole::Tcp, AddressFamily::V4, TCP_PORT),
            (SocketRole::Udp, AddressFamily::V4, UDP_PORT),
        ]
    );
    assert_eq!(
        desired.mappings()[0].transport(),
        MappedTransport::Tcp,
        "the listener is the only TCP mapping"
    );
    assert_eq!(desired.mappings()[1].transport(), MappedTransport::Udp);
}

#[test]
fn a_role_that_never_bound_and_an_unresolved_port_are_both_absent() {
    // A mapping for a socket that refused to bind would forward a port to
    // nothing; a mapping for port 0 asks a gateway for every port.
    let store = SharedAddressLearning::new();
    let v4 = FamilyBinds {
        bound: vec![AddressFamily::V4],
        refused: Vec::new(),
    };
    store.record_bind(SocketRole::Tcp, &v4, TCP_PORT);
    store.record_bind(SocketRole::Udp, &v4, 0);
    let desired = DesiredMappingSet::derive(&store);
    assert_eq!(desired.mappings().len(), 1);
    assert_eq!(desired.mappings()[0].role, SocketRole::Tcp);
}

#[test]
fn an_ipv6_pinhole_waits_for_a_known_ipv6() {
    // On IPv6 a PCP MAP is a pinhole to *our own* address, so asking for one
    // before the store holds a confident v6 would punch a hole at whichever
    // address the request happened to leave from.
    let store = SharedAddressLearning::new();
    let dual = FamilyBinds {
        bound: vec![AddressFamily::V4, AddressFamily::V6],
        refused: Vec::new(),
    };
    store.record_bind(SocketRole::Tcp, &dual, TCP_PORT);
    assert!(
        !DesiredMappingSet::derive(&store).wants(AddressFamily::V6),
        "no Known IPv6 yet"
    );

    let gua: Ipv6Addr = "2001:db8::5".parse().expect("literal");
    store.refresh_interfaces(&[IpAddr::V6(gua)]);
    store.observe(AddressObservation::Address {
        source: ObservationSource::Server,
        address: IpAddr::V6(gua),
    });
    assert!(DesiredMappingSet::derive(&store).wants(AddressFamily::V6));
}

#[test]
fn every_enabled_protocol_probes_at_once() {
    // Preference is a tie-break, not an order of attempts: probing serially
    // would make the slowest protocol the whole subsystem's latency.
    let mut mapper = mapper(bound_v4_store());
    mapper.start(Instant::now());
    assert_eq!(
        probes(&mut mapper),
        vec![
            MappingProtocol::Pcp,
            MappingProtocol::NatPmp,
            MappingProtocol::Upnp
        ]
    );
}

#[test]
fn the_round_closes_at_three_seconds_and_trials_whoever_answered() {
    let t0 = Instant::now();
    let mut mapper = mapper(bound_v4_store());
    mapper.start(t0);
    let _ = drain(&mut mapper);

    probed(
        MappingProtocol::Upnp,
        &[AddressFamily::V4],
        t0 + Duration::from_millis(500),
        &mut mapper,
    );
    assert!(
        drain(&mut mapper).is_empty(),
        "the grace is still open, so no trial has started"
    );
    mapper.tick(t0 + Duration::from_secs(3));
    let asked = answer_maps(&mut mapper, t0 + Duration::from_secs(3), |mapping| {
        granted(mapping.internal_port)
    });
    assert_eq!(asked.len(), 2, "the survivor is trialled with the full set");
}

#[test]
fn the_grace_extends_once_to_fifteen_seconds_while_a_backend_is_still_working() {
    // Measured: an SSDP search plus a description fetch per responder takes
    // about seven seconds on an ordinary LAN, so cutting at three means a
    // permanent LowID on a router that would have answered.
    let t0 = Instant::now();
    let mut mapper = mapper(bound_v4_store());
    mapper.start(t0);
    let _ = drain(&mut mapper);

    probe_absent(
        MappingProtocol::Pcp,
        t0 + Duration::from_millis(50),
        &mut mapper,
    );
    probe_absent(
        MappingProtocol::NatPmp,
        t0 + Duration::from_millis(60),
        &mut mapper,
    );
    mapper.tick(t0 + Duration::from_secs(3));
    assert!(
        drain(&mut mapper).is_empty(),
        "nothing available and UPnP still working: the round is extended, not closed"
    );

    probed(
        MappingProtocol::Upnp,
        &[AddressFamily::V4],
        t0 + Duration::from_secs(7),
        &mut mapper,
    );
    let asked = answer_maps(&mut mapper, t0 + Duration::from_secs(7), |mapping| {
        granted(mapping.internal_port)
    });
    assert_eq!(asked.len(), 2, "the slow responder was still trialled");
}

#[test]
fn the_grace_is_extended_only_once() {
    let t0 = Instant::now();
    let mut mapper = mapper(bound_v4_store());
    mapper.start(t0);
    let _ = drain(&mut mapper);
    probe_absent(MappingProtocol::Pcp, t0, &mut mapper);
    mapper.tick(t0 + Duration::from_secs(3));
    mapper.tick(t0 + Duration::from_secs(15));
    // Both remaining backends never answered and the round is over: the mapper
    // is in backoff, not waiting for a third grace.
    assert!(
        mapper
            .next_wake()
            .is_some_and(|wake| wake >= t0 + Duration::from_secs(45)),
        "the round closed into the backoff ladder"
    );
}

#[test]
fn a_probe_that_answers_after_an_empty_round_is_still_adopted() {
    // A round that ended with nothing has nothing to lose by a late arrival;
    // a round that already installed a set would gain a duplicate.
    let t0 = Instant::now();
    let mut mapper = mapper(bound_v4_store());
    mapper.start(t0);
    let _ = drain(&mut mapper);
    for protocol in MappingProtocol::ALL {
        probe_absent(protocol, t0 + Duration::from_millis(10), &mut mapper);
    }
    assert!(drain(&mut mapper).is_empty(), "the round ended empty");

    probed(
        MappingProtocol::Upnp,
        &[AddressFamily::V4],
        t0 + Duration::from_secs(20),
        &mut mapper,
    );
    let asked = answer_maps(&mut mapper, t0 + Duration::from_secs(20), |mapping| {
        granted(mapping.internal_port)
    });
    assert_eq!(asked.len(), 2, "the late probe was adopted");
}

#[test]
fn an_exact_trial_ends_the_race_before_the_next_candidate_is_asked() {
    // Nothing can beat Exact, so asking the next candidate would only leave a
    // duplicate mapping on the router.
    let t0 = Instant::now();
    let store = bound_v4_store();
    let mut mapper = mapper(store.clone());
    mapper.start(t0);
    let _ = drain(&mut mapper);
    for protocol in MappingProtocol::ALL {
        probed(protocol, &[AddressFamily::V4], t0, &mut mapper);
    }
    let asked = answer_maps(&mut mapper, t0, |mapping| granted(mapping.internal_port));
    assert_eq!(asked.len(), 2);

    let after = drain(&mut mapper);
    assert!(
        !after
            .iter()
            .any(|command| matches!(command, MappingCommand::Map { .. })),
        "no second candidate was trialled: {after:?}"
    );
    assert!(
        after.contains(&MappingCommand::RecheckReachability),
        "a fresh Exact grant rechecks reachability at once: {after:?}"
    );
    assert_eq!(mapper.learned_method(), Some(MappingProtocol::Pcp));
    assert_eq!(verdict_port(&store, SocketRole::Tcp), Some(TCP_PORT));
}

#[test]
fn a_mismatched_trial_keeps_racing_and_the_loser_mappings_go_back() {
    // "Granted" and "granted on the port we asked for" are different outcomes:
    // the hello has no external-port tag, so only the second is a High-ID. A
    // UPnP grant on the right port genuinely beats a PCP grant on the wrong one.
    let t0 = Instant::now();
    let store = bound_v4_store();
    let mut mapper = mapper(store.clone());
    mapper.start(t0);
    let _ = drain(&mut mapper);
    probed(MappingProtocol::Pcp, &[AddressFamily::V4], t0, &mut mapper);
    probed(MappingProtocol::Upnp, &[AddressFamily::V4], t0, &mut mapper);
    mapper.tick(t0 + Duration::from_secs(3));

    // PCP grants everything, all on shifted ports.
    answer_maps(&mut mapper, t0, |mapping| {
        granted(mapping.internal_port + 1000)
    });
    // UPnP is asked next and grants the exact ports.
    let released_before = drain(&mut mapper);
    assert!(
        released_before.iter().any(|command| matches!(
            command,
            MappingCommand::Map {
                protocol: MappingProtocol::Upnp,
                ..
            }
        )),
        "the race continued past the mismatch: {released_before:?}"
    );
    for command in released_before {
        if let MappingCommand::Map {
            protocol, mapping, ..
        } = command
        {
            mapper.on_result(
                crate::port_mapping::MappingResult::Mapped {
                    protocol,
                    mapping,
                    outcome: granted(mapping.internal_port),
                },
                t0,
            );
        }
    }
    let concluded = drain(&mut mapper);
    let released: Vec<_> = concluded
        .iter()
        .filter_map(|command| match command {
            MappingCommand::Release {
                protocol,
                external_port,
                ..
            } => Some((*protocol, *external_port)),
            _ => None,
        })
        .collect();
    assert_eq!(
        released.len(),
        2,
        "the losing PCP trial's mappings were handed back: {concluded:?}"
    );
    assert!(
        released
            .iter()
            .all(|(protocol, port)| *protocol == MappingProtocol::Pcp && *port >= 1000)
    );
    assert_eq!(mapper.learned_method(), Some(MappingProtocol::Upnp));
    assert_eq!(verdict_port(&store, SocketRole::Tcp), Some(TCP_PORT));
}

#[test]
fn a_partial_trial_loses_to_a_mismatched_one_and_a_none_trial_loses_to_both() {
    // The grade order is the whole ranking: Exact > Mismatched > Partial > None.
    assert!(MappingGrade::Exact > MappingGrade::Mismatched);
    assert!(MappingGrade::Mismatched > MappingGrade::Partial);
    assert!(MappingGrade::Partial > MappingGrade::None);

    let t0 = Instant::now();
    let store = bound_v4_store();
    let mut mapper = mapper(store.clone());
    mapper.start(t0);
    let _ = drain(&mut mapper);
    probed(MappingProtocol::Pcp, &[AddressFamily::V4], t0, &mut mapper);
    probed(
        MappingProtocol::NatPmp,
        &[AddressFamily::V4],
        t0,
        &mut mapper,
    );
    mapper.tick(t0 + Duration::from_secs(3));

    // PCP grants only the TCP listener — Partial.
    answer_maps(&mut mapper, t0, |mapping| {
        if mapping.role == SocketRole::Tcp {
            granted(mapping.internal_port)
        } else {
            refused(MappingProtocol::Pcp)
        }
    });
    // NAT-PMP grants everything but shifts the UDP port — Mismatched, which
    // outranks Partial even though PCP is the preferred protocol.
    answer_maps(&mut mapper, t0, |mapping| {
        if mapping.role == SocketRole::Udp {
            granted(mapping.internal_port + 7)
        } else {
            granted(mapping.internal_port)
        }
    });
    assert!(
        mapper
            .diagnostics()
            .iter()
            .all(|row| row.method == Some(MappingProtocol::NatPmp))
    );
    assert_eq!(
        mapper.learned_method(),
        None,
        "a winner short of Exact is not remembered to be probed alone"
    );
    assert_eq!(
        verdict_port(&store, SocketRole::Udp),
        Some(UDP_PORT + 7),
        "a mismatched UDP grant is a useful fact, not a failure"
    );
}

#[test]
fn a_learned_method_turns_the_next_race_into_one_probe_and_falls_back_when_it_is_gone() {
    let t0 = Instant::now();
    let mut mapper = mapper(bound_v4_store()).with_learned_method(Some(MappingProtocol::Upnp));
    mapper.start(t0);
    assert_eq!(
        probes(&mut mapper),
        vec![MappingProtocol::Upnp],
        "the learned method is tried alone"
    );

    probe_absent(MappingProtocol::Upnp, t0, &mut mapper);
    assert_eq!(
        probes(&mut mapper),
        MappingProtocol::ALL.to_vec(),
        "the short round is an optimisation, not a verdict: the full race runs now"
    );
}

#[test]
fn nothing_is_probed_while_nothing_bound() {
    let t0 = Instant::now();
    let mut unbound = mapper(SharedAddressLearning::new());
    unbound.start(t0);
    assert!(drain(&mut unbound).is_empty());
    assert_eq!(unbound.diagnostics(), Vec::new());
}

#[test]
fn a_masked_off_protocol_is_never_asked() {
    let t0 = Instant::now();
    let mut mapper = PortMapper::new(
        PortMappingConfig {
            protocols: MappingProtocol::Upnp.mask_bit(),
            ..PortMappingConfig::default()
        },
        bound_v4_store(),
        1,
    );
    mapper.start(t0);
    assert_eq!(probes(&mut mapper), vec![MappingProtocol::Upnp]);
}

#[test]
fn every_desired_mapping_has_a_diagnostics_row_even_when_it_is_not_mapped() {
    // "The TCP listener is not mapped" is the fact an operator most needs, and
    // a table that lists only successes cannot state it.
    let t0 = Instant::now();
    let mut mapper = mapper(bound_v4_store());
    mapper.start(t0);
    let rows = mapper.diagnostics();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| row.status == MappingStatus::Probing));
    assert!(rows.iter().all(|row| row.external.is_none()));

    let _ = drain(&mut mapper);
    probed(MappingProtocol::Pcp, &[AddressFamily::V4], t0, &mut mapper);
    mapper.tick(t0 + Duration::from_secs(3));
    answer_maps(&mut mapper, t0, |mapping| granted(mapping.internal_port));
    let rows = mapper.diagnostics();
    assert!(rows.iter().all(|row| row.status == MappingStatus::Mapped));
    assert!(
        rows.iter()
            .all(|row| row.method == Some(MappingProtocol::Pcp)),
    );
    assert_eq!(rows[0].external, Some(external(TCP_PORT)));
}

#[test]
fn a_learned_method_that_stops_granting_is_forgotten_so_the_others_get_a_turn() {
    // The trap the short round sets: a method that still *probes* fine but
    // grants nothing would be tried alone on every retry, and the other two
    // protocols would never be reached again.
    let t0 = Instant::now();
    let mut mapper = mapper(bound_v4_store()).with_learned_method(Some(MappingProtocol::Upnp));
    mapper.start(t0);
    assert_eq!(probes(&mut mapper), vec![MappingProtocol::Upnp]);
    probed(MappingProtocol::Upnp, &[AddressFamily::V4], t0, &mut mapper);
    answer_maps(&mut mapper, t0, |_| refused(MappingProtocol::Upnp));
    assert_eq!(
        mapper.learned_method(),
        None,
        "a race that granted nothing forgets"
    );

    let retry = t0 + Duration::from_secs(30);
    mapper.tick(retry);
    assert_eq!(
        probes(&mut mapper),
        MappingProtocol::ALL.to_vec(),
        "the retry is a full race"
    );
}
