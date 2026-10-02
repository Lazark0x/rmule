//! A row leaving the **Desired Mapping Set** (ADR-0086): a
//! re-bind on a different port, or a socket that stopped, releases its
//! granted mapping instead of waiting out its lease — the same `Release`
//! release-on-exit uses, sent before the replacement's `Map`. A `reprobe`
//! (the operator's recheck, the smart-LowID one-shot, the three-failure
//! escape) is a different case, kept as it was: it drops every held lease
//! without a release, because that mapping is not leaving the set, only
//! being re-raced.

use std::time::Duration;

use rmule_net::family::FamilyBinds;
use rmule_net::portmap::MappingProtocol;
use rmule_primitives::AddressFamily;

use crate::address_learning::SocketRole;
use crate::port_mapping::{
    DesiredMapping, MappingCommand, MappingStatus, PortMapper, PortMappingConfig,
};

use super::{
    TCP_PORT, UDP_PORT, answer_maps, bound_v4_store, drain, granted, mapped_over,
    mapper as fresh_mapper, probe_absent, probed, refused,
};

const HOUR: Duration = Duration::from_secs(3600);

#[test]
fn a_row_that_leaves_the_set_is_released_before_the_new_rows_map() {
    // The serve restart shape: the TCP listener stops and comes back on a
    // different port, so the old row leaves the Desired Mapping Set and a new
    // one enters it.
    let (mut mapper, store, t0) = mapped_over(MappingProtocol::Pcp, Some(HOUR));
    let old_tcp = DesiredMapping {
        role: SocketRole::Tcp,
        family: AddressFamily::V4,
        internal_port: TCP_PORT,
        pinhole: None,
    };
    let new_tcp_port = TCP_PORT + 1;
    let v4 = FamilyBinds {
        bound: vec![AddressFamily::V4],
        refused: Vec::new(),
    };
    store.record_bind(SocketRole::Tcp, &v4, new_tcp_port);

    let t1 = t0 + Duration::from_secs(1);
    mapper.start(t1);
    let first = drain(&mut mapper);
    assert_eq!(
        first.first(),
        Some(&MappingCommand::Release {
            protocol: MappingProtocol::Pcp,
            mapping: old_tcp,
            external_port: TCP_PORT,
        }),
        "the vacated port is released before anything else: {first:?}"
    );
    assert!(
        first
            .iter()
            .any(|command| matches!(command, MappingCommand::Probe { .. })),
        "the new port opens a fresh race: {first:?}"
    );

    probed(MappingProtocol::Pcp, &[AddressFamily::V4], t1, &mut mapper);
    let asked = answer_maps(&mut mapper, t1, |mapping| granted(mapping.internal_port));
    assert!(
        asked.iter().any(
            |mapping| mapping.role == SocketRole::Tcp && mapping.internal_port == new_tcp_port
        ),
        "the new row is asked for after the old one was released: {asked:?}"
    );
}

#[test]
fn a_re_derivation_of_an_unchanged_set_emits_nothing() {
    // Nothing bound differently, so nothing to release and no new race —
    // the runtime's periodic re-derivation must stay a no-op.
    let (mut mapper, _store, t0) = mapped_over(MappingProtocol::Pcp, Some(HOUR));
    mapper.start(t0 + Duration::from_secs(5));
    assert!(
        drain(&mut mapper).is_empty(),
        "an unchanged re-derivation queues nothing"
    );
}

#[test]
fn a_row_that_leaves_with_no_sibling_change_is_released_alone() {
    // desired {TCP, UDP} → {TCP}: only the departed UDP row is released, the
    // unaffected TCP row is not touched by a release it does not need.
    let (mut mapper, store, t0) = mapped_over(MappingProtocol::Pcp, Some(HOUR));
    let v4 = FamilyBinds {
        bound: vec![AddressFamily::V4],
        refused: Vec::new(),
    };
    // Port 0 is an unresolved bind, not a port: the role leaves the set.
    store.record_bind(SocketRole::Udp, &v4, 0);

    let t1 = t0 + Duration::from_secs(1);
    mapper.start(t1);
    let commands = drain(&mut mapper);
    let released: Vec<_> = commands
        .iter()
        .filter(|command| matches!(command, MappingCommand::Release { .. }))
        .collect();
    assert_eq!(
        released.len(),
        1,
        "only the departed row is released: {commands:?}"
    );
    assert_eq!(
        released[0],
        &MappingCommand::Release {
            protocol: MappingProtocol::Pcp,
            mapping: DesiredMapping {
                role: SocketRole::Udp,
                family: AddressFamily::V4,
                internal_port: UDP_PORT,
                pinhole: None,
            },
            external_port: UDP_PORT,
        }
    );
}

#[test]
fn a_row_that_leaves_with_no_granted_mapping_is_not_released() {
    // A Partial trial can install with one desired row ungranted (its own
    // answer refused while a sibling's succeeded) — that row never held a
    // lease, so its later departure has nothing to release.
    let t0 = std::time::Instant::now();
    let store = bound_v4_store();
    let mut mapper = PortMapper::new(
        PortMappingConfig {
            protocols: MappingProtocol::Pcp.mask_bit(),
            ..PortMappingConfig::default()
        },
        store.clone(),
        7,
    );
    mapper.start(t0);
    let _ = drain(&mut mapper);
    probed(MappingProtocol::Pcp, &[AddressFamily::V4], t0, &mut mapper);
    answer_maps(&mut mapper, t0, |mapping| {
        if mapping.role == SocketRole::Tcp {
            granted(mapping.internal_port)
        } else {
            refused(MappingProtocol::Pcp)
        }
    });
    assert_eq!(
        mapper
            .diagnostics()
            .iter()
            .find(|row| row.mapping.role == SocketRole::Udp)
            .map(|row| row.status),
        Some(MappingStatus::Failed),
        "the UDP row never held a lease"
    );

    let v4 = FamilyBinds {
        bound: vec![AddressFamily::V4],
        refused: Vec::new(),
    };
    store.record_bind(SocketRole::Udp, &v4, 0);
    mapper.start(t0 + Duration::from_secs(1));
    let commands = drain(&mut mapper);
    assert!(
        !commands
            .iter()
            .any(|command| matches!(command, MappingCommand::Release { .. })),
        "nothing was ever granted for the row that left: {commands:?}"
    );
}

/// `reprobe` is unchanged: a mapping it drops is not leaving the set, only
/// being re-raced, and its finite lease is the real cleanup — the reading
/// ADR-0086 keeps for exactly this path.
#[test]
fn a_reprobe_still_drops_its_leases_without_a_release() {
    let (mut mapper, _store, t0) = mapped_over(MappingProtocol::Pcp, Some(HOUR));
    mapper.reprobe(t0 + Duration::from_secs(1));
    let commands = drain(&mut mapper);
    assert!(
        !commands
            .iter()
            .any(|command| matches!(command, MappingCommand::Release { .. })),
        "a reprobe is not a departure: {commands:?}"
    );
    assert!(
        commands
            .iter()
            .any(|command| matches!(command, MappingCommand::Probe { .. })),
        "it still re-races: {commands:?}"
    );
}

#[test]
fn nothing_to_release_when_nothing_was_ever_mapped() {
    // The ordinary startup path: no prior lease exists, so `start` on a fresh
    // mapper never manufactures a spurious release.
    let t0 = std::time::Instant::now();
    let mut mapper = fresh_mapper(bound_v4_store());
    mapper.start(t0);
    assert!(
        !drain(&mut mapper)
            .iter()
            .any(|command| matches!(command, MappingCommand::Release { .. })),
        "a first start releases nothing"
    );
}

#[test]
fn a_re_race_won_by_another_protocol_releases_the_surviving_rows_old_lease() {
    // ADR-0093 keeps a surviving row's lease across a set change until the
    // race re-grants it; a race won by another protocol re-grants it there,
    // so the old protocol's mapping is handed back rather than overwritten.
    let t0 = std::time::Instant::now();
    let store = bound_v4_store();
    let mut mapper = fresh_mapper(store.clone());
    mapper.start(t0);
    let _ = drain(&mut mapper);
    probed(MappingProtocol::Pcp, &[AddressFamily::V4], t0, &mut mapper);
    probe_absent(MappingProtocol::NatPmp, t0, &mut mapper);
    probe_absent(MappingProtocol::Upnp, t0, &mut mapper);
    answer_maps(&mut mapper, t0, |mapping| granted(mapping.internal_port));
    let _ = drain(&mut mapper);

    // The TCP row moves; the UDP row survives, still leased over PCP.
    let v4 = FamilyBinds {
        bound: vec![AddressFamily::V4],
        refused: Vec::new(),
    };
    store.record_bind(SocketRole::Tcp, &v4, TCP_PORT + 1);
    let t1 = t0 + Duration::from_secs(1);
    mapper.start(t1);
    let _ = drain(&mut mapper);
    // PCP is gone from the gateway; NAT-PMP answers the full race and wins.
    probe_absent(MappingProtocol::Pcp, t1, &mut mapper);
    let _ = drain(&mut mapper);
    probed(
        MappingProtocol::NatPmp,
        &[AddressFamily::V4],
        t1,
        &mut mapper,
    );
    probe_absent(MappingProtocol::Upnp, t1, &mut mapper);
    probe_absent(MappingProtocol::Pcp, t1, &mut mapper);
    answer_maps(&mut mapper, t1, |mapping| granted(mapping.internal_port));

    let udp = DesiredMapping {
        role: SocketRole::Udp,
        family: AddressFamily::V4,
        internal_port: UDP_PORT,
        pinhole: None,
    };
    let released: Vec<_> = drain(&mut mapper)
        .into_iter()
        .filter(|command| matches!(command, MappingCommand::Release { .. }))
        .collect();
    assert_eq!(
        released,
        vec![MappingCommand::Release {
            protocol: MappingProtocol::Pcp,
            mapping: udp,
            external_port: UDP_PORT,
        }],
        "the survivor's PCP lease is handed back once NAT-PMP re-grants it"
    );
}

#[test]
fn a_surviving_lease_past_its_renewal_does_not_make_the_next_wake_a_past_instant() {
    // A set change re-races with the surviving row's lease kept (ADR-0093),
    // and renewals do not fire until the race concludes. The lease's renewal
    // instant, already past, used to be the wake: a runtime that sleeps until
    // then wakes at once, finds nothing to do, and spins.
    let (mut mapper, store, t0) = mapped_over(MappingProtocol::Pcp, Some(HOUR));
    let v4 = FamilyBinds {
        bound: vec![AddressFamily::V4],
        refused: Vec::new(),
    };
    store.record_bind(SocketRole::Tcp, &v4, TCP_PORT + 1);
    let late = t0 + HOUR;
    mapper.start(late);
    let _ = drain(&mut mapper);
    let wake = mapper.next_wake().expect("the probe round's deadline");
    assert!(wake > late, "the wake {wake:?} is already past at {late:?}");
}
