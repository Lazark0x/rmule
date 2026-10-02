//! Leases, renewal, epoch resets and failure (ADR-0086): the RFC ladders, the
//! clamps, the 100 ms-spaced re-add after a gateway reboot, the three-failure
//! escape, the backoff, the smart-LowID one-shot, release-on-exit, and the two
//! ways a grant reads `Degraded`.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use rmule_net::portmap::{MappingError, MappingProtocol};
use rmule_primitives::{AddressFamily, Ipv4Endpoint, PeerEndpoint};

use crate::address_learning::{NatHint, SocketRole};
use crate::port_mapping::renewal::{BACKOFF_CEILING, MAX_LEASE, MIN_ASKED_LEASE};
use crate::port_mapping::{
    GrantAnswer, MappingCommand, MappingResult, MappingStatus, PortMapper, PortMappingConfig,
};

use super::{
    TCP_PORT, UDP_PORT, answer_maps, bound_v4_store, drain, granted, mapped_over, mapper, probed,
    refused, verdict_port,
};

const HOUR: Duration = Duration::from_secs(3600);

#[test]
fn a_pcp_renewal_fires_inside_the_first_rfc_6887_window_and_not_before() {
    // §11.2.1's first window of a 3600 s lease is [1800, 2250) seconds from the
    // grant. Nothing may fire before it, and something must fire inside it.
    let (mut mapper, _store, t0) = mapped_over(MappingProtocol::Pcp, Some(HOUR));
    mapper.tick(t0 + Duration::from_secs(1_799));
    assert!(drain(&mut mapper).is_empty(), "too early to renew");

    mapper.tick(t0 + Duration::from_secs(2_250));
    let renewals: Vec<_> = drain(&mut mapper)
        .into_iter()
        .filter_map(|command| match command {
            MappingCommand::Map {
                mapping,
                suggested_external_port,
                ..
            } => Some((mapping.role, suggested_external_port)),
            _ => None,
        })
        .collect();
    assert_eq!(renewals.len(), 2, "every mapping renews");
    assert!(
        renewals
            .iter()
            .any(|(role, port)| *role == SocketRole::Tcp && *port == TCP_PORT),
        "a renewal suggests the port already granted, not a fresh one"
    );
}

#[test]
fn an_unanswered_renewal_climbs_the_ladder_instead_of_re_firing_every_tick() {
    // The §11.2.1 rungs are a retry schedule inside one lease: re-firing on the
    // next tick would turn a silent gateway into a renewal flood.
    let (mut mapper, _store, t0) = mapped_over(MappingProtocol::Pcp, Some(HOUR));
    mapper.tick(t0 + Duration::from_secs(2_250));
    assert_eq!(drain(&mut mapper).len(), 2);

    mapper.tick(t0 + Duration::from_secs(2_251));
    assert!(
        drain(&mut mapper).is_empty(),
        "the next attempt waits for rung two"
    );
    mapper.tick(t0 + Duration::from_secs(2_925));
    assert_eq!(drain(&mut mapper).len(), 2, "rung two fired");
}

#[test]
fn a_permanent_lease_is_polled_every_thirty_minutes() {
    // IGD1's lease of 0 has no expiry to take a fraction of, and the router can
    // still have forgotten it.
    let (mut mapper, _store, t0) = mapped_over(MappingProtocol::Upnp, None);
    mapper.tick(t0 + Duration::from_secs(1_799));
    assert!(drain(&mut mapper).is_empty());
    mapper.tick(t0 + Duration::from_secs(1_800));
    assert_eq!(drain(&mut mapper).len(), 2, "the verification poll fired");
    // And it paces from the attempt rather than the grant, so it does not
    // re-fire on every later tick.
    mapper.tick(t0 + Duration::from_secs(1_801));
    assert!(drain(&mut mapper).is_empty());
}

#[test]
fn an_absurd_granted_lifetime_is_clamped_to_twenty_four_hours() {
    // A gateway claiming 0xFFFFFFFF seconds would otherwise be believed and the
    // mapping never renewed — the spoofed-lifetime control, not tidiness.
    let (mapper, _store, _t0) = mapped_over(
        MappingProtocol::Pcp,
        Some(Duration::from_secs(u64::from(u32::MAX))),
    );
    assert_eq!(mapper.diagnostics()[0].lease, Some(MAX_LEASE));
}

#[test]
fn three_consecutive_renewal_failures_force_a_full_reprobe() {
    // One lost datagram is normal; three in a row means the gateway changed its
    // mind, or changed.
    let (mut mapper, _store, t0) = mapped_over(MappingProtocol::Pcp, Some(HOUR));
    let mut at = t0 + Duration::from_secs(2_250);
    for round in 1..=3 {
        mapper.tick(at);
        let failed = answer_maps(&mut mapper, at, |_| refused(MappingProtocol::Pcp));
        assert_eq!(failed.len(), 2, "round {round}");
        at += HOUR;
    }
    let after = drain(&mut mapper);
    assert!(
        after
            .iter()
            .any(|command| matches!(command, MappingCommand::Probe { .. })),
        "the third failure re-raced: {after:?}"
    );
    assert!(
        !after
            .iter()
            .any(|command| matches!(command, MappingCommand::Release { .. })),
        "a gateway that stopped answering renewals is not sent a release"
    );
}

#[test]
fn a_gateway_epoch_reset_re_adds_every_mapping_a_hundred_milliseconds_apart() {
    // A rebooted router forgot every mapping while the leases it granted are
    // still nominally alive — nothing but the epoch says so. And a router that
    // just rebooted is the worst moment to send it a burst.
    let (mut mapper, _store, t0) = mapped_over(MappingProtocol::Pcp, Some(HOUR));
    let at = t0 + Duration::from_secs(2_250);
    mapper.tick(at);
    let commands = drain(&mut mapper);
    let first = commands
        .iter()
        .find_map(|command| match command {
            MappingCommand::Map { mapping, .. } => Some(*mapping),
            _ => None,
        })
        .expect("a renewal fired");
    mapper.on_result(
        MappingResult::Mapped {
            protocol: MappingProtocol::Pcp,
            mapping: first,
            outcome: Ok(GrantAnswer {
                external: super::external(first.internal_port),
                lease: Some(HOUR),
                epoch_reset: true,
            }),
        },
        at,
    );

    let mut emitted = 0;
    let mut when = at;
    for step in 0..2 {
        mapper.tick(when);
        let maps: Vec<_> = drain(&mut mapper)
            .into_iter()
            .filter(|command| matches!(command, MappingCommand::Map { .. }))
            .collect();
        assert_eq!(maps.len(), 1, "one re-add per step, step {step}");
        emitted += maps.len();
        // Nothing more until the spacing elapses.
        mapper.tick(when + Duration::from_millis(50));
        assert!(
            drain(&mut mapper).is_empty(),
            "the spacing holds, step {step}"
        );
        when += Duration::from_millis(100);
    }
    assert_eq!(emitted, 2, "the whole set was re-added");
}

#[test]
fn a_completed_epoch_re_add_rechecks_reachability_and_a_renewal_never_does() {
    // Renewals must not trigger one: a helper lookup every ~30 minutes per
    // mapping would pollute the flood limiter's view of us.
    let (mut mapper, _store, t0) = mapped_over(MappingProtocol::Pcp, Some(HOUR));
    let at = t0 + Duration::from_secs(2_250);
    mapper.tick(at);
    let plain = answer_maps(&mut mapper, at, |mapping| granted(mapping.internal_port));
    assert_eq!(plain.len(), 2);
    assert!(
        !drain(&mut mapper).contains(&MappingCommand::RecheckReachability),
        "an ordinary renewal rechecks nothing"
    );

    // Now the same renewal round, but the gateway reports it rebooted.
    let reset_at = at + HOUR;
    mapper.tick(reset_at);
    answer_maps(&mut mapper, reset_at, |mapping| {
        Ok(GrantAnswer {
            external: super::external(mapping.internal_port),
            lease: Some(HOUR),
            epoch_reset: true,
        })
    });
    let mut when = reset_at;
    let mut rechecked = false;
    for _ in 0..4 {
        mapper.tick(when);
        for command in drain(&mut mapper) {
            match command {
                MappingCommand::Map {
                    protocol, mapping, ..
                } => mapper.on_result(
                    MappingResult::Mapped {
                        protocol,
                        mapping,
                        outcome: granted(mapping.internal_port),
                    },
                    when,
                ),
                MappingCommand::RecheckReachability => rechecked = true,
                _ => {}
            }
        }
        rechecked |= drain(&mut mapper).contains(&MappingCommand::RecheckReachability);
        when += Duration::from_millis(100);
    }
    assert!(rechecked, "the re-added set rechecks reachability");
}

#[test]
fn a_mismatched_tcp_grant_is_degraded_and_never_reaches_an_advert() {
    // The eD2k hello carries one port and has no external-port tag, so
    // advertising the internal port would be a lie and the external one is
    // impossible. The UDP roles are the opposite case.
    let t0 = Instant::now();
    let store = bound_v4_store();
    let mut mapper = mapper(store.clone());
    mapper.start(t0);
    let _ = drain(&mut mapper);
    for protocol in MappingProtocol::ALL {
        probed(protocol, &[AddressFamily::V4], t0, &mut mapper);
    }
    // Every candidate shifts every port by the same amount, so all three grade
    // `Mismatched` and the first wins on preference.
    for _ in 0..3 {
        answer_maps(&mut mapper, t0, |mapping| {
            granted(mapping.internal_port + 11)
        });
    }
    let rows = mapper.diagnostics();
    let tcp = rows
        .iter()
        .find(|row| row.mapping.role == SocketRole::Tcp)
        .expect("a TCP row");
    assert_eq!(tcp.status, MappingStatus::Degraded);
    assert_eq!(
        verdict_port(&store, SocketRole::Tcp),
        Some(TCP_PORT),
        "the advert still reads the bound port, never the gateway's"
    );
    let udp = rows
        .iter()
        .find(|row| row.mapping.role == SocketRole::Udp)
        .expect("a UDP row");
    assert_eq!(udp.status, MappingStatus::Mapped);
    assert_eq!(
        verdict_port(&store, SocketRole::Udp),
        Some(UDP_PORT + 11),
        "a mismatched UDP grant is the fact Kad's extern-port rule learns"
    );
}

#[test]
fn a_carrier_grade_external_address_is_degraded_by_the_store_not_by_a_second_copy_of_the_rule() {
    // 100.64/10 means the ISP holds the public address and no mapping on this
    // router reaches past it. Address Learning already refuses it and raises
    // the hint; the mapper reads that verdict rather than re-deriving it.
    let t0 = Instant::now();
    let store = bound_v4_store();
    let mut mapper = mapper(store.clone());
    mapper.start(t0);
    let _ = drain(&mut mapper);
    probed(MappingProtocol::Pcp, &[AddressFamily::V4], t0, &mut mapper);
    mapper.tick(t0 + Duration::from_secs(3));
    answer_maps(&mut mapper, t0, |mapping| {
        Ok(GrantAnswer {
            external: PeerEndpoint::V4(Ipv4Endpoint::new(
                Ipv4Addr::new(100, 96, 0, 3),
                mapping.internal_port,
            )),
            lease: Some(HOUR),
            epoch_reset: false,
        })
    });
    assert!(
        mapper
            .diagnostics()
            .iter()
            .all(|row| row.status == MappingStatus::Degraded)
    );
    assert!(matches!(
        store.nat_hint(AddressFamily::V4),
        Some(NatHint::CarrierGradeNat { .. })
    ));
    assert_eq!(
        verdict_port(&store, SocketRole::Tcp),
        None,
        "the refused grant taught the store no address at all, so no advert claims one"
    );
    assert!(
        !drain(&mut mapper).contains(&MappingCommand::RecheckReachability),
        "a Degraded install has nothing for a recheck to find"
    );
}

#[test]
fn a_race_with_nothing_available_climbs_the_backoff_ladder_and_retries() {
    let t0 = Instant::now();
    let mut mapper = mapper(bound_v4_store());
    mapper.start(t0);
    let _ = drain(&mut mapper);
    for protocol in MappingProtocol::ALL {
        mapper.on_result(
            MappingResult::Probed {
                protocol,
                outcome: Err(MappingError::Unsupported(protocol)),
            },
            t0,
        );
    }
    assert_eq!(mapper.next_wake(), Some(t0 + Duration::from_secs(30)));
    assert!(
        mapper
            .diagnostics()
            .iter()
            .all(|row| row.status == MappingStatus::Failed)
    );
    assert!(
        mapper.diagnostics()[0].last_error.is_some(),
        "the row says why, not only that"
    );

    // The retry re-races, and a second empty round doubles the wait.
    let retry = t0 + Duration::from_secs(30);
    mapper.tick(retry);
    assert_eq!(drain(&mut mapper).len(), 3, "three fresh probes");
    for protocol in MappingProtocol::ALL {
        mapper.on_result(
            MappingResult::Probed {
                protocol,
                outcome: Err(MappingError::Unsupported(protocol)),
            },
            retry,
        );
    }
    assert_eq!(mapper.next_wake(), Some(retry + Duration::from_secs(60)));
}

#[test]
fn a_refusal_hold_off_is_honoured_and_clamped() {
    // RFC 6887 §7.4's hold-off is attacker-controlled input: unclamped, a
    // gateway claiming 0xFFFFFFFF disables port mapping for 136 years.
    let t0 = Instant::now();
    let mut mapper = mapper(bound_v4_store());
    mapper.start(t0);
    let _ = drain(&mut mapper);
    probed(MappingProtocol::Pcp, &[AddressFamily::V4], t0, &mut mapper);
    let asked_at = t0 + Duration::from_secs(3);
    mapper.tick(asked_at);
    answer_maps(&mut mapper, asked_at, |_| {
        Err(MappingError::Refused {
            protocol: MappingProtocol::Pcp,
            refusal: rmule_net::portmap::MappingRefusal::NotAuthorized,
            hold_off: Some(Duration::from_secs(u64::from(u32::MAX))),
        })
    });
    assert_eq!(
        mapper.next_wake(),
        Some(asked_at + BACKOFF_CEILING),
        "the hold-off paced the retry, clamped to thirty minutes"
    );
}

#[test]
fn the_first_low_id_after_a_high_id_re_maps_once() {
    // The mapping that earned the High-ID has evidently stopped working, and
    // nothing else would notice until the lease ran out.
    let (mut mapper, _store, t0) = mapped_over(MappingProtocol::Pcp, Some(HOUR));
    mapper.on_server_id(true, t0);
    assert!(drain(&mut mapper).is_empty(), "a High-ID re-maps nothing");

    mapper.on_server_id(false, t0 + Duration::from_secs(10));
    assert!(
        drain(&mut mapper)
            .iter()
            .any(|command| matches!(command, MappingCommand::Probe { .. })),
        "the High-ID → LowID edge re-raced"
    );

    // One shot: a second LowID in a row is not a new edge.
    let _ = drain(&mut mapper);
    mapper.on_server_id(false, t0 + Duration::from_secs(20));
    assert!(drain(&mut mapper).is_empty());
}

#[test]
fn release_on_exit_hands_every_mapping_back_and_can_be_turned_off() {
    let (mut mapper, _store, _t0) = mapped_over(MappingProtocol::Pcp, Some(HOUR));
    mapper.shutdown();
    let released: Vec<_> = drain(&mut mapper)
        .into_iter()
        .filter(|command| matches!(command, MappingCommand::Release { .. }))
        .collect();
    assert_eq!(released.len(), 2, "every mapping went back");

    let t0 = Instant::now();
    let store = bound_v4_store();
    let mut keeping = PortMapper::new(
        PortMappingConfig {
            release_on_exit: false,
            protocols: MappingProtocol::Pcp.mask_bit(),
            ..PortMappingConfig::default()
        },
        store,
        7,
    );
    keeping.start(t0);
    let _ = drain(&mut keeping);
    probed(MappingProtocol::Pcp, &[AddressFamily::V4], t0, &mut keeping);
    answer_maps(&mut keeping, t0, |mapping| granted(mapping.internal_port));
    let _ = drain(&mut keeping);
    keeping.shutdown();
    assert!(
        drain(&mut keeping).is_empty(),
        "the operator said keep them"
    );
}

#[test]
fn a_zero_configured_lease_is_asked_as_the_floor_never_as_a_delete() {
    // A requested lifetime of zero is a delete in PCP and NAT-PMP: left
    // unclamped, every trial and renewal would release what it asked for.
    let t0 = Instant::now();
    let mut mapper = PortMapper::new(
        PortMappingConfig {
            lease: Duration::ZERO,
            ..PortMappingConfig::default()
        },
        bound_v4_store(),
        7,
    );
    mapper.start(t0);
    let _ = drain(&mut mapper);
    probed(MappingProtocol::Pcp, &[AddressFamily::V4], t0, &mut mapper);
    mapper.tick(t0 + Duration::from_secs(3));
    let leases: Vec<_> = drain(&mut mapper)
        .into_iter()
        .filter_map(|command| match command {
            MappingCommand::Map { lease, .. } => Some(lease),
            _ => None,
        })
        .collect();
    assert_eq!(leases, vec![MIN_ASKED_LEASE; 2]);
}
