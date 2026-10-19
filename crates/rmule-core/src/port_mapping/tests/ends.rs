//! The ends of a grant (ADR-0086, "Every grant has one owner and one end"):
//! every way a grant stops being held leaves nothing behind — no forwarding on
//! the gateway that nothing here will renew or release, no lease row, and no
//! `MappingGrant` observation in **Address Learning** that outlives it.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use rmule_net::family::FamilyBinds;
use rmule_net::portmap::{MappingError, MappingProtocol};
use rmule_primitives::AddressFamily;

use crate::address_learning::SocketRole;
use crate::port_mapping::mapper::TRIAL_DEADLINE;
use crate::port_mapping::{DesiredMapping, MappingCommand, MappingResult, PortMapper};

use super::{
    TCP_PORT, UDP_PORT, answer_maps, bound_v4_store, drain, granted, mapped_over, mapper,
    probe_absent, probed,
};

const HOUR: Duration = Duration::from_secs(3600);

/// The address every scripted grant names.
const GRANTED: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

fn row(role: SocketRole, internal_port: u16) -> DesiredMapping {
    DesiredMapping {
        role,
        family: AddressFamily::V4,
        internal_port,
        pinhole: None,
    }
}

fn releases(commands: &[MappingCommand]) -> Vec<(MappingProtocol, DesiredMapping, u16)> {
    commands
        .iter()
        .filter_map(|command| match command {
            MappingCommand::Release {
                protocol,
                mapping,
                external_port,
            } => Some((*protocol, *mapping, *external_port)),
            _ => None,
        })
        .collect()
}

/// A race where PCP and UPnP both answered the probe, so PCP is trialled
/// first and UPnP waits its turn.
fn pcp_then_upnp(t0: Instant) -> PortMapper {
    let mut mapper = mapper(bound_v4_store());
    mapper.start(t0);
    let _ = drain(&mut mapper);
    probed(MappingProtocol::Pcp, &[AddressFamily::V4], t0, &mut mapper);
    probe_absent(MappingProtocol::NatPmp, t0, &mut mapper);
    probed(MappingProtocol::Upnp, &[AddressFamily::V4], t0, &mut mapper);
    mapper
}

#[test]
fn a_trial_whose_gateway_never_answers_closes_at_its_deadline() {
    // A hung `AddPortMapping` used to wedge the mapper for the session: a
    // trial is judged only when every row answered, and Trialling had no wake.
    let t0 = Instant::now();
    let mut mapper = pcp_then_upnp(t0);
    let silent = drain(&mut mapper);
    assert!(
        silent.iter().any(|command| matches!(
            command,
            MappingCommand::Map {
                protocol: MappingProtocol::Pcp,
                ..
            }
        )),
        "PCP's maps went out: {silent:?}"
    );
    assert_eq!(mapper.next_wake(), Some(t0 + TRIAL_DEADLINE));

    mapper.tick(t0 + TRIAL_DEADLINE);
    let asked = answer_maps(&mut mapper, t0 + TRIAL_DEADLINE, |mapping| {
        granted(mapping.internal_port)
    });
    assert_eq!(asked.len(), 2, "the race moved on to UPnP");
    let rows = mapper.diagnostics();
    assert!(
        rows.iter()
            .all(|row| row.method == Some(MappingProtocol::Upnp)),
        "UPnP installed: {rows:?}"
    );
    assert!(
        rows.iter()
            .all(|row| row.last_error == Some(MappingError::Timeout(MappingProtocol::Pcp))),
        "the silent rows read as PCP timeouts: {rows:?}"
    );
}

#[test]
fn a_grant_that_lands_after_its_trial_closed_is_released_on_arrival() {
    let t0 = Instant::now();
    let mut mapper = pcp_then_upnp(t0);
    let _ = drain(&mut mapper);
    mapper.tick(t0 + TRIAL_DEADLINE);
    let done = t0 + TRIAL_DEADLINE;
    answer_maps(&mut mapper, done, |mapping| granted(mapping.internal_port));
    let _ = drain(&mut mapper);

    let tcp = row(SocketRole::Tcp, TCP_PORT);
    mapper.on_result(
        MappingResult::Mapped {
            protocol: MappingProtocol::Pcp,
            mapping: tcp,
            outcome: granted(TCP_PORT),
        },
        done + Duration::from_secs(1),
    );
    assert_eq!(
        releases(&drain(&mut mapper)),
        vec![(MappingProtocol::Pcp, tcp, TCP_PORT)],
        "nothing here holds PCP's late grant, so it goes back"
    );
    assert_eq!(
        mapper
            .diagnostics()
            .iter()
            .find(|row| row.mapping == tcp)
            .and_then(|row| row.method),
        Some(MappingProtocol::Upnp),
        "the installed UPnP lease is untouched"
    );
}

#[test]
fn an_interrupted_race_releases_every_grant_its_trials_hold() {
    let t0 = Instant::now();
    let mut mapper = pcp_then_upnp(t0);
    // PCP shifts the TCP port, so the race moves on to UPnP with PCP's
    // grants parked among the completed trials.
    answer_maps(&mut mapper, t0, |mapping| {
        granted(match mapping.role {
            SocketRole::Tcp => mapping.internal_port + 1000,
            SocketRole::Udp => mapping.internal_port,
        })
    });
    let _ = drain(&mut mapper);

    let t1 = t0 + Duration::from_secs(1);
    mapper.reprobe(t1);
    let mut released = releases(&drain(&mut mapper));
    released.sort_unstable();
    assert_eq!(
        released,
        vec![
            (
                MappingProtocol::Pcp,
                row(SocketRole::Tcp, TCP_PORT),
                TCP_PORT + 1000
            ),
            (
                MappingProtocol::Pcp,
                row(SocketRole::Udp, UDP_PORT),
                UDP_PORT
            ),
        ],
        "the completed trial's grants go back"
    );

    // UPnP's trial was in flight; its answer lands into the new round.
    let udp = row(SocketRole::Udp, UDP_PORT);
    mapper.on_result(
        MappingResult::Mapped {
            protocol: MappingProtocol::Upnp,
            mapping: udp,
            outcome: granted(UDP_PORT),
        },
        t1,
    );
    assert_eq!(
        releases(&drain(&mut mapper)),
        vec![(MappingProtocol::Upnp, udp, UDP_PORT)],
        "the in-flight trial's late grant goes back too"
    );
}

#[test]
fn a_departed_row_withdraws_its_grant_from_address_learning() {
    let (mut mapper, store, t0) = mapped_over(MappingProtocol::Pcp, Some(HOUR));
    assert_eq!(store.learned_port(SocketRole::Tcp), Some(TCP_PORT));
    let v4 = FamilyBinds {
        bound: vec![AddressFamily::V4],
        refused: Vec::new(),
    };
    store.record_bind(SocketRole::Tcp, &v4, TCP_PORT + 1);

    mapper.start(t0 + Duration::from_secs(1));
    assert_eq!(
        store.learned_port(SocketRole::Tcp),
        None,
        "the released TCP grant no longer names an external port"
    );
    assert_eq!(
        store.address(AddressFamily::V4),
        Some(GRANTED),
        "the UDP lease still stands behind the gateway address"
    );
}

#[test]
fn a_reprobe_withdraws_every_grant_it_drops() {
    let (mut mapper, store, t0) = mapped_over(MappingProtocol::Pcp, Some(HOUR));
    assert_eq!(store.address(AddressFamily::V4), Some(GRANTED));

    mapper.reprobe(t0 + Duration::from_secs(1));
    assert_eq!(store.address(AddressFamily::V4), None);
    assert_eq!(store.learned_port(SocketRole::Udp), None);
    assert_eq!(store.learned_port(SocketRole::Tcp), None);
}

#[test]
fn an_emptied_set_releases_its_leases_once() {
    let (mut mapper, store, t0) = mapped_over(MappingProtocol::Pcp, Some(HOUR));
    store.forget_bind(SocketRole::Tcp);
    store.forget_bind(SocketRole::Udp);

    mapper.start(t0 + Duration::from_secs(1));
    assert_eq!(releases(&drain(&mut mapper)).len(), 2);
    mapper.shutdown();
    assert_eq!(
        releases(&drain(&mut mapper)),
        Vec::new(),
        "quit has nothing left to release"
    );
}

#[test]
fn a_renewal_on_a_moved_external_port_releases_the_old_one_only_under_upnp() {
    // UPnP keys a mapping by its external port, so the old one is a second
    // forwarding; PCP keys it by the internal port, so a release would take
    // down the mapping that just moved.
    for (protocol, releases_old) in [(MappingProtocol::Upnp, true), (MappingProtocol::Pcp, false)] {
        let (mut mapper, store, t0) = mapped_over(protocol, Some(HOUR));
        let due = t0 + HOUR;
        mapper.tick(due);
        answer_maps(&mut mapper, due, |mapping| {
            granted(match mapping.role {
                SocketRole::Udp => UDP_PORT + 5,
                SocketRole::Tcp => TCP_PORT,
            })
        });
        let udp = row(SocketRole::Udp, UDP_PORT);
        let expected = if releases_old {
            vec![(protocol, udp, UDP_PORT)]
        } else {
            Vec::new()
        };
        assert_eq!(releases(&drain(&mut mapper)), expected, "{protocol}");
        assert_eq!(store.learned_port(SocketRole::Udp), Some(UDP_PORT + 5));
    }
}
