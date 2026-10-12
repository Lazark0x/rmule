//! What the one client-UDP socket's bind says about itself — the **total**
//! refusal (ADR-0057) and the **Half-Bound Pair**,
//! named in diagnostics, a start event and the `EnableKad` rejection that
//! follows. Extended for the other two roles: the eD2k listener
//! and server-UDP say the same thing the client-UDP pair already did, at
//! their own binds.
//!
//! Proven against real held ports, never fixed ones, and against Family
//! Pairs' actual partial tolerance rather than a redesign of it: ADR-0085's
//! rule — one family refusing must not take the other down — stays, and what
//! a refusal *costs* is what these tests pin.
//!
//! Everything here runs a real `Core::new`, because the whole claim is about
//! what the production bind site does when the OS refuses it.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, UdpSocket};

use rmule_core::{
    Consequence, Core, CoreCommand, CoreCommandRejectReason, CoreConfig, CoreEvent,
    KadUnavailableReason, PairRole, ServeCommand, ServeEvent, SocketRole,
};
use rmule_net::family::FamilySelection;
use rmule_primitives::AddressFamily;
use socket2::Type;

use crate::fixture::{
    host_binds_ipv6, kad_enable_config, next_expected, reserve_dual_stack_port,
    reserve_dual_stack_port_from, serving_started, skip_without_ipv6,
};

/// A core configured to bind IPv4 only, so a test that holds one IPv4 UDP
/// port produces a **total** bind refusal — `UdpFamilyPair::bind` (ADR-0085)
/// only errors when *every* selected Address Family refuses, and a v4+v6
/// default would leave the pair up on `::` alone, proving nothing about a
/// wholly-refused bind. This is a deployment choice the test makes for
/// determinism (no IPv6 route required in CI), not a change to Family Pair
/// binding itself.
fn v4_only() -> CoreConfig {
    CoreConfig {
        address_families: FamilySelection::v4_only(),
        ..CoreConfig::default()
    }
}

/// A core started on a UDP port the test itself holds reports the port and
/// the OS's real `ErrorKind` — `AddrInUse`, not a guessed-at `Other` — through
/// diagnostics and the start event, and carries the same two facts into the
/// `EnableKad` rejection that follows. Pinned to `AddrInUse` on purpose: a
/// synthesized `Other` here would mean the join in `UdpFamilyPair::bind`
/// (`crates/rmule-net/src/family.rs`) had swallowed the real reason again —
/// exactly the bug this test exists to catch.
#[tokio::test]
async fn a_totally_refused_bind_is_named_in_diagnostics_the_start_event_and_the_kad_rejection() {
    let held = UdpSocket::bind("0.0.0.0:0").expect("hold a v4 UDP port for the test's own life");
    let port = held.local_addr().expect("local addr").port();

    let mut core = Core::builder(v4_only(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings {
            udp_port: port,
            ..rmule_core::CoreSettings::default()
        })
        .build();

    // The start event: emitted once, unprompted, before any command.
    let start = next_expected(&mut core, "the client-UDP bind's start fact", |e| {
        matches!(e, CoreEvent::ClientUdpBindFailed { .. })
    })
    .await;
    let CoreEvent::ClientUdpBindFailed {
        port: reported_port,
        kind,
    } = start
    else {
        unreachable!("the predicate admits only this variant");
    };
    assert_eq!(
        reported_port, port,
        "the start event names the port that was actually asked for"
    );
    assert_eq!(
        kind,
        std::io::ErrorKind::AddrInUse,
        "the real OS reason survives the Family Pair join, not a catch-all Other"
    );

    // The diagnostics row: read synchronously, with no actor round trip, and
    // still there after the start event has scrolled past.
    let snapshot = core.diagnostics_snapshot();
    assert_eq!(
        snapshot.client_udp_bind_failure,
        Some(rmule_core::diagnostics::ClientUdpBindFailure {
            port,
            kind: std::io::ErrorKind::AddrInUse,
        }),
        "the diagnostics row survives past the start event, unlike a log line",
    );

    // The Kad rejection: the same two facts, for a command sent well after
    // the start event, with no way to have re-derived them from a bind that
    // never happened a second time.
    core.send(CoreCommand::EnableKad(kad_enable_config()))
        .await
        .expect("core accepts the command");
    let rejected = next_expected(&mut core, "the Kad rejection", |e| {
        matches!(e, CoreEvent::CommandRejected { .. })
    })
    .await;
    let CoreEvent::CommandRejected { reason } = rejected else {
        unreachable!("the predicate admits only this variant");
    };
    assert_eq!(
        reason,
        CoreCommandRejectReason::KadUnavailable(KadUnavailableReason::UdpUnbound {
            port,
            kind: std::io::ErrorKind::AddrInUse,
        }),
        "EnableKad names the same port and kind the start event and the diagnostics row did",
    );

    drop(held);
}

/// A core whose socket binds reports no bind failure at all — `None`, not a
/// zeroed or default row. Proven by round-tripping `DumpDiagnostics`: the
/// answering `DiagnosticsSnapshot` can only have been built after the whole
/// of core start ran, bind attempt included, so this is not a race against
/// the actor's own init.
///
/// The eD2k listener joins in too: a `StartServing` on an
/// ephemeral wildcard port binds whole, same as the two sockets core start
/// itself binds, so a session where nothing was ever refused has nothing to
/// say about any of the three roles.
#[tokio::test]
async fn a_bound_socket_reports_no_bind_failure() {
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();

    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
    }))
    .await
    .expect("core accepts the command");
    serving_started(&mut core).await;

    core.send(CoreCommand::DumpDiagnostics)
        .await
        .expect("core accepts the command");
    let echoed = next_expected(&mut core, "the diagnostics echo", |e| {
        matches!(e, CoreEvent::DiagnosticsSnapshot { .. })
    })
    .await;
    let CoreEvent::DiagnosticsSnapshot { snapshot } = echoed else {
        unreachable!("the predicate admits only this variant");
    };
    assert_eq!(
        snapshot.client_udp_bind_failure, None,
        "a socket that bound reports nothing of the kind"
    );
    assert_eq!(
        core.diagnostics_snapshot().client_udp_bind_failure,
        None,
        "the sync accessor agrees with the actor-answered echo"
    );
    // An ephemeral port cannot collide, so nothing can be *refused* on this
    // core but a family this host does not have at all — and on a host that
    // does have IPv6, the pair is whole and reports nothing.
    if host_binds_ipv6() {
        assert_eq!(
            snapshot.half_bound_pairs,
            Vec::new(),
            "a whole pair is not a half-bound fact"
        );
    } else {
        assert!(
            snapshot
                .half_bound_pairs
                .iter()
                .all(|half| half.missing == AddressFamily::V6),
            "an ephemeral bind can lose only the family this host lacks"
        );
    }
}

/// **Family Pairs, honestly** (ADR-0085): a refusal on *one* selected family
/// with the other free is not a total bind failure — `UdpFamilyPair::bind`
/// only errors when every selected family refuses — so the bind-failure row
/// stays empty. A different fact takes its place: the pair
/// came up **without IPv4**, and on a client-UDP pair that is Kad, the NAT-T
/// punch path and the IPv4 UDP advert, all off until restart.
///
/// The `EnableKad` refusal is the load-bearing half. The command once
/// was *accepted* on a pair with no IPv4 socket, and the node it started
/// could never send or receive a single Kad datagram.
#[tokio::test]
async fn a_pair_that_came_up_without_ipv4_names_it_and_refuses_kad() {
    // With no `::` socket at all both families refuse: that is the
    // total-failure path, pinned by the first test in this file, and there is
    // no half-bound claim to make.
    if skip_without_ipv6("a_pair_that_came_up_without_ipv4_names_it_and_refuses_kad") {
        return;
    }
    let held = reserve_dual_stack_port(Ipv4Addr::UNSPECIFIED.into(), Type::DGRAM);
    let port = held.port;

    // The default selects both families; v4 is held, v6 is free, so the pair
    // comes up on `::` alone — the half-bound case, not the total one.
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings {
            udp_port: port,
            ..rmule_core::CoreSettings::default()
        })
        .build();

    // Only the client-UDP pair's own fact: another pair's half-bound fact
    // (server-UDP binds at the same start) may land first.
    let start = next_expected(&mut core, "the client-UDP bind's start fact", |e| {
        matches!(
            e,
            CoreEvent::SocketBoundWithoutFamily { half_bound }
                if half_bound.role == PairRole::ClientUdp
        ) || matches!(e, CoreEvent::ClientUdpBindFailed { .. })
    })
    .await;
    let CoreEvent::SocketBoundWithoutFamily { half_bound } = start else {
        panic!("a free `::` socket must produce a pair, not {start:?}");
    };
    assert_eq!(half_bound.role, PairRole::ClientUdp);
    assert_eq!(half_bound.missing, AddressFamily::V4);
    assert_eq!(
        half_bound.kind,
        std::io::ErrorKind::AddrInUse,
        "the family's own OS reason, kept per refusal"
    );
    assert!(
        half_bound.forfeited(Consequence::Kad)
            && half_bound.forfeited(Consequence::NatTraversal)
            && half_bound.forfeited(Consequence::Ipv4UdpAdvert),
        "the consequence table is read, not re-derived: {half_bound}"
    );

    let snapshot = core.diagnostics_snapshot();
    assert_eq!(
        snapshot.client_udp_bind_failure, None,
        "a partial bind is not a total one — the pair still came up on the free family"
    );
    assert_eq!(
        snapshot.half_bound_pairs,
        vec![half_bound],
        "the row and the event carry one fact, read from the same bind table"
    );
    // The advert side: the chooser lists only (family, role) pairs that
    // actually bound, so there is no IPv4 UDP endpoint for any advert to
    // name — which is also why the login's `0xF9` omits its tag outright.
    assert!(
        !snapshot
            .addresses
            .iter()
            .any(|row| row.family == AddressFamily::V4 && row.role == SocketRole::Udp),
        "no IPv4 UDP endpoint is advertised for a socket the node does not hold"
    );

    core.send(CoreCommand::EnableKad(kad_enable_config()))
        .await
        .expect("core accepts the command");
    let rejected = next_expected(&mut core, "the Kad rejection", |e| {
        matches!(e, CoreEvent::CommandRejected { .. })
    })
    .await;
    let CoreEvent::CommandRejected { reason } = rejected else {
        unreachable!("the predicate admits only this variant");
    };
    assert_eq!(
        reason,
        CoreCommandRejectReason::KadUnavailable(KadUnavailableReason::UdpFamilyMissing {
            family: AddressFamily::V4,
            kind: std::io::ErrorKind::AddrInUse,
        }),
        "EnableKad names the family Kad rides and could not get",
    );

    drop(held);
}

/// The mirror, and the reason the consequence is stated *per family* rather
/// than as one "half-bound is bad": a pair that lost IPv6 keeps everything
/// the eD2k network actually runs on. Kad is not refused, the IPv4 UDP
/// endpoint is still advertised, and only the IPv6 reask surface is gone.
#[tokio::test]
async fn a_pair_that_came_up_without_ipv6_keeps_kad_and_every_ipv4_advert() {
    // Nothing to refuse without IPv6: the `::` half was never available,
    // which is "not selected by this deployment", not "refused".
    if skip_without_ipv6("a_pair_that_came_up_without_ipv6_keeps_kad_and_every_ipv4_advert") {
        return;
    }
    // A `::` hold on a port whose IPv4 wildcard was proven free: rmule's v4
    // half binds and its `::` wildcard is refused. The hold is the wildcard,
    // not a literal `::1`: Windows lets a wildcard bind share a port that a
    // specific address holds, so only a wildcard hold refuses it everywhere.
    let held = reserve_dual_stack_port(Ipv6Addr::UNSPECIFIED.into(), Type::DGRAM);
    let port = held.port;

    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings {
            udp_port: port,
            ..rmule_core::CoreSettings::default()
        })
        .build();

    let start = next_expected(&mut core, "the client-UDP bind's start fact", |e| {
        matches!(
            e,
            CoreEvent::SocketBoundWithoutFamily { .. } | CoreEvent::ClientUdpBindFailed { .. }
        )
    })
    .await;
    let CoreEvent::SocketBoundWithoutFamily { half_bound } = start else {
        unreachable!("the IPv4 wildcard on this port was reserved free, so the pair came up");
    };
    assert_eq!(half_bound.missing, AddressFamily::V6);
    assert!(
        !half_bound.forfeited(Consequence::Kad)
            && !half_bound.forfeited(Consequence::NatTraversal)
            && !half_bound.forfeited(Consequence::Ipv4UdpAdvert),
        "losing IPv6 costs nothing IPv4 carries: {half_bound}"
    );

    let snapshot = core.diagnostics_snapshot();
    assert!(
        snapshot
            .addresses
            .iter()
            .any(|row| row.family == AddressFamily::V4 && row.role == SocketRole::Udp),
        "the IPv4 UDP endpoint is still advertised — it is really bound"
    );

    drop(held);
}

/// The reservation the leg above stands on steps past a number
/// whose IPv4 wildcard is already taken — the collision that used to land it
/// on its `unreachable!` arm under a loaded workspace run — instead of handing
/// that number over. The collision is made here, not waited for.
#[test]
fn a_reservation_moves_past_a_port_whose_ipv4_wildcard_is_taken() {
    if skip_without_ipv6("a_reservation_moves_past_a_port_whose_ipv4_wildcard_is_taken") {
        return;
    }
    let taken = reserve_dual_stack_port(Ipv6Addr::LOCALHOST.into(), Type::DGRAM);
    let spare = reserve_dual_stack_port(Ipv6Addr::LOCALHOST.into(), Type::DGRAM);
    let (colliding, next) = (taken.port, spare.port);
    let occupier = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, colliding))
        .expect("the v4 wildcard on this number was just reserved free");
    // Only the IPv4 side collides now: `::1` on the number is free again.
    drop((taken, spare));

    let held =
        reserve_dual_stack_port_from(Ipv6Addr::LOCALHOST.into(), Type::DGRAM, [colliding, next]);

    assert_eq!(
        held.port, next,
        "the number held on IPv4 by someone else is skipped, not handed out"
    );
    drop(occupier);
}

/// The eD2k listener's own half-bound fact: a listener that
/// comes up without IPv4 is the one that forfeits every High ID, and it now
/// says so the moment it binds rather than waiting for an operator to open
/// diagnostics.
///
/// The held socket is the TCP wildcard, not a literal loopback: `StartServing`
/// only pairs both families when `listen_addr` is unspecified
/// (`RuntimeServeRuntimeService::start`), same as the client-UDP and
/// server-UDP binds always are.
#[tokio::test]
async fn a_listener_that_comes_up_without_ipv4_names_it_and_the_row_appears() {
    // With no `::` socket at all a wildcard bind on a v4-held port fails
    // totally — the total-failure shape, not this one.
    if skip_without_ipv6("a_listener_that_comes_up_without_ipv4_names_it_and_the_row_appears") {
        return;
    }
    let held = reserve_dual_stack_port(Ipv4Addr::UNSPECIFIED.into(), Type::STREAM);
    let port = held.port;

    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();
    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port),
    }))
    .await
    .expect("core accepts the command");

    let event = next_expected(
        &mut core,
        "the serve start's verdict, whichever it is",
        |e| {
            matches!(
                e,
                CoreEvent::Serve(
                    ServeEvent::ServingStarted { .. } | ServeEvent::ServingFailed { .. }
                )
            )
        },
    )
    .await;
    let CoreEvent::Serve(ServeEvent::ServingStarted { listen_addr: bound }) = event else {
        panic!("a free `::` socket must produce a listener, not {event:?}");
    };
    assert_eq!(
        bound.port(),
        port,
        "the listener still bound the held port, on the free family"
    );

    let start = next_expected(&mut core, "the eD2k listener's half-bound fact", |e| {
        matches!(e, CoreEvent::SocketBoundWithoutFamily { .. })
    })
    .await;
    let CoreEvent::SocketBoundWithoutFamily { half_bound } = start else {
        unreachable!("the predicate admits only this variant");
    };
    assert_eq!(half_bound.role, PairRole::Ed2kListener);
    assert_eq!(half_bound.missing, AddressFamily::V4);
    assert_eq!(
        half_bound.kind,
        std::io::ErrorKind::AddrInUse,
        "the family's own OS reason"
    );
    assert!(
        half_bound.forfeited(Consequence::Ipv4Dials) && half_bound.forfeited(Consequence::HighId),
        "the consequence table is read, not re-derived: {half_bound}"
    );

    let snapshot = core.diagnostics_snapshot();
    assert_eq!(
        snapshot.half_bound_pairs,
        vec![half_bound],
        "the row and the event carry one fact, read from the same bind table"
    );

    drop(held);
}

/// The server-UDP pair's own half-bound fact: recorded beside
/// the **Address Learning** bind table rather than in it (nothing maps or
/// advertises this socket), but the same fact by the same consequence table.
///
/// No IPv6 host has no reliable signal here at all: unlike the client-UDP
/// bind, a *total* server-UDP refusal emits no `CoreEvent` (only a `warn`
/// log, ADR-0051's pre-existing shape) — so this leg, unlike its siblings
/// above, cannot tell "still starting" from "failed totally and said nothing"
/// without one, and returns early rather than risk a false pass.
#[tokio::test]
async fn a_server_udp_pair_that_comes_up_without_ipv4_names_it_and_the_row_appears() {
    if skip_without_ipv6(
        "a_server_udp_pair_that_comes_up_without_ipv4_names_it_and_the_row_appears",
    ) {
        return;
    }
    let held = reserve_dual_stack_port(Ipv4Addr::UNSPECIFIED.into(), Type::DGRAM);
    let port = held.port;

    let mut core = Core::builder(
        CoreConfig {
            server_udp_port: port,
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
    .settings(rmule_core::CoreSettings::default())
    .build();

    let start = next_expected(&mut core, "the server-UDP bind's half-bound fact", |e| {
        matches!(e, CoreEvent::SocketBoundWithoutFamily { .. })
    })
    .await;
    let CoreEvent::SocketBoundWithoutFamily { half_bound } = start else {
        unreachable!("the predicate admits only this variant");
    };
    assert_eq!(half_bound.role, PairRole::ServerUdp);
    assert_eq!(half_bound.missing, AddressFamily::V4);
    assert_eq!(
        half_bound.kind,
        std::io::ErrorKind::AddrInUse,
        "the family's own OS reason"
    );
    assert_eq!(
        half_bound.forfeits(),
        &[Consequence::ServerUdpSweep],
        "the consequence table is read, not re-derived: {half_bound}"
    );

    let snapshot = core.diagnostics_snapshot();
    assert_eq!(
        snapshot.half_bound_pairs,
        vec![half_bound],
        "the row and the event carry one fact — recorded beside the bind \
         table, but read into the same snapshot vector"
    );

    drop(held);
}
