//! **Port Mapping** end to end through a live core (ADR-0086): the runtime the
//! builder starts, the backends it races, the grant that reaches **Address
//! Learning**, and the operator recheck that drives both halves.
//!
//! The mapper's own rules — the race, the grade matrix, the RFC renewal
//! ladders, the epoch re-add, the backoff — are proven deterministically beside
//! the mapper, where an hour of lease costs a microsecond. What only a live
//! core can prove is the *wiring*: that the runtime starts at all, that a
//! socket binding grows the **Desired Mapping Set**, that a grant lands on the
//! diagnostics level and in the address store, and that turning the feature off
//! really does talk to no gateway.

use rmule_testkit::HANG_GUARD;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use rmule_core::port_mapping::{MappingStatus, PortMappingMode};
use rmule_core::{
    ConfidenceTier, Core, CoreCommand, CoreConfig, PairRole, ServeCommand, SocketRole,
};
use rmule_net::portmap::{MappedTransport, MappingBackend, MappingProtocol};
use rmule_primitives::AddressFamily;
use rmule_testkit::{FakeGateways, GrantPolicy, ScriptedBackend};
use std::net::UdpSocket;
use tokio::net::TcpListener;
use tokio::time::{Duration, timeout};

use crate::fixture::reserve_dual_stack_port;

/// A core wired to `backends` behind a scripted home-LAN gateway.
fn core_with(backends: Vec<Arc<dyn MappingBackend>>, config: CoreConfig) -> Core {
    core_on(rmule_testkit::memory_store(), backends, config)
}

/// The same, on a store the caller holds — so a second core can read back what
/// the first one learned.
fn core_on(
    store: Arc<rmule_core::DurableStore>,
    backends: Vec<Arc<dyn MappingBackend>>,
    config: CoreConfig,
) -> Core {
    Core::builder(config, store)
        .settings(rmule_core::CoreSettings::default())
        .gateway_source(FakeGateways::home_lan())
        .mapping_backends(backends)
        .build()
}

/// Poll the snapshot until `ready` accepts its mapping rows.
async fn mappings_until(
    core: &Core,
    ready: impl Fn(&[rmule_core::port_mapping::MappingDiagnostics]) -> bool,
) -> Vec<rmule_core::port_mapping::MappingDiagnostics> {
    timeout(HANG_GUARD, async {
        loop {
            let rows = core.diagnostics_snapshot().mappings;
            if ready(&rows) {
                return rows;
            }
            // The rows are a polled level with no change notification
            // (`DiagnosticsState` republishes the whole set on write, but
            // keeps no watch), so this sleep-polls rather than spinning a
            // core each leg does not need.
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the mapping rows settled")
}

/// Poll the snapshot until `ready` accepts its half-bound-pair rows.
///
/// The client-UDP mapping row (what [`mappings_until`] waits on) and the
/// server-UDP half-bound fact are written by two independent event paths
/// with no ordering guarantee between them: a one-shot read
/// right after `mappings_until` returns can race the fact. Same polled-level
/// shape as `mappings_until` — `DiagnosticsState` keeps no watch on this
/// level either.
async fn half_bound_until(
    core: &Core,
    ready: impl Fn(&[rmule_net::family::HalfBound]) -> bool,
) -> Vec<rmule_net::family::HalfBound> {
    timeout(HANG_GUARD, async {
        loop {
            let rows = core.diagnostics_snapshot().half_bound_pairs;
            if ready(&rows) {
                return rows;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the half-bound-pair rows settled")
}

#[tokio::test]
async fn a_granted_mapping_reaches_the_diagnostics_level_and_the_address_store() {
    // The whole point of the subsystem in one assertion: a gateway that grants
    // the exact ports turns a firewalled node's own address into something the
    // advert chooser can read, without any advert site knowing a port mapper
    // exists.
    let pcp = Arc::new(ScriptedBackend::available(MappingProtocol::Pcp));
    let core = core_with(vec![pcp.clone()], CoreConfig::default());

    // The client-UDP pair binds with the core, so a row exists before any
    // command is sent — the Desired Mapping Set is derived from what bound.
    let rows = mappings_until(&core, |rows| {
        rows.iter().any(|row| row.mapping.role == SocketRole::Udp)
    })
    .await;
    let client_udp = rows
        .iter()
        .find(|row| row.mapping.role == SocketRole::Udp)
        .expect("a client-UDP row");
    assert_eq!(client_udp.status, MappingStatus::Mapped);
    assert_eq!(client_udp.method, Some(MappingProtocol::Pcp));
    assert_eq!(
        client_udp.external.expect("an external endpoint").port(),
        client_udp.mapping.internal_port,
        "an Exact grant keeps the port the hello advertises"
    );

    // And the store learned it at the mapping-grant tier, which is what puts
    // the endpoint on the CT_EMULE_UDPPORTS advert and route 2's 0x95.
    let learned = timeout(HANG_GUARD, async {
        loop {
            let rows = core.diagnostics_snapshot().addresses;
            if let Some(row) = rows.iter().find(|row| {
                row.role == SocketRole::Udp
                    && row.family == AddressFamily::V4
                    && row.verdict.tier() == Some(ConfidenceTier::MappingGrant)
            }) {
                return *row;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the grant reached Address Learning");
    assert_eq!(
        learned.verdict.known().map(|endpoint| endpoint.ip()),
        Some(std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)))
    );
}

#[tokio::test]
async fn the_ed2k_listener_joins_the_desired_set_when_the_serve_side_binds() {
    // The set grows over a session's life: the client-UDP pair comes up with
    // the core and the listener only when serving starts. A set fixed at
    // startup would never map the one port that earns a High-ID.
    let pcp = Arc::new(ScriptedBackend::available(MappingProtocol::Pcp));
    let mut core = core_with(vec![pcp.clone()], CoreConfig::default());
    let before = mappings_until(&core, |rows| !rows.is_empty()).await;
    assert!(
        !before.iter().any(|row| row.mapping.role == SocketRole::Tcp),
        "nothing is listening yet, so there is no listener to map"
    );

    // A server that accepts and then says nothing: the login is
    // still in flight for the whole of this leg, so the mapping below can only
    // have come from the **Bind Generation** the bind itself bumps — not from
    // anything the login produced. The trigger and the truth stay one object.
    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
    }))
    .await
    .expect("serve accepted");

    let after = mappings_until(&core, |rows| {
        rows.iter()
            .any(|row| row.mapping.role == SocketRole::Tcp && row.status == MappingStatus::Mapped)
    })
    .await;
    let tcp = after
        .iter()
        .find(|row| row.mapping.role == SocketRole::Tcp)
        .expect("a TCP row");
    assert_eq!(tcp.method, Some(MappingProtocol::Pcp));

    // And it follows the listener across a restart: a second
    // start is a first start, so it binds — possibly another port — records
    // that bind, and the **Bind Generation** carries the new set here. A
    // desired set frozen at the first bind would keep asking the gateway to
    // forward a port nothing listens on.
    let holder = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let second_port = holder.local_addr().expect("local addr").port();
    assert_ne!(second_port, tcp.mapping.internal_port);
    core.send(CoreCommand::Serve(ServeCommand::StopServing))
        .await
        .expect("stop accepted");
    crate::fixture::next_expected(&mut core, "the serve activity's ServingStopped", |event| {
        matches!(
            event,
            rmule_core::CoreEvent::Serve(rmule_core::ServeEvent::ServingStopped { .. })
        )
    })
    .await;
    drop(holder);

    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, second_port),
    }))
    .await
    .expect("serve accepted");
    let restarted = mappings_until(&core, |rows| {
        rows.iter().any(|row| {
            row.mapping.role == SocketRole::Tcp
                && row.mapping.internal_port == second_port
                && row.status == MappingStatus::Mapped
        })
    })
    .await;
    assert_eq!(
        restarted
            .iter()
            .filter(|row| row.mapping.role == SocketRole::Tcp)
            .count(),
        1,
        "the port nothing listens on any more left the Desired Mapping Set",
    );

    // And the vacated port was handed back rather than left to expire on its
    // own lease: the old row left the Desired Mapping Set while
    // it still held a granted mapping, so the runtime released it — once, at
    // the exact port it was granted — before asking for the new one.
    let released_tcp: Vec<_> = pcp
        .released()
        .into_iter()
        .filter(|(request, _)| request.transport == MappedTransport::Tcp)
        .collect();
    assert_eq!(
        released_tcp.len(),
        1,
        "exactly one release for the vacated TCP port: {released_tcp:?}"
    );
    let (released_request, released_port) = &released_tcp[0];
    assert_eq!(released_request.internal_port, tcp.mapping.internal_port);
    assert_eq!(
        *released_port,
        tcp.external.expect("a granted endpoint").port()
    );

    let mapped_new_tcp: Vec<_> = pcp
        .asked()
        .into_iter()
        .filter(|request| {
            request.transport == MappedTransport::Tcp && request.internal_port == second_port
        })
        .collect();
    assert_eq!(
        mapped_new_tcp.len(),
        1,
        "exactly one map for the new TCP port: {mapped_new_tcp:?}"
    );
}

#[tokio::test]
async fn a_mismatched_tcp_grant_is_degraded_and_the_advert_keeps_the_bound_port() {
    // The eD2k hello advertises one port and has no external-port tag, so a
    // grant on another port is a silent LowID. Reporting it as "forwarded"
    // beside a permanently firewalled client would be a lie.
    let pcp = Arc::new(
        ScriptedBackend::available(MappingProtocol::Pcp).granting(GrantPolicy::Shifted(1000)),
    );
    let core = core_with(vec![pcp], CoreConfig::default());
    let rows = mappings_until(&core, |rows| {
        rows.iter().any(|row| {
            row.status != MappingStatus::Probing && row.status != MappingStatus::NotMapped
        })
    })
    .await;
    let client_udp = rows
        .iter()
        .find(|row| row.mapping.role == SocketRole::Udp)
        .expect("a client-UDP row");
    assert_eq!(
        client_udp.status,
        MappingStatus::Mapped,
        "a mismatched UDP grant is the same fact Kad's extern-port rule learns"
    );
    assert_eq!(
        client_udp.external.expect("an external endpoint").port(),
        // Wrapping, as the scripted shift is: the internal port here is
        // whatever the OS handed the client-UDP socket, and roughly one
        // ephemeral port in sixteen is within 1000 of the top of the range —
        // which is what made this leg fail one run in twenty on arithmetic
        // that had nothing to do with port mapping.
        client_udp.mapping.internal_port.wrapping_add(1000)
    );
}

#[tokio::test]
async fn port_mapping_off_talks_to_no_gateway_at_all() {
    // The operator who already has a static forward and wants nothing speaking
    // to their router gets exactly that: no probe, no map, and no rows.
    let pcp = Arc::new(ScriptedBackend::available(MappingProtocol::Pcp));
    let core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings {
            port_mapping: PortMappingMode::Off,
            ..rmule_core::CoreSettings::default()
        })
        .gateway_source(FakeGateways::home_lan())
        .mapping_backends(vec![pcp.clone()])
        .build();
    // The recheck command is the strongest nudge there is, and it must still
    // reach nothing.
    core.send(CoreCommand::RecheckReachability)
        .await
        .expect("recheck accepted");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(core.diagnostics_snapshot().mappings.is_empty());
    assert!(pcp.asked().is_empty(), "no gateway was asked anything");
}

#[tokio::test]
async fn the_operator_recheck_re_races_the_mappers() {
    // To an operator "am I reachable" and "is my port forwarded" are one
    // question; a stale mapping is the usual reason a firewall recheck keeps
    // coming back negative. The Kad half is a no-op here (no node running),
    // which is itself the honest behaviour.
    let pcp = Arc::new(ScriptedBackend::available(MappingProtocol::Pcp));
    let core = core_with(vec![pcp.clone()], CoreConfig::default());
    mappings_until(&core, |rows| {
        rows.iter().any(|row| row.status == MappingStatus::Mapped)
    })
    .await;
    let before = pcp.asked().len();

    core.send(CoreCommand::RecheckReachability)
        .await
        .expect("recheck accepted");
    timeout(HANG_GUARD, async {
        while pcp.asked().len() <= before {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the recheck re-raced");
}

#[tokio::test]
async fn the_winning_method_is_remembered_so_the_next_run_opens_with_one_probe() {
    // A full three-protocol race costs a grace window every start. Remembering
    // what worked turns the next one into a single probe — and the fallback to
    // the full race is what keeps that an optimisation rather than a verdict.
    let store = rmule_testkit::memory_store();
    let first_upnp = Arc::new(ScriptedBackend::available(MappingProtocol::Upnp));
    let first_pcp = Arc::new(ScriptedBackend::absent(MappingProtocol::Pcp));
    let first = core_on(
        Arc::clone(&store),
        vec![first_pcp, first_upnp.clone()],
        CoreConfig::default(),
    );
    mappings_until(&first, |rows| {
        rows.iter().any(|row| row.status == MappingStatus::Mapped)
    })
    .await;
    first.shutdown().await;

    // A second core on the same store: PCP is present this time, but the
    // remembered method is asked alone first — so only UPnP is trialled.
    let second_pcp = Arc::new(ScriptedBackend::available(MappingProtocol::Pcp));
    let second_upnp = Arc::new(ScriptedBackend::available(MappingProtocol::Upnp));
    let second = core_on(
        store,
        vec![second_pcp.clone(), second_upnp.clone()],
        CoreConfig::default(),
    );
    mappings_until(&second, |rows| {
        rows.iter().any(|row| row.status == MappingStatus::Mapped)
    })
    .await;
    assert!(
        !second_upnp.asked().is_empty(),
        "the remembered method was trialled"
    );
    assert!(
        second_pcp.asked().is_empty(),
        "the preferred protocol was not even asked: the short round found what worked"
    );
}

/// The server-UDP pair's Half-Bound Pair fact reaches
/// diagnostics but never the Desired Mapping Set: `SocketRole` — the bind
/// table's key, and the type the set is derived from — has no `ServerUdp`
/// variant, on purpose (ADR-0086). The client-UDP row is the proof the set is
/// alive at all; there is exactly one `Udp`-role row throughout, never a
/// second one server-UDP's own bind could only have added by mistake.
#[tokio::test]
async fn a_half_bound_server_udp_pair_never_joins_the_desired_mapping_set() {
    let held = reserve_dual_stack_port(Ipv4Addr::UNSPECIFIED.into(), socket2::Type::DGRAM);
    let port = held.port;

    let pcp = Arc::new(ScriptedBackend::available(MappingProtocol::Pcp));
    let core = core_with(
        vec![pcp],
        CoreConfig {
            server_udp_port: port,
            ..CoreConfig::default()
        },
    );

    // The client-UDP pair binds independently of server-UDP (two sockets),
    // so its row settles regardless of whether this host has IPv6 at all.
    let rows = mappings_until(&core, |rows| {
        rows.iter().any(|row| row.mapping.role == SocketRole::Udp)
    })
    .await;
    assert_eq!(
        rows.iter()
            .filter(|row| row.mapping.role == SocketRole::Udp)
            .count(),
        1,
        "exactly the client-UDP row — a half-bound server-UDP pair added none: {rows:?}",
    );
    assert!(
        !rows.iter().any(|row| row.mapping.role == SocketRole::Tcp),
        "nothing is listening yet either",
    );

    // The fact still reached diagnostics — it is recorded, just not in the
    // table the mapper reads (`DiagnosticsState::record_server_udp_bind`).
    // Skipped on a host with no IPv6 at all: there the bind fails totally,
    // which raises no Half-Bound Pair fact and no CoreEvent either (see
    // `client_udp_bind_failure.rs`), so there would be nothing to find.
    let ipv6_host = UdpSocket::bind("[::]:0").is_ok();
    if ipv6_host {
        // Polled rather than a one-shot read: this fact and the
        // client-UDP mapping row `mappings_until` above waited on come from
        // independent event paths, so nothing orders this fact's arrival
        // before that row's.
        half_bound_until(&core, |rows| {
            rows.iter().any(|half| half.role == PairRole::ServerUdp)
        })
        .await;
    }

    drop(held);
}
