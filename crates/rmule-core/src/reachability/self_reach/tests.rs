//! The owner's union rules against the live families, and the generation.

use std::net::Ipv4Addr;
use std::time::Duration;

use rmule_primitives::{ClientId, Ipv4Endpoint};
use tokio::sync::mpsc;

use super::*;
use crate::reachability::SharedKadVerdicts;

const HIGH: u32 = 0x0A00_0001;
const LOW: u32 = 7;

fn owner() -> (SharedSelfReach, SharedKadVerdicts, SharedOwnIdentity) {
    let kad = SharedKadVerdicts::default();
    let own = SharedOwnIdentity::default();
    let reach = SharedSelfReach::new(
        KadReachLevel::published(kad.clone()),
        own.clone(),
        SharedNattFront::default(),
    );
    (reach, kad, own)
}

fn login(own: &SharedOwnIdentity, id: u32) {
    own.set_connected_session(Some(ConnectedSession {
        server: Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 1), 4661)),
        client_id: ClientId::from_u32(id),
    }));
}

/// The publish's bit `0x08` is `IsFirewalled() && UDP verified open`
/// (`Prefs.cpp:228`), read through the owner — so a server High ID gained
/// or lost mid-session, a Kad TCP verdict opening, and a stopped node each
/// flip it at the next read, with no copy anywhere to refresh.
#[test]
fn the_direct_callback_bit_flips_with_every_family_it_reads() {
    let (reach, kad, own) = owner();
    assert!(!reach.accepts_direct_udp_callback(), "UDP unverified");
    let lease = kad.lease();
    kad.set_udp(UdpReachability::Open { port: 4672 });
    assert!(reach.accepts_direct_udp_callback(), "firewalled, UDP open");

    login(&own, HIGH);
    assert!(!reach.accepts_direct_udp_callback(), "a High ID: dial us");
    assert_eq!(
        reach.kad_tcp(),
        TcpReachability::Firewalled,
        "Kad flag untouched"
    );
    assert!(!reach.firewalled(), "the route chooser's gate opens");
    own.reassign_client_id(ClientId::from_u32(LOW));
    assert!(reach.accepts_direct_udp_callback(), "re-assigned Low ID");
    assert!(reach.firewalled(), "and closes on the re-assignment");

    kad.set_tcp(TcpReachability::Open);
    assert!(!reach.accepts_direct_udp_callback(), "Kad TCP open");
    assert!(!reach.firewalled());

    drop(lease);
    assert!(
        reach.firewalled() && !reach.accepts_direct_udp_callback(),
        "a stopped node reads firewalled and unverified (IsFirewalledKad)"
    );
}

/// The generation wakes on each family's write: a Kad verdict, a session
/// write, the NAT-T front's end — and the front's end only once.
#[tokio::test]
async fn the_reach_generation_wakes_on_every_family() {
    let kad = SharedKadVerdicts::default();
    let own = SharedOwnIdentity::default();
    let natt = SharedNattFront::default();
    let (natt_tx, natt_rx) = mpsc::channel(1);
    natt.install(natt_tx);
    let reach = SharedSelfReach::new(KadReachLevel::published(kad.clone()), own.clone(), natt);
    let mut generation = reach.changes();
    async fn wakes(generation: &mut ReachGeneration) -> Result<(), tokio::time::error::Elapsed> {
        tokio::time::timeout(Duration::from_millis(50), generation.changed()).await
    }

    kad.set_tcp(TcpReachability::Open);
    wakes(&mut generation).await.expect("a Kad verdict write");
    login(&own, HIGH);
    wakes(&mut generation).await.expect("a login");
    drop(natt_rx);
    wakes(&mut generation).await.expect("the NAT-T front's end");
    assert!(!reach.natt_live());
    assert!(
        wakes(&mut generation).await.is_err(),
        "nothing moved since: no wake"
    );
}

/// The diagnostics rows read the owner at the snapshot: a node
/// that proved itself open reads `Open`, and the moment it stops — its lease
/// dropped — `Firewalled`/`Unverified`, never the dead node's last verdict.
#[test]
fn the_diagnostics_rows_read_a_stopped_node_as_unproven() {
    use crate::diagnostics::{KadFirewallVerdict, KadUdpVerdict};

    let (reach, kad, _own) = owner();
    let lease = kad.lease();
    kad.set_tcp(TcpReachability::Open);
    kad.set_udp(UdpReachability::Open { port: 4672 });
    assert_eq!(reach.kad_firewall_verdict(), KadFirewallVerdict::Open);
    assert_eq!(reach.kad_udp_verdict(), KadUdpVerdict::Open { port: 4672 });

    drop(lease);
    assert_eq!(reach.kad_firewall_verdict(), KadFirewallVerdict::Firewalled);
    assert_eq!(reach.kad_udp_verdict(), KadUdpVerdict::Unverified);
}

/// A listener bind and clear are Reach Generation wakes, so a
/// subscriber re-derives Callback Capability at the move rather than on the
/// download runner's 1 s tick — and the owner's answer carries the conjunct.
#[tokio::test]
async fn a_listener_bind_and_clear_wake_the_reach_generation() {
    let (reach, kad, _own) = owner();
    let _lease = kad.lease();
    kad.set_tcp(TcpReachability::Open);
    let mut generation = reach.changes();
    let wake = Duration::from_millis(50);
    assert!(!reach.callback_capability().server_relays());
    let dark = reach.callback_capability();

    let serve = tokio::spawn(std::future::pending::<()>());
    reach.listener().bind(&serve, 4662);
    tokio::time::timeout(wake, generation.changed())
        .await
        .expect("a bind wakes the generation");
    assert_ne!(
        reach.callback_capability(),
        dark,
        "the bound listener admits"
    );

    serve.abort();
    reach.listener().clear();
    tokio::time::timeout(wake, generation.changed())
        .await
        .expect("a clear wakes the generation");
    assert_eq!(reach.callback_capability(), dark);
}

/// The route position reads its two newest families at the call — the
/// client-UDP bind and Quit's clear, a session that went live with the punch
/// and one that ended — and each move wakes the generation. A session whose
/// task ended without clearing the cell reads dark at the next read all the
/// same: the cell holds that session's request half weakly.
#[tokio::test]
async fn the_route_position_follows_the_client_udp_bind_and_the_server_coordinator() {
    let bound = crate::reachability::ClientUdpBound::default();
    let punch = crate::natt::server_punch::SharedServerPunch::default();
    let reach = owner()
        .0
        .with_client_udp(bound.clone())
        .with_server_coordinator(punch.coordinator_session());
    let mut generation = reach.changes();
    let wake = Duration::from_millis(50);
    let position = reach.route_position();
    assert!(!position.udp_on && !position.server_punch);

    bound.set();
    tokio::time::timeout(wake, generation.changed())
        .await
        .expect("the bind wakes the generation");
    assert!(reach.route_position().udp_on);

    let (session, link, _sent) = crate::server_session::tests::fake_session(
        crate::server_session::tests::connected(),
        rmule_ed2k::ServerGrants::default(),
    );
    punch.go_live(&session);
    tokio::time::timeout(wake, generation.changed())
        .await
        .expect("a session going live wakes the generation");
    assert!(reach.route_position().server_punch);

    // The fake session's own exit writes its own cell, not this one: only the
    // weak link can say it is gone.
    drop(link);
    session.closed().await;
    assert!(
        !reach.route_position().server_punch,
        "a session that ended is no coordinator, cleared or not"
    );

    punch.go_dark(&session.coordinator_link());
    tokio::time::timeout(wake, generation.changed())
        .await
        .expect("going dark wakes the generation");
    bound.clear();
    tokio::time::timeout(wake, generation.changed())
        .await
        .expect("Quit's clear wakes the generation");
    assert!(!reach.route_position().udp_on);
}
