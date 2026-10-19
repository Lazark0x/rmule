//! **Port Prediction** at the front (ADR-0091's amendment): the role an
//! introduction starts comes from our Own Mapping, a peer's own two ports can
//! only veto it, a Fan opens 256 mappings toward the punch target from 256
//! distinct sockets, and a Probe waits for the Fan it is meant to meet before
//! drawing its 256 ports. And what may not start one: an
//! introduction with no attempt of ours behind it, a claimed target, a plan
//! past the caps; a Probe fires only once the peer has punched us; a plan's
//! end stops its sends and keeps a socket only for a Tunnel at its own
//! endpoint.

use std::collections::HashSet;

use rmule_net::ed2k::{ClientUdpSocket, PREDICTION_SOCKET_BUDGET};
use rmule_net::family::FamilySelection;
use rmule_peer::natt::{
    PREDICTION_FAN_SOCKETS, PROBE_DELAY, PROBE_PORTS, PortPrediction, PunchTargetSource,
};

use super::super::prediction::PREDICTION_FAN_PLANS_MAX;
use super::*;
use crate::address_learning::{AddressObservation, SharedAddressLearning};

/// A front whose knob is on, over a real loopback client-UDP socket, with
/// `ports` as this round's Kad reports from distinct observers, and the node
/// around it that a leg keeps alive.
async fn predicting(
    ports: &[u16],
) -> (
    NattFront<NullSink>,
    DiagnosticsState,
    Arc<ClientUdpSocket>,
    Surroundings,
) {
    let addresses = SharedAddressLearning::default();
    for (index, port) in ports.iter().enumerate() {
        let observer = Ipv4Addr::new(45, 55, 200, 50 + u8::try_from(index).unwrap());
        addresses.observe(AddressObservation::kad_observed_port(observer, *port));
    }
    let socket = Arc::new(
        ClientUdpSocket::bind_with(0, FamilySelection::v4_only())
            .await
            .expect("bind the client-UDP socket"),
    );
    let (client_udp, _sent) = mpsc::channel(1024);
    let diagnostics = DiagnosticsState::default();
    let own_identity = crate::own_identity::SharedOwnIdentity::default();
    own_identity.set_user_hash(hash(0xAA));
    let around = Surroundings::over(addresses.clone());
    let assembled = assemble(
        NullSink,
        NattIdentity {
            local: RMULE_NATT_CLAIM,
        },
        Arc::new(own_identity) as Arc<dyn NattOwnHash>,
        None,
        NattWiring {
            client_udp,
            server: around.server.clone(),
            reach: around.reach.clone(),
            addresses,
            admit: crate::adapters::SharedTunnelAdmit::default(),
            claims: crate::adapters::AwaitedInbound::default(),
            peer_pin: crate::adapters::SharedPeerPin::default(),
            roster: crate::peer_roster::SharedPeerRoster::default(),
            diagnostics: diagnostics.clone(),
            events: None,
            prediction: Some(PredictionWiring {
                knob: PortPrediction::Birthday,
                socket: Arc::clone(&socket),
            }),
        },
    )
    .expect("the uTP engine starts");
    (assembled.front, diagnostics, socket, around)
}

/// An introduction at `target`, as the side that did not ask: no dial.
fn introduced(peer: UserHash, target: Ipv4Endpoint) -> NattCommand {
    NattCommand::Introduced {
        peer_hash: peer,
        target,
        role: HolepunchRole::Responder,
        burst: false,
        source: PunchTargetSource::Observed,
    }
}

/// Open a server-coordinated **Traversal Attempt** toward `target`, so an
/// introduction naming it has an owner. `advertised_udp` is the candidate's
/// own client-UDP port, when the channel that named it carried one.
async fn begun(
    front: &mut NattFront<NullSink>,
    target: UserHash,
    low_id: u32,
    advertised_udp: Option<u16>,
) {
    front
        .on_command(
            NattCommand::Traverse {
                coordinator: AttemptCoordinator::Server {
                    low_id: ClientId::from_u32(low_id),
                },
                owner: Some(AttemptOwner {
                    target,
                    facts: crate::callback::NattFacts {
                        advertised_udp,
                        ..buddy_facts()
                    },
                    offer: RendezvousOffer {
                        our_user_hash: hash(0xAA),
                        options: NattConnectOptions::advertise(0, true, false),
                        file_hash: None,
                        claimed_endpoint: None,
                        transport: NattTransport::Utp,
                    },
                }),
            },
            Instant::now(),
        )
        .await;
}

/// TEST-NET-1: a burst or a probe set aimed here goes nowhere anyone listens.
fn nowhere(port: u16) -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(192, 0, 2, 1), port)
}

/// A loopback peer, and the punch target that names it.
async fn peer_socket() -> (tokio::net::UdpSocket, Ipv4Endpoint) {
    let peer = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the peer");
    let port = peer.local_addr().expect("peer addr").port();
    (peer, Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, port))
}

/// Wait for `holds` to become true, yielding to the front's tasks.
async fn until(what: &str, mut holds: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !holds() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

fn refusals(diagnostics: &DiagnosticsState) -> (u64, Option<PredictionRefusal>) {
    let session = diagnostics.snapshot().session;
    (
        session.natt_prediction_refusals_total,
        session.natt_last_prediction_refusal,
    )
}

/// Endpoint-dependent (three observers, three ports): the introduction of a
/// peer we hold an attempt toward opens a Fan at once, and the target sees
/// one `0xA1` from each of 256 distinct source ports — 256 mappings on a
/// real NAT.
#[tokio::test]
async fn an_endpoint_dependent_node_fans_256_sockets_at_the_punch_target() {
    let (mut front, diagnostics, _, _around) = predicting(&[31_004, 50_219, 7_781]).await;
    let (peer_socket, target) = peer_socket().await;
    begun(&mut front, hash(0x42), 7, None).await;

    front
        .on_command(introduced(hash(0x42), target), Instant::now())
        .await;

    let mut sources = HashSet::new();
    let mut buf = [0u8; 16];
    for _ in 0..PREDICTION_FAN_SOCKETS {
        let (len, from) =
            tokio::time::timeout(Duration::from_secs(10), peer_socket.recv_from(&mut buf))
                .await
                .expect("the fan's burst arrives")
                .expect("recv");
        assert_eq!(&buf[..len], holepunch_datagram().as_slice());
        sources.insert(from.port());
    }
    assert_eq!(sources.len(), PREDICTION_FAN_SOCKETS);
    // The burst's task records the attempt after its last send.
    until("the attempt to be counted", || {
        diagnostics
            .snapshot()
            .session
            .natt_prediction_attempts_total
            > 0
    })
    .await;
    let session = diagnostics.snapshot().session;
    assert_eq!(session.natt_prediction_probes_total, 256);
    assert_eq!(session.natt_prediction_refusals_total, 0);
}

/// Endpoint-independent (two observers, one port): nothing leaves at the
/// introduction, and nothing leaves three seconds later either until the
/// peer has punched us from the target's address — then a
/// Probe Set of 256 distinct ports is drawn. A punch from a port this side
/// punched — probed, or in the baseline sweep — is a hit and is answered
/// once; any other port is neither.
#[tokio::test]
async fn an_endpoint_independent_node_probes_after_the_fan_it_is_meant_to_meet() {
    let (mut front, diagnostics, _, _around) = predicting(&[4672, 4672]).await;
    let target = nowhere(38_211);
    let t0 = Instant::now();
    begun(&mut front, hash(0x42), 7, None).await;

    front.on_command(introduced(hash(0x42), target), t0).await;
    let drawn = front.predictions.probe_set(&hash(0x42)).expect("a plan");
    assert!(drawn.is_empty(), "the probe waits for the fan");

    // Due, but the peer has not been heard from: deferred, counted once.
    front.drive_predictions(t0 + PROBE_DELAY);
    assert!(front.predictions.probe_set(&hash(0x42)).unwrap().is_empty());
    assert_eq!(
        refusals(&diagnostics),
        (1, Some(PredictionRefusal::PeerSilent))
    );
    front.drive_predictions(t0 + PROBE_DELAY + Duration::from_secs(1));
    assert!(front.predictions.probe_set(&hash(0x42)).unwrap().is_empty());
    assert_eq!(refusals(&diagnostics).0, 1, "one deferral, one count");

    // The peer's own punch, from a Fan socket on its address: now it fires.
    front.note_probe_answer(Ipv4Endpoint::new(target.ip, 60_001));
    front.drive_predictions(t0 + PROBE_DELAY + Duration::from_secs(2));
    let set = front
        .predictions
        .probe_set(&hash(0x42))
        .expect("a plan")
        .clone();
    assert_eq!(set.len(), 256);
    assert!(set.iter().all(|port| PROBE_PORTS.contains(port)));

    // A port nobody punched is no hit and draws no answer; a probed one is
    // answered once, and a second punch from it is not answered again.
    let drawn = *set
        .iter()
        .find(|port| port.abs_diff(target.port) > 16)
        .unwrap();
    let unpunched = (1024..=65535)
        .find(|port| !set.contains(port) && port.abs_diff(target.port) > 16 && *port != 60_001)
        .unwrap();
    assert!(!front.note_probe_answer(Ipv4Endpoint::new(target.ip, unpunched)));
    assert!(front.note_probe_answer(Ipv4Endpoint::new(target.ip, drawn)));
    assert!(!front.note_probe_answer(Ipv4Endpoint::new(target.ip, drawn)));
    // The baseline sweep's ports are ours too: the Fan's mapping may sit there.
    assert!(front.note_probe_answer(Ipv4Endpoint::new(target.ip, target.port + 16)));
    assert_eq!(diagnostics.snapshot().session.natt_prediction_hits_total, 2);
}

/// The veto, joined through the attempt: a requester whose candidate
/// advertised 4672 is introduced at the port the server saw, 50 000. The peer
/// is hard; we are hard too; both-hard is the documented negative, so no plan
/// starts. With the ports agreeing the same node fans.
#[tokio::test]
async fn a_peer_whose_observed_port_is_not_its_advert_vetoes_our_fan() {
    for (introduced_port, plans) in [(50_000, false), (4672, true)] {
        let (mut front, _, _, _around) = predicting(&[31_004, 50_219, 7_781]).await;
        let target_hash = hash(0x42);
        begun(&mut front, target_hash, 7, Some(4672)).await;
        front
            .on_command(
                introduced(target_hash, nowhere(introduced_port)),
                Instant::now(),
            )
            .await;
        assert_eq!(
            front.predictions.probe_set(&target_hash).is_some(),
            plans,
            "introduced at {introduced_port}"
        );
    }
}

/// An introduction this node did not ask for — the Responder road, which any
/// stranger who knows a buddy pairing can drive — opens nothing: three from
/// fresh requester hashes leave no plan and no socket, and each is counted
/// (finding 1, finding 1).
#[tokio::test]
async fn a_strangers_introduction_plans_nothing_and_is_counted() {
    let (mut front, diagnostics, socket, _around) = predicting(&[31_004, 50_219, 7_781]).await;
    let (_peer_socket, target) = peer_socket().await;
    for fill in [0x01, 0x02, 0x03] {
        front
            .on_command(introduced(hash(fill), target), Instant::now())
            .await;
    }
    tokio::task::yield_now().await;
    assert_eq!(front.predictions.len(), 0, "no plan without an attempt");
    assert_eq!(socket.open_prediction_sockets(), 0);
    assert_eq!(
        refusals(&diagnostics),
        (3, Some(PredictionRefusal::NoAttempt))
    );
}

/// Attempts of our own toward three peers, all endpoint-dependent: one Fan
/// plan runs, the other two are refused and counted, and the sockets open
/// stay inside the budget (finding 1).
#[tokio::test]
async fn fan_plans_are_capped_node_wide() {
    let (mut front, diagnostics, socket, _around) = predicting(&[31_004, 50_219, 7_781]).await;
    let (_peer_socket, target) = peer_socket().await;
    for (fill, low_id) in [(0x01, 1), (0x02, 2), (0x03, 3)] {
        begun(&mut front, hash(fill), low_id, None).await;
        front
            .on_command(introduced(hash(fill), target), Instant::now())
            .await;
    }
    assert_eq!(front.predictions.len(), PREDICTION_FAN_PLANS_MAX);
    assert_eq!(refusals(&diagnostics), (2, Some(PredictionRefusal::FanCap)));
    until("the one fan to open", || {
        socket.open_prediction_sockets() >= PREDICTION_FAN_SOCKETS
    })
    .await;
    assert_eq!(socket.open_prediction_sockets(), PREDICTION_FAN_SOCKETS);
    assert!(socket.open_prediction_sockets() <= PREDICTION_SOCKET_BUDGET);
}

/// A target that is only the requester's own claim starts no plan, attempt
/// or not: the burst and the dial go there, 256 sockets do not.
#[tokio::test]
async fn a_claimed_target_starts_no_plan() {
    let (mut front, diagnostics, _, _around) = predicting(&[31_004, 50_219, 7_781]).await;
    begun(&mut front, hash(0x42), 7, None).await;
    front
        .on_command(
            NattCommand::Introduced {
                peer_hash: hash(0x42),
                target: nowhere(31_999),
                role: HolepunchRole::Responder,
                burst: false,
                source: PunchTargetSource::PublicClaim,
            },
            Instant::now(),
        )
        .await;
    assert_eq!(front.predictions.len(), 0);
    assert_eq!(
        refusals(&diagnostics),
        (1, Some(PredictionRefusal::ClaimedTarget))
    );
}

/// A plan that ends with no Tunnel keeps a Fan socket only for a path held
/// at the target's own endpoint. A path to another port on the same address
/// — another peer behind that NAT — keeps nothing (finding 3).
#[tokio::test]
async fn ending_a_plan_keeps_no_socket_for_another_peer_behind_the_address() {
    let (mut front, diagnostics, socket, _around) = predicting(&[31_004, 50_219, 7_781]).await;
    let (peer_socket, target) = peer_socket().await;
    begun(&mut front, hash(0x42), 7, None).await;
    front
        .on_command(introduced(hash(0x42), target), Instant::now())
        .await;
    // The peer answers the first Fan datagram it sees: a hit, a route.
    let mut buf = [0u8; 16];
    let (_, fan_socket) =
        tokio::time::timeout(Duration::from_secs(10), peer_socket.recv_from(&mut buf))
            .await
            .expect("the fan's burst arrives")
            .expect("recv");
    peer_socket
        .send_to(&holepunch_datagram(), fan_socket)
        .await
        .expect("punch back");
    until("the hit to be counted", || {
        diagnostics.snapshot().session.natt_prediction_hits_total == 1
    })
    .await;

    // Somebody else behind the target's address holds a punched path.
    let t0 = Instant::now();
    front.paths.on_path_open(
        Ipv4Endpoint::new(target.ip, target.port.wrapping_add(1)),
        4672,
        None,
        t0,
    );
    front.end_prediction(&hash(0x42), false);
    until("the fan to close", || socket.open_prediction_sockets() == 0).await;
    assert_eq!(front.predictions.len(), 0);
}

/// A plan's end stops the sends its attempt started: the target sees far
/// fewer than the Fan's 256 datagrams once the plan ended part-way through
/// the paced burst (finding 4).
#[tokio::test(start_paused = true)]
async fn ending_a_plan_stops_its_burst() {
    let (mut front, _, socket, _around) = predicting(&[31_004, 50_219, 7_781]).await;
    let (peer_socket, target) = peer_socket().await;
    begun(&mut front, hash(0x42), 7, None).await;
    front
        .on_command(introduced(hash(0x42), target), Instant::now())
        .await;
    let mut buf = [0u8; 16];
    let _ = tokio::time::timeout(Duration::from_secs(10), peer_socket.recv_from(&mut buf))
        .await
        .expect("the fan's burst starts")
        .expect("recv");

    front.end_prediction(&hash(0x42), false);
    let mut arrived = 1;
    // Paused time: each wait auto-advances, so a burst still running would
    // finish inside this loop and every datagram would count.
    while tokio::time::timeout(Duration::from_secs(1), peer_socket.recv_from(&mut buf))
        .await
        .is_ok()
    {
        arrived += 1;
    }
    assert!(
        arrived < PREDICTION_FAN_SOCKETS,
        "the burst was stopped, not run to its end: {arrived} arrived"
    );
    assert_eq!(socket.open_prediction_sockets(), 0);
}
