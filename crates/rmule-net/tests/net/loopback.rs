//! Two real `rmule_net::kad` nodes over localhost UDP bootstrap and converge —
//! the live half of the ADR-0043 tracer bullet, no Docker involved.
//!
//! The same conversation is driven over **both** transports (ADR-0057): a node
//! that binds its own Family Pair, and a node fed from a socket somebody else
//! owns, the way a core's client-UDP demux front feeds it. One body, two
//! transports — if the unified path ever diverged from the standalone one, the
//! bootstrap would stop converging here rather than in a live session.

use rmule_testkit::HANG_GUARD;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use rmule_kad::{KadCommand, KadEvent, KadId, KadNodeConfig, KadNodeEndpoint};
use rmule_net::ed2k::ClientUdpSocket;
use rmule_net::family::FamilySelection;
use rmule_net::kad::{
    KAD_INLET_CAPACITY, KadInlet, KadNetConfig, KadNetHandle, KadTraffic, spawn, spawn_over,
};
use rmule_primitives::{Ipv4Endpoint, PeerEndpoint};

fn id(byte: u8) -> KadId {
    KadId::from_bytes([byte; KadId::BYTE_LEN])
}

fn config(id_byte: u8) -> KadNetConfig {
    KadNetConfig {
        node: KadNodeConfig {
            id: id(id_byte),
            tcp_port: 4662,
            // The advertised UDP port is patched to the real bound port by the
            // spawn entry when it is 0.
            udp_port: 0,
            user_hash: rmule_kad::UserHash::from_bytes([id_byte; 16]),
        },
        capture_dir: None,
        nodes_dat_path: None,
        firewall_self_check: false,
        obfuscation: None,
        contact_admission: None,
    }
}

/// Which transport a node in this leg runs on.
#[derive(Clone, Copy, Debug)]
enum Transport {
    /// The driver binds and owns its Family Pair — the standalone node.
    Owned,
    /// A `ClientUdpSocket` somebody else owns feeds the node, and every answer
    /// leaves by that bind — the core's unified socket, minus the demux.
    Shared,
}

/// Start one node on `transport`, bound to an ephemeral loopback-reachable
/// port. The shared arm stands up the minimum a core's front does: drain the
/// socket, hand every IPv4 datagram to the inlet, and keep the socket alive
/// for the sends.
async fn start(transport: Transport, id_byte: u8) -> KadNetHandle {
    match transport {
        Transport::Owned => spawn(config(id_byte), SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("node binds"),
        Transport::Shared => {
            let socket = Arc::new(
                ClientUdpSocket::bind_with(0, FamilySelection::v4_only())
                    .await
                    .expect("shared socket binds"),
            );
            let (tx, datagrams) = tokio::sync::mpsc::channel(KAD_INLET_CAPACITY);
            let feed = Arc::clone(&socket);
            tokio::spawn(async move {
                while let Ok((bytes, from)) = feed.recv().await {
                    let PeerEndpoint::V4(from) = from else {
                        continue;
                    };
                    if tx.send((from, bytes)).await.is_err() {
                        return;
                    }
                }
            });
            spawn_over(
                config(id_byte),
                KadInlet {
                    datagrams,
                    socket: Arc::clone(&socket),
                    traffic: KadTraffic::default(),
                },
            )
            .await
            .expect("node starts over the shared socket")
        }
    }
}

async fn wait_for(
    handle: &mut KadNetHandle,
    mut predicate: impl FnMut(&KadEvent) -> bool,
) -> Vec<KadEvent> {
    let mut seen = Vec::new();
    tokio::time::timeout(HANG_GUARD, async {
        loop {
            let event = handle
                .next_event()
                .await
                .expect("driver stays alive while waiting");
            let done = predicate(&event);
            seen.push(event);
            if done {
                return;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for event; saw {seen:?}"));
    seen
}

/// The bootstrap conversation, run end to end on one transport.
async fn bootstrap_and_converge(transport: Transport) {
    let mut a = start(transport, 0xA1).await;
    let mut b = start(transport, 0xB1).await;

    let b_endpoint = KadNodeEndpoint::new(Ipv4Addr::LOCALHOST, b.local_addr().port());
    a.command(KadCommand::Bootstrap {
        endpoint: b_endpoint,
    })
    .await
    .expect("driver accepts commands");

    // A learns B live from the bootstrap response, then B's hello response
    // resolves A's probe.
    let a_events = wait_for(&mut a, |event| {
        *event == KadEvent::ContactResponded { id: id(0xB1) }
    })
    .await;
    assert!(
        a_events.contains(&KadEvent::ContactAdded {
            id: id(0xB1),
            endpoint: b_endpoint,
        }),
        "A stores B at its real localhost endpoint: {a_events:?}"
    );

    // B learns A from A's advertisement hello, at A's real bound port.
    let a_endpoint = KadNodeEndpoint::new(Ipv4Addr::LOCALHOST, a.local_addr().port());
    wait_for(&mut b, |event| {
        *event
            == KadEvent::ContactAdded {
                id: id(0xA1),
                endpoint: a_endpoint,
            }
    })
    .await;

    let a_summary = a.shutdown().await.expect("A shuts down cleanly");
    let b_summary = b.shutdown().await.expect("B shuts down cleanly");
    // A sent bootstrap req + hello req; B sent bootstrap res + hello res.
    assert_eq!(a_summary.datagrams_out, 2);
    assert_eq!(a_summary.datagrams_in, 2);
    assert_eq!(b_summary.datagrams_out, 2);
    assert_eq!(b_summary.datagrams_in, 2);
}

#[tokio::test]
async fn two_nodes_bootstrap_and_converge_over_localhost_udp() {
    bootstrap_and_converge(Transport::Owned).await;
}

#[tokio::test]
async fn two_nodes_bootstrap_and_converge_over_a_socket_they_do_not_own() {
    bootstrap_and_converge(Transport::Shared).await;
}

#[tokio::test]
async fn shutdown_without_traffic_reports_an_empty_summary() {
    let handle = spawn(config(0xC1), SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("node binds");
    let summary = handle.shutdown().await.expect("clean shutdown");
    assert_eq!(summary.datagrams_in, 0);
    assert_eq!(summary.datagrams_out, 0);
    assert_eq!(summary.non_ipv4_dropped, 0);
}

/// The socket's owner going away ends the node: the inlet closes, the driver
/// finishes its run and the handle reports the summary — it never spins on a
/// closed channel.
#[tokio::test]
async fn a_closed_inlet_ends_the_unified_driver() {
    let socket = Arc::new(
        ClientUdpSocket::bind_with(0, FamilySelection::v4_only())
            .await
            .expect("shared socket binds"),
    );
    let (tx, datagrams) = tokio::sync::mpsc::channel(KAD_INLET_CAPACITY);
    let handle = spawn_over(
        config(0xD1),
        KadInlet {
            datagrams,
            socket: Arc::clone(&socket),
            traffic: KadTraffic::default(),
        },
    )
    .await
    .expect("node starts over the shared socket");
    drop(tx);

    let summary = tokio::time::timeout(HANG_GUARD, handle.shutdown())
        .await
        .expect("the driver ends on its own when the inlet closes")
        .expect("clean shutdown");
    assert_eq!(summary.datagrams_in, 0);
}

/// A datagram handed to the inlet reaches the node byte for byte: the inlet
/// carries what arrived, not what the front thought it was.
#[tokio::test]
async fn an_injected_datagram_reaches_the_node_unaltered() {
    let socket = Arc::new(
        ClientUdpSocket::bind_with(0, FamilySelection::v4_only())
            .await
            .expect("shared socket binds"),
    );
    let (tx, datagrams) = tokio::sync::mpsc::channel(KAD_INLET_CAPACITY);
    let listener = spawn_over(
        config(0xE1),
        KadInlet {
            datagrams,
            socket: Arc::clone(&socket),
            traffic: KadTraffic::default(),
        },
    )
    .await
    .expect("node starts over the shared socket");

    // A real bootstrap request, captured off the wire rather than hand-framed:
    // a standalone node emits one at a plain socket, and those exact bytes go
    // into the unified node's inlet.
    let probe = ClientUdpSocket::bind_with(0, FamilySelection::v4_only())
        .await
        .expect("probe socket binds");
    let probe_port = probe.local_port();
    let speaker = spawn(config(0xF1), SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("speaker binds");
    speaker
        .command(KadCommand::Bootstrap {
            endpoint: KadNodeEndpoint::new(Ipv4Addr::LOCALHOST, probe_port),
        })
        .await
        .expect("driver accepts commands");
    let (bytes, _) = tokio::time::timeout(HANG_GUARD, probe.recv())
        .await
        .expect("the speaker emits its bootstrap request")
        .expect("receive succeeds");
    // The inlet's endpoint is what the answer is addressed to — not anything
    // inside the bytes — so naming the probe here is what brings the answer
    // back to it. That is the front's contract: it names the source, the node
    // trusts it.
    tx.send((
        Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, probe_port),
        bytes.clone(),
    ))
    .await
    .expect("the inlet takes it");

    // The node answered the injected datagram — on the shared socket, to the
    // endpoint the inlet named.
    let (answer, answered_to) = tokio::time::timeout(HANG_GUARD, probe.recv())
        .await
        .expect("the unified node answers the injected bootstrap")
        .expect("receive succeeds");
    assert_eq!(
        answered_to,
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, socket.local_port())),
        "the answer leaves by the shared bind, which is what a buddy observes"
    );
    assert_eq!(answer[0], 0xE4, "a plaintext Kad2 answer");

    let _ = speaker.shutdown().await;
    let summary = listener.shutdown().await.expect("clean shutdown");
    assert_eq!(summary.datagrams_in, 1);
    assert_eq!(summary.datagrams_out, 1);
}
