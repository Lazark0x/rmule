//! The **Prediction Fan** over real loopback sockets (ADR-0091's
//! port-prediction amendment): a Fan's burst leaves from as many ports as it
//! has sockets, a reply to one of them is a hit that routes the peer there and
//! is answered once, and the hit datagram reaches the ordinary `recv` as the
//! peer's.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rmule_net::ed2k::ClientUdpSocket;
use rmule_net::family::FamilySelection;
use rmule_primitives::{Ipv4Endpoint, PeerEndpoint};
use tokio::net::UdpSocket;

const ANSWER: &[u8] = &[0xC5, 0xA1];
const WAIT: Duration = Duration::from_secs(5);

async fn recv_from(socket: &UdpSocket) -> (Vec<u8>, SocketAddrV4) {
    let mut buf = [0u8; 64];
    let (len, from) = tokio::time::timeout(WAIT, socket.recv_from(&mut buf))
        .await
        .expect("a datagram in time")
        .expect("recv");
    let SocketAddr::V4(from) = from else {
        panic!("loopback is IPv4")
    };
    (buf[..len].to_vec(), from)
}

fn v4(addr: SocketAddrV4) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(*addr.ip(), addr.port()))
}

#[tokio::test]
async fn a_hit_routes_the_peer_through_its_fan_socket_and_joins_recv() {
    let node = ClientUdpSocket::bind_with(0, FamilySelection::v4_only())
        .await
        .expect("bind the client-UDP socket");
    let advertised = node.local_port();
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the peer");
    let SocketAddr::V4(peer_addr) = peer.local_addr().expect("peer addr") else {
        unreachable!()
    };
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    let fan = node
        .open_prediction_fan(
            peer_addr,
            4,
            ANSWER.to_vec(),
            Arc::new(move |_| {
                counted.fetch_add(1, Ordering::Relaxed);
            }),
        )
        .await
        .expect("open the fan");

    // Four sockets, four mappings: the burst leaves from four distinct ports,
    // none of them the advertised bind.
    let sent = node
        .prediction_fan_burst(fan, peer_addr, b"punch", Duration::ZERO)
        .await;
    assert_eq!(sent, 4);
    let mut sources = HashSet::new();
    for _ in 0..4 {
        let (bytes, from) = recv_from(&peer).await;
        assert_eq!(bytes, b"punch");
        sources.insert(from.port());
    }
    assert_eq!(sources.len(), 4);
    assert!(!sources.contains(&advertised));

    // The peer reaches one of them: that is the hit.
    let hit = SocketAddrV4::new(Ipv4Addr::LOCALHOST, *sources.iter().next().unwrap());
    peer.send_to(b"probe", hit).await.expect("probe");
    let (answer, answered_from) = recv_from(&peer).await;
    assert_eq!(answer, ANSWER, "the hit socket answers once");
    assert_eq!(answered_from, hit);
    let (bytes, from) = tokio::time::timeout(WAIT, node.recv())
        .await
        .expect("the hit reaches recv")
        .expect("recv");
    assert_eq!(bytes, b"probe");
    assert_eq!(from, v4(peer_addr));
    assert_eq!(hits.load(Ordering::Relaxed), 1);

    // Everything the node sends the peer now leaves by the hit socket, even
    // after the fan closes — the route kept it.
    node.close_prediction_fan(fan, true);
    node.send_to_peer(v4(peer_addr), b"tunnel")
        .await
        .expect("routed send");
    let (bytes, from) = recv_from(&peer).await;
    assert_eq!((bytes.as_slice(), from), (&b"tunnel"[..], hit));
    peer.send_to(b"more", hit).await.expect("second datagram");
    let (bytes, _) = tokio::time::timeout(WAIT, node.recv())
        .await
        .expect("the routed socket still reads")
        .expect("recv");
    assert_eq!(bytes, b"more");

    // Released, the peer is back on the advertised bind.
    node.release_prediction_route(peer_addr);
    node.send_to_peer(v4(peer_addr), b"plain")
        .await
        .expect("plain send");
    let (bytes, from) = recv_from(&peer).await;
    assert_eq!(bytes, b"plain");
    assert_eq!(from.port(), advertised);
}

#[tokio::test]
async fn a_fan_closed_without_keeping_routes_leaves_the_advertised_bind() {
    let node = ClientUdpSocket::bind_with(0, FamilySelection::v4_only())
        .await
        .expect("bind the client-UDP socket");
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the peer");
    let SocketAddr::V4(peer_addr) = peer.local_addr().expect("peer addr") else {
        unreachable!()
    };
    let fan = node
        .open_prediction_fan(peer_addr, 2, ANSWER.to_vec(), Arc::new(|_| {}))
        .await
        .expect("open the fan");
    node.prediction_fan_burst(fan, peer_addr, b"punch", Duration::ZERO)
        .await;
    let (_, first) = recv_from(&peer).await;
    let _ = recv_from(&peer).await;
    peer.send_to(b"probe", first).await.expect("probe");
    let _ = recv_from(&peer).await; // the answer
    let _ = tokio::time::timeout(WAIT, node.recv()).await.expect("hit");

    node.close_prediction_fan(fan, false);
    node.send_to_peer(v4(peer_addr), b"plain")
        .await
        .expect("plain send");
    let (_, from) = recv_from(&peer).await;
    assert_eq!(from.port(), node.local_port());
}
