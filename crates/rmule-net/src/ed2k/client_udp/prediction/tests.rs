//! The Fan's ownership rules over real loopback sockets: a bind that fails
//! part-way leaves nothing behind, only the punch target's own endpoint is a
//! hit, and a socket lives exactly as long as its Fan or its Route does.

use std::sync::Mutex;
use std::time::Duration;

use super::*;

const ANSWER: &[u8] = &[0xC5, 0xA1];
const WAIT: Duration = Duration::from_secs(5);

fn loopback(port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
}

fn v4(addr: SocketAddrV4) -> PeerEndpoint {
    crate::family::endpoint_of(SocketAddr::V4(addr))
}

async fn bind_peer() -> (UdpSocket, SocketAddrV4) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind a loopback peer");
    let SocketAddr::V4(addr) = socket.local_addr().expect("peer addr") else {
        unreachable!("loopback is IPv4")
    };
    (socket, addr)
}

async fn recv_from(socket: &UdpSocket) -> (Vec<u8>, SocketAddrV4) {
    let mut buf = [0u8; 64];
    let (len, from) = tokio::time::timeout(WAIT, socket.recv_from(&mut buf))
        .await
        .expect("a datagram in time")
        .expect("recv");
    let SocketAddr::V4(from) = from else {
        unreachable!("loopback is IPv4")
    };
    (buf[..len].to_vec(), from)
}

async fn inlet_next(fans: &PredictionFans) -> (Vec<u8>, PeerEndpoint) {
    tokio::time::timeout(WAIT, async { fans.inlet().lock().await.recv().await })
        .await
        .expect("an inlet datagram in time")
        .expect("the inlet is open")
}

/// A binder that hands out real loopback sockets, remembering a weak handle
/// to each, and fails on call number `fail_at` (0-based).
fn recording_binder(
    fail_at: usize,
    seen: Arc<Mutex<Vec<Weak<UdpSocket>>>>,
) -> impl FnMut() -> io::Result<Arc<UdpSocket>> {
    let mut calls = 0;
    move || {
        let call = calls;
        calls += 1;
        if call == fail_at {
            return Err(io::Error::from(io::ErrorKind::AddrInUse));
        }
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        socket.set_nonblocking(true)?;
        let socket = Arc::new(UdpSocket::from_std(socket)?);
        seen.lock()
            .expect("recorded sockets")
            .push(Arc::downgrade(&socket));
        Ok(socket)
    }
}

/// The fourth bind of a six-socket Fan fails: the three bound before it are
/// closed, no reader holds one, the budget is whole and no Fan exists.
#[tokio::test]
async fn a_bind_that_fails_part_way_leaves_no_socket_and_no_reader() {
    let fans = PredictionFans::default();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let opened = fans.open_with(
        loopback(9),
        6,
        ANSWER.to_vec(),
        Arc::new(|_| {}),
        recording_binder(3, Arc::clone(&seen)),
    );
    assert!(opened.is_err(), "the fan does not open");
    // Let any reader that was (wrongly) spawned get scheduled once.
    tokio::task::yield_now().await;
    let seen = seen.lock().expect("recorded sockets");
    assert_eq!(seen.len(), 3, "three binds succeeded before the failure");
    assert!(
        seen.iter().all(|socket| socket.upgrade().is_none()),
        "no reader task holds a socket the failed fan bound"
    );
    assert_eq!(fans.open_sockets(), 0);
    assert!(fans.fans.lock().expect("fans").is_empty());
}

/// The Fan is for one endpoint. A datagram from the peer's address on another
/// port is neither a hit nor delivered; the peer's own then is both.
#[tokio::test]
async fn a_datagram_from_the_peer_address_on_a_foreign_port_installs_no_route() {
    let fans = PredictionFans::default();
    let (peer, peer_addr) = bind_peer().await;
    let (stranger, stranger_addr) = bind_peer().await;
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    let fan = fans
        .open(
            peer_addr,
            1,
            ANSWER.to_vec(),
            Arc::new(move |_| {
                counted.fetch_add(1, Ordering::Relaxed);
            }),
        )
        .await
        .expect("open the fan");
    assert_eq!(
        fans.burst(fan, peer_addr, b"punch", Duration::ZERO).await,
        1
    );
    let (_, fan_socket) = recv_from(&peer).await;

    stranger
        .send_to(b"stranger", fan_socket)
        .await
        .expect("stranger send");
    peer.send_to(b"probe", fan_socket).await.expect("peer send");

    // Only the peer's datagram comes through, and it is the first the inlet
    // sees: the stranger's was dropped ahead of it.
    let (bytes, from) = inlet_next(&fans).await;
    assert_eq!((bytes.as_slice(), from), (&b"probe"[..], v4(peer_addr)));
    assert_eq!(hits.load(Ordering::Relaxed), 1);
    assert!(fans.route(v4(stranger_addr)).is_none());
    assert!(fans.route(v4(peer_addr)).is_some());
    let (answer, _) = recv_from(&peer).await;
    assert_eq!(answer, ANSWER, "the hit is answered to the peer");
    assert!(
        tokio::time::timeout(
            Duration::from_millis(200),
            stranger.recv_from(&mut [0u8; 8])
        )
        .await
        .is_err(),
        "the stranger is answered nothing"
    );
}

/// A Fan's close drops every socket without a route, reader included; the
/// routed socket lives on with its route and keeps reading; releasing the
/// route closes it and its reader, and the budget reads zero again.
#[tokio::test]
async fn a_socket_lives_as_long_as_its_fan_or_its_route() {
    let fans = PredictionFans::default();
    let (peer, peer_addr) = bind_peer().await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let fan = fans
        .open_with(
            peer_addr,
            2,
            ANSWER.to_vec(),
            Arc::new(|_| {}),
            recording_binder(usize::MAX, Arc::clone(&seen)),
        )
        .expect("open the fan");
    assert_eq!(fans.open_sockets(), 2);
    assert_eq!(
        fans.burst(fan, peer_addr, b"punch", Duration::ZERO).await,
        2
    );
    let (_, hit) = recv_from(&peer).await;
    let _ = recv_from(&peer).await;
    peer.send_to(b"probe", hit).await.expect("probe");
    let _ = inlet_next(&fans).await;
    let _ = recv_from(&peer).await; // the answer

    fans.close(fan, true);
    tokio::task::yield_now().await;
    assert_eq!(fans.open_sockets(), 1, "only the routed socket survives");
    let alive: Vec<Arc<UdpSocket>> = seen
        .lock()
        .expect("recorded sockets")
        .iter()
        .filter_map(Weak::upgrade)
        .collect();
    assert_eq!(alive.len(), 1);
    assert_eq!(
        alive[0].local_addr().expect("addr").port(),
        hit.port(),
        "the survivor is the socket the route holds"
    );
    drop(alive);

    // Still read on, still routed.
    peer.send_to(b"more", hit).await.expect("second datagram");
    let (bytes, _) = inlet_next(&fans).await;
    assert_eq!(bytes, b"more");
    assert!(fans.route(v4(peer_addr)).is_some());

    fans.release(peer_addr);
    tokio::task::yield_now().await;
    assert_eq!(fans.open_sockets(), 0);
    assert!(fans.route(v4(peer_addr)).is_none());
    assert!(
        seen.lock()
            .expect("recorded sockets")
            .iter()
            .all(|socket| socket.upgrade().is_none()),
        "no reader survives the route's release"
    );
}

/// The budget is node-wide across Fans: a second Fan gets only the room the
/// first left, and a third gets nothing until one closes.
#[tokio::test]
async fn fans_share_one_socket_budget() {
    let fans = PredictionFans::default();
    let first = fans
        .open(
            loopback(9),
            PREDICTION_SOCKET_BUDGET - 3,
            ANSWER.to_vec(),
            Arc::new(|_| {}),
        )
        .await
        .expect("the first fan opens");
    assert_eq!(fans.open_sockets(), PREDICTION_SOCKET_BUDGET - 3);
    let second = fans
        .open(loopback(9), 8, ANSWER.to_vec(), Arc::new(|_| {}))
        .await
        .expect("the second fan opens what is left");
    assert_eq!(fans.open_sockets(), PREDICTION_SOCKET_BUDGET);
    assert_eq!(
        fans.fans.lock().expect("fans")[&second.0].sockets.len(),
        3,
        "the second fan is cut to the room left"
    );
    assert!(
        fans.open(loopback(9), 1, ANSWER.to_vec(), Arc::new(|_| {}))
            .await
            .is_err(),
        "no room at all is a refusal"
    );
    fans.close(first, false);
    assert_eq!(fans.open_sockets(), 3);
}

/// A receive error on a Fan socket — here the ICMP port-unreachable a
/// connected socket reports after sending to a closed port — is tolerated,
/// and the peer's datagram that follows still arrives as a hit.
#[tokio::test]
async fn a_receive_error_leaves_the_fan_reader_listening() {
    let fans = PredictionFans::default();
    let (peer, peer_addr) = bind_peer().await;
    let fan_socket: Arc<Mutex<Option<Arc<UdpSocket>>>> = Arc::new(Mutex::new(None));
    let kept = Arc::clone(&fan_socket);
    fans.open_with(
        peer_addr,
        1,
        ANSWER.to_vec(),
        Arc::new(|_| {}),
        move || {
            let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
            // Connected, so the platform reports the ICMP answer to a
            // datagram it sent as an error on the next receive.
            socket.connect(peer_addr)?;
            socket.set_nonblocking(true)?;
            let socket = Arc::new(UdpSocket::from_std(socket)?);
            *kept.lock().expect("fan socket") = Some(Arc::clone(&socket));
            Ok(socket)
        },
    )
    .expect("open the fan");
    let socket = fan_socket
        .lock()
        .expect("fan socket")
        .clone()
        .expect("the binder ran");
    let SocketAddr::V4(fan_addr) = socket.local_addr().expect("fan addr") else {
        unreachable!("loopback is IPv4")
    };

    // The peer's port closes, the Fan sends into it, and the ICMP answer
    // lands on the Fan socket's next receive.
    drop(peer);
    socket.send(b"probe").await.expect("send into the closed port");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let peer = UdpSocket::bind(SocketAddr::V4(peer_addr))
        .await
        .expect("the peer's port binds again");
    peer.send_to(b"answer", fan_addr).await.expect("peer send");
    let (bytes, from) = inlet_next(&fans).await;
    assert_eq!((bytes.as_slice(), from), (&b"answer"[..], v4(peer_addr)));
}
