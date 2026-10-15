//! Family Pair unit tests: the receive-error budget, the ephemeral pair's
//! one shared port and its re-roll on an IPv6 collision, the one pump that
//! merges both families, and the Windows ICMP-reset switch.

use super::*;

#[test]
fn a_budget_tolerates_errors_below_the_threshold() {
    let mut budget = ReceiveErrorBudget::new();
    for _ in 0..RECEIVE_ERROR_BUDGET - 1 {
        assert_eq!(
            budget.record_error(io::ErrorKind::Other),
            ReceiveErrorOutcome::Tolerated
        );
    }
}

#[test]
fn a_budget_exhausts_at_the_threshold_naming_the_kind_and_count() {
    let mut budget = ReceiveErrorBudget::new();
    for _ in 0..RECEIVE_ERROR_BUDGET - 1 {
        let _ = budget.record_error(io::ErrorKind::ConnectionReset);
    }
    assert_eq!(
        budget.record_error(io::ErrorKind::ConnectionReset),
        ReceiveErrorOutcome::Exhausted {
            kind: io::ErrorKind::ConnectionReset,
            consecutive: RECEIVE_ERROR_BUDGET,
        }
    );
}

#[test]
fn a_success_between_errors_resets_the_budget() {
    let mut budget = ReceiveErrorBudget::new();
    for _ in 0..RECEIVE_ERROR_BUDGET - 1 {
        let _ = budget.record_error(io::ErrorKind::Other);
    }
    budget.record_success();
    // The near-exhausted streak is gone: another full run tolerates.
    for _ in 0..RECEIVE_ERROR_BUDGET - 1 {
        assert_eq!(
            budget.record_error(io::ErrorKind::Other),
            ReceiveErrorOutcome::Tolerated
        );
    }
}

#[tokio::test]
async fn an_ephemeral_pair_shares_one_port_across_both_families() {
    let pair = UdpFamilyPair::bind(0, FamilySelection::default())
        .await
        .expect("at least one family binds on any host");
    assert_ne!(pair.local_port(), 0, "the ephemeral port resolved");
    assert!(
        !pair.binds().bound.is_empty(),
        "a pair with no family is an error, not a pair"
    );
    for socket in [&pair.v4, &pair.v6].into_iter().flatten() {
        assert_eq!(
            socket.local_addr().expect("bound").port(),
            pair.local_port(),
            "every bound half sits on the one advertised port"
        );
    }
}

/// A scripted bind: `taken` ports refuse IPv6 with `AddrInUse`, `absent`
/// refuses IPv6 outright, and each IPv4 ephemeral bind gets the next
/// number from `next`.
fn scripted_bind(
    next: &std::cell::Cell<u16>,
    taken: &[u16],
    absent: bool,
) -> impl Fn(SocketAddr) -> io::Result<((), u16)> {
    move |addr| match addr {
        SocketAddr::V4(_) if addr.port() == 0 => {
            next.set(next.get() + 1);
            Ok(((), next.get()))
        }
        SocketAddr::V4(_) => Ok(((), addr.port())),
        SocketAddr::V6(_) if absent => Err(io::ErrorKind::Unsupported.into()),
        SocketAddr::V6(_) if taken.contains(&addr.port()) => Err(io::ErrorKind::AddrInUse.into()),
        SocketAddr::V6(_) => Ok(((), addr.port())),
    }
}

/// An ephemeral IPv4 port that IPv6 already holds
/// is a collision, not an absent family, so the pair re-rolls and comes up
/// whole on a fresh number instead of silently IPv4-only.
#[test]
fn an_ephemeral_collision_on_the_ipv6_half_rebinds_the_whole_pair() {
    let next = std::cell::Cell::new(40_000);
    let bind = scripted_bind(&next, &[40_001, 40_002], false);
    let (v4, v6, port, binds) = bind_pair(0, FamilySelection::default(), bind).expect("bind");
    assert_eq!(port, 40_003);
    assert!(v4.is_some() && v6.is_some(), "both halves on one port");
    assert!(
        binds.refused.is_empty(),
        "a re-rolled collision is not a refusal"
    );
}

/// Only a collision re-rolls: an absent family, or a port the operator
/// chose, keeps the first outcome; and the re-roll is bounded.
#[test]
fn only_an_ephemeral_collision_rerolls_and_only_a_bounded_number_of_times() {
    let next = std::cell::Cell::new(40_000);
    let (_, v6, port, _) = bind_pair(
        0,
        FamilySelection::default(),
        scripted_bind(&next, &[], true),
    )
    .expect("bind");
    assert_eq!((v6, port), (None, 40_001), "an absent family is final");

    let (_, v6, port, _) = bind_pair(
        4672,
        FamilySelection::default(),
        scripted_bind(&next, &[4672], false),
    )
    .expect("bind");
    assert_eq!((v6, port), (None, 4672), "a chosen port is never moved");

    let next = std::cell::Cell::new(40_000);
    let every: Vec<u16> = (40_001..=40_100).collect();
    let (v4, v6, _, binds) = bind_pair(
        0,
        FamilySelection::default(),
        scripted_bind(&next, &every, false),
    )
    .expect("bind");
    assert_eq!(next.get(), 40_000 + EPHEMERAL_PAIR_ATTEMPTS as u16);
    assert!(v4.is_some() && v6.is_none(), "settles for the half it has");
    assert_eq!(binds.refused.len(), 1);
}

#[tokio::test]
async fn a_pair_receives_on_the_family_the_sender_used() {
    let pair = UdpFamilyPair::bind(0, FamilySelection::default())
        .await
        .expect("bind");
    let sender = UdpFamilyPair::bind(0, FamilySelection::v4_only())
        .await
        .expect("bind");
    let target = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, pair.local_port()));

    sender.send_to(target, b"ping").await.expect("send");
    let mut scratch = [0u8; 64];
    let (len, from) = pair.recv(&mut scratch).await.expect("recv");
    assert_eq!(&scratch[..len], b"ping");
    assert_eq!(from.family(), AddressFamily::V4);
}

#[tokio::test]
async fn sending_to_an_unbound_family_is_refused_not_dropped() {
    let pair = UdpFamilyPair::bind(0, FamilySelection::v4_only())
        .await
        .expect("bind");
    let v6 = PeerEndpoint::V6(Ipv6Endpoint::new(Ipv6Addr::LOCALHOST, 4662));
    let error = pair.send_to(v6, b"ping").await.expect_err("no v6 socket");
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
}

#[tokio::test]
async fn one_pump_merges_both_families_in_whichever_order_they_arrive() {
    let pair = UdpFamilyPair::bind(0, FamilySelection::default())
        .await
        .expect("bind");
    if !pair.binds().holds(AddressFamily::V6) {
        // An IPv4-only host: the refused family is absent, which is the
        // documented outcome, and there is no merge left to prove.
        return;
    }
    let sender = UdpFamilyPair::bind(0, FamilySelection::default())
        .await
        .expect("bind");
    let port = pair.local_port();
    let v6 = PeerEndpoint::V6(Ipv6Endpoint::new(Ipv6Addr::LOCALHOST, port));
    let v4 = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, port));

    sender.send_to(v6, b"six").await.expect("send v6");
    let mut scratch = [0u8; 64];
    let (len, from) = pair.recv(&mut scratch).await.expect("recv v6");
    assert_eq!(
        (&scratch[..len], from.family()),
        (&b"six"[..], AddressFamily::V6)
    );

    sender.send_to(v4, b"four").await.expect("send v4");
    let (len, from) = pair.recv(&mut scratch).await.expect("recv v4");
    assert_eq!(
        (&scratch[..len], from.family()),
        (&b"four"[..], AddressFamily::V4),
        "the same pump serves the other family with no rebind"
    );
}

/// A restart binds its listener again at once, while the
/// connections the previous run closed still sit in `TIME_WAIT` on the port
/// (macOS holds them 2 × MSL = 30 s). The listener's side closes first — rmule
/// closing a peer link at Quit is exactly that — so the `TIME_WAIT` is on the
/// listening port itself.
#[tokio::test]
async fn a_listener_rebinds_its_port_at_once_after_it_closed_a_connection() {
    use tokio::io::AsyncReadExt;

    let pair = TcpFamilyPair::bind(0, FamilySelection::v4_only())
        .await
        .expect("bind");
    let port = pair.local_port();
    let mut dialer = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("dial");
    let (accepted, _) = pair.accept().await.expect("accept");
    drop(accepted);
    let mut rest = Vec::new();
    dialer
        .read_to_end(&mut rest)
        .await
        .expect("the FIN arrives");
    drop(dialer);
    drop(pair);

    let again = TcpFamilyPair::bind(port, FamilySelection::v4_only()).await;
    assert!(
        again.is_ok(),
        "the port's TIME_WAIT must not refuse the listener: {:?}",
        again.err()
    );
}

/// The listener's address options must not let a second rmule listen on a
/// port a running one holds: `SO_REUSEADDR` on Unix, none on Windows.
#[tokio::test]
async fn a_second_listener_on_a_held_port_is_still_refused() {
    let held = TcpFamilyPair::bind(0, FamilySelection::v4_only())
        .await
        .expect("bind");
    let second = TcpFamilyPair::bind(held.local_port(), FamilySelection::v4_only()).await;
    assert_eq!(
        second.err().map(|error| error.kind()),
        Some(io::ErrorKind::AddrInUse)
    );
}

/// Windows answers a datagram sent to a closed port with an error on the
/// sender's next receive; the ICMP-reset switch keeps the pair receiving the
/// next datagram instead, as Linux and macOS do. A socket bound without the
/// switch, given the same two datagrams, is the control: it must see the
/// reset, or this setup proves nothing about the switch.
#[cfg(windows)]
#[tokio::test]
async fn a_datagram_to_a_closed_port_leaves_the_next_receive_intact() {
    let closed = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let closed_port = closed.local_addr().expect("address").port();
    drop(closed);
    let pair = UdpFamilyPair::bind_literal((Ipv4Addr::LOCALHOST, 0).into())
        .await
        .expect("bind");
    let control = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    pair.send_to(
        endpoint_of((Ipv4Addr::LOCALHOST, closed_port).into()),
        b"to a stale contact",
    )
    .await
    .expect("send");
    control
        .send_to(b"to a stale contact", (Ipv4Addr::LOCALHOST, closed_port))
        .await
        .expect("send");
    // Loopback's port-unreachable lands well inside this, so a report left
    // switched on is queued ahead of the live datagrams below.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let live = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    for port in [
        pair.local_port(),
        control.local_addr().expect("address").port(),
    ] {
        live.send_to(b"live", (Ipv4Addr::LOCALHOST, port))
            .await
            .expect("send");
    }
    let mut scratch = [0_u8; 64];
    let unswitched = tokio::time::timeout(Duration::from_secs(2), control.recv_from(&mut scratch))
        .await
        .expect("the control's receive within 2s");
    assert_eq!(
        unswitched.err().map(|error| error.kind()),
        Some(io::ErrorKind::ConnectionReset),
        "without the switch the ICMP answer fails the next receive"
    );
    let (len, from) = tokio::time::timeout(Duration::from_secs(2), pair.recv(&mut scratch))
        .await
        .expect("a datagram within 2s")
        .expect("the receive after an ICMP unreachable still succeeds");
    assert_eq!(
        (&scratch[..len], from),
        (
            &b"live"[..],
            endpoint_of(live.local_addr().expect("address"))
        )
    );
}

/// A link-local source names no host without its scope id, so the receive and
/// accept edges refuse it; every other source, IPv6 global or IPv4, passes as
/// its endpoint.
#[test]
fn a_link_local_source_is_refused_at_the_edge() {
    let link_local: SocketAddr = "[fe80::1%1]:4672".parse().expect("a scoped address");
    assert_eq!(source_endpoint(link_local), None);
    let global: SocketAddr = "[2001:db8::1]:4672".parse().expect("an address");
    assert_eq!(source_endpoint(global), Some(endpoint_of(global)));
    let v4: SocketAddr = "198.51.100.1:4672".parse().expect("an address");
    assert_eq!(source_endpoint(v4), Some(endpoint_of(v4)));
}
