//! Server-UDP datagram socket loopback: a datagram sent A→B arrives
//! intact at B with A's source endpoint.
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use rmule_net::ed2k::ServerUdpSocket;

#[tokio::test]
async fn datagram_round_trips_with_source_endpoint() {
    let a = ServerUdpSocket::bind().await.unwrap();
    let b = ServerUdpSocket::bind().await.unwrap();
    // Both bind the wildcard address in both families (a Family Pair); reach
    // B over loopback, since a wildcard address is not a sendable destination.
    let b_dest = SocketAddrV4::new(Ipv4Addr::LOCALHOST, b.local_port());

    a.send_to(b_dest, b"glob-get-sources").await.unwrap();

    let (data, src) = tokio::time::timeout(Duration::from_secs(2), b.recv())
        .await
        .expect("datagram within 2s")
        .expect("recv ok");
    assert_eq!(data, b"glob-get-sources");
    assert_eq!(src.port(), a.local_port(), "recv reports the sender's port");
}
