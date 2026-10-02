//! Offline replay proving the cross-service composition pattern end-to-end:
//! mock eD2k server + mock peer + real `rmule_net::ed2k::Connection` + real
//! `rmule_net::peer::Connection`. No live network required.

use std::net::Ipv4Addr;
use std::time::Duration;

use rmule_ed2k::{Ed2kEvent, IdChange, LoginRequest, PeerCallback};
use rmule_net::ed2k::{ConnectOptions, Connection};
use rmule_net::peer::{ConnectOptions as PeerOptions, Connection as PeerConnection};
use rmule_peer::{HelloAnswer, PeerEvent, PeerHandshakeContext, PeerHelloBody};
use rmule_primitives::{
    ClientId, ClientIdentity, Ed2kText, Ipv4Endpoint, Packet, ServerEndpoint, Tag, TagName,
    TagValue, UserHash,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn identity() -> ClientIdentity {
    ClientIdentity::new(
        UserHash::from_bytes([0x77; UserHash::BYTE_LEN]),
        Ed2kText::from_utf8("rmule-replay"),
        4662,
        60,
    )
}

fn answer_bytes() -> Vec<u8> {
    let body = PeerHelloBody {
        user_hash: UserHash::from_bytes([0xEE; UserHash::BYTE_LEN]),
        client_id: ClientId::from_u32(0x10000003),
        tcp_port: 4662,
        tags: vec![Tag::new(
            TagName::length_prefixed_id(0x01),
            TagValue::String(Ed2kText::from_utf8("mock-peer")),
        )],
        connected_server: Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0),
    };
    HelloAnswer::new(body).encode_packet().encode()
}

#[tokio::test]
async fn callback_replay_drives_server_then_peer_dial() {
    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    let peer_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer_listener.local_addr().unwrap();

    // Bound on the loopback literal: the address is known, only the port was
    // the OS's to choose.
    let peer_v4 = std::net::Ipv4Addr::LOCALHOST;

    // Mock server: read login, write id_change + callback notification.
    let server_task = tokio::spawn(async move {
        let (mut sock, _) = server_listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = sock.read(&mut buf).await.unwrap();
        let (login_packet, _) = Packet::decode(&buf[..n]).expect("login frame");
        let _ = LoginRequest::decode_packet(&login_packet).expect("login decodes");

        let id_change = IdChange {
            client_id: ClientId::from_u32(0x10000001),
            tcp_flags: None,
            standard_tcp_port: None,
            public_ip: None,
            obfuscation_tcp_port: None,
            trailing: Vec::new(),
        };
        sock.write_all(&id_change.encode_packet().encode())
            .await
            .unwrap();

        let cb = PeerCallback::new(Ipv4Endpoint::new(peer_v4, peer_addr.port()));
        sock.write_all(&cb.encode_packet().encode()).await.unwrap();

        // Wait until client closes.
        let mut sink = [0u8; 256];
        let _ = sock.read(&mut sink).await;
    });

    // Mock peer: read hello, write hello_answer.
    let peer_task = tokio::spawn(async move {
        let (mut sock, _) = peer_listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = sock.read(&mut buf).await.unwrap();
        assert!(n > 0, "received hello bytes");
        sock.write_all(&answer_bytes()).await.unwrap();
        let mut sink = [0u8; 256];
        let _ = sock.read(&mut sink).await;
    });

    let server_endpoint =
        ServerEndpoint::parse_host_port(&format!("127.0.0.1:{}", server_addr.port())).unwrap();
    let mut server_conn = Connection::connect_with_options(
        server_endpoint,
        identity(),
        ConnectOptions {
            connect_timeout: Duration::from_secs(2),
            login_timeout: Duration::from_secs(2),
            capture_dir: None,
            obfuscation: None,
            advertised_ipv6: None,
            udp_ports: None,
        },
    )
    .await
    .expect("connect server");

    let mut observed_callback = None;
    let mut client_id = None;
    while let Some(event) = server_conn.next_event().await {
        if let Ed2kEvent::LoginAccepted { client_id: id, .. } = &event {
            client_id = Some(*id);
        }
        if let Ed2kEvent::PeerCallbackRequested { peer, .. } = event {
            observed_callback = Some(peer);
            break;
        }
    }
    let peer = observed_callback.expect("PeerCallbackRequested arrived");
    let client_id = client_id.expect("LoginAccepted observed");

    let ctx = PeerHandshakeContext {
        identity: identity(),
        client_id,
        connected_server: Some(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, server_addr.port())),
    };
    let mut peer_conn = PeerConnection::connect(
        peer,
        ctx,
        PeerOptions {
            connect_timeout: Duration::from_secs(2),
            hello_timeout: Duration::from_secs(2),
            capture_dir: None,
            ..Default::default()
        },
    )
    .await
    .expect("connect peer");

    let mut identified = false;
    while let Some(event) = peer_conn.next_event().await {
        if let PeerEvent::PeerIdentified { identity } = &event {
            assert_eq!(
                identity.nickname().map(|n| n.to_display_string()),
                Some("mock-peer".to_owned())
            );
            identified = true;
            break;
        }
        if matches!(event, PeerEvent::Disconnected { .. }) {
            break;
        }
    }
    assert!(identified, "peer side reached PeerIdentified");

    peer_conn.shutdown().await.expect("peer shutdown");
    server_conn.shutdown().await.expect("server shutdown");
    let _ = server_task.await;
    let _ = peer_task.await;
}
