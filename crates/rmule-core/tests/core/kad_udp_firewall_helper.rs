//! rmule as **UDP Firewall Helper**, end to end (ADR-0058): a
//! stranger dials a production Core's eD2k port, completes the hello and
//! sends `OP_FWCHECKUDPREQ` (`0xA7`); the Core's Kad node answers
//! `KADEMLIA2_FIREWALLUDP` (`0x62`) at the port the request named, from its
//! Kad socket — aMule `ClientTCPSocket.cpp:1942-1948` →
//! `BaseClient.cpp:4021-4030`.

use rmule_testkit::HANG_GUARD;
use std::net::{Ipv4Addr, SocketAddrV4};

use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, KadEnableConfig, KadId, ServeCommand, ServeEvent,
};
use rmule_peer::{PeerCommand, PeerHandshakeContext, SideCommand};
use rmule_primitives::{ClientId, ClientIdentity, Ed2kText, Ipv4Endpoint, PeerEndpoint, UserHash};
use tokio::time::timeout;

fn reserve_tcp_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

async fn until(core: &mut Core, wanted: impl Fn(&CoreEvent) -> bool) {
    loop {
        let event = timeout(HANG_GUARD, core.next_event())
            .await
            .expect("core emitted the awaited event")
            .expect("core event stream stayed open");
        if wanted(&event) {
            return;
        }
    }
}

#[tokio::test]
async fn an_inbound_0xa7_draws_a_0x62_at_the_requested_port() {
    let tcp = reserve_tcp_port();
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings {
            nickname: "rmule-helper".to_owned(),
            tcp_port: tcp,
            ..rmule_core::CoreSettings::default()
        })
        .kad_id(KadId::from_bytes([0xA2; KadId::BYTE_LEN]))
        .build();
    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, tcp),
    }))
    .await
    .unwrap();
    until(&mut core, |event| {
        matches!(event, CoreEvent::Serve(ServeEvent::ServingStarted { .. }))
    })
    .await;
    core.send(CoreCommand::EnableKad(KadEnableConfig {
        bootstrap: Vec::new(),
        contacts: Vec::new(),
        nodes_dat_path: None,
        assume_open_reachability: false,
        kad_capture_dir: None,
        kad_shutdown: None,
    }))
    .await
    .unwrap();
    // Kad is up once the snapshot names a node — the moment a hello may
    // name its Kad port (aMule's `Kademlia::IsRunning() ? kadPort : 0`).
    timeout(HANG_GUARD, async {
        loop {
            core.send(CoreCommand::DumpDiagnostics).await.unwrap();
            if let Some(CoreEvent::DiagnosticsSnapshot { snapshot }) = core.next_event().await
                && snapshot.kad.is_some()
            {
                return;
            }
        }
    })
    .await
    .expect("Kad started");
    let drain = tokio::spawn(async move { while core.next_event().await.is_some() {} });

    // The requester's Kad socket: where it asks the helper to answer.
    let requester_udp = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = requester_udp.local_addr().unwrap().port();
    let mut request = port.to_le_bytes().to_vec();
    request.extend_from_slice(&0u16.to_le_bytes()); // no distinct extern port
    request.extend_from_slice(&0u32.to_le_bytes()); // no verify key

    let ctx = PeerHandshakeContext {
        identity: ClientIdentity::new(
            UserHash::from_bytes([0xB3; UserHash::BYTE_LEN]),
            Ed2kText::from_utf8("udp-requester"),
            4662,
            0x3C,
        ),
        client_id: ClientId::from_u32(0),
        ed2k_client_id: ClientId::from_u32(0),
        public_ip: None,
        connected_server: None,
    };
    // The first peer the listener admits since Kad came up: its hello answer
    // must already say what an aMule requester checks before it sends the
    // request (`BaseClient.cpp:3972-3979`) — a Kad port and a Kad version of
    // at least 6.
    let (conn, helper) = rmule_net::peer::Connection::connect_identified(
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, tcp)),
        ctx,
        rmule_net::peer::ConnectOptions::default(),
    )
    .await
    .expect("the Core accepts the requester's dial");
    assert!(
        helper.serves_udp_firewall_checks(),
        "the hello answer names the running Kad node's port and version"
    );
    conn.send(PeerCommand::Side(SideCommand::SendKadUdpFirewallRequest {
        request,
    }))
    .await
    .expect("the request goes out");
    let mut buffer = [0u8; 64];
    let (len, _) = timeout(HANG_GUARD, requester_udp.recv_from(&mut buffer))
        .await
        .expect("the Core answered 0x62")
        .unwrap();
    let answer = buffer[..len].to_vec();
    let _ = conn.shutdown().await;

    let mut expected = vec![0xE4, 0x62, 0x00];
    expected.extend_from_slice(&port.to_le_bytes());
    assert_eq!(
        answer, expected,
        "an unbiased 0x62 naming the tested port, as BaseClient.cpp:4021-4030 writes it"
    );
    drain.abort();
}

/// rmule as **requester** of the same check: before its UDP
/// self-check may engage a helper it must learn the port a NAT maps its Kad
/// socket to, so a Kad-enabled Core pings a contact with `KADEMLIA2_PING`
/// (`0x60`) at once — aMule's cadence in `Kademlia.cpp:223-243`. The helper
/// gate itself is pinned sans-I/O (`rmule-kad`'s `node_extern_port`): on
/// loopback every observer shares `127.0.0.1`, so the two agreeing
/// observers that settle the port cannot exist in-process.
#[tokio::test]
async fn a_kad_core_pings_a_contact_for_its_extern_port() {
    let contact = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let contact_port = contact.local_addr().unwrap().port();
    let tcp = reserve_tcp_port();
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings {
            nickname: "rmule-asker".to_owned(),
            tcp_port: tcp,
            ..rmule_core::CoreSettings::default()
        })
        .kad_id(KadId::from_bytes([0xA3; KadId::BYTE_LEN]))
        .build();
    core.send(CoreCommand::EnableKad(KadEnableConfig {
        bootstrap: Vec::new(),
        contacts: vec![rmule_kad::KadContact::new(
            KadId::from_bytes([0x5C; KadId::BYTE_LEN]),
            rmule_kad::KadNodeEndpoint::new(Ipv4Addr::LOCALHOST, contact_port),
            4662,
            8,
        )],
        nodes_dat_path: None,
        assume_open_reachability: false,
        kad_capture_dir: None,
        kad_shutdown: None,
    }))
    .await
    .unwrap();
    let drain = tokio::spawn(async move { while core.next_event().await.is_some() {} });

    // The join hellos reach the contact too; wait for the ping among them.
    let ping = [0xE4, 0x60];
    let asker = timeout(HANG_GUARD, async {
        let mut buffer = [0u8; 256];
        loop {
            let (len, from) = contact.recv_from(&mut buffer).await.unwrap();
            if buffer[..len] == ping {
                return from;
            }
        }
    })
    .await
    .expect("the Core pinged its contact for its extern port");
    drain.abort();
    assert_eq!(
        asker.ip(),
        std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
        "from its Kad socket"
    );
}
