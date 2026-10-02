//! The **Callback Walk** driven by a real `Core`'s download: a
//! Kad buddy row that names its buddy by ID alone — `TAG_BUDDYHASH`, no
//! `TAG_SERVERIP`/`TAG_SERVERPORT` — reaches the buddy anyway, because the
//! download's Kad node walks toward that ID and sends the `0x52` to the node
//! sitting on it, as aMule's `FINDSOURCE` does (`BaseClient.cpp:2160-2170`).
//!
//! Everything is real but the publisher: the storer and the buddy are
//! `rmule_net::kad` nodes on loopback, and the downloader is a production
//! `Core` whose own Kad node finds the row, admits the road and walks. The
//! publisher is **stubbed** as one raw `KADEMLIA2_PUBLISH_SOURCE_REQ` from a
//! bare socket — the row an aMule publisher writes when its buddy's endpoint
//! reads zero — because an rmule publisher always knows its buddy's endpoint
//! and so never writes that shape. The buddy node holds no link to the
//! publisher, so the leg stops at the `0x52` it decodes: the dial-back and
//! its adoption are the endpoint-known leg's (`natt_buddy_download`), through
//! the same Dial-Back Claim.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadFailure, KadEnableConfig,
    PeerReachRoute, PeerTransferService, PeerWorker,
};
use rmule_kad::{KadBuddyContact, KadEvent, KadId, KadPublishedSource, KadSourceLookupRequest};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{Ed2kFileLink, PeerEndpoint, ServerEndpoint, SourceLookupTarget, UserHash};
use tokio::time::timeout;

/// The firewalled publisher's identity on the row.
const TARGET_HASH: UserHash = UserHash::from_bytes([0xAB; UserHash::BYTE_LEN]);
/// The buddy relationship ID the row names — and the buddy node's own Kad ID,
/// since the publisher recruited it by walking toward exactly this ID.
const BUDDY_ID: KadId = KadId::from_bytes([0x7A; KadId::BYTE_LEN]);

/// A buddy-reachable row has no dialable endpoint: a dial would mean the row
/// took the wrong road.
struct NeverDials;

impl PeerTransferService for NeverDials {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        _file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        panic!("a buddy-reachable Kad row has no dialable endpoint, yet {peer} was dialed");
    }
}

async fn kad_node(id: KadId) -> (rmule_net::kad::KadNetHandle, SocketAddrV4) {
    let handle = rmule_net::kad::spawn(
        rmule_net::kad::KadNetConfig {
            node: rmule_kad::KadNodeConfig {
                id,
                tcp_port: 4662,
                udp_port: 0,
                user_hash: UserHash::from_bytes([0xCC; UserHash::BYTE_LEN]),
            },
            capture_dir: None,
            nodes_dat_path: None,
            firewall_self_check: false,
            datagram_obfuscation: false,
            verify_keys: None,
            contact_admission: None,
        },
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .await
    .expect("a Kad node binds loopback UDP");
    let SocketAddr::V4(addr) = handle.local_addr() else {
        panic!("bound IPv4 loopback");
    };
    (handle, addr)
}

#[tokio::test]
async fn a_buddy_named_by_id_alone_is_walked_to_and_sent_the_0x52() {
    let bytes = vec![0x5A_u8; 4096];
    let file = rmule_testkit::file_link("walked-buddy.bin", &bytes);
    let key = KadSourceLookupRequest::new(SourceLookupTarget::new(file.file_hash, file.size))
        .kad_target();

    // The storer sits on the file's key, the buddy on its buddy ID.
    let (storer, storer_addr) = kad_node(key).await;
    let (mut buddy, _) = kad_node(BUDDY_ID).await;

    // The buddy is part of the mesh the way any node is: it joined off the
    // storer, so the storer names it to a walk toward the buddy ID.
    buddy
        .command(rmule_kad::KadCommand::Bootstrap {
            endpoint: rmule_kad::KadNodeEndpoint::new(Ipv4Addr::LOCALHOST, storer_addr.port()),
        })
        .await
        .unwrap();
    timeout(Duration::from_secs(10), async {
        while !matches!(
            buddy.next_event().await,
            Some(KadEvent::ContactResponded { id }) if id == key
        ) {}
    })
    .await
    .expect("the buddy joins off the storer");

    // The stubbed publisher: a type-3 row naming the buddy by ID alone, the
    // crypt byte of the captured aMule `0x44` (no NAT-T, so no punch).
    let publisher = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let publish = rmule_testkit::kad_source::publish_datagram(
        key,
        rmule_primitives::kad_wire_id(*TARGET_HASH.as_bytes()),
        KadPublishedSource {
            source_type: Some(3),
            tcp_port: Some(4662),
            file_size: Some(file.size),
            encryption: Some(0x00),
            buddy: Some(KadBuddyContact {
                buddy_id: BUDDY_ID,
                buddy_udp: None,
                buddy_ipv6: None,
                buddy_udp_ipv6: None,
            }),
            ..KadPublishedSource::default()
        },
    );
    publisher.send_to(&publish, storer_addr).await.unwrap();

    // A callable downloader: High-ID from the server, a bound listener, and a
    // Kad node bootstrapped off the storer alone — the buddy is found by the
    // walk, not handed over.
    let server = rmule_testkit::FakeEd2kServer::start().await;
    let server_ep = ServerEndpoint::parse_host_port(&server.local_addr().to_string()).unwrap();
    let mut core = Core::builder(
        CoreConfig {
            kad_sweep_interval: Duration::from_millis(100),
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
    .peer_transfer(NeverDials)
    .build();
    let port = crate::fixture::free_port().await;
    core.send(CoreCommand::Serve(rmule_core::ServeCommand::StartServing {
        listen_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
        credentials: crate::fixture::identity_with_port(port).into(),
    }))
    .await
    .unwrap();
    crate::fixture::serving_started(&mut core).await;
    rmule_testkit::connect_to(
        &core,
        &server_ep,
        crate::fixture::identity_with_port(port).into(),
    )
    .await;
    core.send(CoreCommand::EnableKad(KadEnableConfig {
        peer_credentials: crate::fixture::identity_with_port(port).into(),
        bootstrap: vec![storer_addr],
        ..crate::fixture::kad_enable_config()
    }))
    .await
    .unwrap();
    let out = tempfile::tempdir().unwrap();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server_ep),
        credentials: crate::fixture::identity_with_port(port).into(),
        output_path: out.path().join("walked-buddy.bin"),
    }))
    .await
    .unwrap();

    // The road is the buddy's callback, reached by a walk: the row gave no
    // endpoint to send the `0x52` to.
    let route = crate::fixture::next_matching(&mut core, |event| {
        matches!(event, CoreEvent::PeerReachRouted { .. })
    })
    .await;
    assert!(
        matches!(
            route,
            CoreEvent::PeerReachRouted {
                route: PeerReachRoute::CallbackWalk { buddy_id },
                ..
            } if buddy_id == BUDDY_ID
        ),
        "an ID-only buddy is walked toward: {route:?}"
    );
    let drain = tokio::spawn(async move { while core.next_event().await.is_some() {} });

    // The buddy decodes a real `0x52` naming itself, the file, and the port
    // the publisher is to dial.
    let relayed = timeout(Duration::from_secs(15), async {
        loop {
            match buddy.next_event().await.expect("buddy node runs") {
                KadEvent::CallbackRelayRequested {
                    buddy_id,
                    file_hash,
                    requester_tcp_port,
                    ..
                } => return (buddy_id, file_hash, requester_tcp_port),
                _ => continue,
            }
        }
    })
    .await
    .expect("the walk's 0x52 reaches the buddy within 15s");
    let file_hash = rmule_testkit::file_link("walked-buddy.bin", &bytes).file_hash;
    assert_eq!(relayed, (BUDDY_ID, file_hash, port));

    drain.abort();
    let _ = storer.shutdown().await;
    let _ = buddy.shutdown().await;
}
