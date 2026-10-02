//! Serverless E2E (ADR-0043 acceptance): two production rmule
//! Cores and one bare `rmule_net::kad` storer node, all on localhost UDP/TCP.
//! rmule-A shares a file, publishes it into the DHT; rmule-B bootstraps off
//! the same storer, discovers A through a Kad source search, dials A's serve
//! listener, and downloads the file. **No eD2k server exists anywhere** —
//! both Cores are given a dead server endpoint and must run entirely on Kad.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent, KadEnableConfig,
    KadId, ServeCommand, ServeEvent,
};
use rmule_primitives::{
    ClientIdentity, Ed2kFileLink, Ed2kText, FileHashSummary, ServerEndpoint, SourceLookupTarget,
    UserHash,
};
use tokio::time::timeout;

/// Reserve a free loopback TCP port (bind ephemeral, read, release). The
/// tiny reuse race is acceptable on loopback in a test.
fn reserve_tcp_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

async fn next_event(core: &mut Core) -> CoreEvent {
    timeout(Duration::from_secs(10), core.next_event())
        .await
        .expect("core emitted next event within 10s")
        .expect("core event stream stayed open")
}

#[tokio::test]
async fn rmule_b_discovers_and_downloads_rmule_a_via_kad_with_no_server() {
    // The shared payload: ~160 KiB, single eD2k part.
    let bytes: Vec<u8> = (0..40_000u32).flat_map(u32::to_le_bytes).collect();
    let summary = FileHashSummary::digest_bytes(&bytes);
    let target = SourceLookupTarget::new(summary.file_hash(), summary.file_size());

    // The storer: a bare Kad node whose ID sits exactly on the file's Kad
    // key, so A's publish walk and B's search walk both terminate at it.
    let storer_id = rmule_kad::KadSourceLookupRequest::new(target).kad_target();
    let storer = rmule_net::kad::spawn(
        rmule_net::kad::KadNetConfig {
            node: rmule_kad::KadNodeConfig {
                id: storer_id,
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
    .expect("storer node binds loopback UDP");
    let SocketAddr::V4(storer_addr) = storer.local_addr() else {
        panic!("storer bound IPv4 loopback");
    };
    let bootstrap = vec![storer_addr];

    // Nothing listens here: every server interaction must fail.
    let dead_server = ServerEndpoint::new("127.0.0.1", 1).unwrap();
    let config = CoreConfig {
        kad_sweep_interval: Duration::from_millis(100),
        kad_reask_interval: Duration::from_millis(500),
        ..CoreConfig::default()
    };

    // --- rmule-A: serve + share + publish.
    let dir_a = tempfile::tempdir().unwrap();
    std::fs::write(dir_a.path().join("payload.bin"), &bytes).unwrap();
    let tcp_a = reserve_tcp_port();
    let identity_a = ClientIdentity::new(
        UserHash::from_bytes([0xAA; UserHash::BYTE_LEN]),
        Ed2kText::from_utf8("rmule-a"),
        tcp_a,
        60,
    );
    let mut core_a = Core::new(config.clone(), rmule_testkit::memory_store());
    core_a
        .send(CoreCommand::Serve(ServeCommand::StartServing {
            listen_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, tcp_a),
            credentials: identity_a.clone().into(),
        }))
        .await
        .unwrap();
    loop {
        if matches!(
            next_event(&mut core_a).await,
            CoreEvent::Serve(ServeEvent::ServingStarted { .. })
        ) {
            break;
        }
    }
    core_a
        .send(CoreCommand::EnableKad(KadEnableConfig {
            kad_id: KadId::from_bytes([0xAA; KadId::BYTE_LEN]),
            peer_credentials: identity_a.clone().into(),
            bootstrap: bootstrap.clone(),
            contacts: Vec::new(),
            nodes_dat_path: None,
            // A publishes, so it must read reachable: a firewalled node with
            // no buddy publishes no source row (aMule's `PrepareToStop`),
            // and a one-storer swarm cannot prove it open.
            assume_open_reachability: true,
            kad_udp_key: 0,
            kad_capture_dir: None,
            kad_shutdown: None,
        }))
        .await
        .unwrap();
    // Let A's bootstrap settle before the share registers: the sweep's
    // immediate publish is the only shot until the node's 5-hour republish,
    // so it must find the storer already in A's routing table. No event
    // reports a settled routing table, so this is a fixed wait — wide enough
    // to hold while every other leg of this binary runs alongside it.
    tokio::time::sleep(Duration::from_secs(1)).await;
    rmule_testkit::share_directory(&mut core_a, dir_a.path()).await;
    // Keep A's event channel drained so its actor never blocks on a full
    // buffer while serving B.
    let drain_a = tokio::spawn(async move { while core_a.next_event().await.is_some() {} });

    // --- rmule-B: bootstrap, search, download. The durable repository lands
    // the completed file on disk for the byte-for-byte assert.
    let dir_b = tempfile::tempdir().unwrap();
    let mut core_b = Core::new(config, rmule_testkit::memory_store());
    let user_hash_b = UserHash::from_bytes([0xBB; UserHash::BYTE_LEN]);
    core_b
        .send(CoreCommand::EnableKad(KadEnableConfig {
            kad_id: KadId::from_bytes([0xBB; KadId::BYTE_LEN]),
            peer_credentials: ClientIdentity::new(
                user_hash_b,
                Ed2kText::from_utf8("rmule-b"),
                4664,
                60,
            )
            .into(),
            bootstrap,
            contacts: Vec::new(),
            nodes_dat_path: None,
            assume_open_reachability: false,
            kad_udp_key: 0,
            kad_capture_dir: None,
            kad_shutdown: None,
        }))
        .await
        .unwrap();

    let output_path = dir_b.path().join("downloaded.bin");
    let identity_b = ClientIdentity::new(user_hash_b, Ed2kText::from_utf8("rmule-b"), 4664, 60);
    core_b
        .send(CoreCommand::Download(DownloadCommand::StartDownload {
            file: Ed2kFileLink {
                name: Ed2kText::from_utf8("payload.bin"),
                size: summary.file_size(),
                file_hash: summary.file_hash(),
                part_hash_set: summary.part_hash_set().cloned(),
                aich_root: None,
                ipv6_sources: Vec::new(),
                sources: Default::default(),
            },
            source_hint: Some(dead_server),
            credentials: identity_b.into(),
            output_path: output_path.clone(),
        }))
        .await
        .unwrap();

    let mut events = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let event = tokio::time::timeout_at(deadline, core_b.next_event())
            .await
            .expect("B completed the Kad-discovered download within 30s")
            .expect("B's event stream stayed open");
        match &event {
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => {
                events.push(event);
                break;
            }
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("serverless download failed: {reason:?} (events: {events:?})");
            }
            _ => events.push(event),
        }
    }

    // Serverless proof: B never logged in anywhere.
    assert!(
        !events.iter().any(|event| matches!(
            event,
            CoreEvent::Download(DownloadEvent::ServerLoginAccepted { .. })
        )),
        "no server login may occur in the serverless E2E: {events:?}"
    );
    assert_eq!(
        std::fs::read(&output_path).unwrap(),
        bytes,
        "B downloaded A's exact bytes via Kad discovery"
    );

    drain_a.abort();
    let _ = storer.shutdown().await;
}
