//! The **Publish Connect Options**, end to end: a production
//! rmule Core — reachable (a firewalled one with no buddy publishes no row, aMule's
//! `PrepareToStop`), running `Requested` crypt and its
//! NAT-T front — publishes
//! a shared file into a bare `rmule_net::kad` storer, and the row that storer
//! re-serves decodes through the widened Kad reader to the options the Core
//! actually holds.
//!
//! Every bit is checked against the owner that holds it: the crypt policy
//! (supports + requests, not requires), the ADR-0060 verdicts (not
//! firewalled, so no direct-callback bit), and the NAT-T front (uTP served,
//! QUIC dark, ADR-0091).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, KadEnableConfig, KadId, ServeCommand, ServeEvent,
};
use rmule_primitives::{ClientIdentity, Ed2kText, FileHashSummary, SourceLookupTarget, UserHash};
use tokio::time::timeout;

fn reserve_tcp_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

async fn until(core: &mut Core, wanted: impl Fn(&CoreEvent) -> bool) {
    loop {
        let event = timeout(Duration::from_secs(10), core.next_event())
            .await
            .expect("core emitted the awaited event within 10s")
            .expect("core event stream stayed open");
        if wanted(&event) {
            return;
        }
    }
}

#[tokio::test]
async fn a_reachable_rmule_publishes_the_connect_options_it_holds() {
    let bytes: Vec<u8> = (0..16_384u32).flat_map(u32::to_le_bytes).collect();
    let summary = FileHashSummary::digest_bytes(&bytes);
    let target = SourceLookupTarget::new(summary.file_hash(), summary.file_size());
    let key = rmule_kad::KadSourceLookupRequest::new(target).kad_target();

    // The storer sits on the file's Kad key, so the publish walk ends at it.
    let storer = rmule_net::kad::spawn(
        rmule_net::kad::KadNetConfig {
            node: rmule_kad::KadNodeConfig {
                id: key,
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

    let config = CoreConfig {
        kad_sweep_interval: Duration::from_millis(100),
        peer_crypt: Some(rmule_net::peer::ObfuscationPolicy::Requested),
        ..CoreConfig::default()
    };
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("payload.bin"), &bytes).unwrap();
    let tcp = reserve_tcp_port();
    let user_hash = UserHash::from_bytes([0xA1; UserHash::BYTE_LEN]);
    let identity = ClientIdentity::new(user_hash, Ed2kText::from_utf8("rmule-fw"), tcp, 60);
    let mut core = Core::builder(config, rmule_testkit::memory_store())
        .user_hash(user_hash)
        .build();
    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, tcp),
        credentials: identity.clone().into(),
    }))
    .await
    .unwrap();
    until(&mut core, |event| {
        matches!(event, CoreEvent::Serve(ServeEvent::ServingStarted { .. }))
    })
    .await;
    core.send(CoreCommand::EnableKad(KadEnableConfig {
        kad_id: KadId::from_bytes([0xA1; KadId::BYTE_LEN]),
        peer_credentials: identity.into(),
        bootstrap: vec![storer_addr],
        contacts: Vec::new(),
        nodes_dat_path: None,
        // Reachable, so the Core publishes the direct row: firewalled with no
        // buddy, it would publish nothing.
        assume_open_reachability: true,
        kad_udp_key: 0,
        kad_capture_dir: None,
        kad_shutdown: None,
    }))
    .await
    .unwrap();
    // The publish fires once, on the share; the storer must already be in
    // the routing table (same fixed settle as the serverless E2E).
    tokio::time::sleep(Duration::from_secs(1)).await;
    rmule_testkit::share_directory(&mut core, dir.path()).await;
    let drain = tokio::spawn(async move { while core.next_event().await.is_some() {} });

    // A searcher that is nothing but a socket: ask the storer for the key's
    // sources until the row lands, and read it through the widened reader.
    let searcher = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let search = rmule_testkit::kad_source::search_datagram(key, 0, summary.file_size());
    let row = timeout(Duration::from_secs(15), async {
        let mut buffer = [0u8; 2048];
        loop {
            searcher.send_to(&search, storer_addr).await.unwrap();
            let Ok(Ok((len, _))) =
                timeout(Duration::from_millis(300), searcher.recv_from(&mut buffer)).await
            else {
                continue;
            };
            let Ok(rmule_kad::KadDecoded::Plain(envelope)) =
                rmule_kad::decode_exact(&buffer[..len])
            else {
                continue;
            };
            if envelope.opcode() != 0x3B {
                continue;
            }
            if let Some(facts) = rmule_kad::decode_source_result(&envelope)
                .expect("the storer's 0x3B decodes")
                .iter()
                .find_map(|row| row.facts().filter(|facts| facts.user_hash == user_hash))
            {
                return facts;
            }
        }
    })
    .await
    .expect("the storer re-served the Core's publish within 15s");

    // Reachable, so the row is the direct one — the byte is what varies.
    assert_eq!(row.source_type, 1);
    let options = row
        .connect_options
        .expect("the Core's publish carried TAG_ENCRYPTION");
    assert!(
        options.supports_crypt() && options.requests_crypt() && !options.requires_crypt(),
        "the Requested policy's ladder: {:#04x}",
        options.as_byte()
    );
    assert!(
        !options.supports_direct_udp_callback(),
        "not firewalled, so the ADR-0060 verdict earns no direct callback"
    );
    assert!(options.supports_natt_utp(), "the NAT-T front serves uTP");
    assert!(
        !options.supports_natt_quic(),
        "QUIC stays dark until a harness-proven handshake"
    );
    assert_eq!(options.as_byte(), 0x83, "and no bit beyond those");

    drain.abort();
    let _ = storer.shutdown().await;
}
