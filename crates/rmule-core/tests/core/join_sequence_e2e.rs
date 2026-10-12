//! Extended cold-start E2E (ADR-0067): the full dual-network first-run arc,
//! in-process, driven through the core [`run_join_sequence`].
//!
//! This extends `rmule-bootstrap/tests/bootstrap/cold_start_e2e.rs` (server.met
//! fetch → parse → login) with the core Join Sequence orchestration and the
//! parallel Kad join:
//!
//! empty [`DurableAppConfig`] → [`run_join_sequence`] loads the empty
//! list → the first-run hook fetches a server.met from a **local HTTP fixture**
//! through the real [`ReqwestFetcher`] → parses / merges / **persists** the
//! endpoint → dispatches the **eD2k join** (one `AddServer` per row) and,
//! independently, the **Kad join** ([`EnableKad`], which really binds a Kad UDP
//! socket) to a live [`Core`]. Then the acquired server **accepts a login**
//! (High-ID), and the Kad join — seeded with a live loopback counterparty node
//! — reaches contact: the Core's node walks the ADR-0067 Bootstrap Dial
//! List, the counterparty answers, and the diagnostics snapshot reports aMule's
//! `HasHadContact` (`kad.contact_responded`), the observable the production
//! cold-start caller (`rmule-tools ed2k bootstrap-fetch`) waits on.
//!
//! Loopback only — the ReqwestFetcher GETs a local fixture, the login is against
//! the ADR-0040 [`FakeEd2kServer`], and both Kad sockets bind `127.0.0.1`. No
//! external network is touched. The served server.met bytes are crate-built
//! valid payloads (the server.met tag primitives), not an aMule capture.

use rmule_core::DurableAppConfig;
use rmule_testkit::HANG_GUARD;
use std::net::Ipv4Addr;

use crate::fixture::identity_with_port;
use crate::fixture::login_and_read_id;
use rmule_bootstrap::{BootstrapConfig, ReqwestFetcher};
use rmule_core::{
    Core, CoreCommand, CoreCommandRejectReason, CoreConfig, CoreEvent, FirstRunFetch, JoinConfig,
    KadEnableConfig, ServerListStore, run_join_sequence,
};
use rmule_primitives::{Ed2kText, Ipv4Endpoint, ServerEndpoint, Tag, TagName, TagValue, UserHash};
use rmule_testkit::FakeEd2kServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{Duration, timeout};

// --- local HTTP/1.1 fixture (mirrors the cold-start E2E) --------------------

/// Spawn a one-shot HTTP/1.1 server that answers the first request with
/// `response` and closes. Returns the URL to GET.
async fn spawn_http_fixture(response: Vec<u8>) -> String {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(&response).await;
            let _ = sock.flush().await;
        }
    });
    format!("http://{addr}/server.met")
}

fn http_ok(body: &[u8]) -> Vec<u8> {
    let mut response =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    response.extend_from_slice(body);
    response
}

// --- server.met payload builder (crate-built valid bytes, not a capture) ----

fn server_met_one(ip: Ipv4Addr, port: u16, name: &str) -> Vec<u8> {
    let name_tag = Tag::new(
        TagName::compact_id(0x01),
        TagValue::String(Ed2kText::from_utf8(name)),
    );
    let mut bytes = vec![0xE0u8];
    bytes.extend_from_slice(&1u32.to_le_bytes()); // one row
    bytes.extend_from_slice(&Ipv4Endpoint::new(ip, port).encode());
    bytes.extend_from_slice(&1u32.to_le_bytes()); // one tag
    bytes.extend(name_tag.encode());
    bytes
}

// --- login handshake (mirrors the cold-start E2E) ---------------------------

/// Drain core events until the `DumpDiagnostics` barrier answers, failing if any
/// join command was rejected first. The core processes commands FIFO, so a
/// `CommandRejected` from the `EnableKad` join necessarily precedes the
/// `DiagnosticsSnapshot` — draining to the barrier is a deterministic
/// "the Kad join was accepted" assertion with no sleep.
async fn assert_no_join_rejection(core: &mut Core) {
    core.send(CoreCommand::DumpDiagnostics).await.unwrap();
    loop {
        let event = timeout(HANG_GUARD, core.next_event())
            .await
            .expect("core answered the diagnostics barrier")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::CommandRejected { reason } => {
                assert!(
                    !matches!(reason, CoreCommandRejectReason::KadUnavailable(_)),
                    "the parallel Kad join must be accepted"
                );
                panic!("a join command was rejected: {reason:?}");
            }
            CoreEvent::DiagnosticsSnapshot { .. } => break,
            _ => {}
        }
    }
}

// --- the arc ----------------------------------------------------------------

#[tokio::test]
async fn cold_start_join_sequence_fetches_persists_logs_in_and_joins_kad() {
    // A fresh install: an ADR-0040 test server is the eD2k network, and rmule
    // knows no servers and has no persisted state.
    let server = FakeEd2kServer::start().await;
    let server_addr = server.local_addr();
    let store = DurableAppConfig::new(rmule_testkit::memory_store());
    assert!(
        store.servers().unwrap().is_empty(),
        "cold start: empty list"
    );

    // A mirror serves a server.met naming exactly that server.
    let payload = server_met_one(*server_addr.ip(), server_addr.port(), "Cold Start Server");
    let url = spawn_http_fixture(http_ok(&payload)).await;

    // A live loopback counterparty node is the Kad network: the Core's node
    // bootstrap-dials it off the ADR-0067 dial list and its BOOTSTRAP_RES
    // answer is what flips `HasHadContact`.
    let mut counterparty = rmule_net::kad::spawn(
        rmule_net::kad::KadNetConfig {
            node: rmule_kad::KadNodeConfig {
                id: rmule_core::KadId::from_bytes([0x5E; 16]),
                tcp_port: 4665,
                udp_port: 0,
                user_hash: UserHash::from_bytes([0x5E; UserHash::BYTE_LEN]),
            },
            capture_dir: None,
            nodes_dat_path: None,
            firewall_self_check: false,
            obfuscation: None,
            contact_admission: None,
        },
        (Ipv4Addr::LOCALHOST, 0).into(),
    )
    .await
    .expect("spawn loopback Kad counterparty");
    let counterparty_addr = counterparty.local_addr();
    let std::net::SocketAddr::V4(counterparty_addr) = counterparty_addr else {
        panic!("loopback counterparty bound non-IPv4: {counterparty_addr}");
    };
    // Keep the counterparty's event stream drained so its driver never stalls.
    tokio::spawn(async move { while counterparty.next_event().await.is_some() {} });

    // The Kad join carries the counterparty as its one bootstrap seed (the
    // front-end-supplied half of ADR-0067's deliberate no-auto-fetch
    // asymmetry); the node's identity is core's own.
    // The core's one UDP socket takes the *configured* port, which the default
    // `CoreConfig` leaves ephemeral — the stored `DEFAULT_UDP_PORT` (4672)
    // is the well-known port any eD2k client on the developer's machine already
    // holds. The port under test is the *join*, not the number.
    let kad_enable = KadEnableConfig {
        bootstrap: vec![counterparty_addr],
        contacts: Vec::new(),
        nodes_dat_path: None,
        assume_open_reachability: false,
        kad_capture_dir: None,
        kad_shutdown: None,
    };

    // A live Core is the join sink: the eD2k join sets its managed list, the Kad
    // join really binds a UDP socket and spawns the node.
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();

    // The production first-run path: the real ReqwestFetcher, injected — reqwest
    // never entered core, the caller supplied it.
    let fetcher = ReqwestFetcher::from_config(&BootstrapConfig::default()).unwrap();
    let bootstrap = BootstrapConfig {
        server_met_url: url,
        ..BootstrapConfig::default()
    };

    let outcome = run_join_sequence(
        &store,
        &fetcher,
        &bootstrap,
        &JoinConfig::default(),
        kad_enable,
        core.kad_id(),
        &core,
    )
    .await
    .expect("join sequence");

    // The first-run hook fetched, parsed, and installed exactly the advertised
    // server, and persisted it to the store.
    assert_eq!(outcome.first_run, FirstRunFetch::Installed { added: 1 });
    let acquired = ServerEndpoint::new(server_addr.ip().to_string(), server_addr.port()).unwrap();
    assert_eq!(outcome.servers, vec![acquired.clone()]);
    let persisted = store.servers().unwrap();
    assert_eq!(
        persisted
            .iter()
            .map(|s| s.endpoint.clone())
            .collect::<Vec<_>>(),
        vec![acquired],
        "the acquired server is persisted for the next start"
    );
    assert_eq!(
        persisted[0].name.to_display_string(),
        "Cold Start Server",
        "with the name the mirror advertised (ADR-0080)"
    );

    // The Kad join was accepted (it binds a real loopback UDP socket).
    assert_no_join_rejection(&mut core).await;

    // connect → login: the freshly acquired server accepts our login. Answer
    // the back-connect port check (`OP_HELLO` → `OP_HELLOANSWER`)
    // so the probe grants a crisp High-ID.
    let (advertised, check_listener) =
        rmule_testkit::spawn_check_answering_listener(identity_with_port(0)).await;

    let id = login_and_read_id(server_addr, advertised).await;
    assert!(
        id.is_high_id(),
        "the acquired server accepted our login, got {id:?}"
    );
    check_listener.abort();

    // The Kad join reaches contact: the Core's node dials the seeded
    // counterparty (first dial fires promptly), the counterparty's answer flips
    // aMule's `HasHadContact`, and the diagnostics snapshot reports it — the
    // exact observable the production cold-start runner polls.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        core.send(CoreCommand::DumpDiagnostics).await.unwrap();
        let contact = loop {
            let event = timeout(HANG_GUARD, core.next_event())
                .await
                .expect("core answered the diagnostics barrier")
                .expect("core event stream stayed open");
            if let CoreEvent::DiagnosticsSnapshot { snapshot } = event {
                let kad = snapshot
                    .kad
                    .expect("EnableKad accepted, so the snapshot reports Kad state");
                break kad.contact_responded;
            }
        };
        if contact {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the seeded counterparty never flipped HasHadContact"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
