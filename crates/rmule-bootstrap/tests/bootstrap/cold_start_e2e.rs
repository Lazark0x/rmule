//! Cold-start E2E (ADR-0065): the full amuled first-run arc, in-process.
//!
//! empty server list → **real [`ReqwestFetcher`]** GET of a server.met from a
//! **local HTTP fixture** → parse-before-install → merge → the parsed endpoint
//! **connects and logs in** against the ADR-0040 [`FakeEd2kServer`]. No socket
//! reaches outside the loopback interface; no external network is touched.
//!
//! The served server.met bytes are crate-built valid payloads (the same eD2k
//! tag primitives the `rmule-ed2k` decoder's own vectors use), *not* an aMule
//! capture. The aMule-authored golden served over this same fixture is the
//! `full` gap's capture evidence and a documented **missing asset** (see the
//! crate-level evidence note) — it needs a pinned aMule in Docker to author,
//! which this deterministic environment cannot run.
//!
//! Only built with the `reqwest-fetcher` feature (default on): the arc's whole
//! point is exercising the real I/O corner.
#![cfg(feature = "reqwest-fetcher")]

use rmule_testkit::HANG_GUARD;
use std::net::{Ipv4Addr, SocketAddrV4};

use rmule_bootstrap::{BootstrapConfig, FetchError, Fetcher, ReqwestFetcher, fetch_server_met};
use rmule_ed2k::{IdChange, LoginRequest};
use rmule_primitives::{
    Capabilities, ClientId, ClientIdentity, CryptStance, Ed2kText, Ipv4Endpoint, Packet, Tag,
    TagName, TagValue, UserHash,
};
use rmule_testkit::FakeEd2kServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

// --- local HTTP/1.1 fixture ------------------------------------------------

/// Spawn a one-shot HTTP/1.1 server that answers the first request with
/// `response` (full status line + headers + body) and closes. Returns the URL
/// to GET.
async fn spawn_http_fixture(response: Vec<u8>) -> String {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            // Drain the request head so the client's write completes.
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

fn http_status(code: u16, reason: &str) -> Vec<u8> {
    format!("HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\n\r\n").into_bytes()
}

// --- server.met payload builder (crate-built valid bytes, not an aMule
// capture) ------------------------------------------------------------------

const HEADER_AMULE: u8 = 0xE0;
const TAG_SERVERNAME: u8 = 0x01;

fn server_met_one(ip: Ipv4Addr, port: u16, name: &str) -> Vec<u8> {
    let name_tag = Tag::new(
        TagName::compact_id(TAG_SERVERNAME),
        TagValue::String(Ed2kText::from_utf8(name)),
    );

    let mut bytes = vec![HEADER_AMULE];
    bytes.extend_from_slice(&1u32.to_le_bytes()); // one row
    bytes.extend_from_slice(&Ipv4Endpoint::new(ip, port).encode());
    bytes.extend_from_slice(&1u32.to_le_bytes()); // one tag
    bytes.extend(name_tag.encode());
    bytes
}

// --- login handshake (mirrors fake_ed2k_server_probe.rs) -------------------

fn identity_with_port(port: u16) -> ClientIdentity {
    ClientIdentity::new(
        UserHash::from_bytes([0x33; UserHash::BYTE_LEN]),
        Ed2kText::from_utf8("cold-start-client"),
        port,
        60,
    )
}

async fn login_and_read_id(server: SocketAddrV4, advertised_port: u16) -> ClientId {
    let mut sock = TcpStream::connect(server).await.unwrap();
    let login = LoginRequest::from_identity(
        &identity_with_port(advertised_port),
        &Capabilities::shipped(CryptStance::disabled()),
    );
    sock.write_all(&login.encode_packet().encode())
        .await
        .unwrap();

    let mut buf = Vec::new();
    loop {
        if let Ok((packet, consumed)) = Packet::decode(&buf) {
            buf.drain(..consumed);
            return IdChange::decode_packet(&packet)
                .expect("IdChange")
                .client_id;
        }
        let mut tmp = [0u8; 4096];
        let n = timeout(HANG_GUARD, sock.read(&mut tmp))
            .await
            .expect("IdChange")
            .expect("read ok");
        assert!(n > 0, "server closed before sending IdChange");
        buf.extend_from_slice(&tmp[..n]);
    }
}

// --- the arc ---------------------------------------------------------------

#[tokio::test]
async fn cold_start_fetches_parses_and_logs_into_the_acquired_server() {
    // A fresh install: an ADR-0040 test server is the network, and rmule knows
    // no servers at all.
    let server = FakeEd2kServer::start().await;
    let server_addr = server.local_addr();

    // A mirror serves a server.met naming exactly that server.
    let payload = server_met_one(*server_addr.ip(), server_addr.port(), "Cold Start Server");
    let url = spawn_http_fixture(http_ok(&payload)).await;

    // The production fetch path: real reqwest, real GET, empty installed list.
    let fetcher = ReqwestFetcher::from_config(&BootstrapConfig::default()).unwrap();
    let install = fetch_server_met(
        &fetcher,
        &url,
        BootstrapConfig::default().max_server_met_bytes,
        Vec::new(),
    )
    .await
    .expect("cold-start acquisition");

    // Parse-and-merge produced exactly the advertised server.
    assert_eq!(install.added(), 1);
    let acquired = install.servers()[0].endpoint();
    assert_eq!(acquired.ip, *server_addr.ip());
    assert_eq!(acquired.port, server_addr.port());

    // Now dial the *acquired* endpoint and complete a login — the arc's payoff.
    // Answer the back-connect port check (`OP_HELLO` → `OP_HELLOANSWER`)
    // so the probe grants High-ID, making "login accepted" a crisp,
    // deterministic assertion.
    let (advertised, check_listener) =
        rmule_testkit::spawn_check_answering_listener(identity_with_port(0)).await;

    let acquired_addr = SocketAddrV4::new(acquired.ip, acquired.port);
    let id = login_and_read_id(acquired_addr, advertised).await;
    assert!(
        id.is_high_id(),
        "the freshly acquired server accepted our login, got {id:?}"
    );
    check_listener.abort();
}

// --- the I/O corner's failure mapping (real reqwest, local fixture) --------

#[tokio::test]
async fn reqwest_fetcher_rejects_non_success_status() {
    let url = spawn_http_fixture(http_status(404, "Not Found")).await;
    let fetcher = ReqwestFetcher::from_config(&BootstrapConfig::default()).unwrap();

    let outcome = fetcher.get(&url, 4096).await;

    assert!(
        matches!(outcome, Err(FetchError::Status { status: 404, .. })),
        "a mirror's 404 must reject, not parse as a list; got {outcome:?}"
    );
}

#[tokio::test]
async fn reqwest_fetcher_enforces_the_size_cap_while_streaming() {
    let body = vec![0xABu8; 8192];
    let url = spawn_http_fixture(http_ok(&body)).await;
    let fetcher = ReqwestFetcher::from_config(&BootstrapConfig::default()).unwrap();

    let cap = 4096;
    let outcome = fetcher.get(&url, cap).await;

    assert_eq!(outcome, Err(FetchError::TooLarge { cap }));
}
