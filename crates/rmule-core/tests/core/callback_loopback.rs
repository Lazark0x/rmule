//! Low-ID callback loopback (ADR-0039) over the deterministic `FakeEd2kServer`
//! (ADR-0040 Correctness Tier): rmule **A** serves (binds its listener before
//! login → the server's Back-Connect Probe grants High-ID → Callback Capability),
//! discovers a Low-ID source **B** via the server's `OP_FOUNDSOURCES`, and asks
//! the server to relay `OP_CALLBACKREQUEST`. The server relays
//! `OP_CALLBACKREQUESTED` across **B's own server session** (multi-client); B
//! dials A's listener advertising its server-assigned low id + the connected
//! server (the real correlation key), and A's accept-router adopts that inbound
//! connection as a worker and downloads a verified part.
//!
//! Unlike the cycle-9 fake, nothing is shortcut: the High-ID, the relay, and the
//! `(connected_server, client_id)` correlation are all exercised through real
//! sockets, so this regresses the four interop-only bugs cycle-11 surfaced.
//!
//! The same B also witnesses the other side of **Callback Capability**: a
//! Low-ID, Kad-open rmule is callable, but never through its own server.

use rmule_testkit::HANG_GUARD;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use crate::fixture::{dead_port, free_port, serving_started};
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent, ServeCommand,
};
use rmule_ed2k::{IdChange, LoginRequest, Opcode, PeerCallback};
use rmule_net::peer::{ConnectOptions, Connection};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{
    Capabilities, ClientIdentity, CryptStance, Ed2kText, Ipv4Endpoint, Packet, PeerEndpoint,
    ServerEndpoint, UserHash,
};
use rmule_testkit::FakeEd2kServer;
use rmule_testkit::file_link;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::timeout;

async fn read_packet(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Packet {
    loop {
        if let Ok((packet, consumed)) = Packet::decode(buf) {
            buf.drain(..consumed);
            return packet;
        }
        let mut tmp = [0u8; 4096];
        let n = timeout(HANG_GUARD, stream.read(&mut tmp))
            .await
            .expect("server frame")
            .expect("read ok");
        assert!(n > 0, "server closed unexpectedly");
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// B's login as a real Low-ID client of the server (an aMule stand-in): it
/// advertises an unreachable port, so the probe assigns it a Low ID and the
/// server registers it as a source. Returns the live server link, its read
/// buffer, the id and the identity it logged in with.
async fn b_logs_in_low_id(
    server_addr: SocketAddrV4,
) -> (
    TcpStream,
    Vec<u8>,
    rmule_primitives::ClientId,
    ClientIdentity,
) {
    let b_unreachable_port = dead_port().await;
    let b_user_hash = UserHash::from_bytes([0x0B; UserHash::BYTE_LEN]);
    let b_identity = ClientIdentity::new(
        b_user_hash,
        Ed2kText::from_utf8("low-id-source"),
        b_unreachable_port,
        60,
    );

    let mut server_sock = TcpStream::connect(server_addr).await.unwrap();
    server_sock
        .write_all(
            &LoginRequest::from_identity(
                &b_identity,
                &Capabilities::shipped(CryptStance::disabled()),
            )
            .encode_packet()
            .encode(),
        )
        .await
        .unwrap();

    let mut buf = Vec::new();
    // IdChange → our server-assigned low id (we are now a registered source).
    let id_change = IdChange::decode_packet(&read_packet(&mut server_sock, &mut buf).await)
        .expect("IdChange for B");
    let low_id = id_change.client_id;
    assert!(
        low_id.is_low_id(),
        "B must be assigned a Low-ID, got {low_id:?}"
    );
    (server_sock, buf, low_id, b_identity)
}

/// B — logs in Low-ID, signals ready once it is a registered source, then
/// waits for the relayed `OP_CALLBACKREQUESTED`, dials A, and serves the
/// file's one block.
async fn b_low_id_peer(
    server_addr: SocketAddrV4,
    file_bytes: Vec<u8>,
    ready_tx: oneshot::Sender<()>,
) {
    let (mut server_sock, mut buf, low_id, b_identity) = b_logs_in_low_id(server_addr).await;
    let _ = ready_tx.send(());

    // 2) Wait for the relayed OP_CALLBACKREQUESTED → A's dialable endpoint.
    let a_endpoint = loop {
        let packet = read_packet(&mut server_sock, &mut buf).await;
        if packet.opcode() == Opcode::PeerCallback.as_u8() {
            break PeerCallback::decode_packet(&packet)
                .expect("OP_CALLBACKREQUESTED")
                .peer;
        }
    };

    // 3) Dial A as the Low-ID source: advertise our low id + the connected server,
    //    which together are the correlation key A matches.
    let ctx = PeerHandshakeContext {
        identity: b_identity,
        client_id: low_id,
        ed2k_client_id: low_id,
        public_ip: None,
        connected_server: Some(Ipv4Endpoint::new(*server_addr.ip(), server_addr.port())),
    };
    let mut b = Connection::connect(PeerEndpoint::V4(a_endpoint), ctx, ConnectOptions::default())
        .await
        .expect("B dials A's listener");

    // 4) Serve the file: answer each requester probe, then stream the one block.
    crate::fixture::serve_called_back(&mut b, "callback.bin", &file_bytes).await;
}

#[tokio::test]
async fn callback_adopts_low_id_peer_and_downloads_a_part() {
    let out = tempfile::tempdir().unwrap();
    // A small sub-part file: one block, no part hash set (verified at finalize).
    let bytes = vec![0x5A_u8; 4096];
    let file = file_link("callback.bin", &bytes);

    let server = FakeEd2kServer::start().await;
    let server_addr = server.local_addr();
    let server_ep = ServerEndpoint::parse_host_port(&server_addr.to_string()).unwrap();

    // B connects first and becomes a registered Low-ID source before A looks up.
    let (ready_tx, ready_rx) = oneshot::channel();
    let b_task = tokio::spawn(b_low_id_peer(server_addr, bytes.clone(), ready_tx));

    // A serves on a KNOWN port P its Core Settings name, so its login
    // advertises exactly the port it bound: the serve start answers the
    // server's port-check hello during the login → High-ID → Callback
    // Capability. (Production binds a fixed configured port; the alignment
    // here mirrors that — see ADR-0040.)
    let p = free_port().await;
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(
            crate::fixture::settings_on(p),
            out.path(),
        ))
        .build();
    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, p),
    }))
    .await
    .unwrap();
    let a_listen = serving_started(&mut core).await;
    rmule_testkit::connect_to(&core, &server_ep).await;
    assert_eq!(
        a_listen.port(),
        p,
        "rmule bound the requested listener port"
    );

    // Wait until B is a registered source, then start the download.
    timeout(HANG_GUARD, ready_rx)
        .await
        .expect("B registered")
        .expect("B ready signal");

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server_ep),
        name: rmule_testkit::file_name("callback.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
        kad_aich_root: None,
    }))
    .await
    .unwrap();

    // A discovers B (Low-ID), requests a callback, adopts the inbound dial, and
    // completes the download from it.
    let mut saw_peer = false;
    loop {
        let event = timeout(HANG_GUARD, core.next_event())
            .await
            .expect("core emitted event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Download(DownloadEvent::PeerSelected { .. }) => saw_peer = true,
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    }
    assert!(saw_peer, "PeerSelected emitted for the adopted Low-ID peer");

    let _ = b_task.await;
}

/// The carve-out in aMule's `CanDoCallback` (`amule.cpp:3216-3224`):
/// Low-ID on the server but Kad-open, a node is callable — except for a
/// source on its own server, where "we prevent a callback to the server as this
/// breaks the protocol and will get you banned". rmule, listening but assigned
/// a Low ID, with an open Kad verdict, finds B on its own server and never asks
/// that server to relay a callback; B is left to the punch road, which that
/// same server coordinates.
#[tokio::test]
async fn a_low_id_kad_open_downloader_never_asks_its_own_server_to_relay_a_callback() {
    let out = tempfile::tempdir().unwrap();
    let bytes = vec![0x5A_u8; 4096];
    let server = FakeEd2kServer::start().await;
    let server_addr = server.local_addr();
    let server_ep = ServerEndpoint::parse_host_port(&server_addr.to_string()).unwrap();

    let (mut b_sock, mut b_buf, b_id, _) = b_logs_in_low_id(server_addr).await;

    // A listens on P but advertises a port nothing answers, so the probe
    // assigns it a Low ID while its listener is bound; its Kad verdict is open.
    let p = free_port().await;
    let advertised = dead_port().await;
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(
            crate::fixture::settings_on(advertised),
            out.path(),
        ))
        .kad(crate::fixture::VerdictOnlyKad)
        .kad_reach(rmule_core::KadReachLevel::fixed(true))
        .build();
    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, p),
    }))
    .await
    .unwrap();
    serving_started(&mut core).await;
    rmule_testkit::connect_to(&core, &server_ep).await;
    let ids = timeout(HANG_GUARD, server.assigned_ids_after(2))
        .await
        .expect("A's login reaches the server");
    assert!(
        ids.get(1).is_some_and(|id| id.is_low_id()),
        "A must be Low-ID on the server for the carve-out to apply, got {ids:?}"
    );
    core.send(CoreCommand::EnableKad(crate::fixture::kad_enable_config()))
        .await
        .expect("kad enabled");

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link("carve-out.bin", &bytes),
        source_hint: Some(server_ep),
        name: rmule_testkit::file_name("carve-out.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
        kad_aich_root: None,
    }))
    .await
    .unwrap();

    // B was admitted — on the punch road: our own server introduces us.
    crate::fixture::next_matching(&mut core, |event| {
        matches!(
            event,
            CoreEvent::PeerReachRouted {
                route: rmule_core::PeerReachRoute::ServerPunch { low_id },
                ..
            } if *low_id == b_id
        )
    })
    .await;

    // And the server relayed nothing to B: no `OP_CALLBACKREQUEST` was sent.
    let mut tmp = [0u8; 4096];
    while let Ok(read) = timeout(Duration::from_millis(500), b_sock.read(&mut tmp)).await {
        let n = read.expect("B's server link reads");
        assert!(n > 0, "the server closed B's link");
        b_buf.extend_from_slice(&tmp[..n]);
        while let Ok((packet, consumed)) = Packet::decode(&b_buf) {
            b_buf.drain(..consumed);
            assert_ne!(
                packet.opcode(),
                Opcode::PeerCallback.as_u8(),
                "a Low-ID node asked its own server to relay a callback"
            );
        }
    }
}
