//! Per-server Low-ID callback loopback (ADR-0051 + ADR-0039) over the
//! deterministic Correctness Tier (ADR-0040): rmule **A** serves (binds its listener
//! before login → the connected server's Back-Connect Probe grants High-ID → Callback
//! Capability) and runs an armed download whose connected server has **no** source.
//! A *different* server **G**, queried over server-UDP, answers with a **Low-ID**
//! global source **B**; A asks G — over UDP, `OP_GLOBCALLBACKREQUEST` — to relay a
//! callback carrying A's own contact. G relays it to B; B dials A's listener
//! advertising its `(source_server = G, client_id = low_id)` correlation key, and A's
//! accept-router adopts that inbound connection as a worker and downloads a verified
//! part.
//!
//! The UDP-relayed sibling of `callback_loopback` (the connected-server case): the
//! only new transport is G's UDP socket and the per-server callback. G's UDP endpoint
//! is used for both the answer source and B's reported `connected_server`, so the
//! Correctness Tier exercises the full `(source_server, low_id)` correlation without
//! the real-server UDP-vs-TCP port split (a Compatibility-Tier concern).

use rmule_testkit::HANG_GUARD;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use crate::fixture::{dead_port, free_port, serving_started};
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent, ServeCommand,
};
use rmule_ed2k::{GlobCallbackRequest, Opcode};
use rmule_net::peer::{ConnectOptions, Connection};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{
    ClientId, ClientIdentity, Ed2kText, Ipv4Endpoint, Packet, PacketProtocol, PeerEndpoint,
    ServerEndpoint, UserHash,
};
use rmule_testkit::FakeEd2kServer;
use rmule_testkit::file_link;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::time::timeout;

/// A Low-ID the global server **G** "assigns" B (any value below the High-ID
/// threshold; non-zero so it is callback-routable).
const B_LOW_ID: u32 = 0x00AB_CDEF;

/// B — the Low-ID **global** source. It is unknown to the connected server; G is its
/// source-server. It waits for G to relay rmule's contact (the requester endpoint G
/// read out of `OP_GLOBCALLBACKREQUEST`), dials A advertising `(source_server = G,
/// client_id = B_LOW_ID)`, and serves the file's one block.
async fn b_global_low_id_peer(
    g_tcp: Ipv4Endpoint,
    dial_rx: oneshot::Receiver<Ipv4Endpoint>,
    file_bytes: Vec<u8>,
) {
    let a_endpoint = timeout(HANG_GUARD, dial_rx)
        .await
        .expect("G relays rmule's contact")
        .expect("relay channel stayed open");

    let b_identity = ClientIdentity::new(
        UserHash::from_bytes([0x0B; UserHash::BYTE_LEN]),
        Ed2kText::from_utf8("low-id-global-source"),
        dead_port().await,
        60,
    );
    let ctx = PeerHandshakeContext {
        identity: b_identity,
        client_id: ClientId::from_u32(B_LOW_ID),
        ed2k_client_id: ClientId::from_u32(B_LOW_ID),
        public_ip: None,
        // B reports G's TCP endpoint (where it "logged in") — the key rmule derives
        // from the answer's UDP source (− the +4 server-UDP offset).
        connected_server: Some(g_tcp),
    };
    let mut b = Connection::connect(PeerEndpoint::V4(a_endpoint), ctx, ConnectOptions::default())
        .await
        .expect("B dials A's listener");

    crate::fixture::serve_called_back(&mut b, "global-callback.bin", &file_bytes).await;
}

#[tokio::test]
async fn per_server_global_callback_adopts_low_id_peer_and_downloads_a_part() {
    let out = tempfile::tempdir().unwrap();
    let bytes = vec![0x5A_u8; 4096];
    let file = file_link("global-callback.bin", &bytes);
    let file_hash = file.file_hash;

    // Connected server C: logs rmule in (High-ID via the reachability probe) but holds
    // no source for the file — B lives only on the global server G.
    let server = FakeEd2kServer::start().await;
    let server_addr = server.local_addr();
    let server_ep = ServerEndpoint::parse_host_port(&server_addr.to_string()).unwrap();

    // Global server G (server-UDP): answers `OP_GLOBGETSOURCES` with B as a Low-ID
    // source, and on `OP_GLOBCALLBACKREQUEST` relays rmule's contact to B. After
    // relaying it stops advertising the source, so the loopback drives exactly one
    // callback (deterministic).
    let g_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let SocketAddr::V4(g_udp_addr) = g_udp.local_addr().unwrap() else {
        panic!("expected v4 loopback");
    };
    // G binds its UDP socket at port U; its TCP endpoint (what rmule queries, keys the
    // callback on, and B reports as `connected_server`) is U − 4, the eD2k server-UDP
    // offset. rmule's send adapter adds the +4 back to reach G's UDP socket.
    const SERVER_UDP_OFFSET: u16 = 4;
    let g_tcp = Ipv4Endpoint::new(*g_udp_addr.ip(), g_udp_addr.port() - SERVER_UDP_OFFSET);
    let (dial_tx, dial_rx) = oneshot::channel::<Ipv4Endpoint>();
    let g_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let mut dial_tx = Some(dial_tx);
        let mut relayed = false;
        while let Ok((n, src)) = g_udp.recv_from(&mut buf).await {
            // eD2k UDP datagrams are `[protocol 0xE3][opcode][payload]` — no length
            // prefix; dispatch on the opcode byte.
            let datagram = &buf[..n];
            let [0xE3, opcode, ..] = datagram else {
                continue;
            };
            if *opcode == Opcode::GlobGetSources.as_u8() && !relayed {
                // Answer with B as a Low-ID source (client_id below the High-ID
                // threshold → not dialable; only callback-able via G).
                let mut payload = file_hash.as_bytes().to_vec();
                payload.push(1);
                payload.extend_from_slice(&B_LOW_ID.to_le_bytes());
                payload.extend_from_slice(&4662u16.to_le_bytes());
                let answer = Packet::new(
                    PacketProtocol::Edonkey,
                    Opcode::GlobFoundSources.as_u8(),
                    payload,
                )
                .encode_udp();
                let _ = g_udp.send_to(&answer, src).await;
            } else if *opcode == Opcode::GlobCallbackRequest.as_u8() {
                let request =
                    GlobCallbackRequest::decode_udp(datagram).expect("OP_GLOBCALLBACKREQUEST");
                assert_eq!(
                    request.low_id,
                    ClientId::from_u32(B_LOW_ID),
                    "the callback targets B's low id"
                );
                relayed = true;
                if let Some(tx) = dial_tx.take() {
                    // Relay rmule's own contact (read from the payload) so B dials it.
                    let _ = tx.send(request.requester);
                }
            }
        }
    });

    let b_task = tokio::spawn(b_global_low_id_peer(g_tcp, dial_rx, bytes.clone()));

    // rmule A: serve on a known port P (identity.tcp_port == P, the advertise-what-you-
    // bind invariant) so the serve start answers the connected server's port-check
    // hello during the login → High-ID → Callback Capability. A short sweep
    // interval fires discovery promptly.
    let p = free_port().await;
    let config = CoreConfig {
        global_source_interval: Duration::from_millis(50),
        ..CoreConfig::default()
    };
    let mut core = Core::builder(config, rmule_testkit::memory_store())
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
    serving_started(&mut core).await;
    rmule_testkit::connect_to(&core, &server_ep).await;

    // Arm global discovery with G, then start the armed download against C.
    crate::fixture::list_server(
        &core,
        &ServerEndpoint::parse_host_port(&format!("127.0.0.1:{}", g_tcp.port)).unwrap(),
    )
    .await;

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server_ep),
        name: rmule_testkit::file_name("global-callback.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
        kad_aich_root: None,
    }))
    .await
    .unwrap();

    // A waits for sources, discovers B (Low-ID global), requests a per-server
    // callback, adopts the inbound dial, and completes the download from it.
    let mut saw_waiting = false;
    let mut saw_peer = false;
    loop {
        let event = timeout(HANG_GUARD, core.next_event())
            .await
            .expect("core emitted event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Download(DownloadEvent::WaitingForSources { .. }) => saw_waiting = true,
            CoreEvent::Download(DownloadEvent::PeerSelected { .. }) => saw_peer = true,
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    }
    assert!(
        saw_waiting,
        "WaitingForSources emitted: armed download with no connected-server source"
    );
    assert!(
        saw_peer,
        "PeerSelected emitted for the adopted Low-ID global peer"
    );

    g_task.abort();
    let _ = b_task.await;
}
