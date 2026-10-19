//! The other end of the Low-ID callback (ADR-0061) over the deterministic
//! `FakeEd2kServer`: the server's Back-Connect Probe of rmule is blocked, so
//! it is **Low-ID**; a High-ID requester on the
//! same server asks for a callback to it (`OP_CALLBACKREQUEST`), the server
//! relays `OP_CALLBACKREQUESTED`, and rmule dials the requester back and serves
//! it the file over that link, as aMule's `TryToConnect` does.
//!
//! Every hop is a real socket through the built core — the session's relay
//! arm, the dial-back seam the builder installs and the serve pipeline it
//! enters — so only the counterparty is a fake: rmule's side, not interop.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};

use rmule_core::{Core, CoreCommand, CoreConfig, ServeCommand};
use rmule_ed2k::{CallbackRequest, IdChange, LoginRequest};
use rmule_net::peer::{ConnectOptions, Connection, PeerListener};
use rmule_peer::{
    ConnectionEvent, PartRanges, PeerCommand, PeerEvent, PeerHandshakeContext, RequesterCommand,
    RequesterEvent,
};
use rmule_primitives::{
    Capabilities, ClientId, ClientIdentity, CryptStance, Ed2kText, FileHashSummary, Packet,
    ServerEndpoint, UserHash,
};
use rmule_testkit::{FakeEd2kServer, HANG_GUARD};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::timeout;

use crate::fixture::{free_port, serving_started, settings_on};

const SHARER_HASH: UserHash = UserHash::from_bytes([0x5A; UserHash::BYTE_LEN]);
const REQUESTER_HASH: UserHash = UserHash::from_bytes([0xC1; UserHash::BYTE_LEN]);

/// The requester's listener: it answers the server's port check, and hands
/// over the first connection whose hello names the sharer — the dial-back.
fn requester_accepts(
    listener: PeerListener,
    ctx: PeerHandshakeContext,
) -> oneshot::Receiver<Connection> {
    let (dialed_tx, dialed_rx) = oneshot::channel();
    tokio::spawn(async move {
        let mut dialed_tx = Some(dialed_tx);
        loop {
            let Ok(mut conn) = listener
                .accept(ctx.clone(), ConnectOptions::default())
                .await
            else {
                continue;
            };
            let identified = loop {
                match conn.next_event().await {
                    Some(PeerEvent::Connection(ConnectionEvent::Identified { identity })) => {
                        break Some(identity.user_hash());
                    }
                    Some(_) => {}
                    None => break None,
                }
            };
            if identified == Some(SHARER_HASH) {
                if let Some(tx) = dialed_tx.take() {
                    let _ = tx.send(conn);
                }
            } else {
                // The port check, answered: drained until it closes.
                tokio::spawn(async move { while conn.next_event().await.is_some() {} });
            }
        }
    });
    dialed_rx
}

/// Read `core`'s event stream for the rest of the leg, as a front end does,
/// keeping a short line per event for a failure to show. The core has one
/// bounded stream and its activities await room in it, so a reader that
/// stops stalls the serve side as soon as the stream fills: after it framed
/// the grant, before it reads the part request.
fn keep_reading(mut core: Core) -> Arc<Mutex<Vec<String>>> {
    let said = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&said);
    tokio::spawn(async move {
        while let Some(event) = core.next_event().await {
            log.lock().unwrap().push(brief(&event));
        }
    });
    said
}

/// One event, cut to a line a failure can list.
fn brief(event: &impl std::fmt::Debug) -> String {
    format!("{event:?}").chars().take(120).collect()
}

async fn read_packet(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Packet {
    loop {
        if let Ok((packet, consumed)) = Packet::decode(buf) {
            buf.drain(..consumed);
            return packet;
        }
        let mut chunk = [0u8; 4096];
        let n = timeout(HANG_GUARD, stream.read(&mut chunk))
            .await
            .expect("a server frame")
            .expect("read ok");
        assert!(n > 0, "the server closed");
        buf.extend_from_slice(&chunk[..n]);
    }
}

#[tokio::test]
async fn a_low_id_core_dials_back_the_relayed_requester_and_serves_it() {
    let server = FakeEd2kServer::start().await;
    let server_addr = server.local_addr();
    let server_ep = ServerEndpoint::parse_host_port(&server_addr.to_string()).unwrap();
    let bytes = vec![0x5C_u8; 4096];
    let file_hash = FileHashSummary::digest_bytes(&bytes).file_hash();
    let share = tempfile::tempdir().unwrap();
    tokio::fs::write(share.path().join("relayed.bin"), &bytes)
        .await
        .unwrap();

    let port = free_port().await;
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(settings_on(port))
        .user_hash(SHARER_HASH)
        .build();
    let shared = rmule_testkit::share_directory(&mut core, share.path()).await;
    assert_eq!(shared, [file_hash], "the first pass shared relayed.bin");
    // Our inbound TCP is blocked for the probe, so the server assigns a Low
    // ID; the requester's, after it, is open.
    server.set_probe_blocked(true).await;
    rmule_testkit::connect_to(&core, &server_ep).await;
    let sharer_id = server.assigned_ids_after(1).await[0];
    assert!(sharer_id.is_low_id(), "the sharer is Low-ID: {sharer_id:?}");
    server.set_probe_blocked(false).await;
    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
    }))
    .await
    .unwrap();
    serving_started(&mut core).await;
    let core_said = keep_reading(core);

    // The requester: High-ID on the same server, its listener answering both
    // the probe and, later, our dial-back.
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let identity = ClientIdentity::new(
        REQUESTER_HASH,
        Ed2kText::from_utf8("high-id-requester"),
        listener.local_port(),
        60,
    );
    let ctx = PeerHandshakeContext {
        identity: identity.clone(),
        client_id: ClientId::from_u32(0),
        ed2k_client_id: ClientId::from_u32(0),
        public_ip: None,
        connected_server: None,
    };
    let dialed = requester_accepts(listener, ctx);
    let mut server_link = TcpStream::connect(server_addr).await.unwrap();
    server_link
        .write_all(
            &LoginRequest::from_identity(
                &identity,
                &Capabilities::shipped(CryptStance::disabled()),
            )
            .encode_packet()
            .encode(),
        )
        .await
        .unwrap();
    let mut buf = Vec::new();
    let requester_id = IdChange::decode_packet(&read_packet(&mut server_link, &mut buf).await)
        .expect("the requester's IdChange")
        .client_id;
    assert!(requester_id.is_high_id(), "the probe reached the requester");

    server_link
        .write_all(&CallbackRequest::new(sharer_id).encode_packet().encode())
        .await
        .unwrap();
    let mut link = timeout(HANG_GUARD, dialed)
        .await
        .expect("the sharer dials the requester back")
        .expect("the listener task lives");

    let ranges = PartRanges::new([(0, bytes.len() as u64), (0, 0), (0, 0)]).unwrap();
    link.send(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash,
        file_size: bytes.len() as u64,
        ranges,
    }))
    .await
    .unwrap();
    // What the requester met on the way, so a stall names its step.
    let mut requester_saw = Vec::new();
    let received = timeout(HANG_GUARD, async {
        let mut got = Vec::new();
        while let Some(event) = link.next_event().await {
            if let PeerEvent::Requester(RequesterEvent::PartReceived { bytes, .. }) = event {
                got.extend_from_slice(&bytes);
                if got.len() >= 4096 {
                    break;
                }
            } else {
                requester_saw.push(brief(&event));
            }
        }
        got
    })
    .await;
    let Ok(received) = received else {
        panic!(
            "the sharer never served the requester over the dialed link; the requester met \
             {requester_saw:#?}; the sharer's core said {:#?}",
            core_said.lock().unwrap()
        );
    };
    assert_eq!(received, bytes);
}
