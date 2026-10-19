//! Dials that never happen (banned, IP-filtered, crypt-incompatible), each
//! named before its terminal fact, a refused connect, and the mid-part
//! shutdown.

use super::*;
use crate::service::DialEnd;

/// A refused dial's first two facts: why, then the terminal one.
///
/// The wait is the dial's own connect timeout, a hang guard rather than a
/// speed bar: Windows reports a refused connect only after it has re-sent the
/// SYN twice, about 2 s even on loopback.
async fn first_two(worker: &mut PeerWorker) -> [Option<PeerWorkerEvent>; 2] {
    let bound = PeerConnectOptions::default().connect_timeout;
    let mut next = async || {
        timeout(bound, worker.next_event())
            .await
            .expect("each fact within the connect timeout")
    };
    [next().await, next().await]
}

/// The seeds the human's run held: remembered peers whose crypt stance no
/// record ever stated, dialed under a `required` policy. Each is refused
/// before any socket and says it was refused for the unknown stance.
#[tokio::test]
async fn a_required_policy_names_a_stanceless_seed_s_refusal() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let adverts = HelloAdverts {
        obfuscation: crate::obfuscation_policy::SharedObfuscationPolicy::new(Some(
            ObfuscationPolicy::Required,
        )),
        ..HelloAdverts::default()
    };
    let mut transfer = RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT)
        .with_hello_adverts(adverts);
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        listener.local_port(),
    ));
    let mut worker = transfer
        .start_download_worker(
            peer,
            dialed_serve_ctx(),
            a_file(),
            WorkerBrief::fresh(&a_file()),
        )
        .await
        .unwrap();

    assert_eq!(
        first_two(&mut worker).await,
        [
            Some(PeerWorkerEvent::DialEnded {
                cause: DialEnd::CryptStanceUnknown
            }),
            Some(PeerWorkerEvent::CryptIncompatible)
        ]
    );
    assert!(
        timeout(
            Duration::from_millis(300),
            listener.accept(dialed_serve_ctx(), PeerConnectOptions::default())
        )
        .await
        .is_err(),
        "a refused seed is never dialed"
    );
}

/// The obfuscation policy changes live (ADR-0046): each dial reads it as it
/// starts, so the dial made before a change to `Required` reaches its
/// stanceless peer, and the very next one is refused before any socket. The
/// next dial is to another peer: one to the same peer would wait on the
/// first one's link instead of dialing (ADR-0107).
#[tokio::test]
async fn a_live_policy_change_reaches_the_very_next_dial() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let other = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let policy = crate::obfuscation_policy::SharedObfuscationPolicy::default();
    let mut transfer = RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT)
        .with_hello_adverts(HelloAdverts {
            obfuscation: policy.clone(),
            ..HelloAdverts::default()
        });
    let at = |port| PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, port));
    let dial = async |transfer: &mut RuntimePeerTransferService, peer| {
        transfer
            .start_download_worker(
                peer,
                dialed_serve_ctx(),
                a_file(),
                WorkerBrief::fresh(&a_file()),
            )
            .await
            .unwrap()
    };

    let _before = dial(&mut transfer, at(listener.local_port())).await;
    timeout(
        Duration::from_secs(2),
        listener.accept(dialed_serve_ctx(), PeerConnectOptions::default()),
    )
    .await
    .expect("the dial before the change reaches the peer")
    .expect("in plaintext, as off dials");

    policy.set(Some(ObfuscationPolicy::Required));
    let mut after = dial(&mut transfer, at(other.local_port())).await;
    assert_eq!(
        first_two(&mut after).await,
        [
            Some(PeerWorkerEvent::DialEnded {
                cause: DialEnd::CryptStanceUnknown
            }),
            Some(PeerWorkerEvent::CryptIncompatible)
        ]
    );
    assert!(
        timeout(
            Duration::from_millis(300),
            other.accept(dialed_serve_ctx(), PeerConnectOptions::default())
        )
        .await
        .is_err(),
        "the refused dial opens no socket"
    );
}

/// A port nobody listens on refuses the connect, and the worker says so.
#[tokio::test]
async fn a_refused_connect_is_named() {
    let closed = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let mut transfer = RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT);
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, port));
    let mut worker = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), a_file())
        .await
        .unwrap();
    assert_eq!(
        first_two(&mut worker).await,
        [
            Some(PeerWorkerEvent::DialEnded {
                cause: DialEnd::ConnectionRefused
            }),
            Some(PeerWorkerEvent::Disconnected)
        ]
    );
}

/// ADR-0064: a banned candidate source is never dialed at all — the
/// same silent-failure shape a real connect refusal takes, so the
/// download runner backfills the slot exactly as it would for any other
/// dead source.
#[tokio::test]
async fn a_banned_peer_is_never_dialed() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());

    let ban_store: SharedBanStore = SharedBanStore::default();
    ban_store
        .lock()
        .await
        .ban(std::net::IpAddr::V4(*bound.ip()), std::time::Instant::now());

    let mut transfer =
        RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT).with_ban_store(ban_store);
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(*bound.ip(), bound.port()));
    let file = Ed2kFileLink {
        name: Ed2kText::from_utf8("dummy"),
        size: 4096,
        file_hash: FileHash::from_bytes([0xAB; FileHash::BYTE_LEN]),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    };
    let mut worker = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), file)
        .await
        .unwrap();

    // The worker says why, then reports a disconnect — the same shape as a
    // real connect failure — without ever touching the socket.
    assert_eq!(
        first_two(&mut worker).await,
        [
            Some(PeerWorkerEvent::DialEnded {
                cause: DialEnd::Banned
            }),
            Some(PeerWorkerEvent::Disconnected)
        ]
    );

    // And the listener never saw a connection at all.
    assert!(
        timeout(
            Duration::from_millis(300),
            listener.accept(dialed_serve_ctx(), PeerConnectOptions::default())
        )
        .await
        .is_err(),
        "a banned candidate source is never dialed"
    );
}

/// The IP filter's dial gate (aMule `CUpDownClient::TryToConnect` /
/// `SendHelloPacket`): an IP-filtered candidate source is never dialed —
/// the same silent connect-failure shape the ban gate takes, so the
/// runner backfills the slot.
#[tokio::test]
async fn an_ip_filtered_peer_is_never_dialed() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());

    let ip_filter = SharedIpFilter::default();
    *ip_filter.write().expect("ip filter lock") = loopback_blocking_ip_filter();

    let mut transfer =
        RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT).with_ip_filter(ip_filter);
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(*bound.ip(), bound.port()));
    let file = Ed2kFileLink {
        name: Ed2kText::from_utf8("dummy"),
        size: 4096,
        file_hash: FileHash::from_bytes([0xAB; FileHash::BYTE_LEN]),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    };
    let mut worker = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), file)
        .await
        .unwrap();

    assert_eq!(
        first_two(&mut worker).await,
        [
            Some(PeerWorkerEvent::DialEnded {
                cause: DialEnd::IpFiltered
            }),
            Some(PeerWorkerEvent::Disconnected)
        ]
    );

    assert!(
        timeout(
            Duration::from_millis(300),
            listener.accept(dialed_serve_ctx(), PeerConnectOptions::default())
        )
        .await
        .is_err(),
        "an IP-filtered candidate source is never dialed"
    );
}

/// A source whose record says it requires obfuscation, dialed by a
/// node whose obfuscation is off, is refused before any socket (aMule's
/// contact precondition) — and reported as that, not as a dead source, so the
/// brain retires it for the reason it was never reached.
#[tokio::test]
async fn a_peer_requiring_crypt_is_reported_crypt_incompatible_while_ours_is_off() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let mut transfer = RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT);
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(*bound.ip(), bound.port()));
    let file = Ed2kFileLink {
        name: Ed2kText::from_utf8("dummy"),
        size: 4096,
        file_hash: FileHash::from_bytes([0xAB; FileHash::BYTE_LEN]),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    };
    let brief = WorkerBrief {
        peer_crypt: PeerCrypt::new(
            CryptStance::new(true, true, true),
            Some(UserHash::from_bytes([0x5A; UserHash::BYTE_LEN])),
        ),
        ..WorkerBrief::fresh(&file)
    };
    let mut worker = transfer
        .start_download_worker(peer, dialed_serve_ctx(), file, brief)
        .await
        .unwrap();

    assert_eq!(
        first_two(&mut worker).await,
        [
            Some(PeerWorkerEvent::DialEnded {
                cause: DialEnd::CryptRequiredByPeer
            }),
            Some(PeerWorkerEvent::CryptIncompatible)
        ]
    );
    assert!(
        timeout(
            Duration::from_millis(300),
            listener.accept(dialed_serve_ctx(), PeerConnectOptions::default())
        )
        .await
        .is_err(),
        "a crypt-incompatible source is never dialed"
    );
}

/// A worker told to shut down mid-part stops at once — the
/// block loop reads its command channel between blocks — rather than waiting
/// out a part the download has already let go of (aMule
/// `CUpDownClient::Disconnected` aborts the transfer on the spot). The peer
/// grants a slot and then sends nothing, so without the poll only the
/// ten-minute slot budget could end the stream.
#[tokio::test]
async fn a_shutdown_mid_part_stops_the_stream_at_once() {
    use rmule_testkit::{FakePeer, PeerScript, ServePolicy};

    let bytes = vec![0x5A; 4096];
    let file = rmule_testkit::file_link("mid-part.bin", &bytes);
    let uploader = FakePeer::bind().await;
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(
        *uploader.addr().ip(),
        uploader.addr().port(),
    ));
    let peer_task = uploader.spawn(PeerScript {
        serve: ServePolicy::Nothing,
        ..PeerScript::serving(file.file_hash, bytes)
    });
    let mut transfer = RuntimePeerTransferService::new(Duration::from_secs(600));
    let mut worker = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), file.clone())
        .await
        .unwrap();
    worker
        .send(PeerWorkerCommand::RequestBlocks {
            blocks: vec![crate::BlockPlan {
                part_index: 0,
                start: 0,
                end: file.size,
            }],
        })
        .await
        .unwrap();
    loop {
        let event = timeout(Duration::from_secs(5), worker.next_event())
            .await
            .expect("the slot is granted within 5s");
        if event == Some(PeerWorkerEvent::SlotGranted) {
            break;
        }
        assert!(event.is_some(), "the worker must stay up until the grant");
    }

    worker
        .send(PeerWorkerCommand::Shutdown { cancel: true })
        .await
        .unwrap();

    let stats = timeout(Duration::from_secs(3), peer_task)
        .await
        .expect("the worker closed the socket at the shutdown, mid-part")
        .unwrap();
    assert_eq!(stats.cancel_transfer_count, 1);
}
