//! A **Dial in Flight** (ADR-0107 invariant 11): two downloads of one peer
//! that start together dial once, and a dial that fails before its hello
//! retires every download waiting on it.

use super::*;

fn dummy_file(seed: u8) -> Ed2kFileLink {
    Ed2kFileLink {
        name: Ed2kText::from_utf8("dummy"),
        size: 4096,
        file_hash: FileHashSummary::digest_bytes(&[seed; 4096]).file_hash(),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    }
}

/// Two downloads of one peer that start together dial once (ADR-0107
/// invariant 11): the second finds the first one's **Dial in Flight**, waits
/// on it, and rides the one link once the first lets go. Two dials raced two
/// hellos, and stock aMule closed the first socket for the second
/// (`ClientList.cpp:400-403`).
#[tokio::test]
async fn two_downloads_started_together_dial_once_and_the_second_rides_the_link() {
    use crate::adapters::PeerWorkerEvent;
    use crate::service::LinkTurn;

    let (first_file, second_file) = (dummy_file(0xB1), dummy_file(0xB2));
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let (asked_tx, mut asked_rx) = mpsc::channel(8);
    let first_hash = first_file.file_hash;
    // The peer: each link reports the files asked on it, tagged with the
    // link's number, and refuses the first file so its download lets go.
    let mock = tokio::spawn(async move {
        let mut link = 0_u32;
        loop {
            let mut conn = listener
                .accept(dialed_serve_ctx(), PeerConnectOptions::default())
                .await
                .unwrap();
            link += 1;
            let asked_tx = asked_tx.clone();
            tokio::spawn(async move {
                while let Some(event) = conn.next_event().await {
                    let asked = match event {
                        PeerEvent::Server(
                            ServerEvent::FileRequested { file_hash, .. }
                            | ServerEvent::FileBundleRequested { file_hash, .. },
                        ) => file_hash,
                        _ => continue,
                    };
                    let _ = asked_tx.send((link, asked)).await;
                    if asked == first_hash {
                        let _ = conn
                            .send(PeerCommand::Server(ServerCommand::AnswerFileNotFound {
                                file_hash: asked,
                            }))
                            .await;
                    }
                }
            });
        }
    });

    let mut transfer = RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT);
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(*bound.ip(), bound.port()));
    let _first = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), first_file.clone())
        .await
        .unwrap();
    let mut second = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), second_file.clone())
        .await
        .unwrap();

    let waiting = timeout(Duration::from_secs(5), second.next_event()).await;
    assert!(
        matches!(
            waiting,
            Ok(Some(PeerWorkerEvent::LinkShared {
                turn: LinkTurn::Waiting
            }))
        ),
        "the second download waits on the first one's dial: {waiting:?}"
    );
    let mut asked = Vec::new();
    for _ in 0..2 {
        let next = timeout(Duration::from_secs(5), asked_rx.recv()).await;
        asked.extend(next.ok().flatten());
    }
    assert_eq!(
        asked,
        [(1, first_file.file_hash), (1, second_file.file_hash)],
        "both files are asked on the one link"
    );
    assert!(matches!(
        second.next_event().await,
        Some(PeerWorkerEvent::LinkShared {
            turn: LinkTurn::Riding
        })
    ));
    mock.abort();
}

/// A dial that closes before its hello retires every download waiting on it
/// with the cause its dialer reads, and nobody dials again: aMule's one
/// client in `DS_CONNECTING` is a dead source for every file
/// (`BaseClient.cpp:1340-1346`, `DownloadQueue.cpp:763-786`).
#[tokio::test]
async fn a_dial_closed_before_its_hello_retires_every_download_waiting_on_it() {
    use crate::adapters::PeerWorkerEvent;

    let listener = tokio::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let bound = listener.local_addr().unwrap();
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = accepted.clone();
    // The peer takes every connection and closes it unanswered, a moment
    // later, so the second download is already waiting.
    let mock = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                drop(socket);
            });
        }
    });

    let mut transfer = RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT);
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, bound.port()));
    let mut first = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), dummy_file(0xC1))
        .await
        .unwrap();
    let mut second = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), dummy_file(0xC2))
        .await
        .unwrap();

    async fn dial_end(worker: &mut crate::adapters::PeerWorker) -> Option<crate::service::DialEnd> {
        let mut cause = None;
        loop {
            match timeout(Duration::from_secs(10), worker.next_event()).await {
                Ok(Some(PeerWorkerEvent::DialEnded { cause: ended })) => cause = Some(ended),
                Ok(Some(PeerWorkerEvent::Disconnected)) | Ok(None) | Err(_) => return cause,
                Ok(Some(_)) => {}
            }
        }
    }
    let first_cause = dial_end(&mut first).await;
    let second_cause = dial_end(&mut second).await;
    assert!(first_cause.is_some(), "the dialer names why its dial ended");
    assert_eq!(
        second_cause, first_cause,
        "the waiter ends for the dial's cause"
    );
    assert_eq!(
        accepted.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "one dial reached the peer"
    );
    mock.abort();
}
