//! A **Link Rider** waiting when its link ends is handed back (ADR-0107
//! invariant 9): it dials nothing, and its download keeps the source standing
//! on the peer's queue, as aMule keeps the client for its A4AF file
//! (`BaseClient.cpp:1283-1284`, `:1322-1328`).

use super::*;
use crate::adapters::PeerWorkerEvent;
use crate::service::LinkTurn;

/// What the sharer saw: a link accepted, by number, or a file asked on one.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Linked(u32),
    Asked(u32, rmule_primitives::FileHash),
}

/// A sharer that reports every link and every file asked on it, and closes
/// its first link when `close` fires — a stock uploader whose link fails
/// under the download riding it.
fn closing_sharer(listener: PeerListener, mut close: mpsc::Receiver<()>) -> mpsc::Receiver<Seen> {
    let (seen_tx, seen_rx) = mpsc::channel(16);
    tokio::spawn(async move {
        let mut link = 0_u32;
        loop {
            let Ok(mut conn) = listener
                .accept(dialed_serve_ctx(), PeerConnectOptions::default())
                .await
            else {
                return;
            };
            link += 1;
            let _ = seen_tx.send(Seen::Linked(link)).await;
            let seen_tx = seen_tx.clone();
            if link > 1 {
                continue;
            }
            loop {
                tokio::select! {
                    event = conn.next_event() => match event {
                        Some(PeerEvent::Server(
                            ServerEvent::FileRequested { file_hash, .. }
                            | ServerEvent::FileBundleRequested { file_hash, .. },
                        )) => {
                            let _ = seen_tx.send(Seen::Asked(link, file_hash)).await;
                        }
                        Some(_) => {}
                        None => break,
                    },
                    _ = close.recv() => {
                        let _ = conn.shutdown().await;
                        break;
                    }
                }
            }
        }
    });
    seen_rx
}

/// A download waiting on a link that fails under its rider is handed back:
/// it says so and ends, and nothing dials the peer again — the dial that
/// found a dead sharer failed the download on one refused connection.
#[tokio::test]
async fn a_waiter_whose_link_fails_under_the_rider_is_handed_back_and_dials_nothing() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        listener.local_port(),
    ));
    let (close_tx, close_rx) = mpsc::channel(1);
    let mut seen = closing_sharer(listener, close_rx);
    let (first_file, second_file) = (dummy_file(0xD1), dummy_file(0xD2));
    let mut transfer = RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT);
    let _rider = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), first_file.clone())
        .await
        .unwrap();
    let wait = Duration::from_secs(5);
    assert_eq!(
        timeout(wait, seen.recv()).await.ok().flatten(),
        Some(Seen::Linked(1))
    );
    assert_eq!(
        timeout(wait, seen.recv()).await.ok().flatten(),
        Some(Seen::Asked(1, first_file.file_hash))
    );
    let mut waiter = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), second_file)
        .await
        .unwrap();
    let waiting = timeout(wait, waiter.next_event()).await;
    assert!(
        matches!(
            waiting,
            Ok(Some(PeerWorkerEvent::LinkShared {
                turn: LinkTurn::Waiting
            }))
        ),
        "{waiting:?}"
    );

    close_tx.send(()).await.unwrap();
    let mut reported = Vec::new();
    while let Ok(Some(event)) = timeout(wait, waiter.next_event()).await {
        reported.push(event);
    }
    assert_eq!(reported, vec![PeerWorkerEvent::HandedBack]);
    assert_eq!(
        timeout(Duration::from_millis(500), seen.recv())
            .await
            .ok()
            .flatten(),
        None,
        "nothing dials the peer again"
    );
}
