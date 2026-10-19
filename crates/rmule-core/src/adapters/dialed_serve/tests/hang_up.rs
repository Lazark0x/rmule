//! The **Queued Hang-Up** on a link rmule dialed (ADR-0116 invariant 3,
//! ADR-0107 invariant 9): a serving node closes the link its ranked rider
//! leaves, well inside the uploader's 40 s silent-link close
//! (`ClientTCPSocket.cpp:201-229`), unless another download waits on it or
//! the peer pulls on our serve side over it.

use rmule_primitives::FileHash;

use super::*;
use crate::adapters::PeerWorkerEvent;
use crate::adapters::peer_transfer::{PeerWorker, PeerWorkerCommand};
use crate::service::LinkTurn;

/// What the sharer saw on a link it accepted, tagged with the link's number.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Asked(u32, FileHash),
    Closed(u32),
}

/// A sharer that answers every file asked with its name and ranks every slot
/// ask, as a stock uploader with no free slot does; with `pull`, it asks us
/// for that file over each link it accepts, once the hellos are done. It
/// reports each file asked and each link's close.
fn ranking_sharer(listener: PeerListener, pull: Option<FileHash>) -> mpsc::Receiver<Seen> {
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
            let seen_tx = seen_tx.clone();
            tokio::spawn(async move {
                while let Some(event) = conn.next_event().await {
                    let reply = match event {
                        PeerEvent::Connection(ConnectionEvent::Identified { .. }) => {
                            let Some(file_hash) = pull else { continue };
                            PeerCommand::Requester(RequesterCommand::ProbeFile {
                                file_hash,
                                file_size: 4096,
                                own_status: PartBitmap::one_part_complete(),
                            })
                        }
                        PeerEvent::Server(
                            ServerEvent::FileRequested { file_hash, .. }
                            | ServerEvent::FileBundleRequested { file_hash, .. },
                        ) => {
                            let _ = seen_tx.send(Seen::Asked(link, file_hash)).await;
                            PeerCommand::Server(ServerCommand::AnswerFileName {
                                file_hash,
                                file_name: Ed2kText::from_utf8("dummy"),
                            })
                        }
                        PeerEvent::Server(ServerEvent::SlotRequested { .. }) => {
                            PeerCommand::Server(ServerCommand::SetQueueRank { rank: 5 })
                        }
                        PeerEvent::Connection(ConnectionEvent::Disconnected { .. }) => break,
                        _ => continue,
                    };
                    if conn.send(reply).await.is_err() {
                        break;
                    }
                }
                let _ = seen_tx.send(Seen::Closed(link)).await;
            });
        }
    });
    seen_rx
}

/// A peer-transfer adapter whose dialed links serve, and a serve task that
/// holds every serve half it is handed and reads it to its end, asking
/// nothing of it.
fn serving_transfer() -> RuntimePeerTransferService {
    let (dialed_tx, mut dialed_rx) = mpsc::channel::<crate::adapters::LinkServeHalf>(4);
    let sink = SharedDialedServeSink::default();
    sink.install_for_good(dialed_tx);
    tokio::spawn(async move {
        while let Some(crate::adapters::LinkServeHalf {
            conn: mut serve_conn,
            ..
        }) = dialed_rx.recv().await
        {
            tokio::spawn(async move { while serve_conn.next_event().await.is_some() {} });
        }
    });
    RuntimePeerTransferService::with_dialed_serve_sink(crate::DEFAULT_SLOT_WAIT_TIMEOUT, sink)
}

/// Drive `worker` as its download does: ask the slot at the probe's answer,
/// and end the worker at its rank without a grant, the Queued Hang-Up.
async fn hang_up_at_rank(worker: &mut PeerWorker) {
    timeout(Duration::from_secs(5), async {
        while let Some(event) = worker.next_event().await {
            match event {
                PeerWorkerEvent::PartsAdvertised { .. } => {
                    worker.send(PeerWorkerCommand::AskSlot).await.unwrap();
                }
                PeerWorkerEvent::Queued { .. } => {
                    let shutdown = PeerWorkerCommand::Shutdown { cancel: false };
                    worker.send(shutdown).await.unwrap();
                    return;
                }
                _ => {}
            }
        }
        panic!("the worker ended before its rank");
    })
    .await
    .expect("the sharer ranked the slot ask");
}

/// The next thing the sharer saw within `wait`, if any.
async fn next_seen(seen: &mut mpsc::Receiver<Seen>, wait: Duration) -> Option<Seen> {
    timeout(wait, seen.recv()).await.ok().flatten()
}

fn local_peer(listener: &PeerListener) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        listener.local_port(),
    ))
}

/// A rider ranked without a grant on a link nothing else holds closes the
/// link at once, though the node serves: the sharer reads our close within
/// seconds, not at its own 40 s timeout. Its place stays the record's, and the
/// uploader promotes it by dial-back (`UploadQueue.cpp:206-210`).
#[tokio::test]
async fn a_rider_ranked_alone_on_a_link_closes_it() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let peer = local_peer(&listener);
    let mut seen = ranking_sharer(listener, None);
    let file = dummy_file(0xC1);
    let mut transfer = serving_transfer();
    let mut worker = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), file.clone())
        .await
        .unwrap();

    hang_up_at_rank(&mut worker).await;
    let wait = Duration::from_secs(5);
    assert_eq!(
        next_seen(&mut seen, wait).await,
        Some(Seen::Asked(1, file.file_hash))
    );
    assert_eq!(
        next_seen(&mut seen, wait).await,
        Some(Seen::Closed(1)),
        "the hang-up closes the link"
    );
}

/// A download waiting on the link takes it when the rider hangs up at its
/// rank, and the link stays up for it; the last rider's hang-up closes it.
#[tokio::test]
async fn a_link_a_download_waits_on_outlives_the_ranked_rider() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let peer = local_peer(&listener);
    let mut seen = ranking_sharer(listener, None);
    let (first_file, second_file) = (dummy_file(0xC2), dummy_file(0xC3));
    let mut transfer = serving_transfer();
    let mut first = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), first_file.clone())
        .await
        .unwrap();
    let wait = Duration::from_secs(5);
    assert_eq!(
        next_seen(&mut seen, wait).await,
        Some(Seen::Asked(1, first_file.file_hash))
    );
    let mut second = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), second_file.clone())
        .await
        .unwrap();
    let waiting = timeout(wait, second.next_event()).await;
    assert!(
        matches!(
            waiting,
            Ok(Some(PeerWorkerEvent::LinkShared {
                turn: LinkTurn::Waiting
            }))
        ),
        "{waiting:?}"
    );

    hang_up_at_rank(&mut first).await;
    assert_eq!(
        next_seen(&mut seen, wait).await,
        Some(Seen::Asked(1, second_file.file_hash)),
        "the waiter asks on the same link, which stayed up for it"
    );
    hang_up_at_rank(&mut second).await;
    assert_eq!(next_seen(&mut seen, wait).await, Some(Seen::Closed(1)));
}

/// A peer that asked our serve side for a file over the link holds it: the
/// rider's hang-up leaves the link up for the peer's pull (ADR-0031).
#[tokio::test]
async fn a_link_the_peer_pulls_on_outlives_the_ranked_rider() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let peer = local_peer(&listener);
    let shared = dummy_file(0xC5).file_hash;
    let mut seen = ranking_sharer(listener, Some(shared));
    let file = dummy_file(0xC4);
    let mut transfer = serving_transfer();
    let mut worker = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), file.clone())
        .await
        .unwrap();

    hang_up_at_rank(&mut worker).await;
    assert_eq!(
        next_seen(&mut seen, Duration::from_secs(5)).await,
        Some(Seen::Asked(1, file.file_hash))
    );
    assert_eq!(
        next_seen(&mut seen, Duration::from_secs(1)).await,
        None,
        "the peer's pull keeps the link"
    );
}
