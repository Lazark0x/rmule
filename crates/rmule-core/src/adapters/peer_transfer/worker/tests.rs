//! The block loop's reaction to the notices a shared link raises, how the
//! probe wait and the block loop report a peer that lacks the file, what the
//! wait between handouts hears on the link, and how handed blocks are asked
//! and reported (ADR-0117).

use rmule_peer::{FileProbeStatus, NoticeEvent, PeerError, PeerEvent, RequesterEvent};
use tokio::sync::mpsc;

use super::wait::{Idled, idle_wait};
use super::*;
use crate::BlockPlan;

/// Part 0's block `start..end`.
fn block(start: u64, end: u64) -> BlockPlan {
    BlockPlan {
        part_index: 0,
        start,
        end,
    }
}

/// Hand `blocks` to `pipeline` and run [`stream_blocks`] over `link`.
async fn streamed(
    link: &mut WorkerLink<'_>,
    pipeline: &mut Pipeline,
    file: &Ed2kFileLink,
    blocks: &[BlockPlan],
    budget: Duration,
) -> Streamed {
    pipeline.hand(blocks);
    stream_blocks(link, pipeline, file, budget).await
}

/// The events `worker_events` carries once its sender is dropped.
async fn drained(mut worker_events: mpsc::Receiver<PeerWorkerEvent>) -> Vec<PeerWorkerEvent> {
    let mut reported = Vec::new();
    while let Some(event) = worker_events.recv().await {
        reported.push(event);
    }
    reported
}

/// The `BlocksWanted` a stream reports once its pipeline drained at depth 3.
const DRAINED: PeerWorkerEvent = PeerWorkerEvent::BlocksWanted {
    room: 3,
    drained: true,
};

/// Run [`stream_blocks`] over `bytes` with `notice` arriving before the
/// part's one block, and return the worker events it reported.
async fn events_after_notice(bytes: &[u8], notice: PeerError) -> Vec<PeerWorkerEvent> {
    events_after(bytes, |_| {
        PeerEvent::Notice(NoticeEvent::CommandRejected { reason: notice })
    })
    .await
}

/// Run [`stream_blocks`] over `bytes` with the event `first` makes of
/// the file's hash arriving before the part's one block, and return the
/// worker events it reported.
async fn events_after(
    bytes: &[u8],
    first: impl FnOnce(rmule_primitives::FileHash) -> PeerEvent,
) -> Vec<PeerWorkerEvent> {
    let file = rmule_testkit::file_link("notice.bin", bytes);
    let (events_tx, mut events) = mpsc::channel(8);
    let (cmd_tx, _cmd_rx) = mpsc::channel(8);
    let (event_tx, worker_events) = mpsc::channel(8);
    let (_worker_cmd_tx, mut worker_cmd_rx) = mpsc::channel(8);
    events_tx.send(first(file.file_hash)).await.unwrap();
    events_tx
        .send(PeerEvent::Requester(RequesterEvent::PartReceived {
            file_hash: file.file_hash,
            offset: 0,
            bytes: bytes.to_vec(),
        }))
        .await
        .unwrap();
    let mut link = WorkerLink {
        events: &mut events,
        cmd_tx: &cmd_tx,
        event_tx: &event_tx,
        commands: &mut worker_cmd_rx,
        deferred: VecDeque::new(),
    };
    streamed(
        &mut link,
        &mut Pipeline::new(),
        &file,
        &[block(0, bytes.len() as u64)],
        Duration::from_secs(5),
    )
    .await;
    drop(link);
    drop(event_tx);
    drained(worker_events).await
}

#[tokio::test]
async fn a_refused_serving_command_does_not_end_the_download() {
    let reported = events_after_notice(&[0x5A; 1024], PeerError::ServeSlotNotGranted).await;
    assert!(
        reported.contains(&DRAINED),
        "the block after the notice still lands: {reported:?}"
    );
    assert!(!reported.contains(&PeerWorkerEvent::Disconnected));
}

#[tokio::test]
async fn a_refused_download_command_still_ends_the_download() {
    let reported = events_after_notice(&[0x5A; 1024], PeerError::SlotBusy).await;
    assert_eq!(reported, vec![PeerWorkerEvent::Disconnected]);
}

/// A mid-slot `OP_FILEREQANSNOFIL` is the peer lacking the file, reported as
/// the probe reports it — no parts — and never as a disconnect the download
/// would keep the source's standing on (ADR-0090).
#[tokio::test]
async fn a_mid_slot_no_file_answer_is_reported_as_no_parts() {
    let reported = events_after(&[0x5A; 1024], |file_hash| {
        PeerEvent::Requester(RequesterEvent::FileProbed {
            file_hash,
            status: FileProbeStatus::NotAvailable,
        })
    })
    .await;
    assert_eq!(
        reported,
        vec![PeerWorkerEvent::PartsAdvertised {
            parts: None,
            complete: false
        }]
    );
}

/// The probe's no-file answer is the worker's last word: no disconnect
/// follows it.
#[tokio::test]
async fn a_probe_answered_with_no_file_reports_no_parts_and_nothing_after() {
    let file = rmule_testkit::file_link("notice.bin", &[0x5A; 1024]);
    let (events_tx, mut events) = mpsc::channel(8);
    let (cmd_tx, _cmd_rx) = mpsc::channel(8);
    let (event_tx, mut worker_events) = mpsc::channel(8);
    let (_worker_cmd_tx, mut worker_cmd_rx) = mpsc::channel(8);
    events_tx
        .send(PeerEvent::Requester(RequesterEvent::FileProbed {
            file_hash: file.file_hash,
            status: FileProbeStatus::NotAvailable,
        }))
        .await
        .unwrap();
    let mut link = WorkerLink {
        events: &mut events,
        cmd_tx: &cmd_tx,
        event_tx: &event_tx,
        commands: &mut worker_cmd_rx,
        deferred: VecDeque::new(),
    };
    let probed = await_probe(&mut link, file.file_hash, Duration::from_secs(5)).await;
    assert!(matches!(probed, Streamed::WindDown));
    drop(event_tx);
    let mut reported = Vec::new();
    while let Some(event) = worker_events.recv().await {
        reported.push(event);
    }
    assert_eq!(
        reported,
        vec![PeerWorkerEvent::PartsAdvertised {
            parts: None,
            complete: false
        }]
    );
}

/// `OP_OUTOFPARTREQS` on the granted slot ends the transfer, not the worker:
/// it reports being queued again and goes back for its next command, the
/// block that would have followed left unread (ADR-0057).
#[tokio::test]
async fn a_requeue_reports_itself_and_leaves_the_worker_on_its_link() {
    let reported = events_after(&[0x5A; 1024], |file_hash| {
        PeerEvent::Requester(RequesterEvent::Requeued { file_hash })
    })
    .await;
    assert_eq!(reported, vec![PeerWorkerEvent::Requeued]);
}

/// A compressed block the session could not inflate will not come again on
/// this slot: a stock uploader drops a second ask for a block it has sent
/// (aMule `UploadClient.cpp:503-511`). The block is reported lost, for core
/// to free, and the slot is kept, the drained pipeline asking for more at once
/// rather than idling out the no-progress budget (ADR-0029 "A lost block is
/// freed").
#[tokio::test(start_paused = true)]
async fn a_block_that_fails_to_inflate_is_freed_and_the_slot_kept() {
    let bytes = [0x5A; 1024];
    let file = rmule_testkit::file_link("corrupt.bin", &bytes);
    let (events_tx, mut events) = mpsc::channel(8);
    let (cmd_tx, _cmd_rx) = mpsc::channel(8);
    let (event_tx, worker_events) = mpsc::channel(8);
    let (_worker_cmd_tx, mut worker_cmd_rx) = mpsc::channel(8);
    events_tx
        .send(PeerEvent::Requester(
            RequesterEvent::CompressedPartSkipped {
                file_hash: file.file_hash,
                offset: 0,
                reason: rmule_peer::InflateFailed::Corrupt,
            },
        ))
        .await
        .unwrap();
    let mut link = WorkerLink {
        events: &mut events,
        cmd_tx: &cmd_tx,
        event_tx: &event_tx,
        commands: &mut worker_cmd_rx,
        deferred: VecDeque::new(),
    };
    let started = tokio::time::Instant::now();
    let ended = streamed(
        &mut link,
        &mut Pipeline::new(),
        &file,
        &[block(0, 1024)],
        Duration::from_secs(180),
    )
    .await;
    assert_eq!(
        started.elapsed(),
        Duration::ZERO,
        "no wait on the lost block"
    );
    assert!(matches!(ended, Streamed::Next), "the slot is kept");
    drop(link);
    drop(event_tx);
    assert_eq!(
        drained(worker_events).await,
        vec![
            PeerWorkerEvent::BlockLost {
                start: 0,
                end: 1024
            },
            DRAINED
        ]
    );
    drop(events_tx);
}

/// Run [`idle_wait`] over `link_events`, the link closing after them, with no
/// command sent and a slot budget of `budget`, and return the worker events
/// it reported.
async fn idled_over(link_events: Vec<PeerEvent>, budget: Duration) -> Vec<PeerWorkerEvent> {
    let file = rmule_testkit::file_link("idle.bin", &[0x5A; 1024]);
    let (events_tx, mut events) = mpsc::channel(8);
    let (cmd_tx, _cmd_rx) = mpsc::channel(8);
    let (event_tx, mut worker_events) = mpsc::channel(8);
    let (_worker_cmd_tx, mut worker_cmd_rx) = mpsc::channel(8);
    let closes = !link_events.is_empty();
    for event in link_events {
        events_tx.send(event).await.unwrap();
    }
    // With nothing to hear, the link stays open until the wait has ended.
    let open = (!closes).then_some(events_tx);
    let mut link = WorkerLink {
        events: &mut events,
        cmd_tx: &cmd_tx,
        event_tx: &event_tx,
        commands: &mut worker_cmd_rx,
        deferred: VecDeque::new(),
    };
    let idled = idle_wait(
        &mut link,
        &mut Pipeline::new(),
        file.file_hash,
        tokio::time::Instant::now() + budget,
    )
    .await;
    assert!(matches!(idled, Idled::Ended | Idled::Stalled));
    drop(open);
    drop(event_tx);
    let mut reported = Vec::new();
    while let Some(event) = worker_events.recv().await {
        reported.push(event);
    }
    reported
}

/// A queued worker waiting with no command hears its slot ask leave, its
/// rank and its grant, and its link closing reaches the download as
/// `Disconnected` at once — no command needed to notice it (ADR-0026).
#[tokio::test]
async fn the_wait_between_handouts_hears_the_slot_and_the_links_end() {
    let file_hash = rmule_testkit::file_link("idle.bin", &[0x5A; 1024]).file_hash;
    let reported = idled_over(
        vec![
            PeerEvent::Requester(RequesterEvent::SlotAsked { file_hash }),
            PeerEvent::Requester(RequesterEvent::QueueRanked { file_hash, rank: 4 }),
            PeerEvent::Requester(RequesterEvent::SlotGranted {
                file_hash,
                asked: rmule_peer::AskedRanges::default(),
            }),
        ],
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(
        reported,
        vec![
            PeerWorkerEvent::SlotAsked,
            PeerWorkerEvent::Queued { rank: 4 },
            PeerWorkerEvent::SlotGranted,
            PeerWorkerEvent::Disconnected,
        ]
    );
}

/// A wait between handouts that hears nothing within the slot budget ends the
/// worker with `SlotTimeout`.
#[tokio::test]
async fn a_silent_wait_between_handouts_ends_at_the_slot_budget() {
    let reported = idled_over(Vec::new(), Duration::ZERO).await;
    assert_eq!(reported, vec![PeerWorkerEvent::SlotTimeout]);
}

/// The ranges of every `OP_REQUESTPARTS` the worker sent, in order.
fn asked(cmd_rx: &mut mpsc::Receiver<PeerCommand>) -> Vec<Vec<(u64, u64)>> {
    let mut asked = Vec::new();
    while let Ok(command) = cmd_rx.try_recv() {
        if let PeerCommand::Requester(RequesterCommand::RequestParts { ranges, .. }) = command {
            asked.push(
                ranges
                    .as_array()
                    .iter()
                    .copied()
                    .filter(|(start, end)| end > start)
                    .collect(),
            );
        }
    }
    asked
}

/// A stream asks three handed blocks at once, then one more as each lands,
/// so two stay queued at the uploader while one arrives (ADR-0029); once
/// everything handed is asked it says the room each landing leaves, and at
/// the drain that it drained (ADR-0117).
#[tokio::test]
async fn handed_blocks_stream_asked_ahead_and_report_their_room() {
    const BLOCK: u64 = rmule_peer::EMBLOCKSIZE;
    let bytes = vec![0x5A; (5 * BLOCK) as usize];
    let file = rmule_testkit::file_link("deep.bin", &bytes);
    let (events_tx, mut events) = mpsc::channel(8);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
    let (event_tx, worker_events) = mpsc::channel(16);
    let (_worker_cmd_tx, mut worker_cmd_rx) = mpsc::channel(8);
    for block in 0..5u64 {
        let start = (block * BLOCK) as usize;
        events_tx
            .send(PeerEvent::Requester(RequesterEvent::PartReceived {
                file_hash: file.file_hash,
                offset: block * BLOCK,
                bytes: bytes[start..start + BLOCK as usize].to_vec(),
            }))
            .await
            .unwrap();
    }
    let handed: Vec<BlockPlan> = (0..5u64)
        .map(|n| block(n * BLOCK, (n + 1) * BLOCK))
        .collect();
    let mut link = WorkerLink {
        events: &mut events,
        cmd_tx: &cmd_tx,
        event_tx: &event_tx,
        commands: &mut worker_cmd_rx,
        deferred: VecDeque::new(),
    };
    let ended = streamed(
        &mut link,
        &mut Pipeline::new(),
        &file,
        &handed,
        Duration::from_secs(5),
    )
    .await;
    assert!(matches!(ended, Streamed::Next));
    assert_eq!(
        asked(&mut cmd_rx),
        vec![
            vec![(0, BLOCK), (BLOCK, 2 * BLOCK), (2 * BLOCK, 3 * BLOCK)],
            vec![(3 * BLOCK, 4 * BLOCK)],
            vec![(4 * BLOCK, 5 * BLOCK)],
        ]
    );
    drop(link);
    drop(event_tx);
    let wants: Vec<PeerWorkerEvent> = drained(worker_events)
        .await
        .into_iter()
        .filter(|event| matches!(event, PeerWorkerEvent::BlocksWanted { .. }))
        .collect();
    assert_eq!(
        wants,
        vec![
            PeerWorkerEvent::BlocksWanted {
                room: 1,
                drained: false
            },
            PeerWorkerEvent::BlocksWanted {
                room: 2,
                drained: false
            },
            DRAINED,
        ]
    );
}

/// The grant the wait between handouts hears hands the next stream the link's
/// Asked Ranges: after a silent release to this file, no block repeats a
/// range the uploader still holds from the last one (ADR-0107).
#[tokio::test]
async fn a_grant_heard_between_handouts_keeps_the_stream_off_the_asked_ranges() {
    const BLOCK: u64 = rmule_peer::EMBLOCKSIZE;
    let file = rmule_testkit::file_link("switch.bin", &vec![0x5A; (4 * BLOCK) as usize]);
    let mut held = rmule_peer::AskedRanges::default();
    for block in 0..3 {
        held.insert(block * BLOCK, (block + 1) * BLOCK);
    }
    let (events_tx, mut events) = mpsc::channel(8);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
    let (event_tx, _worker_events) = mpsc::channel(16);
    let (_worker_cmd_tx, mut worker_cmd_rx) = mpsc::channel(8);
    events_tx
        .send(PeerEvent::Requester(RequesterEvent::SlotGranted {
            file_hash: file.file_hash,
            asked: held.clone(),
        }))
        .await
        .unwrap();
    let mut link = WorkerLink {
        events: &mut events,
        cmd_tx: &cmd_tx,
        event_tx: &event_tx,
        commands: &mut worker_cmd_rx,
        deferred: VecDeque::new(),
    };
    let mut pipeline = Pipeline::new();
    idle_wait(
        &mut link,
        &mut pipeline,
        file.file_hash,
        tokio::time::Instant::now(),
    )
    .await;
    drop(events_tx);
    streamed(
        &mut link,
        &mut pipeline,
        &file,
        &[block(0, 4 * BLOCK)],
        Duration::from_secs(5),
    )
    .await;
    let first = asked(&mut cmd_rx)
        .into_iter()
        .next()
        .expect("the stream asks");
    assert_eq!(first.len(), 3);
    assert!(
        first.iter().all(|&(start, end)| !held.contains(start, end)),
        "no block repeats a held range: {first:?}"
    );
}

/// Blocks handed while a stream waits queue behind what it holds and are
/// asked once its first byte proves the slot; the stream drains through both
/// (ADR-0117).
#[tokio::test]
async fn blocks_handed_mid_stream_queue_behind_the_rest() {
    let bytes = [0x5A; 1024];
    let file = rmule_testkit::file_link("handed.bin", &bytes);
    let (events_tx, mut events) = mpsc::channel(8);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
    let (event_tx, worker_events) = mpsc::channel(8);
    let (worker_cmd_tx, mut worker_cmd_rx) = mpsc::channel(8);
    worker_cmd_tx
        .send(PeerWorkerCommand::RequestBlocks {
            blocks: vec![block(512, 1024)],
        })
        .await
        .unwrap();
    for start in [0, 512] {
        events_tx
            .send(PeerEvent::Requester(RequesterEvent::PartReceived {
                file_hash: file.file_hash,
                offset: start,
                bytes: bytes[start as usize..start as usize + 512].to_vec(),
            }))
            .await
            .unwrap();
    }
    let mut link = WorkerLink {
        events: &mut events,
        cmd_tx: &cmd_tx,
        event_tx: &event_tx,
        commands: &mut worker_cmd_rx,
        deferred: VecDeque::new(),
    };
    let ended = streamed(
        &mut link,
        &mut Pipeline::new(),
        &file,
        &[block(0, 512)],
        Duration::from_secs(5),
    )
    .await;
    assert!(matches!(ended, Streamed::Next));
    assert!(link.deferred.is_empty(), "the handout was taken");
    assert_eq!(asked(&mut cmd_rx), vec![vec![(0, 512)], vec![(512, 1024)]]);
    drop(link);
    drop(event_tx);
    assert_eq!(drained(worker_events).await.last(), Some(&DRAINED));
}

/// The download's hash-set ask, handed to a granted worker while its blocks
/// stream, leaves at once rather than at the drain: the uploader is asked
/// while the transfer runs, and the blocks stream on (ADR-0026).
#[tokio::test]
async fn the_hash_set_ask_leaves_while_blocks_stream() {
    let bytes = [0x5A; 512];
    let file = rmule_testkit::file_link("asked.bin", &bytes);
    let (events_tx, mut events) = mpsc::channel(8);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
    let (event_tx, worker_events) = mpsc::channel(8);
    let (worker_cmd_tx, mut worker_cmd_rx) = mpsc::channel(8);
    worker_cmd_tx
        .send(PeerWorkerCommand::RequestHashSet)
        .await
        .unwrap();
    events_tx
        .send(PeerEvent::Requester(RequesterEvent::PartReceived {
            file_hash: file.file_hash,
            offset: 0,
            bytes: bytes.to_vec(),
        }))
        .await
        .unwrap();
    let mut link = WorkerLink {
        events: &mut events,
        cmd_tx: &cmd_tx,
        event_tx: &event_tx,
        commands: &mut worker_cmd_rx,
        deferred: VecDeque::new(),
    };
    let ended = streamed(
        &mut link,
        &mut Pipeline::new(),
        &file,
        &[block(0, 512)],
        Duration::from_secs(5),
    )
    .await;
    assert!(matches!(ended, Streamed::Next));
    assert!(link.deferred.is_empty(), "nothing waits for the drain");
    drop(link);
    drop(cmd_tx);
    let mut sent = Vec::new();
    while let Some(command) = cmd_rx.recv().await {
        sent.push(command);
    }
    assert!(
        sent.contains(&PeerCommand::Requester(RequesterCommand::RequestHashSet {
            file_hash: file.file_hash
        })),
        "{sent:?}"
    );
    drop(event_tx);
    assert_eq!(drained(worker_events).await.last(), Some(&DRAINED));
}

/// Run [`work_the_link`] with the probe answered and `first` arriving on the
/// link, the download handing the file's one block at once and nothing more, under a slot
/// budget of 100 ms; the commands the worker framed onto the link, in order.
async fn worked_until_the_budget(first: Option<PeerEvent>) -> Vec<PeerCommand> {
    let file = rmule_testkit::file_link("stall.bin", &[0x5A; 1024]);
    let (events_tx, requester_rx) = mpsc::channel(8);
    let (peer_cmd_tx, mut peer_cmd_rx) = mpsc::channel(32);
    let (event_tx, _worker_events) = mpsc::channel(32);
    let (command_tx, command_rx) = mpsc::channel(8);
    events_tx
        .send(PeerEvent::Requester(RequesterEvent::FileProbed {
            file_hash: file.file_hash,
            status: FileProbeStatus::Available {
                file_name: rmule_primitives::Ed2kText::from_utf8("stall.bin"),
                bitmap: rmule_peer::PartBitmap::one_part_complete(),
                complete: true,
            },
        }))
        .await
        .unwrap();
    if let Some(first) = first {
        events_tx.send(first).await.unwrap();
    }
    command_tx
        .send(PeerWorkerCommand::RequestBlocks {
            blocks: vec![block(0, 1024)],
        })
        .await
        .unwrap();
    work_the_link(
        WorkerHalves {
            peer_cmd_tx,
            requester_rx,
        },
        None,
        &file,
        rmule_peer::PartBitmap::downloader_empty(1024),
        false,
        command_rx,
        event_tx,
        Duration::from_millis(100),
    )
    .await;
    drop((events_tx, command_tx));
    let mut sent = Vec::new();
    while let Ok(command) = peer_cmd_rx.try_recv() {
        sent.push(command);
    }
    sent
}

/// A granted slot that delivers no byte for the slot budget goes back with
/// `OP_CANCELTRANSFER`, as aMule's downloader cancels at `DOWNLOADTIMEOUT`
/// (`DownloadClient.cpp:1188-1196`, ADR-0056 item 4); a stream that never
/// held a grant ends silently.
#[tokio::test]
async fn a_granted_slot_that_streams_nothing_for_the_budget_is_given_back() {
    let file_hash = rmule_testkit::file_link("stall.bin", &[0x5A; 1024]).file_hash;
    let granted = PeerEvent::Requester(RequesterEvent::SlotGranted {
        file_hash,
        asked: rmule_peer::AskedRanges::default(),
    });
    let teardown = |sent: &[PeerCommand]| sent.last().cloned();
    assert!(matches!(
        teardown(&worked_until_the_budget(Some(granted)).await),
        Some(PeerCommand::Requester(
            RequesterCommand::CancelTransfer { .. }
        ))
    ));
    assert!(matches!(
        teardown(&worked_until_the_budget(None).await),
        Some(PeerCommand::Requester(RequesterCommand::ReleaseSlot { .. }))
    ));
}
