//! The block loop's reaction to the notices a shared link raises, how the
//! probe wait and the block loop report a peer that lacks the file, and what
//! the wait between parts hears on the link.

use rmule_peer::{FileProbeStatus, NoticeEvent, PeerError, PeerEvent, RequesterEvent};
use tokio::sync::mpsc;

use super::wait::{Idled, idle_wait};
use super::*;
use crate::PartPlan;

/// Run [`stream_part_download`] over `bytes` with `notice` arriving before the
/// part's one block, and return the worker events it reported.
async fn events_after_notice(bytes: &[u8], notice: PeerError) -> Vec<PeerWorkerEvent> {
    events_after(bytes, |_| {
        PeerEvent::Notice(NoticeEvent::CommandRejected { reason: notice })
    })
    .await
}

/// Run [`stream_part_download`] over `bytes` with the event `first` makes of
/// the file's hash arriving before the part's one block, and return the
/// worker events it reported.
async fn events_after(
    bytes: &[u8],
    first: impl FnOnce(rmule_primitives::FileHash) -> PeerEvent,
) -> Vec<PeerWorkerEvent> {
    let file = rmule_testkit::file_link("notice.bin", bytes);
    let (events_tx, mut events) = mpsc::channel(8);
    let (cmd_tx, _cmd_rx) = mpsc::channel(8);
    let (event_tx, mut worker_events) = mpsc::channel(8);
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
    let plan = PartPlan {
        part_index: 0,
        offset: 0,
        len: bytes.len() as u64,
    };
    let mut link = WorkerLink {
        events: &mut events,
        cmd_tx: &cmd_tx,
        event_tx: &event_tx,
        commands: &mut worker_cmd_rx,
        deferred: VecDeque::new(),
    };
    stream_part_download(
        &mut link,
        &mut Pipeline::new(),
        &file,
        plan,
        0,
        Duration::from_secs(5),
    )
    .await;
    drop(event_tx);
    let mut reported = Vec::new();
    while let Some(event) = worker_events.recv().await {
        reported.push(event);
    }
    reported
}

#[tokio::test]
async fn a_refused_serving_command_does_not_end_the_download() {
    let reported = events_after_notice(&[0x5A; 1024], PeerError::ServeSlotNotGranted).await;
    assert!(
        reported.contains(&PeerWorkerEvent::PartStreamed { part_index: 0 }),
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
        file.file_hash,
        tokio::time::Instant::now() + budget,
    )
    .await;
    assert!(matches!(idled, Idled::Ended));
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
async fn the_wait_between_parts_hears_the_slot_and_the_links_end() {
    let file_hash = rmule_testkit::file_link("idle.bin", &[0x5A; 1024]).file_hash;
    let reported = idled_over(
        vec![
            PeerEvent::Requester(RequesterEvent::SlotAsked { file_hash }),
            PeerEvent::Requester(RequesterEvent::QueueRanked { file_hash, rank: 4 }),
            PeerEvent::Requester(RequesterEvent::SlotGranted { file_hash }),
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

/// A wait between parts that hears nothing within the slot budget ends the
/// worker with `SlotTimeout`.
#[tokio::test]
async fn a_silent_wait_between_parts_ends_at_the_slot_budget() {
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

/// A stream asks three blocks at once, then one more as each lands, so
/// two stay queued at the uploader while one arrives (ADR-0029).
#[tokio::test]
async fn a_part_streams_with_blocks_asked_ahead() {
    const BLOCK: u64 = rmule_peer::EMBLOCKSIZE;
    let bytes = vec![0x5A; (5 * BLOCK) as usize];
    let file = rmule_testkit::file_link("deep.bin", &bytes);
    let (events_tx, mut events) = mpsc::channel(8);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
    let (event_tx, mut worker_events) = mpsc::channel(16);
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
    let plan = PartPlan {
        part_index: 0,
        offset: 0,
        len: 5 * BLOCK,
    };
    let mut link = WorkerLink {
        events: &mut events,
        cmd_tx: &cmd_tx,
        event_tx: &event_tx,
        commands: &mut worker_cmd_rx,
        deferred: VecDeque::new(),
    };
    let streamed = stream_part_download(
        &mut link,
        &mut Pipeline::new(),
        &file,
        plan,
        0,
        Duration::from_secs(5),
    )
    .await;
    assert!(matches!(streamed, Streamed::Next));
    assert_eq!(
        asked(&mut cmd_rx),
        vec![
            vec![(0, BLOCK), (BLOCK, 2 * BLOCK), (2 * BLOCK, 3 * BLOCK)],
            vec![(3 * BLOCK, 4 * BLOCK)],
            vec![(4 * BLOCK, 5 * BLOCK)],
        ]
    );
    drop(event_tx);
    let mut reported = Vec::new();
    while let Some(event) = worker_events.recv().await {
        reported.push(event);
    }
    assert_eq!(
        reported.last(),
        Some(&PeerWorkerEvent::PartStreamed { part_index: 0 })
    );
}

/// A part handed mid-stream ends the old stream at once, without
/// `PartStreamed`, the new part waiting to be served next (ADR-0026).
#[tokio::test]
async fn a_part_handed_mid_stream_ends_the_old_one() {
    let file = rmule_testkit::file_link("handed.bin", &[0x5A; 1024]);
    let (_events_tx, mut events) = mpsc::channel(8);
    let (cmd_tx, _cmd_rx) = mpsc::channel(8);
    let (event_tx, mut worker_events) = mpsc::channel(8);
    let (worker_cmd_tx, mut worker_cmd_rx) = mpsc::channel(8);
    let next = PartPlan {
        part_index: 1,
        offset: 512,
        len: 512,
    };
    worker_cmd_tx
        .send(PeerWorkerCommand::RequestPart {
            plan: next,
            resume_offset: 512,
        })
        .await
        .unwrap();
    let mut link = WorkerLink {
        events: &mut events,
        cmd_tx: &cmd_tx,
        event_tx: &event_tx,
        commands: &mut worker_cmd_rx,
        deferred: VecDeque::new(),
    };
    let plan = PartPlan {
        part_index: 0,
        offset: 0,
        len: 512,
    };
    let streamed = stream_part_download(
        &mut link,
        &mut Pipeline::new(),
        &file,
        plan,
        0,
        Duration::from_secs(5),
    )
    .await;
    assert!(matches!(streamed, Streamed::Next));
    assert!(matches!(
        link.deferred.front(),
        Some(PeerWorkerCommand::RequestPart { plan, .. }) if *plan == next
    ));
    drop(link);
    drop(event_tx);
    assert_eq!(
        worker_events.recv().await,
        None,
        "no PartStreamed for the old part"
    );
}
