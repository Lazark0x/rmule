//! The block loop's reaction to the notices a shared link raises, and how the
//! probe wait and the block loop report a peer that lacks the file.

use rmule_peer::{FileProbeStatus, NoticeEvent, PeerError, PeerEvent, RequesterEvent};
use tokio::sync::mpsc;

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
    stream_part_download(&mut link, &file, plan, 0, Duration::from_secs(5)).await;
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
