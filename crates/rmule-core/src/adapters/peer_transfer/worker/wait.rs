//! The waits a worker shares between its connect-time probe, the wait between
//! parts and each part's stream: reading the next peer event while serving the
//! commands that arrive first, the event arms all of them forward alike — the
//! slot's answers among them — the probe wait the slot ask waits on
//! (ADR-0112), and the wait between parts, which reads the link too (ADR-0026).

use std::time::Duration;

use rmule_peer::{
    ConnectionEvent, FileProbeStatus, NoticeEvent, PeerCommand, PeerEvent, RequesterCommand,
    RequesterEvent, SlotReleaseReason,
};
use rmule_primitives::FileHash;
use tokio::sync::mpsc;

use super::pipeline::Pipeline;
use super::{Streamed, WorkerLink};
use crate::adapters::peer_transfer::{PeerWorkerCommand, PeerWorkerEvent};

/// Wait for the peer's answer to the connect-time file probe and report it as
/// `PartsAdvertised` (ADR-0112) — the event the brain assigns the worker's
/// first part on. The wait reads and serves what the part stream does
/// ([`next_event`], [`forward_shared`]) and is bounded by `timeout`, ending in
/// `SlotTimeout` like a stalled stream. A peer lacking the file reports no
/// parts, its own fact the download retires it on (ADR-0090), and the worker
/// ends.
pub(super) async fn await_probe(
    link: &mut WorkerLink<'_>,
    file_hash: FileHash,
    timeout: Duration,
) -> Streamed {
    let event_tx = link.event_tx;
    let deadline = tokio::time::Instant::now() + timeout;
    let status = loop {
        let event = match next_event(link, file_hash, deadline).await {
            Ok(event) => event,
            // Never sent before the probe answers; served after it if it were.
            Err(Streamed::Reassigned) => continue,
            Err(end) => return end,
        };
        match forward_shared(event_tx, file_hash, event).await {
            Ok(Some(PeerEvent::Requester(RequesterEvent::FileProbed {
                file_hash: probed,
                status,
            }))) if probed == file_hash => break status,
            Ok(_) => {}
            Err(Ended) => return Streamed::WindDown,
        }
    };
    let (parts, complete) = match status {
        FileProbeStatus::Available {
            bitmap, complete, ..
        } => (Some(bitmap), complete),
        FileProbeStatus::NotAvailable => (None, false),
    };
    let lacks_file = parts.is_none();
    if event_tx
        .send(PeerWorkerEvent::PartsAdvertised { parts, complete })
        .await
        .is_err()
        || lacks_file
    {
        return Streamed::WindDown;
    }
    Streamed::Next
}

/// The worker's next peer event, the commands that arrive first served on
/// the way: the command channel is read first so a `Shutdown` is never
/// starved by a busy peer and stops the wait at once (aMule's
/// `CUpDownClient::Disconnected` aborts a transfer on the spot); an AICH root
/// ask (ADR-0038) and the download's hash-set ask, which only a granted
/// worker is handed (ADR-0026), go out as they come; a part handed meanwhile waits in
/// `deferred` and ends the wait as `Reassigned`; anything else waits in
/// `deferred`. No event by `deadline` reports `SlotTimeout` and ends the
/// wait as `Stalled`.
pub(super) async fn next_event(
    link: &mut WorkerLink<'_>,
    file_hash: FileHash,
    deadline: tokio::time::Instant,
) -> Result<Option<PeerEvent>, Streamed> {
    loop {
        tokio::select! {
            biased;
            command = link.commands.recv() => match command {
                Some(PeerWorkerCommand::Shutdown { cancel }) => {
                    return Err(Streamed::Shutdown { cancel });
                }
                Some(PeerWorkerCommand::RequestAichFileHash) => {
                    let _ = link.cmd_tx
                        .send(PeerCommand::Requester(RequesterCommand::RequestAichFileHash { file_hash }))
                        .await;
                }
                Some(PeerWorkerCommand::RequestHashSet) => {
                    let _ = link.cmd_tx
                        .send(PeerCommand::Requester(RequesterCommand::RequestHashSet { file_hash }))
                        .await;
                }
                Some(later @ PeerWorkerCommand::RequestPart { .. }) => {
                    // The download handed this worker a part while it works
                    // another: its old part is no longer its own (ADR-0026
                    // "Bounded racing"), so the wait ends and the new part is
                    // served next.
                    link.deferred.push_back(later);
                    return Err(Streamed::Reassigned);
                }
                Some(later) => link.deferred.push_back(later),
                None => return Err(Streamed::WindDown),
            },
            waited = tokio::time::timeout_at(deadline, link.events.recv()) => {
                return match waited {
                    Ok(event) => Ok(event),
                    Err(_) => {
                        let _ = link.event_tx.send(PeerWorkerEvent::SlotTimeout).await;
                        Err(Streamed::Stalled)
                    }
                };
            }
        }
    }
}

/// The connection or the download side ended; `Disconnected` was sent when
/// the peer's side did.
pub(super) struct Ended;

/// How the wait between parts ended.
pub(super) enum Idled {
    /// The download sent a command.
    Command(PeerWorkerCommand),
    /// `OP_OUTOFPARTREQS` queued the flow again: a new slot wait begins.
    Requeued,
    /// The link or the download ended the worker; whatever ended it was
    /// reported.
    Ended,
    /// The slot budget ran out with no command and no grant, reported as
    /// `SlotTimeout`; a slot the worker holds goes back (ADR-0056).
    Stalled,
}

/// Wait between parts for the download's next command, reading the link
/// meanwhile, so a queued worker hears its rank and grant and any worker hears
/// its link close at once (ADR-0026): the shared arms ([`forward_shared`]) and
/// the slot's answers ([`forward_slot_news`]) are forwarded as they come. No
/// command and no grant by `deadline` reports `SlotTimeout`. A grant hands
/// `pipeline` the link's Asked Ranges.
pub(super) async fn idle_wait(
    link: &mut WorkerLink<'_>,
    pipeline: &mut Pipeline,
    file_hash: FileHash,
    deadline: tokio::time::Instant,
) -> Idled {
    loop {
        let waited = tokio::select! {
            biased;
            command = link.commands.recv() => {
                return command.map_or(Idled::Ended, Idled::Command);
            }
            waited = tokio::time::timeout_at(deadline, link.events.recv()) => waited,
        };
        let Ok(event) = waited else {
            let _ = link.event_tx.send(PeerWorkerEvent::SlotTimeout).await;
            return Idled::Stalled;
        };
        let event = match forward_shared(link.event_tx, file_hash, event).await {
            Ok(Some(event)) => event,
            Ok(None) => continue,
            Err(Ended) => return Idled::Ended,
        };
        match forward_slot_news(link.event_tx, pipeline, file_hash, &event).await {
            Ok(Some(SlotNews::Requeued)) => return Idled::Requeued,
            Ok(Some(SlotNews::Noted) | None) => {}
            Err(Ended) => return Idled::Ended,
        }
    }
}

/// What a slot answer on the link came to once [`forward_slot_news`] read it.
pub(super) enum SlotNews {
    /// Forwarded, or ignored; keep waiting.
    Noted,
    /// `OP_OUTOFPARTREQS` queued the flow again, forwarded as `Requeued`.
    Requeued,
}

/// The slot's answers every wait after the probe forwards alike: the slot ask
/// leaving (`SlotAsked`), each rank (`Queued`), the grant, the flow queued
/// again (`Requeued`, ADR-0057); a peer saying mid-flow that it lacks the file
/// is reported as the probe reports it, and the slot's other ends as
/// `Disconnected`, both ending the worker. Our own release is ignored. The
/// grant hands `pipeline` the ranges the uploader still holds as asked of
/// the link, so no block repeats one (ADR-0107).
/// `Ok(None)` for an event that is no slot answer, the caller's own to read.
pub(super) async fn forward_slot_news(
    event_tx: &mpsc::Sender<PeerWorkerEvent>,
    pipeline: &mut Pipeline,
    file_hash: FileHash,
    event: &PeerEvent,
) -> Result<Option<SlotNews>, Ended> {
    let PeerEvent::Requester(requester) = event else {
        return Ok(None);
    };
    let (report, news) = match requester {
        RequesterEvent::SlotAsked { file_hash: asked } if *asked == file_hash => {
            (PeerWorkerEvent::SlotAsked, SlotNews::Noted)
        }
        RequesterEvent::QueueRanked {
            file_hash: ranked,
            rank,
        }
        | RequesterEvent::QueueProgress {
            file_hash: ranked,
            new_rank: rank,
            ..
        } if *ranked == file_hash => (PeerWorkerEvent::Queued { rank: *rank }, SlotNews::Noted),
        RequesterEvent::SlotGranted {
            file_hash: granted,
            asked,
        } if *granted == file_hash => {
            pipeline.granted(asked);
            (PeerWorkerEvent::SlotGranted, SlotNews::Noted)
        }
        RequesterEvent::Requeued {
            file_hash: requeued,
        } if *requeued == file_hash => (PeerWorkerEvent::Requeued, SlotNews::Requeued),
        RequesterEvent::SlotReleased {
            file_hash: released,
            reason: SlotReleaseReason::DownloadComplete,
        } if *released == file_hash => return Ok(Some(SlotNews::Noted)),
        // A mid-flow `OP_FILEREQANSNOFIL`: the peer lacks the file after all,
        // reported as the probe reports it, and the download retires the
        // source on it (ADR-0090).
        RequesterEvent::FileProbed {
            file_hash: probed,
            status: FileProbeStatus::NotAvailable,
        } if *probed == file_hash => {
            let _ = event_tx
                .send(PeerWorkerEvent::PartsAdvertised {
                    parts: None,
                    complete: false,
                })
                .await;
            return Err(Ended);
        }
        RequesterEvent::SlotReleased {
            file_hash: released,
            ..
        } if *released == file_hash => {
            let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
            return Err(Ended);
        }
        _ => return Ok(None),
    };
    match event_tx.send(report).await {
        Ok(()) => Ok(Some(news)),
        Err(_) => Err(Ended),
    }
}

/// The arms the probe wait and the part stream share: exchanged sources
/// (ADR-0055), a hash set and an AICH root proposal (ADR-0038) forwarded as
/// they come; a refused serving command ignored, since it concerns the serve
/// half (aMule's `RemoveFromUploadQueue` leaves the socket alone,
/// `UploadQueue.cpp:560-587`); any other refusal and the connection's end
/// reported as `Disconnected`. `Ok(None)` when the event was forwarded or
/// ignored, `Ok(Some(event))` for one only the caller's own wait reads.
pub(super) async fn forward_shared(
    event_tx: &mpsc::Sender<PeerWorkerEvent>,
    file_hash: FileHash,
    event: Option<PeerEvent>,
) -> Result<Option<PeerEvent>, Ended> {
    match event {
        Some(PeerEvent::Requester(RequesterEvent::HashSetReceived {
            file_hash: received,
            part_hashes,
        })) if received == file_hash => {
            if event_tx
                .send(PeerWorkerEvent::HashSetReceived { part_hashes })
                .await
                .is_err()
            {
                return Err(Ended);
            }
        }
        Some(PeerEvent::Requester(RequesterEvent::SourcesReceived {
            file_hash: received,
            sources,
        })) if received == file_hash => {
            let _ = event_tx
                .send(PeerWorkerEvent::SourcesReceived { sources })
                .await;
        }
        // No file guard: the 0x9D answer carries no file hash.
        Some(PeerEvent::Requester(RequesterEvent::AichFileHashReceived { root })) => {
            let _ = event_tx
                .send(PeerWorkerEvent::AichFileHashReceived { root })
                .await;
        }
        Some(PeerEvent::Notice(NoticeEvent::CommandRejected { reason }))
            if reason.is_serving_refusal() => {}
        Some(PeerEvent::Notice(NoticeEvent::CommandRejected { .. }))
        | Some(PeerEvent::Connection(ConnectionEvent::Disconnected { .. }))
        | None => {
            let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
            return Err(Ended);
        }
        Some(event) => return Ok(Some(event)),
    }
    Ok(None)
}
