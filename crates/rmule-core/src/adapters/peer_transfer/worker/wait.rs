//! The waits a worker shares between its connect-time probe and each part's
//! stream: reading the next peer event while serving the commands that arrive
//! first, the event arms both forward alike, and the probe wait the first
//! part waits on (ADR-0112).

use std::time::Duration;

use rmule_peer::{
    ConnectionEvent, FileProbeStatus, NoticeEvent, PeerCommand, PeerEvent, RequesterCommand,
    RequesterEvent,
};
use rmule_primitives::FileHash;
use tokio::sync::mpsc;

use super::{PartCommands, Streamed};
use crate::adapters::peer_transfer::{PeerWorkerCommand, PeerWorkerEvent};

/// Wait for the peer's answer to the connect-time file probe and report it as
/// `PartsAdvertised` (ADR-0112) — the event the brain assigns the worker's
/// first part on. The wait reads and serves what the part stream does
/// ([`next_event`], [`forward_shared`]) and is bounded by `timeout`, ending in
/// `SlotTimeout` like a stalled stream. A peer lacking the file reports no
/// parts, then `Disconnected`, and the worker ends.
pub(super) async fn await_probe(
    events: &mut mpsc::Receiver<PeerEvent>,
    cmd_tx: &mpsc::Sender<PeerCommand>,
    event_tx: &mpsc::Sender<PeerWorkerEvent>,
    mut commands: PartCommands<'_>,
    file_hash: FileHash,
    timeout: Duration,
) -> Streamed {
    let deadline = tokio::time::Instant::now() + timeout;
    let status = loop {
        let event =
            match next_event(events, cmd_tx, event_tx, &mut commands, file_hash, deadline).await {
                Ok(event) => event,
                Err(end) => return end,
            };
        match forward_shared(event_tx, file_hash, event).await {
            Forward::Own(PeerEvent::Requester(RequesterEvent::FileProbed {
                file_hash: probed,
                status,
            })) if probed == file_hash => break status,
            Forward::Done | Forward::Own(_) => {}
            Forward::Ended => return Streamed::WindDown,
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
    {
        return Streamed::WindDown;
    }
    if lacks_file {
        let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
        return Streamed::WindDown;
    }
    Streamed::Next
}

/// The worker's next peer event, the commands that arrive first served on
/// the way: the command channel is read first so a `Shutdown` is never
/// starved by a busy peer and stops the wait at once (aMule's
/// `CUpDownClient::Disconnected` aborts a transfer on the spot); an AICH root
/// ask goes out as it comes (ADR-0038); anything else waits in `deferred`. No
/// event by `deadline` reports `SlotTimeout`.
pub(super) async fn next_event(
    events: &mut mpsc::Receiver<PeerEvent>,
    cmd_tx: &mpsc::Sender<PeerCommand>,
    event_tx: &mpsc::Sender<PeerWorkerEvent>,
    commands: &mut PartCommands<'_>,
    file_hash: FileHash,
    deadline: tokio::time::Instant,
) -> Result<Option<PeerEvent>, Streamed> {
    loop {
        tokio::select! {
            biased;
            command = commands.rx.recv() => match command {
                Some(PeerWorkerCommand::Shutdown { cancel }) => {
                    return Err(Streamed::Shutdown { cancel });
                }
                Some(PeerWorkerCommand::RequestAichFileHash) => {
                    let _ = cmd_tx
                        .send(PeerCommand::Requester(RequesterCommand::RequestAichFileHash { file_hash }))
                        .await;
                }
                Some(later) => commands.deferred.push_back(later),
                None => return Err(Streamed::WindDown),
            },
            waited = tokio::time::timeout_at(deadline, events.recv()) => {
                return match waited {
                    Ok(event) => Ok(event),
                    Err(_) => {
                        let _ = event_tx.send(PeerWorkerEvent::SlotTimeout).await;
                        Err(Streamed::WindDown)
                    }
                };
            }
        }
    }
}

/// What [`forward_shared`] made of one peer event.
pub(super) enum Forward {
    /// Forwarded, or ignored as every wait ignores it.
    Done,
    /// The connection or the download side ended; `Disconnected` is sent
    /// when the peer's side did.
    Ended,
    /// An event only the caller's own wait reads.
    Own(PeerEvent),
}

/// The arms the probe wait and the part stream share: exchanged sources
/// (ADR-0055), a hash set and an AICH root proposal (ADR-0038) forwarded as
/// they come; a refused serving command ignored, since it concerns the serve
/// half (aMule's `RemoveFromUploadQueue` leaves the socket alone,
/// `UploadQueue.cpp:560-587`); any other refusal and the connection's end
/// reported as `Disconnected`.
pub(super) async fn forward_shared(
    event_tx: &mpsc::Sender<PeerWorkerEvent>,
    file_hash: FileHash,
    event: Option<PeerEvent>,
) -> Forward {
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
                return Forward::Ended;
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
            return Forward::Ended;
        }
        Some(event) => return Forward::Own(event),
    }
    Forward::Done
}
