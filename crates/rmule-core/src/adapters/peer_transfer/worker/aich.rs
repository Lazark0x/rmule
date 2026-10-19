//! The AICH recovery detour a corrupt part sends a worker on (ADR-0038): the
//! `OP_AICHREQUEST` its link holds open, the answer forwarded when it comes —
//! while blocks stream or before the worker idles — and the empty answer that
//! stands in at the slot budget or the link's end, so the download falls back
//! to retire-all rather than stranding the part.

use rmule_peer::{ConnectionEvent, PeerCommand, PeerEvent, RequesterCommand, RequesterEvent};
use rmule_primitives::{AichRootHash, FileHash};

use super::WorkerLink;
use crate::adapters::peer_transfer::PeerWorkerEvent;

impl WorkerLink<'_> {
    /// Ask the peer for the AICH recovery data of `part`, quoting the trusted
    /// master `root` (`OP_AICHREQUEST`, ADR-0038), and start its budget.
    /// `false` when the link is gone, reported as `Disconnected`.
    pub(super) async fn ask_aich(
        &mut self,
        file_hash: FileHash,
        part: u16,
        root: AichRootHash,
    ) -> bool {
        let ask = RequesterCommand::RequestAich {
            file_hash,
            part,
            root,
        };
        if self.cmd_tx.send(PeerCommand::Requester(ask)).await.is_err() {
            let _ = self.event_tx.send(PeerWorkerEvent::Disconnected).await;
            return false;
        }
        self.aich = Some((part, tokio::time::Instant::now() + self.aich_budget));
        true
    }

    /// What `event` does to the AICH ask held: the peer's answer for its part
    /// ends it, returned for the caller to forward; the link's end ends it with
    /// an empty answer, sent here, so the download falls back to retire-all.
    pub(super) async fn settle_aich(
        &mut self,
        file_hash: FileHash,
        event: &Option<PeerEvent>,
    ) -> Option<PeerWorkerEvent> {
        let (part, _) = self.aich?;
        match event {
            Some(PeerEvent::Requester(RequesterEvent::AichAnswerReceived {
                file_hash: answered,
                part: answered_part,
                recovery_data,
                ..
            })) if *answered == file_hash && *answered_part == part => {
                self.aich = None;
                Some(PeerWorkerEvent::AichAnswerReceived {
                    part,
                    recovery_data: recovery_data.clone(),
                })
            }
            None | Some(PeerEvent::Connection(ConnectionEvent::Disconnected { .. })) => {
                self.give_up_aich().await;
                None
            }
            Some(_) => None,
        }
    }

    /// The AICH ask held went unanswered: an empty answer stands in, so the
    /// download falls back to retire-all. `false` when the download is gone.
    pub(super) async fn give_up_aich(&mut self) -> bool {
        let Some((part, _)) = self.aich.take() else {
            return true;
        };
        self.event_tx
            .send(PeerWorkerEvent::AichAnswerReceived {
                part,
                recovery_data: Vec::new(),
            })
            .await
            .is_ok()
    }
}

/// Wait for the answer to the AICH ask `link` holds and forward it to core
/// (ADR-0038). The recovery data verifies against the trusted root core-side,
/// so asking any connected peer is safe. At the ask's budget, or a disconnect,
/// forwards an *empty* answer so the runner resolves the awaiting part via the
/// MD4 retire-all fallback rather than stranding it. Other events meanwhile
/// are not read for the download. Returns `false` (winding the worker down)
/// only on disconnect.
pub(super) async fn await_aich_answer(link: &mut WorkerLink<'_>, file_hash: FileHash) -> bool {
    let Some((_, due)) = link.aich else {
        return true;
    };
    loop {
        match tokio::time::timeout_at(due, link.events.recv()).await {
            Ok(event) => {
                let ended = matches!(
                    event,
                    None | Some(PeerEvent::Connection(ConnectionEvent::Disconnected { .. }))
                );
                let answer = link.settle_aich(file_hash, &event).await;
                if ended {
                    let _ = link.event_tx.send(PeerWorkerEvent::Disconnected).await;
                    return false;
                }
                if let Some(answer) = answer {
                    return link.event_tx.send(answer).await.is_ok();
                }
            }
            Err(_) => return link.give_up_aich().await,
        }
    }
}
