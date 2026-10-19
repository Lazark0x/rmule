//! The AICH recovery detour a corrupt part sends a worker on (ADR-0038): the
//! `OP_AICHREQUEST` its link holds open, one at a time, a later one leaving
//! once it settles; the answer forwarded by whichever wait reads it — while
//! blocks stream, the probe waits or the worker waits between handouts — so
//! the worker keeps hearing its link meanwhile (ADR-0117); and the empty
//! answer that stands in at the slot budget or the link's end, so the
//! download leaves the part to its refetch rather than stranding it.

use rmule_peer::{ConnectionEvent, PeerCommand, PeerEvent, RequesterCommand, RequesterEvent};
use rmule_primitives::{AichRootHash, FileHash};

use super::WorkerLink;
use crate::adapters::peer_transfer::PeerWorkerEvent;

impl WorkerLink<'_> {
    /// Ask the peer for the AICH recovery data of `part`, quoting the trusted
    /// master `root` (`OP_AICHREQUEST`, ADR-0038), and start its budget; with
    /// an ask already out, it leaves once that one settles. `false` when the
    /// link is gone, reported as `Disconnected`.
    pub(super) async fn ask_aich(
        &mut self,
        file_hash: FileHash,
        part: u16,
        root: AichRootHash,
    ) -> bool {
        if self.aich.is_some() {
            self.aich_queued.push_back((part, root));
            return true;
        }
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

    /// When the AICH ask out stops waiting for its answer, if one is out.
    pub(super) fn aich_due(&self) -> Option<tokio::time::Instant> {
        self.aich.map(|(_, due)| due)
    }

    /// What `event` does to the AICH ask out: the peer's answer for its part
    /// ends it, returned for the caller to forward, and the next ask leaves;
    /// the link's end ends every ask held with an empty answer, sent here, so
    /// the download leaves their parts to their refetch.
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
                self.ask_next_aich(file_hash).await;
                Some(PeerWorkerEvent::AichAnswerReceived {
                    part,
                    recovery_data: recovery_data.clone(),
                })
            }
            None | Some(PeerEvent::Connection(ConnectionEvent::Disconnected { .. })) => {
                self.aich = None;
                let queued: Vec<u16> = self.aich_queued.drain(..).map(|(part, _)| part).collect();
                for part in std::iter::once(part).chain(queued) {
                    if !self.unanswered(part).await {
                        break;
                    }
                }
                None
            }
            Some(_) => None,
        }
    }

    /// The AICH ask out went unanswered for its budget: an empty answer stands
    /// in, so the download leaves its part to its refetch, and the next ask
    /// leaves. `false` when the download is gone.
    pub(super) async fn give_up_aich(&mut self, file_hash: FileHash) -> bool {
        let Some((part, _)) = self.aich.take() else {
            return true;
        };
        if !self.unanswered(part).await {
            return false;
        }
        self.ask_next_aich(file_hash).await;
        true
    }

    /// Ask the next AICH recovery that waited for the one before it.
    async fn ask_next_aich(&mut self, file_hash: FileHash) {
        if let Some((part, root)) = self.aich_queued.pop_front() {
            self.ask_aich(file_hash, part, root).await;
        }
    }

    /// Tell the download `part`'s recovery ask is not answered. `false` when
    /// the download is gone.
    async fn unanswered(&self, part: u16) -> bool {
        self.event_tx
            .send(PeerWorkerEvent::AichAnswerReceived {
                part,
                recovery_data: Vec::new(),
            })
            .await
            .is_ok()
    }
}
