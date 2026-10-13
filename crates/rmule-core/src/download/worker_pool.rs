//! The live peer-worker fleet for one download: the pool that spawns a worker
//! per candidate slot, the command channel each worker listens on, and the
//! shutdown that tears the fleet down. It holds no scheduling policy — the brain
//! decides who works, this only keeps the handles.

use rmule_peer::PeerHandshakeContext;
use rmule_primitives::Ed2kFileLink;
use rmule_primitives::PeerEndpoint;
use tokio::sync::mpsc;
use tracing::Instrument;

use crate::adapters::{
    PeerTransferService, PeerWorker, PeerWorkerCommand, PeerWorkerEvent, SourceLookupService,
    WorkerBrief,
};
use crate::download::runner::RunnerContext;
use crate::service::DownloadId;

/// One spawned worker's incarnation: no two workers ever put on the wire by
/// one run share one, even at the same endpoint. The facts a worker reports
/// carry it, so a late fact from a worker the brain already released — its
/// `Disconnected` after the `Shutdown`, a block it was still streaming — is
/// told apart from the live worker a re-spawn put at the same endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct WorkerId(pub(super) u64);

/// A worker's fact on the shared stream: which incarnation, at which endpoint.
pub(super) type WorkerFact = (WorkerId, PeerEndpoint, PeerWorkerEvent);

/// The live command channel + diagnostics slot for one spawned worker.
pub(super) struct WorkerCommandChannel {
    pub(super) id: WorkerId,
    pub(super) peer: PeerEndpoint,
    pub(super) slot: crate::diagnostics::WorkerSlot,
    tx: mpsc::Sender<PeerWorkerCommand>,
}

impl WorkerCommandChannel {
    /// Send `command`. A closed channel is a worker that just ended; its
    /// terminal fact retires it (ADR-0030), so a dropped send is benign.
    pub(super) async fn send(&self, command: PeerWorkerCommand) {
        let _ = self.tx.send(command).await;
    }
}

/// The runner's live workers' command channels: exactly the workers the
/// brain holds, one per endpoint. A channel joins when its worker is put on the
/// wire and leaves when the brain releases it ([`Self::end`]) — so a `Send`
/// for an endpoint reaches the worker living there now, never an ended one's
/// closed channel. `DownloadState` owns the scheduling-side worker identity
/// (peer -> slot, connected) and the candidate pool / free slots.
#[derive(Default)]
pub(super) struct WorkerChannels {
    minted: u64,
    live: Vec<WorkerCommandChannel>,
}

impl WorkerChannels {
    /// Register a worker just put on the wire at `peer`, minting its
    /// incarnation. A channel still registered at `peer` is dropped, which
    /// closes it and ends that worker at its next command read.
    pub(super) fn register(
        &mut self,
        peer: PeerEndpoint,
        slot: crate::diagnostics::WorkerSlot,
        tx: mpsc::Sender<PeerWorkerCommand>,
    ) -> WorkerId {
        self.minted += 1;
        let id = WorkerId(self.minted);
        self.live.retain(|c| c.peer != peer);
        self.live.push(WorkerCommandChannel { id, peer, slot, tx });
        id
    }

    /// Send `command` to the live worker at `peer`, if any.
    pub(super) async fn send(&self, peer: PeerEndpoint, command: PeerWorkerCommand) {
        if let Some(channel) = self.live.iter().find(|c| c.peer == peer) {
            channel.send(command).await;
        }
    }

    /// End the live worker at `peer`: tell it `Shutdown { cancel }` and drop
    /// its channel, so its later facts read as stale. `cancel` gives back a
    /// slot the peer granted with `OP_CANCELTRANSFER` (ADR-0056).
    pub(super) async fn end(&mut self, peer: PeerEndpoint, cancel: bool) {
        if let Some(at) = self.live.iter().position(|c| c.peer == peer) {
            let channel = self.live.swap_remove(at);
            channel.send(PeerWorkerCommand::Shutdown { cancel }).await;
        }
    }

    /// Whether `worker` is still live — a fact from any other is stale.
    pub(super) fn is_live(&self, worker: WorkerId) -> bool {
        self.live.iter().any(|c| c.id == worker)
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &WorkerCommandChannel> {
        self.live.iter()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.live.is_empty()
    }
}

/// The context needed to put one candidate source on the wire (ADR-0030).
/// `DownloadState` owns the candidate pool, the free slots, and the
/// concurrency cap and decides *who* to spawn into *which* slot; this struct
/// is the spawn mechanism the runner uses to enact a `Spawn` decision. It
/// keeps `fact_tx` alive for the whole run so a worker spawned mid-download
/// can join the shared event stream.
pub(super) struct WorkerPool<'a, S, P> {
    pub(super) runner: &'a RunnerContext<S, P>,
    pub(super) file: &'a Ed2kFileLink,
    pub(super) ctx: PeerHandshakeContext,
    pub(super) fact_tx: mpsc::Sender<WorkerFact>,
}

impl<S, P> WorkerPool<'_, S, P>
where
    S: SourceLookupService,
    P: PeerTransferService,
{
    /// Put one candidate `peer` on the wire in diagnostics `slot`, enacting a
    /// `Spawn` decision. On success the worker gets a fact-forwarding task
    /// feeding the shared event stream and is registered while it connects
    /// (identification arrives later as a `Connected` / `Disconnected` worker
    /// event, ADR-0030). `Err(())` means the source could not even start a
    /// worker — the caller hands it back to `DownloadState::on_spawn_failed`
    /// to free the slot and try the next candidate.
    pub(super) async fn spawn_one(
        &mut self,
        download_id: DownloadId,
        peer: PeerEndpoint,
        slot: crate::diagnostics::WorkerSlot,
        brief: WorkerBrief,
        command_channels: &mut WorkerChannels,
    ) -> Result<(), ()> {
        let started = {
            let mut peer_transfer = self.runner.rt.peer_transfer.lock().await;
            peer_transfer
                .start_download_worker(
                    peer,
                    // `ctx` is built once at fleet start; the id and the
                    // server are read at each spawn, as aMule reads both at
                    // send time — only the identity is the fleet's own.
                    crate::server_session::live_peer_handshake_context(
                        &self.ctx.identity,
                        &self.runner.rt.reach,
                    ),
                    self.file.clone(),
                    brief,
                )
                .await
        };
        let mut worker = started.map_err(|_| ())?;
        self.runner
            .rt
            .diagnostics
            .attach_worker(download_id, slot, peer);
        let id = command_channels.register(peer, slot, worker.command_sender());
        let fact_tx = self.fact_tx.clone();
        let worker_span = tracing::info_span!(
            "peer_worker",
            worker_slot = slot.as_usize(),
            peer = %peer,
        );
        tokio::spawn(
            async move {
                while let Some(event) = worker.next_event().await {
                    if fact_tx.send((id, peer, event)).await.is_err() {
                        break;
                    }
                }
            }
            .instrument(worker_span),
        );
        Ok(())
    }

    /// Register a pre-built adopted worker (a called-back Low-ID peer, ADR-0039)
    /// into diagnostics `slot` and the runner's `command_channels`, then forward
    /// its events onto the shared stream — the registration half of
    /// [`Self::spawn_one`] without the dial. The peer dialed *in*, but
    /// `DownloadState::on_callback_connected` now binds it **without assigning**
    /// The worker's own `Connected` event flows the normal assignment
    /// path exactly like a dialed worker, so it is forwarded here verbatim rather
    /// than filtered — the invariant (adopt = bind, `Connected` = assign) lives in
    /// one place, the brain.
    pub(super) fn register_adopted(
        &self,
        download_id: DownloadId,
        peer: PeerEndpoint,
        slot: crate::diagnostics::WorkerSlot,
        mut worker: PeerWorker,
        command_channels: &mut WorkerChannels,
    ) {
        self.runner
            .rt
            .diagnostics
            .attach_worker(download_id, slot, peer);
        let id = command_channels.register(peer, slot, worker.command_sender());
        let fact_tx = self.fact_tx.clone();
        let worker_span = tracing::info_span!(
            "peer_worker",
            worker_slot = slot.as_usize(),
            peer = %peer,
        );
        tokio::spawn(
            async move {
                while let Some(event) = worker.next_event().await {
                    if fact_tx.send((id, peer, event)).await.is_err() {
                        break;
                    }
                }
            }
            .instrument(worker_span),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A worker ended at release and a fresh one re-spawned at the same
    /// endpoint: a command for that endpoint reaches the live worker,
    /// never the ended one's channel, and the ended one's facts read as stale.
    #[tokio::test]
    async fn a_command_for_a_respawned_endpoint_reaches_the_live_worker() {
        let peer = PeerEndpoint::V4(rmule_primitives::Ipv4Endpoint::new(
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            4662,
        ));
        let slot = crate::diagnostics::WorkerSlot::from_usize(0);
        let mut channels = WorkerChannels::default();
        let (ended_tx, mut ended_rx) = mpsc::channel(4);
        let ended = channels.register(peer, slot, ended_tx);
        channels.end(peer, false).await;
        let (live_tx, mut live_rx) = mpsc::channel(4);
        let live = channels.register(peer, slot, live_tx);

        channels
            .send(peer, PeerWorkerCommand::RequestAichFileHash)
            .await;

        assert!(matches!(
            live_rx.try_recv(),
            Ok(PeerWorkerCommand::RequestAichFileHash)
        ));
        assert!(matches!(
            ended_rx.try_recv(),
            Ok(PeerWorkerCommand::Shutdown { cancel: false })
        ));
        assert!(
            ended_rx.try_recv().is_err(),
            "the ended worker got nothing more"
        );
        assert!(!channels.is_live(ended) && channels.is_live(live));
    }
}
