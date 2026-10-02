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
use crate::own_identity::SharedOwnIdentity;
use crate::service::DownloadId;

/// The hello context for one spawn, read from the session's live self-facts:
/// `ctx` is built once at fleet start, but a worker spawned after a
/// mid-session `OP_IDCHANGE` must stamp the id the server holds *now*, and one spawned after the
/// operator connected, reconnected or moved must name the server of that session, or none without
/// one — aMule reads both at send time. Only the identity is the fleet's own.
fn live_client_id(ctx: &PeerHandshakeContext, own: &SharedOwnIdentity) -> PeerHandshakeContext {
    crate::server_session::live_peer_handshake_context(&ctx.identity, own)
}

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

    /// End the live worker at `peer`: tell it `Shutdown { cancel: false }` and
    /// drop its channel, so its later facts read as stale.
    pub(super) async fn end(&mut self, peer: PeerEndpoint) {
        if let Some(at) = self.live.iter().position(|c| c.peer == peer) {
            let channel = self.live.swap_remove(at);
            channel
                .send(PeerWorkerCommand::Shutdown { cancel: false })
                .await;
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
            let mut peer_transfer = self.runner.peer_transfer.lock().await;
            peer_transfer
                .start_download_worker(
                    peer,
                    live_client_id(&self.ctx, self.runner.server_session.own_identity()),
                    self.file.clone(),
                    brief,
                )
                .await
        };
        let mut worker = started.map_err(|_| ())?;
        self.runner
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
    use rmule_peer::{Hello, HelloAdvert, PeerHelloBody};
    use std::net::Ipv4Addr;

    use rmule_primitives::{ClientId, ClientIdentity, Ed2kText, Ipv4Endpoint, UserHash};

    use super::*;
    use crate::own_identity::ConnectedSession;

    fn identity() -> ClientIdentity {
        ClientIdentity::new(
            UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
            Ed2kText::from_utf8("worker-pool-test"),
            4662,
            60,
        )
    }

    /// A fleet's `ctx` is built once at download start; a worker spawned
    /// after a mid-session `OP_IDCHANGE` must still stamp the id the session
    /// holds *now*, not the one the fleet started with — proven
    /// at the wire frame, not just the struct.
    #[test]
    fn a_spawn_after_a_mid_session_reassignment_stamps_the_new_id_in_the_hello() {
        let own = SharedOwnIdentity::default();
        own.set_connected_session(Some(ConnectedSession {
            server: None,
            client_id: ClientId::from_u32(0x0000_2A57),
        }));
        let ctx = PeerHandshakeContext {
            identity: identity(),
            client_id: ClientId::from_u32(0x0000_2A57),
            connected_server: None,
        };
        assert_eq!(
            live_client_id(&ctx, &own).client_id,
            ClientId::from_u32(0x0000_2A57),
            "still logged in with the fleet's own id"
        );

        // The mid-session OP_IDCHANGE (`reassign_client_id`): `ctx`
        // itself never changes, only the session self-facts it is read
        // against at each spawn.
        own.reassign_client_id(ClientId::from_u32(0x0100_007F));
        let refreshed = live_client_id(&ctx, &own);
        assert_eq!(
            refreshed.client_id,
            ClientId::from_u32(0x0100_007F),
            "the fleet's ctx is stale; the live read is not"
        );

        // Decode the hello bytes: the wire round trip a peer worker actually
        // sends carries the new id, not the fleet-start one.
        let hello = Hello::new(PeerHelloBody::from_handshake_context(
            &refreshed,
            &HelloAdvert::default(),
        ));
        let decoded = Hello::decode_packet(&hello.encode_packet())
            .expect("a hello we just built decodes")
            .into_body();
        assert_eq!(decoded.client_id, ClientId::from_u32(0x0100_007F));
    }

    /// A hello names the server of the session it rides — whatever
    /// server the download was started on — and none without a session,
    /// as aMule's `SendHelloTypePacket` writes the connected server or zeros
    /// (`BaseClient.cpp:1621-1628`). Read at the wire frame.
    #[test]
    fn a_spawn_names_the_live_sessions_server_and_none_without_one() {
        let own = SharedOwnIdentity::default();
        let stored = Ipv4Endpoint::new(Ipv4Addr::new(192, 0, 2, 1), 4661);
        let live = Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4242);
        // The fleet was started naming its stored server.
        let ctx = PeerHandshakeContext {
            identity: identity(),
            client_id: ClientId::from_u32(0x0100_007F),
            connected_server: Some(stored),
        };
        let wire = |ctx: &PeerHandshakeContext| {
            let hello = Hello::new(PeerHelloBody::from_handshake_context(
                ctx,
                &HelloAdvert::default(),
            ));
            Hello::decode_packet(&hello.encode_packet())
                .expect("a hello we just built decodes")
                .into_body()
        };

        let unconnected = wire(&live_client_id(&ctx, &own));
        assert_eq!(
            unconnected.connected_server,
            Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0),
            "no session: zeros"
        );
        assert_eq!(unconnected.client_id, ClientId::from_u32(0));

        own.set_connected_session(Some(ConnectedSession {
            server: Some(live),
            client_id: ClientId::from_u32(0x0100_007F),
        }));
        let connected = wire(&live_client_id(&ctx, &own));
        assert_eq!(connected.connected_server, live);
    }

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
        channels.end(peer).await;
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
