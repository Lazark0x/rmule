//! The download's reask leg (ADR-0057 §2): the **Remote-Queued Pool**, the
//! per-peer facts observed off the worker event stream that feed it, the sweep
//! that ticks a due `OP_REASKFILEPING` (`0x90`) out the shared client-UDP send,
//! and the `0x91`/`0x92`/`0x93` reply quartet that feeds back. A ranked-then-
//! hung-up source keeps its earned queue standing here without holding a socket.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use rmule_peer::ReaskFilePing;
use rmule_primitives::PeerEndpoint;
use tokio::sync::mpsc;

use crate::adapters::{PeerTransferService, PeerWorkerEvent, SourceLookupService};
use crate::client_udp::{ClientUdpDatagram, ClientUdpSend, PeerUdpCryptTarget};
use crate::download::remote_queue::{ReaskAction, RemoteQueuedPool, ReplyOutcome, UdpContact};
use crate::download::state::{Decision, DownloadState};
use crate::error::DownloadFailure;
use crate::peer_roster::{PeerRelation, SharedPeerRoster};
use crate::service::{DownloadEvent, DownloadId, SharedReaskReplySink, send_download_event};

use super::enact::{LoopCtx, enact_drain};

/// How often the reask sweep polls the Remote-Queued Pool (ADR-0057). aMule's
/// download-queue `Process` runs about once a second; the reask *period* stays
/// the stock `FILEREASKTIME` — this is only the poll cadence, comfortably finer
/// than the 20 s UDP-ping window so a due ping is never missed.
pub(super) const REASK_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// The download runner's live reask state (ADR-0057): the **Remote-Queued
/// Pool**, the per-peer facts observed off the worker event stream that feed it,
/// and the live client-UDP send half its `0x90` pings ride. Built per download;
/// its sink lease routes the shared socket's reply quartet here for its life.
pub(super) struct ReaskWiring {
    pub(super) pool: RemoteQueuedPool,
    /// Per-peer facts since the worker connected: the peer's client-UDP reask
    /// contact (from `UdpContact`) and, once it queued us, the rank + the instant
    /// we learned it — the reask clock origin. aMule dates the cycle from ask
    /// time, so a source pooled on hang-up reasks on schedule, not a slot-wait
    /// later.
    pub(super) observed: HashMap<PeerEndpoint, PeerReaskObservation>,
    /// The client-UDP send half a `0x90` reask ping rides out; `None` when the
    /// shared socket did not bind (every reask then falls to the TCP full ask).
    pub(super) client_udp_tx: Option<mpsc::Sender<ClientUdpSend>>,
    /// Clears this download's reply-sink install on drop.
    pub(super) _sink_lease: ReaskSinkLease,
    /// The one Peer Roster (ADR-0059 "Roster relations"): every
    /// pooled source holds a `Queued` relation for this download, added as it
    /// enters the pool and removed as it leaves — or, for whatever is still
    /// pooled when the download ends, as this wiring drops.
    pub(super) peer_roster: SharedPeerRoster,
    /// Whose `Queued` relations these are.
    pub(super) download_id: DownloadId,
}

impl ReaskWiring {
    /// Pool `peer` (ADR-0057) and mark it known: a source that queued us and
    /// hung up is aMule's `DS_ONQUEUE` client, still in the client list.
    fn enter_pool(
        &mut self,
        peer: PeerEndpoint,
        contact: Option<UdpContact>,
        rank: u16,
        at: Instant,
    ) {
        self.pool.enter(peer, contact, rank, at);
        if let Some(v4) = peer.as_v4() {
            self.peer_roster
                .mark_known(PeerRelation::Queued(self.download_id), v4);
        }
    }

    /// Take `peer` out of the pool; its `Queued` relation ends with it.
    fn leave_pool(&mut self, peer: PeerEndpoint) -> bool {
        let pooled = self.pool.remove(peer);
        self.forget_queued(peer);
        pooled
    }

    /// Hold `endpoint` for this download's `0x90` in the shared **Reask
    /// Routes** (ADR-0107); `false` while another download's ping there is
    /// unanswered.
    fn claim_ping(&self, endpoint: PeerEndpoint, download_id: DownloadId) -> bool {
        self._sink_lease
            .sink
            .lock()
            .expect("reask reply sink mutex")
            .claim_ping(endpoint, download_id, Instant::now())
    }

    /// End `peer`'s `Queued` relation — the pool already let it go.
    fn forget_queued(&self, peer: PeerEndpoint) {
        if let Some(v4) = peer.as_v4() {
            self.peer_roster
                .forget(PeerRelation::Queued(self.download_id), v4);
        }
    }
}

/// The download's end is the pool's terminal event: every source still pooled
/// leaves the roster with it, however the runner exits.
impl Drop for ReaskWiring {
    fn drop(&mut self) {
        for peer in self.pool.peers() {
            self.forget_queued(peer);
        }
    }
}

#[derive(Default, Clone, Copy)]
pub(super) struct PeerReaskObservation {
    pub(super) udp_contact: Option<UdpContact>,
    pub(super) queued: Option<(u16, Instant)>,
}

/// RAII lease on one download's reply-sink install in the shared **Reask
/// Routes**: removes that install and its pings in flight — and only those —
/// on drop, so a finished download stops receiving reask replies while the
/// downloads beside it keep theirs.
pub(super) struct ReaskSinkLease {
    sink: SharedReaskReplySink,
    download_id: DownloadId,
}

impl ReaskSinkLease {
    /// Install `reply_tx` as `download_id`'s reply sink for the lease's life.
    pub(super) fn install(
        sink: SharedReaskReplySink,
        download_id: DownloadId,
        reply_tx: mpsc::Sender<ClientUdpDatagram>,
    ) -> Self {
        sink.lock()
            .expect("reask reply sink mutex")
            .install(download_id, reply_tx);
        Self { sink, download_id }
    }
}

impl Drop for ReaskSinkLease {
    fn drop(&mut self) {
        self.sink
            .lock()
            .expect("reask reply sink mutex")
            .remove(self.download_id);
    }
}

/// Observe one worker event for reask standing (ADR-0057), *before* the
/// scheduling brain acts on it. Records the peer's client-UDP contact and queue
/// rank; on a retire *while queued* it pools the source — keeping its earned
/// standing — and tells the brain it is remote-queued (so the brain's release
/// does not fail the download, and a sighting does not pool it twice); a grant
/// or transfer clears any standing.
pub(super) async fn observe_worker_event_for_reask<S, P>(
    reask: &mut ReaskWiring,
    ctx: &mut LoopCtx<'_, S, P>,
    peer: PeerEndpoint,
    event: &PeerWorkerEvent,
) where
    S: SourceLookupService,
    P: PeerTransferService,
{
    match event {
        PeerWorkerEvent::UdpContact {
            udp_port,
            udp_version,
        } => {
            // The peer's UDP contact is its own address at the port its hello
            // advertised, in its own **Address Family**: the client-UDP
            // surface is a Family Pair (ADR-0085) and the reask quartet is
            // byte-identical over IPv6 (ADR-0087), so an IPv6 source earns a
            // UDP contact exactly as an IPv4 one does.
            reask.observed.entry(peer).or_default().udp_contact = Some(UdpContact {
                endpoint: peer.with_port(*udp_port),
                version: *udp_version,
            });
        }
        PeerWorkerEvent::Queued { rank } => {
            reask.observed.entry(peer).or_default().queued = Some((*rank, Instant::now()));
        }
        // The peer-side half of the source-ask gate (ADR-0108), kept past
        // this connection for the sweep below.
        PeerWorkerEvent::SourceExchange { support } => {
            ctx.source_ask_clock.learned(peer, *support);
        }
        // A grant or any transfer progress means the source is live, not
        // reask-standing: drop it from the pool and clear its queued mark.
        PeerWorkerEvent::SlotGranted
        | PeerWorkerEvent::BlockReceived { .. }
        | PeerWorkerEvent::PartStreamed { .. } => {
            if reask.leave_pool(peer) {
                ctx.state.leave_remote_queue(peer);
            }
            if let Some(obs) = reask.observed.get_mut(&peer) {
                obs.queued = None;
            }
        }
        // A worker retiring while it held a queue rank hangs up but keeps its
        // standing: pool it on the ask-time clock and hand the brain its
        // membership, so its terminal `NoUsableSources` check keeps the
        // download alive and a sighting merges instead of re-pooling.
        PeerWorkerEvent::Disconnected
        | PeerWorkerEvent::SlotTimeout
        | PeerWorkerEvent::SlotRejected => {
            if let Some(obs) = reask.observed.remove(&peer)
                && let Some((rank, queued_at)) = obs.queued
            {
                reask.enter_pool(peer, obs.udp_contact, rank, queued_at);
                // `OP_OUTOFPARTREQS` (`SlotRejected`) means the source holds no
                // part we need: reask it at ×2 the period, TCP-only, until it does
                // (aMule `DS_NONEEDEDPARTS`).
                if matches!(event, PeerWorkerEvent::SlotRejected) {
                    reask.pool.set_no_needed_parts(peer, true);
                }
                ctx.state.enter_remote_queue(peer);
                send_download_event(
                    ctx.evt_tx,
                    DownloadEvent::SourceRemoteQueued {
                        download_id: ctx.download_id,
                        peer,
                        rank,
                    },
                )
                .await;
            }
        }
        _ => {}
    }
}

/// Run one reask sweep (ADR-0057): tick the pool and enact each due action — a
/// UDP `0x90` ping out the shared socket, or a TCP full ask that pulls the source
/// back into the brain's candidate pool to re-dial.
pub(super) async fn drive_reask_sweep<S, P>(
    reask: &mut ReaskWiring,
    ctx: &mut LoopCtx<'_, S, P>,
) -> Result<(), DownloadFailure>
where
    S: SourceLookupService,
    P: PeerTransferService,
{
    // The ADR-0057 reask gate is aMule's `!IsFirewalled()`
    // (`DownloadClient.cpp:1269`), asked of Self Reach at the sweep
    // — never a copy of it.
    let reachable = !ctx.callbacks.facts.reach.firewalled();
    let now = Instant::now();
    // aMule asks `IsSourceRequestAllowed` at ping time and leaves a source
    // whose ask is due to the TCP reask, which carries it (stock 2.3.3
    // `DownloadClient.cpp:1269-1273`, ADR-0108): re-read for every pooled
    // source at every sweep, because the answer moves with the clock.
    let counts = ctx.state.source_counts();
    let due: Vec<_> = reask
        .pool
        .peers()
        .map(|peer| {
            let due = ctx.source_ask_clock.due(peer, now, counts);
            (peer, due)
        })
        .collect();
    for (peer, due) in due {
        reask.pool.set_sx_due(peer, due);
    }
    for action in reask.pool.tick(now, reachable) {
        match action {
            ReaskAction::UdpPing {
                peer,
                udp_endpoint,
                udp_version,
            } => {
                // The version-gated `0x90` for the download's file: our part
                // status when the source is UDPv4 (`> 3`), our complete-source
                // count when `> 2` (rmule tracks none, so `0` — honest and
                // wire-shaped). Ride it out the shared client-UDP socket, with
                // the source's crypt target attached — aMule gates its own
                // `UDPReaskForDownload` send on the very same per-peer predicate
                // (`ShouldReceiveCryptUDPPackets`, `DownloadClient.cpp`).
                if let Some(tx) = &reask.client_udp_tx {
                    // One `0x90` in flight per peer endpoint across the
                    // Download Set (ADR-0107): the reply names no file, so a
                    // second download's ping to this endpoint waits for the
                    // next sweep until the first is answered or lapses.
                    if !reask.claim_ping(udp_endpoint, ctx.download_id) {
                        reask.pool.defer_udp_ping(peer);
                        continue;
                    }
                    let ping = ReaskFilePing {
                        file_hash: ctx.file.file_hash,
                        part_status: (udp_version > 3).then(|| ctx.state.our_part_status()),
                        complete_sources: (udp_version > 2).then_some(0),
                    }
                    .encode_udp();
                    let _ = tx
                        .send(ClientUdpSend::to_peer(
                            udp_endpoint,
                            ping,
                            hello_udp_crypt_target(&ctx.state, peer),
                        ))
                        .await;
                }
            }
            ReaskAction::TcpFullAsk { peer } => {
                // The FILEREASKTIME fallback / direct path: the source leaves the
                // pool and rejoins the brain's candidates, which re-dials it (the
                // existing TCP reask machinery). Single-ownership — a source is
                // either pooled standing or a brain candidate/worker, never both.
                reask.leave_pool(peer);
                reask.observed.remove(&peer);
                let mut q: VecDeque<Decision> = ctx.state.readd_source(peer).into();
                enact_drain(&mut q, ctx).await?;
            }
        }
    }
    Ok(())
}

/// Consume one reask reply datagram (`0x91`/`0x92`/`0x93`) into its source's
/// standing (ADR-0057) and surface the outcome as a download event — a reply
/// that changed nothing included, with its reason, and counted.
pub(super) async fn consume_reask_reply<S, P>(
    reask: &mut ReaskWiring,
    ctx: &mut LoopCtx<'_, S, P>,
    udp_src: PeerEndpoint,
    datagram: &[u8],
) where
    S: SourceLookupService,
    P: PeerTransferService,
{
    let event = match reask
        .pool
        .on_reply_datagram(Instant::now(), udp_src, datagram)
    {
        ReplyOutcome::RankRecorded {
            peer,
            rank,
            complete,
        } => {
            // A UDPv4 ack's part status is an advertisement like a probe's
            // (aMule `ProcessFileStatus(true, …)`, stock 2.3.3
            // `ClientUDPSocket.cpp:258-260`; ADR-0108).
            if let Some(complete) = complete {
                ctx.source_ask_clock
                    .advertised(peer, complete, Instant::now());
            }
            Some(DownloadEvent::SourceReaskAcked {
                download_id: ctx.download_id,
                peer,
                rank,
            })
        }
        ReplyOutcome::QueueFull { peer } => Some(DownloadEvent::SourceReaskQueueFull {
            download_id: ctx.download_id,
            peer,
        }),
        ReplyOutcome::Dropped { peer } => {
            // It no longer has the file: aMule drops the source and with it
            // `m_bCompleteSource` (ADR-0108).
            ctx.source_ask_clock.advertised(peer, false, Instant::now());
            reask.forget_queued(peer);
            ctx.state.leave_remote_queue(peer);
            Some(DownloadEvent::SourceReaskDropped {
                download_id: ctx.download_id,
                peer,
            })
        }
        ReplyOutcome::Ignored { reason } => {
            ctx.runner
                .diagnostics
                .count_reask_reply_ignored(ctx.download_id);
            Some(DownloadEvent::ReaskReplyIgnored {
                download_id: ctx.download_id,
                peer: udp_src,
                reason,
            })
        }
    };
    if let Some(event) = event {
        send_download_event(ctx.evt_tx, event).await;
    }
}

/// The source's peer-UDP crypt target (ADR-0046) — the User Hash and stance
/// its own hello stated, read off the download's one hello attachment
/// (`hello_crypts`, ADR-0049) rather than a second copy: a `0x90` is
/// obfuscated only if that stance (and ours) allows it, and a source whose
/// hello no worker read has no target, so its reask goes plain. aMule gates
/// its `UDPReaskForDownload` on the same client flags the TCP dial reads
/// (`ShouldReceiveCryptUDPPackets`, `BaseClient.cpp:2631-2633`).
fn hello_udp_crypt_target(state: &DownloadState, peer: PeerEndpoint) -> Option<PeerUdpCryptTarget> {
    let hello = state.hello_crypt(peer)?;
    Some(PeerUdpCryptTarget::new(hello.user_hash()?, hello.stance()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two downloads of the **Download Set** hold installs side by side, and
    /// one ending removes only its own — the other keeps its replies.
    #[test]
    fn a_sink_lease_removes_only_its_own_install() {
        let sink = SharedReaskReplySink::default();
        let (first_tx, _first_rx) = mpsc::channel(1);
        let (second_tx, _second_rx) = mpsc::channel(1);
        let first = ReaskSinkLease::install(sink.clone(), DownloadId::from_u64(1), first_tx);
        let _second = ReaskSinkLease::install(sink.clone(), DownloadId::from_u64(2), second_tx);
        assert_eq!(sink.lock().unwrap().installed(), 2);

        drop(first);
        assert_eq!(sink.lock().unwrap().installed(), 1);
    }
}
